/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Signal processing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
// Universal unwind backtrace via GCC's libgcc — works on glibc AND musl, static AND dynamic
#if defined(USE_UNWIND)
#  include <unwind.h>
#  include <limits.h>    // PATH_MAX
#  include <inttypes.h>  // SCNxPTR — portable sscanf format for uintptr_t
#  include <sys/mman.h>  // mmap() — used for the intentional crash test subcommand
#  include <dlfcn.h>     // dladdr() — dynamic symbol lookup from .dynsym
#endif
#include "signals.h"
// logging routines
#include "log.h"
// ls_dir()
#include "files.h"
// gettid()
#include "daemon.h"
// Eventqueue routines
#include "events.h"
// sleepms()
#include "timers.h"
// struct config
#include "config/config.h"

#define BINARY_NAME "pihole-FTL"

volatile sig_atomic_t killed = 0;
static volatile pid_t mpid = 0;
static time_t FTLstarttime = 0;
volatile int exit_code = EXIT_SUCCESS;

// Binary path stored by init_backtrace() — signal-handler-safe static buffer,
// never reallocated, safe to read from any context including signal handlers
#if defined(USE_UNWIND)
static char bin_path[PATH_MAX] = { 0 };
#endif

#if defined(USE_UNWIND)
// PIE load base address — set once at startup by init_backtrace() using the
// __ehdr_start linker symbol (GNU ld / lld / mold). __ehdr_start points to the
// ELF header in memory, which equals the ASLR slide for PIE binaries and the
// static load address for non-PIE. Either way: file_vaddr = runtime_addr -
// exe_load_addr is exactly what addr2line expects. This is a linker symbol, not
// a libc function, so it is reliable on glibc AND musl, static AND dynamic —
// unlike dl_iterate_phdr, whose behaviour for static executables varies across
// musl versions and may leave exe_load_addr == 0.
static uintptr_t exe_load_addr = 0;
// Provided by the linker for every ELF executable (GNU ld, lld, mold, gold).
extern const char __ehdr_start;
#endif // USE_UNWIND

// Initialize the backtrace subsystem.
// Must be called early in main() (before handle_signals()) so that bin_path
// and exe_load_addr are ready when the first crash handler fires.
void init_backtrace(const char *argv0)
{
#if defined(USE_UNWIND)
	// /proc/self/exe gives the canonical absolute path even when argv[0] is
	// a relative path, a bare binary name, or a symlink.
	ssize_t len = readlink("/proc/self/exe", bin_path, sizeof(bin_path) - 1u);
	if(len > 0)
		bin_path[len] = '\0';
	else if(argv0 != NULL)
	{
		strncpy(bin_path, argv0, sizeof(bin_path) - 1u);
		bin_path[sizeof(bin_path) - 1u] = '\0';
	}

	// Cache the PIE load base address for addr2line offset adjustment.
	// __ehdr_start is a linker symbol pointing at the ELF header in memory,
	// which equals the ASLR load base for PIE binaries.
	exe_load_addr = (uintptr_t)&__ehdr_start;
#else
	// Unused, cannot generate backtraces right now on non-gcc targets —
	// this silences a warning about unused parameters in this case
	(void)argv0;
#endif // USE_UNWIND
}

#if defined(USE_UNWIND)
// State carried through each _Unwind_Backtrace callback invocation
struct unwind_state {
	void **frames;
	int    count;
	int    max;
};

// Callback invoked by _Unwind_Backtrace for each frame on the call stack.
// Signal-handler-safe: no heap allocation, no stdio, no locks.
static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context *ctx, void *arg)
{
	struct unwind_state *state = (struct unwind_state *)arg;
	if(state->count >= state->max)
		return _URC_END_OF_STACK;
	uintptr_t ip = _Unwind_GetIP(ctx);
	if(ip == 0)
		return _URC_END_OF_STACK;
	// Subtract 1 so the address points at the call instruction rather than
	// the return address — addr2line then resolves the correct source line.
	state->frames[state->count++] = (void *)(ip - 1u);
	return _URC_NO_REASON;
}
#endif // USE_UNWIND (unwind_callback)

#if defined(USE_UNWIND)
// Look up which /proc/self/maps entry contains addr and copy the basename
// of the mapped file (e.g. "libc.so.6", "[vdso]") into buf.
// buf is left empty when the address is not found or has no path.
static void find_mapping_name(const void *addr, char *buf, const size_t buflen)
{
	FILE *maps = fopen("/proc/self/maps", "r");
	if(maps == NULL)
		return;

	const uintptr_t a = (uintptr_t)addr;
	char line[512];
	while(fgets(line, sizeof(line), maps) != NULL)
	{
		uintptr_t start = 0, end = 0;
		char path[256] = { 0 };
		// Format: start-end perms offset dev inode [path]
		// Use %*s (not %*llx etc.) to avoid the GNU -Wformat= restriction
		// that forbids combining the assignment-suppression modifier with a
		// length modifier. We only care about start, end, and path.
		const int n = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %*s %*s %*s %*s %255s",
		                     &start, &end, path);
		if(n >= 2 && a >= start && a < end && path[0] != '\0')
		{
			const char *base = strrchr(path, '/');
			strncpy(buf, base ? base + 1 : path, buflen - 1u);
			buf[buflen - 1u] = '\0';
			break;
		}
	}
	fclose(maps);
}

// Log one backtrace frame as a single line.
// Resolved:   "  #N  func_name                    src/file.c:line"
// Unresolved: "  #N  0xADDRESS  (reason)"
static void log_frame(const int idx, const void *addr, const void *rel_addr)
{
	if(!config.misc.addr2line.v.b)
	{
		log_info("  #%-2i  %p  (addr2line disabled via config)", idx, addr);
		return;
	}
	if(bin_path[0] == '\0')
	{
		log_info("  #%-2i  %p  (binary path unknown)", idx, addr);
		return;
	}

	char cmd[512];
	snprintf(cmd, sizeof(cmd), "addr2line -f -e %s %p", bin_path, rel_addr);

	FILE *fp = popen(cmd, "r");
	if(fp == NULL)
	{
		log_info("  #%-2i  %p  (addr2line not available)", idx, addr);
		return;
	}

	char func[256] = { 0 }, loc[256] = { 0 };
	if(fgets(func, sizeof(func), fp) != NULL)
	{
		char *nl = strchr(func, '\n');
		if(nl != NULL) *nl = '\0';
	}
	if(fgets(loc, sizeof(loc), fp) != NULL)
	{
		char *nl = strchr(loc, '\n');
		if(nl != NULL) *nl = '\0';
	}
	pclose(fp);

	if(strcmp(func, "??") == 0)
	{
		// addr2line found nothing — the frame is in a shared library or a
		// stripped section.  Try dladdr() which reads .dynsym, the dynamic
		// symbol table present in every shared library (even stripped ones).
		Dl_info dl = { 0 };
		if(dladdr(addr, &dl) != 0 && dl.dli_sname != NULL)
		{
			// Library basename (e.g. "libc.so.6")
			const char *lib = dl.dli_fname ? strrchr(dl.dli_fname, '/') : NULL;
			const char *libname = lib ? lib + 1 : (dl.dli_fname ? dl.dli_fname : "?");
			// Byte offset from the nearest preceding symbol
			const uintptr_t offset = (uintptr_t)addr - (uintptr_t)dl.dli_saddr;
			log_info("  #%-2i  %p  (%s  %s+0x%zx)", idx, addr, libname, dl.dli_sname, (size_t)offset);
		}
		else
		{
			// dladdr() gave nothing — fall back to /proc/self/maps for at
			// least the library/mapping name ([vdso], [stack], etc.).
			char mapping[128] = { 0 };
			find_mapping_name(addr, mapping, sizeof(mapping));
			if(mapping[0] != '\0')
				log_info("  #%-2i  %p  (%s, no debug info)", idx, addr, mapping);
			else
				log_info("  #%-2i  %p  (no debug info)", idx, addr);
		}
		return;
	}

	// Strip the compile-time source root to show project-relative paths
	// (e.g. "src/signals.c:42" instead of "/home/user/FTL/src/signals.c:42").
	const char *display_loc = loc;
#if defined(SOURCE_ROOT)
	if(strncmp(loc, SOURCE_ROOT, sizeof(SOURCE_ROOT) - 1u) == 0)
		display_loc = loc + sizeof(SOURCE_ROOT) - 1u;
#endif

	log_info("  #%-2i  %-30s  %s", idx, func, display_loc);
}
#endif // USE_UNWIND

volatile sig_atomic_t thread_cancellable[THREADS_MAX] = { false };
const char * const thread_names[THREADS_MAX] = {
	"database",
	"housekeeper",
	"dns-client",
	"timer",
	"ntp-client",
	"ntp-server4",
	"ntp-server6",
	"webserver",
};

// Private prototypes
static void terminate(void);

// Return the (null-terminated) name of the calling thread
// The name is stored in the buffer as well as returned for convenience
static char * __attribute__ ((nonnull (1))) getthread_name(char buffer[16])
{
	prctl(PR_GET_NAME, buffer, 0, 0, 0);
	return buffer;
}


// Log backtrace to the FTL log.
// Uses _Unwind_Backtrace (GCC libgcc) on all targets — glibc AND musl,
// static-pie AND dynamic, all architectures.
void generate_backtrace(void)
{
#if defined(USE_UNWIND)
	void *frames[128];
	struct unwind_state state = { frames, 0, 128 };
	_Unwind_Backtrace(unwind_callback, &state);

	log_info("Backtrace (%d frames):", state.count);
	for(int i = 0; i < state.count; i++)
	{
		void *rel = (void *)((uintptr_t)frames[i] - exe_load_addr);
		log_frame(i, frames[i], rel);
	}
#else
	log_info("!!! INFO: pihole-FTL has not been compiled with unwinding support, cannot generate backtrace !!!");
#endif
}

/**
 * @brief Terminates the program due to an error.
 *
 * This function sets the exit code to indicate failure and raises a SIGTERM
 * signal to terminate the main process. It is intended to be called when a
 * critical error occurs that requires the program to exit.
 */
static void terminate_error(void)
{
	exit_code = EXIT_FAILURE;
	raise(SIGTERM);
}

static void __attribute__((noreturn)) signal_handler(int sig, siginfo_t *si, void *context)
{
	(void)context;
	log_info("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	log_info("---------------------------->  FTL crashed!  <----------------------------");
	log_info("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	log_info("Please report a bug at https://github.com/pi-hole/FTL/issues");
	log_info("and include in your report already the following details:");

	if(FTLstarttime != 0)
	{
		log_info("FTL has been running for %lli seconds", (long long)time(NULL) - FTLstarttime);
	}
	log_FTL_version(true);
	char namebuf[16];
	log_info("Process details: MID: %i", mpid);
	log_info("                 PID: %i", getpid());
	log_info("                 TID: %i", gettid());
	log_info("                 Name: %s", getthread_name(namebuf));

	log_info("Received signal: %s", strsignal(sig));
	log_info("     at address: %p", si->si_addr);

	// Segmentation fault - program crashed
	if(sig == SIGSEGV)
	{
		switch (si->si_code)
		{
			case SEGV_MAPERR:  log_info("     with code:  SEGV_MAPERR (Address not mapped to object)"); break;
			case SEGV_ACCERR:  log_info("     with code:  SEGV_ACCERR (Invalid permissions for mapped object)"); break;
#ifdef SEGV_BNDERR
			case SEGV_BNDERR:  log_info("     with code:  SEGV_BNDERR (Failed address bound checks)"); break;
#endif
#ifdef SEGV_PKUERR
			case SEGV_PKUERR:  log_info("     with code:  SEGV_PKUERR (Protection key checking failure)"); break;
#endif
#ifdef SEGV_ACCADI
			case SEGV_ACCADI:  log_info("     with code:  SEGV_ACCADI (ADI not enabled for mapped object)"); break;
#endif
#ifdef SEGV_ADIDERR
			case SEGV_ADIDERR: log_info("     with code:  SEGV_ADIDERR (Disrupting MCD error)"); break;
#endif
#ifdef SEGV_ADIPERR
			case SEGV_ADIPERR: log_info("     with code:  SEGV_ADIPERR (Precise MCD exception)"); break;
#endif
			default:           log_info("     with code:  Unknown (%i)", si->si_code); break;
		}
	}

	// Bus error - memory manager problem
	else if(sig == SIGBUS)
	{
		switch (si->si_code)
		{
			case BUS_ADRALN:    log_info("     with code:  BUS_ADRALN (Invalid address alignment)"); break;
			case BUS_ADRERR:    log_info("     with code:  BUS_ADRERR (Non-existent physical address)"); break;
			case BUS_OBJERR:    log_info("     with code:  BUS_OBJERR (Object specific hardware error)"); break;
#if defined (BUS_MCEERR_AR)
			// 2025-May: not defined by uClibc
			case BUS_MCEERR_AR: log_info("     with code:  BUS_MCEERR_AR (Hardware memory error: action required)"); break;
#endif
#if defined (BUS_MCEERR_AO)
			// 2025-May: not defined by uClibc
			case BUS_MCEERR_AO: log_info("     with code:  BUS_MCEERR_AO (Hardware memory error: action optional)"); break;
#endif
			default:            log_info("     with code:  Unknown (%i)", si->si_code); break;
		}
	}

	// Illegal error - Illegal instruction detected
	else if(sig == SIGILL)
	{
		switch (si->si_code)
		{
			case ILL_ILLOPC:   log_info("     with code:  ILL_ILLOPC (Illegal opcode)"); break;
			case ILL_ILLOPN:   log_info("     with code:  ILL_ILLOPN (Illegal operand)"); break;
			case ILL_ILLADR:   log_info("     with code:  ILL_ILLADR (Illegal addressing mode)"); break;
			case ILL_ILLTRP:   log_info("     with code:  ILL_ILLTRP (Illegal trap)"); break;
			case ILL_PRVOPC:   log_info("     with code:  ILL_PRVOPC (Privileged opcode)"); break;
			case ILL_PRVREG:   log_info("     with code:  ILL_PRVREG (Privileged register)"); break;
			case ILL_COPROC:   log_info("     with code:  ILL_COPROC (Coprocessor error)"); break;
			case ILL_BADSTK:   log_info("     with code:  ILL_BADSTK (Internal stack error)"); break;
#ifdef ILL_BADIADDR
			case ILL_BADIADDR: log_info("     with code:  ILL_BADIADDR (Unimplemented instruction address)"); break;
#endif
			default:           log_info("     with code:  Unknown (%i)", si->si_code); break;
		}
	}

	// Floating point exception error
	else if(sig == SIGFPE)
	{
		switch (si->si_code)
		{
			case FPE_INTDIV:   log_info("     with code:  FPE_INTDIV (Integer divide by zero)"); break;
			case FPE_INTOVF:   log_info("     with code:  FPE_INTOVF (Integer overflow)"); break;
			case FPE_FLTDIV:   log_info("     with code:  FPE_FLTDIV (Floating point divide by zero)"); break;
			case FPE_FLTOVF:   log_info("     with code:  FPE_FLTOVF (Floating point overflow)"); break;
			case FPE_FLTUND:   log_info("     with code:  FPE_FLTUND (Floating point underflow)"); break;
			case FPE_FLTRES:   log_info("     with code:  FPE_FLTRES (Floating point inexact result)"); break;
			case FPE_FLTINV:   log_info("     with code:  FPE_FLTINV (Floating point invalid operation)"); break;
			case FPE_FLTSUB:   log_info("     with code:  FPE_FLTSUB (Subscript out of range)"); break;
#ifdef FPE_FLTUNK
			case FPE_FLTUNK:   log_info("     with code:  FPE_FLTUNK (Undiagnosed floating-point exception)"); break;
#endif
#ifdef FPE_CONDTRAP
			case FPE_CONDTRAP: log_info("     with code:  FPE_CONDTRAP (Trap on condition)"); break;
#endif
			default:           log_info("     with code:  Unknown (%i)", si->si_code); break;
		}
	}

	generate_backtrace();

	// Flush stdout immediately so the backtrace is visible even if a
	// subsequent fault in cleanup() kills the process before exit() runs.
	fflush(stdout);

	// Print content of /dev/shm
	ls_dir("/dev/shm");

	log_info("Please also include some lines from above the !!!!!!!!! header.");
	log_info("Thank you for helping us to improve our FTL engine!");

	// Terminate main process if crash happened in a TCP worker
	if(main_pid() != getpid())
	{
		// This is a forked process
		log_info("Asking parent pihole-FTL (PID %i) to shut down", (int)mpid);
		kill(mpid, SIGRTMIN+2);
		log_info("FTL fork terminated!");

		// Terminate fork indicating failure
		exit(EXIT_FAILURE);
	}
	else if(gettid() != getpid())
	{
		// This is a thread, signal to the main process to shut down
		log_info("Shutting down thread...");
		terminate_error();

		// Exit the thread here, it failed anyway
		pthread_exit(NULL);
	}
	else
	{
		// This is the main process
		cleanup(EXIT_FAILURE);

		// Terminate process indicating failure
		exit(EXIT_FAILURE);
	}
}

static void SIGRT_handler(int signum, siginfo_t *si, void *context)
{
	(void)context;
	(void)si;
	// Backup errno
	const int _errno = errno;

	// Ignore real-time signals outside of the main process (TCP forks)
	if(mpid != getpid())
	{
		// Restore errno before returning
		errno = _errno;
		return;
	}

	int rtsig = signum - SIGRTMIN;
	log_info("Received: %s (%d -> %d)", strsignal(signum), signum, rtsig);

	if(rtsig == 0)
	{
		// Reload
		// - gravity
		// - allowed domains and regex
		// - denied domains and regex
		// WITHOUT wiping the DNS cache itself
		set_event(RELOAD_GRAVITY);
	}
	else if(rtsig == 2)
	{
		// Terminate FTL indicating failure
		terminate_error();
	}
	else if(rtsig == 3)
	{
		// Reimport alias-clients from database
		set_event(REIMPORT_ALIASCLIENTS);
	}
	else if(rtsig == 4)
	{
		// Re-resolve all clients and forward destinations
		// Force refreshing hostnames according to
		// REFRESH_HOSTNAMES config option
		set_event(RERESOLVE_HOSTNAMES_FORCE);
	}
	else if(rtsig == 5)
	{
		// Parse neighbor cache
		set_event(PARSE_NEIGHBOR_CACHE);
	}
	// else if(rtsig == 6)
	// {
	// 	// Signal internally used to signal dnsmasq it has to stop
	// }
	else if(rtsig == 7)
	{
		// Search for hash collisions in the lookup tables
		set_event(SEARCH_LOOKUP_HASH_COLLISIONS);
	}

	// SIGRT32: Used internally by valgrind, do not use

	// Restore errno before returning back to previous context
	errno = _errno;
}

static void SIGTERM_handler(int signum, siginfo_t *si, void *context)
{
	(void)context;
	// Ignore SIGTERM outside of the main process (TCP forks)
	if(mpid != getpid())
	{
		log_debug(DEBUG_ANY, "Ignoring SIGTERM in TCP worker");
		return;
	}
	log_debug(DEBUG_ANY, "Received SIGTERM");

	// Get PID and UID of the process that sent the terminating signal
	const pid_t kill_pid = si->si_pid;
	const uid_t kill_uid = si->si_uid;

	// Get name of the process that sent the terminating signal
	char kill_name[256] = { 0 };
	char kill_exe [256] = { 0 };
	snprintf(kill_exe, sizeof(kill_exe), "/proc/%ld/cmdline", (long int)kill_pid);
	FILE *fp = fopen(kill_exe, "r");
	if(fp != NULL)
	{
		// Successfully opened file
		size_t read = 0;
		// Read line from file
		if((read = fread(kill_name, sizeof(char), sizeof(kill_name), fp)) > 0)
		{
			// Successfully read line

			// cmdline contains the command-line arguments as a set
			// of strings separated by null bytes ('\0'), with a
			// further null byte after the last string. Hence, we
			// need to replace all null bytes with spaces for
			// displaying it below
			for(unsigned int i = 0; i < min((size_t)read, sizeof(kill_name)); i++)
			{
				if(kill_name[i] == '\0')
					kill_name[i] = ' ';
			}

			// Remove any trailing spaces
			for(unsigned int i = read - 1; i > 0; i--)
			{
				if(kill_name[i] == ' ')
					kill_name[i] = '\0';
				else
					break;
			}
		}
		else
		{
			// Failed to read line
			strcpy(kill_name, "N/A");
		}
	}
	else
	{
		// Failed to open file
		strcpy(kill_name, "N/A");
	}

	// Get username of the process that sent the terminating signal
	char kill_user[256] = { 0 };
	struct passwd *pwd = getpwuid(kill_uid);
	if(pwd != NULL)
	{
		// Successfully obtained username
		strncpy(kill_user, pwd->pw_name, sizeof(kill_user));
	}
	else
	{
		// Failed to obtain username
		strcpy(kill_user, "N/A");
	}

	// Log who sent the signal
	log_info("Asked to terminate by \"%s\" (PID %ld, user %s UID %ld)",
	         kill_name, (long int)kill_pid, kill_user, (long int)kill_uid);

	// Check if we can terminate
	want_terminate = true;
	check_if_want_terminate();
}

// Checks if the program should terminate or not
static time_t last_term_warning = 0;
void check_if_want_terminate(void)
{
	if(!want_terminate)
		// We are not asked to terminate
		return;

	// Return early if we are not allowed to terminate
	if(gravity_running)
	{
		// Only log once every 30 seconds or if any debugging is enabled
		if(time(NULL) - last_term_warning > 30 || debug_flags[DEBUG_ANY])
		{
			log_info("Not terminating as gravity is still running...");
			last_term_warning = time(NULL);
		}
		return;
	}

	// Terminate if gravity is not running
	terminate();
}

// Terminates the DNS service by signaling or marking it as failed
static void terminate(void)
{
	// Terminate dnsmasq to stop DNS service
	if(!dnsmasq_failed)
	{
		log_debug(DEBUG_ANY, "Sending SIGUSR6 to dnsmasq to stop DNS service");
		raise(SIGUSR6);
	}
	else
	{
		log_debug(DEBUG_ANY, "Embedded dnsmasq failed, exiting on request");
		killed = true;
	}
}

// Register ordinary signals handler
void handle_signals(void)
{
	struct sigaction old_action;

	const int signals[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTERM };
	for(unsigned int i = 0; i < ArraySize(signals); i++)
	{
		// Catch this signal
		sigaction (signals[i], NULL, &old_action);
		if(old_action.sa_handler != SIG_IGN)
		{
			struct sigaction SIGaction = { 0 };
			SIGaction.sa_flags = SA_SIGINFO;
			sigemptyset(&SIGaction.sa_mask);
			SIGaction.sa_sigaction = signals[i] != SIGTERM ? &signal_handler : &SIGTERM_handler;
			sigaction(signals[i], &SIGaction, NULL);
		}
	}

	// Log start time of FTL
	FTLstarttime = time(NULL);
}

// Register real-time signal handler
void handle_realtime_signals(void)
{
	// This function is only called once (after forking), store the PID of
	// the main process
	mpid = getpid();

	// Catch all real-time signals
	for(int signum = SIGRTMIN; signum <= SIGRTMAX; signum++)
	{
		if(signum == SIGUSR6)
			// Skip SIGUSR6 as it is used internally to signify
			// dnsmasq to stop
			continue;
		if(signum == SIGUSR32)
			// Skip SIGUSR32 as it is used internally by valgrind
			// and should not be used
			continue;

		struct sigaction SIGACTION = { 0 };
		SIGACTION.sa_flags = SA_SIGINFO;
		sigemptyset(&SIGACTION.sa_mask);
		SIGACTION.sa_sigaction = &SIGRT_handler;
		sigaction(signum, &SIGACTION, NULL);
	}
}

// Return PID of the main FTL process
pid_t main_pid(void)
{
	if(mpid > 0)
		// Has already been set
		return mpid;
	else
		// Has not been set so far
		return getpid();
}

void thread_sleepms(const enum thread_types thread, const int milliseconds)
{
	if(killed)
		return;

	thread_cancellable[thread] = true;
	sleepms(milliseconds);
	thread_cancellable[thread] = false;
}

static void print_signal(int signum, siginfo_t *si, void *context)
{
	printf("Received signal %d: \"%s\"\n", signum, strsignal(signum));
	fflush(stdin);
	if(signum == SIGTERM)
		exit(EXIT_SUCCESS);
}

// Register handler that catches *all* signals and displays them
int sigtest(void)
{
	printf("PID: %d\n", getpid());
	// Catch all real-time signals
	for(int signum = 0; signum <= SIGRTMAX; signum++)
	{
		struct sigaction SIGACTION = { 0 };
		SIGACTION.sa_flags = SA_SIGINFO;
		sigemptyset(&SIGACTION.sa_mask);
		SIGACTION.sa_sigaction = &print_signal;
		sigaction(signum, &SIGACTION, NULL);
	}

	printf("Waiting (30sec)...\n");
	fflush(stdin);

	// Sleep here for 30 seconds
	sleepms(30000);

	// Exit successfully
	return EXIT_SUCCESS;
}

int sigrtmin(void)
{
	printf("%d\n", SIGRTMIN);
	return EXIT_SUCCESS;
}

void restart_ftl(const char *reason)
{
	log_info("Restarting FTL: %s", reason);
	exit_code = RESTART_FTL_CODE;
	// Send SIGTERM to FTL
	kill(main_pid(), SIGTERM);
}

/**
 * @brief Checks if the current process is being debugged.
 *
 * This function reads the /proc/self/status file to determine if the current
 * process is being debugged by looking for the TracerPid field. If the field
 * is found and has a non-zero value, it indicates that the process is being
 * debugged.
 *
 * @return The PID of the debugger if the process is being debugged, otherwise 0.
 */
pid_t debugger(void)
{
	FILE *status = fopen("/proc/self/status", "r");
	if(status == NULL)
	{
		// Failed to open status file, assume not being debugged
		log_debug(DEBUG_ANY, "Failed to open /proc/self/status: %s", strerror(errno));
		return 0;
	}

	char line[256] = { 0 };
	while(fgets(line, sizeof(line), status) != NULL)
	{
		if(strncmp(line, "TracerPid:", 10) == 0)
		{
			// TracerPid field found
			fclose(status);
			return atoi(line + 10);
		}
	}
	fclose(status);
	return 0;
}
