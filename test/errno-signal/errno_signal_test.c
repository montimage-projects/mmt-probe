/*
 * errno_signal_test.c - Regression test for the review note N1 of #7/#10:
 * a signal handler that returns must preserve errno.
 *
 * signal_handler() in src/main.c returns to the interrupted code on the
 * SIGINT/SIGTERM/SIGRES arms (the crash arms _exit or die by the signal,
 * and the monitor's _monitor_signal_handler() only sets a flag). A libc
 * call inside the handler - e.g., the best-effort write() of a report
 * helper failing with EBADF when stderr is gone - then left errno
 * clobbered for the interrupted code. The handler now saves errno at
 * entry and restores it before returning.
 *
 * This driver includes main.c so the real handler and its file-scope
 * flags are visible; the probe's main() is renamed out of the way. It is
 * compiled with -ffunction-sections and linked with --gc-sections, so
 * only the code reachable from the handler is kept - the rest of the
 * probe (options, configuration, capture, outputs) is discarded and
 * needs no stubs. The only external the kept code calls is
 * _stop_modules()'s pcap_capture_stop(), stubbed below.
 */

//the default build adds -DNDEBUG, which would compile every check below
// out and turn this driver into a no-op
#undef NDEBUG

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define main probe_main
#include "../../src/main.c"
#undef main

//_stop_modules() hook: no capture is running in this test
void pcap_capture_stop( probe_context_t *context ){
	(void) context;
}

//one child per returning signal: install the real handler, close stderr
// so the report write() fails with EBADF, set a sentinel errno, raise
// the signal, then check the handler ran and left errno untouched. The
// child exits 0 only when both hold, so the parent's waitpid() asserts
// the pair - and, on a handler without the save/restore, the failing
// write()'s EBADF survives and the child exits 1.
static void _check_signal( int sig ){
	pid_t pid = fork();
	assert( pid >= 0 );
	if( pid == 0 ){
		assert( signal( sig, signal_handler ) != SIG_ERR );
		assert( close( STDERR_FILENO ) == 0 );
		errno = EDOM;
		raise( sig );
		//the handler returned: its entry flag must be set and errno
		// must be the sentinel again, not the write()'s EBADF
		_exit( main_processing_signal == sig && errno == EDOM ? 0 : 1 );
	}
	int status = 0;
	assert( waitpid( pid, &status, 0 ) == pid );
	assert( WIFEXITED( status ) && WEXITSTATUS( status ) == 0 );
}

int main( void ){
	_check_signal( SIGINT );
	_check_signal( SIGTERM );
	_check_signal( SIGRES );

	printf( "errno-signal: all assertions passed\n" );
	return 0;
}
