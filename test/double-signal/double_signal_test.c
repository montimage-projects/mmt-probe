/*
 * double_signal_test.c - Regression test for issue #45: a repeat of the
 * termination signal the processing child is already handling must not
 * cut the shutdown drain short.
 *
 * In online mode two everyday cases deliver the same SIGINT or SIGTERM
 * twice to the processing child:
 *   - a terminal Ctrl+C reaches the whole process group, and the monitor
 *     then forwards the same signal a second time;
 *   - systemd's default KillMode=control-group signals the child
 *     directly, and the monitor forwards a SIGTERM too.
 * signal_handler() in src/main.c used to take the context->is_exiting
 * branch on that second signal: _report_second_signal() then
 * EXIT_NORMALLY() - _exit(0) - which skipped the security drain
 * (mmt_sec_unregister), the output fclose/.sem and the stdio flush, so
 * the last alerts were lost.
 *
 * A repeat of the signal being handled is now a no-op: the handler
 * returns so the drain finishes. A different second signal still asks
 * to exit right now, and a crash signal while exiting keeps its
 * behaviour (offline: die by the signal; online: exit immediately).
 *
 * This driver includes main.c so the real handler and its file-scope
 * flags are visible; the probe's main() is renamed out of the way. It is
 * compiled with -ffunction-sections and linked with --gc-sections, so
 * only the code reachable from the handler is kept - the rest of the
 * probe (options, configuration, capture, outputs) is discarded and
 * needs no stubs. The only external the kept code calls is
 * _stop_modules()'s pcap_capture_stop(), stubbed below - the same
 * pattern as test/errno-signal.
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

//the static configuration the handler dereferences through
// get_context()->config->input->input_mode
static probe_conf_t        conf_storage;
static input_source_conf_t input_storage;

//put the processing child in the state the second signal finds it in:
// is_exiting raised by the first signal `armed`, main_processing_signal
// recording it, input_mode deciding the offline crash arms
static void _arm_exiting( int armed, int input_mode ){
	probe_context_t *context = get_context();
	context->config          = &conf_storage;
	context->config->input   = &input_storage;
	context->config->input->input_mode = input_mode;
	context->is_exiting      = true;
	main_processing_signal   = armed;
}

//the raised signal must leave the handler alone - a no-op: the handler
// returns, main_processing_signal still records the armed signal and the
// sentinel errno survives the report write()s. The child encodes the
// outcome in its exit status: 7 when all of that held, 1 when errno or
// the recorded signal was clobbered. On the unfixed code the handler
// exits immediately with status 0, so the parent sees 0, not 7.
static void _expect_noop( const char *name, int armed, int raised, int input_mode ){
	pid_t pid = fork();
	assert( pid >= 0 );
	if( pid == 0 ){
		assert( signal( raised, signal_handler ) != SIG_ERR );
		_arm_exiting( armed, input_mode );
		errno = EDOM;
		raise( raised );
		_exit( main_processing_signal == armed && errno == EDOM ? 7 : 1 );
	}
	int status = 0;
	assert( waitpid( pid, &status, 0 ) == pid );
	if( !( WIFEXITED( status ) && WEXITSTATUS( status ) == 7 ) ){
		printf( "FAIL %s: expected a no-op return (child fate: status 0x%x)\n",
				name, status );
		exit( 1 );
	}
	printf( "PASS %s\n", name );
}

//the raised signal must keep the "second signal exits immediately"
// behaviour: the handler does not return - it exits with status 0
// (EXIT_NORMALLY) - so a sentinel _exit(42) behind raise() must never
// be reached. Same expectation on the unfixed and the fixed code.
static void _expect_hard_exit( const char *name, int armed, int raised, int input_mode ){
	pid_t pid = fork();
	assert( pid >= 0 );
	if( pid == 0 ){
		assert( signal( raised, signal_handler ) != SIG_ERR );
		_arm_exiting( armed, input_mode );
		raise( raised );
		_exit( 42 );
	}
	int status = 0;
	assert( waitpid( pid, &status, 0 ) == pid );
	if( !( WIFEXITED( status ) && WEXITSTATUS( status ) == 0 ) ){
		printf( "FAIL %s: expected an immediate exit 0 (child fate: status 0x%x)\n",
				name, status );
		exit( 1 );
	}
	printf( "PASS %s\n", name );
}

//in offline mode a crash signal while exiting still dies by that signal
// (there is no monitor to restart the probe): the child must be reported
// killed, not exited. Same expectation on the unfixed and the fixed code.
static void _expect_signal_death( const char *name, int armed, int raised, int input_mode ){
	pid_t pid = fork();
	assert( pid >= 0 );
	if( pid == 0 ){
		assert( signal( raised, signal_handler ) != SIG_ERR );
		_arm_exiting( armed, input_mode );
		raise( raised );
		_exit( 42 );
	}
	int status = 0;
	assert( waitpid( pid, &status, 0 ) == pid );
	if( !( WIFSIGNALED( status ) && WTERMSIG( status ) == raised ) ){
		printf( "FAIL %s: expected a death by signal %d (child fate: status 0x%x)\n",
				name, raised, status );
		exit( 1 );
	}
	printf( "PASS %s\n", name );
}

int main( void ){
	//the issue case - online mode: a repeat of the termination signal
	// being handled returns so the drain can finish
	_expect_noop( "online repeated SIGINT is a no-op",
			SIGINT, SIGINT, ONLINE_ANALYSIS );
	_expect_noop( "online repeated SIGTERM is a no-op",
			SIGTERM, SIGTERM, ONLINE_ANALYSIS );
	_expect_noop( "online repeated SIGINT after SIGTERM-armed check order",
			SIGTERM, SIGTERM, ONLINE_ANALYSIS );

	//the same branch is shared with offline mode
	_expect_noop( "offline repeated SIGINT is a no-op",
			SIGINT, SIGINT, OFFLINE_ANALYSIS );
	_expect_noop( "offline repeated SIGTERM is a no-op",
			SIGTERM, SIGTERM, OFFLINE_ANALYSIS );

	//a different second signal still asks to exit right now - the hard
	// exit path the issue's chosen option keeps
	_expect_hard_exit( "online SIGTERM while handling SIGINT exits now",
			SIGINT, SIGTERM, ONLINE_ANALYSIS );
	_expect_hard_exit( "online SIGINT while handling SIGTERM exits now",
			SIGTERM, SIGINT, ONLINE_ANALYSIS );
	_expect_hard_exit( "offline SIGTERM while handling SIGINT exits now",
			SIGINT, SIGTERM, OFFLINE_ANALYSIS );

	//a crash signal while exiting keeps its behaviour: offline dies by
	// the signal, online reports the second signal and exits
	_expect_signal_death( "offline SIGSEGV while exiting dies by SIGSEGV",
			SIGINT, SIGSEGV, OFFLINE_ANALYSIS );
	_expect_hard_exit( "online SIGSEGV while exiting exits now",
			SIGINT, SIGSEGV, ONLINE_ANALYSIS );

	printf( "double-signal: all assertions passed\n" );
	return 0;
}
