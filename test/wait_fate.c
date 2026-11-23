/*
 * wait_fate.c - test helper for test/crash_exit_status.sh (issue #2).
 *
 * POSIX wait reports 128 + signum both for a process killed by that signal
 * and for one calling _exit(128 + signum): only waitpid()'s status can tell
 * a real signal death (WIFSIGNALED) from a normal exit. This wrapper forks
 * and execs the probe, writes the child's pid to <pidfile> so the test can
 * signal it, waits for it, then writes its fate to <fatefile> as
 * "exit <n>" or "signal <n>". Its own exit status mirrors the child's
 * (128 + signum on a signal death), so a shell sees the same value as for
 * the probe itself.
 *
 * Usage: wait_fate <pidfile> <fatefile> <command> [args...]
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char **argv){
	if( argc < 4 )
		return 2;
	const char *pidfile  = argv[1];
	const char *fatefile = argv[2];

	pid_t pid = fork();
	if( pid < 0 )
		return 2;
	if( pid == 0 ){
		execvp( argv[3], &argv[3] );
		_exit( 127 );
	}

	FILE *f = fopen( pidfile, "w" );
	if( f != NULL ){
		fprintf( f, "%d\n", (int) pid );
		fclose( f );
	}

	int status = 0;
	while( waitpid( pid, &status, 0 ) < 0 && errno == EINTR )
		;

	f = fopen( fatefile, "w" );
	if( f != NULL ){
		if( WIFSIGNALED( status ) )
			fprintf( f, "signal %d\n", WTERMSIG( status ) );
		else if( WIFEXITED( status ) )
			fprintf( f, "exit %d\n", WEXITSTATUS( status ) );
		else
			fprintf( f, "status %d\n", status );
		fclose( f );
	}

	if( WIFSIGNALED( status ) )
		return 128 + WTERMSIG( status );
	if( WIFEXITED( status ) )
		return WEXITSTATUS( status );
	return 1;
}
