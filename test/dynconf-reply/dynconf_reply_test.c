/*
 * dynconf_reply_test.c - Regression test for the dynamic-conf control
 * socket reply path.
 *
 * _reply() accumulated the would-be lengths reported by snprintf and
 * vsnprintf into its offset, so a reply longer than BUFFER_SIZE moved the
 * offset past the end of the message buffer and write() sent stack bytes
 * beyond it to the client. A -1 from write() was added to the index, so a
 * write error looped forever. The socket descriptor was copied with
 * strncpy(dst, src, sizeof dst), leaving sun_path unterminated when the
 * configured dynamic-config.descriptor does not fit, and IS_CMD matched a
 * command by prefix, so "startXYZ" ran as "start".
 *
 * It also covers the update{} parser: an empty parameter body
 * ("update{}", "update{\n}") and the other malformed shapes must be
 * rejected with CMD_SYNTAX_ERROR by scans bounded to the body - on the
 * unfixed code "update{\n}" drives an unbounded scan past the stack
 * buffer (ASan stack-buffer-overflow). A client that connects and closes
 * without sending must end the connection instead of spinning on EOF,
 * a peer closing before the reply must not kill the process by SIGPIPE,
 * and an over-long descriptor must stop the probe once, with the
 * do-not-restart exit status, instead of abort-looping.
 *
 * This driver includes server.c directly, as _reply() and _processing()
 * are private to it. The bus and the configuration validators are stubbed:
 * the bus accepts every command and every parameter is taken as valid.
 */

//the default build adds -DNDEBUG, which would compile every check below -
// including the socketpair() calls - out and turn this driver into a no-op
#undef NDEBUG

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "../../src/modules/dynamic_conf/server.c"

//the bus always accepts the command
mmt_bus_code_t mmt_bus_publish( const char *message, size_t message_size, uint16_t *reply_code ){
	(void) message; (void) message_size; (void) reply_code;
	return MMT_BUS_SUCCESS;
}

//resolve identities from the real list, like configure_override.c does
const identity_t* conf_get_identity_from_string( const char * ident_str ){
	const identity_t *identities;
	size_t i, nb_parameters = conf_get_identities( &identities );
	for( i=0; i<nb_parameters; i++ )
		if( strcmp( ident_str, identities[i].ident ) == 0 )
			return &identities[i];
	return NULL;
}

//every value is valid
const char* conf_validate_data_value( const identity_t *ident, const char *data_value ){
	(void) ident; (void) data_value;
	return NULL;
}

static void _socket_pair( int sv[2] ){
	assert( socketpair( AF_UNIX, SOCK_STREAM, 0, sv ) == 0 );
	//a large-enough send buffer so a multi-BUFFER_SIZE reply never blocks
	int size = 1 << 20;
	setsockopt( sv[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof( size ));
}

//a reply longer than BUFFER_SIZE is truncated to what fits the buffer -
// never sends a byte past it. On the unfixed code ASan reports a
// stack-buffer-overflow at write(); without ASan the peer receives more
// than BUFFER_SIZE bytes.
static void test_reply_truncates( void ){
	int sv[2];
	_socket_pair( sv );

	char payload[ 3 * BUFFER_SIZE ];
	memset( payload, 'A', sizeof( payload ));
	payload[ sizeof( payload ) - 1 ] = '\0';

	_reply( sv[0], CMD_SUCCESS, "%s", payload );
	shutdown( sv[0], SHUT_WR );

	char received[ 4 * BUFFER_SIZE ];
	ssize_t total = 0, n;
	while( total < (ssize_t) sizeof( received )
			&& (n = read( sv[1], received + total, sizeof( received ) - total )) > 0 )
		total += n;

	close( sv[0] );
	close( sv[1] );

	//"0 " followed by the payload, truncated at the end of the buffer
	assert( total == BUFFER_SIZE - 1 );
	assert( received[0] == '0' && received[1] == ' ' && received[2] == 'A' );
	assert( received[ total - 1 ] == 'A' );
}

//a closed peer makes write() fail: the loop must end instead of adding -1
// to the index and spinning. The alarm kills this test if it does not
// terminate.
static void test_reply_write_error_stops( void ){
	int sv[2];
	_socket_pair( sv );
	close( sv[1] ); //the peer is already gone
	signal( SIGPIPE, SIG_IGN );

	alarm( 10 );
	_reply( sv[0], CMD_SUCCESS, "hello" );
	alarm( 0 );

	close( sv[0] );
}

//send one '\0'-terminated command to _processing() and collect the reply
static void _send_command( const char *cmd, size_t cmd_len, char *reply, size_t reply_size ){
	int sv[2];
	_socket_pair( sv );

	assert( write( sv[1], cmd, cmd_len ) == (ssize_t) cmd_len );
	shutdown( sv[1], SHUT_WR );
	_processing( sv[0] ); //closes sv[0]

	ssize_t total = 0, n;
	while( total < (ssize_t) reply_size - 1
			&& (n = read( sv[1], reply + total, reply_size - 1 - total )) > 0 )
		total += n;
	reply[ total ] = '\0';
	close( sv[1] );
}

//a command matches whole words only, except "update" whose parameters are
// glued to it: "update{...}". Valid commands still work.
static void test_command_framing( void ){
	char reply[ BUFFER_SIZE ];

	_send_command( "start\0", 6, reply, sizeof( reply ));
	assert( strstr( reply, "Successfully processed the command: start" ) != NULL );

	//a prefix is not a command: "startXYZ" must be rejected, not run as "start"
	_send_command( "startXYZ\0", 9, reply, sizeof( reply ));
	assert( strstr( reply, "Does not support" ) != NULL );

	_send_command( "lsjunk\0", 7, reply, sizeof( reply ));
	assert( strstr( reply, "Does not support" ) != NULL );

	//"update{...}" is the documented form (docs/dynamic_conf.md)
	_send_command( "update{\ninput.mode=online\n}\0", 28, reply, sizeof( reply ));
	assert( strstr( reply, "Successfully processed the command: update" ) != NULL );

	_send_command( "updateXYZ{}\0", 12, reply, sizeof( reply ));
	assert( strstr( reply, "Does not support" ) != NULL );

	//a multi-line valid update still works
	_send_command( "update{\ninput.mode=online\nprobe-id=7\n}\0", 39,
			reply, sizeof( reply ));
	assert( strstr( reply, "Successfully processed the command: update" ) != NULL );
}

//an empty parameter body is a syntax error, answered without any
//out-of-bounds access: on the unfixed code "update{\n}" runs an
//unbounded scan past the stack buffer (ASan stack-buffer-overflow).
static void test_update_empty_body_rejected( void ){
	char reply[ BUFFER_SIZE ];

	_send_command( "update{\n}\0", 10, reply, sizeof( reply ));
	assert( reply[0] == '1' && reply[1] == ' ' ); //CMD_SYNTAX_ERROR
	assert( strstr( reply, "must contain at least one parameter" ) != NULL );

	_send_command( "update{}\0", 9, reply, sizeof( reply ));
	assert( reply[0] == '1' && reply[1] == ' ' );
	assert( strstr( reply, "must contain at least one parameter" ) != NULL );

	//a body of only newline lines has no parameter either
	_send_command( "update{\n\n}\0", 11, reply, sizeof( reply ));
	assert( reply[0] == '1' && reply[1] == ' ' );
}

//the other malformed update shapes are rejected too; on the unfixed code
//two of them are wrongly accepted - a junk byte glued after '{' is eaten
//by the unconditional "jump over" and a '}' inside the body lands in a
//parameter value.
static void test_update_malformed_rejected( void ){
	char reply[ BUFFER_SIZE ];
	size_t i;
	const char *cases[] = {
		//missing the leading newline after '{'
		"update{Xinput.mode=online\n}\0",
		//a parameter line without '='
		"update{\ninput.mode\n}\0",
		//an empty parameter name
		"update{\n=online\n}\0",
		//an empty value
		"update{\ninput.mode=\n}\0",
		//a '}' inside the body
		"update{\ninput.mode=on}line\n}\0",
		//no '\n' after the last parameter
		"update{\ninput.mode=online}\0",
		//an empty line between parameters
		"update{\ninput.mode=online\n\n}\0",
	};
	for( i = 0; i < sizeof( cases ) / sizeof( cases[0] ); i++ ){
		_send_command( cases[i], strlen( cases[i] ) + 1, reply, sizeof( reply ));
		assert( reply[0] == '1' && reply[1] == ' ' ); //CMD_SYNTAX_ERROR
	}
}

//a client that connects and closes without sending must end the
//connection: on the unfixed code read() returns 0 forever and
//_processing spins (the server serves no other client until killed).
static void test_eof_disconnects( void ){
	int sv[2];
	_socket_pair( sv );
	close( sv[1] ); //the peer is already gone

	pid_t pid = fork();
	assert( pid >= 0 );
	if( pid == 0 ){
		_processing( sv[0] ); //closes sv[0]; must return, not spin
		_exit( 0 );
	}
	close( sv[0] );

	int status = 0, waited;
	pid_t r = 0;
	for( waited = 0; waited < 100; waited++ ){ //1s bound
		r = waitpid( pid, &status, WNOHANG );
		if( r == pid ) break;
		usleep( 10 * 1000 );
	}
	if( r == 0 ){ //still spinning on EOF
		kill( pid, SIGKILL );
		waitpid( pid, &status, 0 );
	}
	assert( r == pid ); //_processing returned within 1 s
	assert( WIFEXITED( status ) && WEXITSTATUS( status ) == 0 );
}

//a peer that closes before the reply makes write() raise SIGPIPE: the
//control child must ignore it (SIG_IGN installed by
//dynamic_conf_server_start_processing itself - the test process does not
//mask it) and survive. On the unfixed code the child dies by SIGPIPE.
static void test_sigpipe_survives( void ){
	char path[ 64 ];
	snprintf( path, sizeof( path ), "/tmp/mmt-dynconf-sigpipe-%ld.sock",
			(long) getpid() );
	unlink( path );

	pid_t pid = fork();
	assert( pid >= 0 );
	if( pid == 0 ){
		//the ignore must come from the server code, not from this test
		signal( SIGPIPE, SIG_DFL );
		dynamic_conf_server_start_processing( path );
		_exit( 2 ); //returned - must not be reached (accept() loops)
	}

	//wait for the server to listen
	int fd = -1, waited;
	struct sockaddr_un addr;
	memset( &addr, 0, sizeof( addr ));
	addr.sun_family = AF_UNIX;
	strcpy( addr.sun_path, path );
	for( waited = 0; waited < 100; waited++ ){
		fd = socket( AF_UNIX, SOCK_STREAM, 0 );
		assert( fd >= 0 );
		if( connect( fd, (struct sockaddr *) &addr, sizeof( addr )) == 0 )
			break;
		close( fd ); fd = -1;
		usleep( 20 * 1000 );
	}
	assert( fd >= 0 ); //server is accepting

	//send a command then close immediately: the reply meets a dead peer
	assert( write( fd, "start\0", 6 ) == 6 );
	close( fd );
	usleep( 200 * 1000 ); //let the server reach its reply

	int status = 0;
	assert( waitpid( pid, &status, WNOHANG ) == 0 ); //still alive

	kill( pid, SIGTERM );
	waitpid( pid, &status, 0 );
	unlink( path );
}

//a descriptor longer than sun_path is rejected at start-up with a clear
//error on stderr, and the process exits with EXIT_STATUS_NO_RESTART: a
//signal death would make the monitor re-create the child over the same
//bad config, about once a second. On the unfixed code a truncated,
//unterminated path is bound instead and the child keeps serving - it has
//to be killed; on the first fix it aborted by SIGABRT, which loops the
//same way under the monitor.
static void test_long_descriptor_rejected( void ){
	char descriptor[ 300 ];
	int n = snprintf( descriptor, sizeof( descriptor ),
			"/tmp/mmt-dynconf-test-%ld-", (long) getpid() );
	memset( descriptor + n, 'a', 200 );
	descriptor[ n + 200 ] = '\0';
	assert( strlen( descriptor ) >= sizeof( address.sun_path ));

	int pipefd[2];
	assert( pipe( pipefd ) == 0 );
	//the child's stderr carries the rejection message
	assert( fcntl( pipefd[0], F_SETFL, fcntl( pipefd[0], F_GETFL ) | O_NONBLOCK ) == 0 );

	pid_t pid = fork();
	assert( pid >= 0 );
	if( pid == 0 ){
		dup2( pipefd[1], STDERR_FILENO );
		dynamic_conf_server_start_processing( descriptor );
		_exit( 2 ); //serving - must not be reached
	}
	close( pipefd[1] );

	int status = 0, waited;
	pid_t r = 0;
	for( waited = 0; waited < 50; waited++ ){ //5s bound
		r = waitpid( pid, &status, WNOHANG );
		if( r == pid ) break;
		usleep( 100 * 1000 );
	}
	if( r == 0 ){ //still serving on a truncated path
		kill( pid, SIGKILL );
		waitpid( pid, &status, 0 );
	}

	char child_err[ 4096 ];
	size_t err_len = 0;
	ssize_t nrd;
	while( err_len < sizeof( child_err ) - 1
			&& (nrd = read( pipefd[0], child_err + err_len, sizeof( child_err ) - 1 - err_len )) > 0 )
		err_len += nrd;
	child_err[ err_len ] = '\0';
	close( pipefd[0] );

	//drop the socket file the unfixed code may have bound: its name is the
	// descriptor truncated to sun_path (no terminating '\0')
	char truncated[ sizeof( address.sun_path ) + 1 ];
	memcpy( truncated, descriptor, sizeof( address.sun_path ));
	truncated[ sizeof( address.sun_path )] = '\0';
	unlink( truncated );

	//EXIT_STATUS_NO_RESTART = 3: reported once, never restarted
	assert( WIFEXITED( status ) && WEXITSTATUS( status ) == 3 );
	assert( strstr( child_err, "too long" ) != NULL );
}

int main( void ){
	test_reply_truncates();
	test_reply_write_error_stops();
	test_command_framing();
	test_update_empty_body_rejected();
	test_update_malformed_rejected();
	test_eof_disconnects();
	test_sigpipe_survives();
	test_long_descriptor_rejected();

	printf( "dynconf-reply: all assertions passed\n" );
	return 0;
}
