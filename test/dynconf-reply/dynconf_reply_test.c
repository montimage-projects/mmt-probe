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
 * And it covers the refused-update reply (issue #40): an update{}
 * parameter the subscriber cannot apply - an absent block, a "not
 * supported yet" field - must reach the client as CMD_INTERNAL_ERROR
 * through the blocking publish, not as the "0 Successfully processed"
 * acknowledgment the fire-and-forget publish produced. The companion
 * conf_validate_data_value() fix makes a non-numeric value for a
 * UINT16_T/UINT32_T parameter a syntax error, while enum-like parameters
 * keep taking their names (output.format=JSON stays valid).
 *
 * This driver includes configure.c, configure_override.c, server.c and
 * dynamic_conf.c directly: _reply() and _processing() are private to
 * server.c and _receive_message() to dynamic_conf.c, and the real
 * validators and the real override path are what the legs check. Only
 * the mmt-bus functions, get_context() and
 * dynamic_conf_need_to_restart_to_update() are stubbed.
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

#include "../../src/configure.c"
#include "../../src/configure_override.c"
#include "../../src/modules/dynamic_conf/server.c"
#include "../../src/modules/dynamic_conf/dynamic_conf.c"

//a real probe_conf_t parsed by the real conf_load_from_file(): minimal,
// with no dynamic-config block so 'dynamic-config.*' overrides have no
// field to write to and are refused
static probe_conf_t *_load_test_conf( void ){
	char path[ 128 ];
	snprintf( path, sizeof( path ), "/tmp/mmt-dynconf-conf-%ld.conf",
			(long) getpid() );

	FILE *f = fopen( path, "w" );
	assert( f != NULL );
	fputs( "probe-id    = 1\n"
			"stack-type  = 1\n"
			"input {\n"
			"    mode   = OFFLINE\n"
			"    source = \"check.pcap\"\n"
			"}\n"
			"output {\n"
			"    format       = CSV\n"
			"    cache-max    = 1000\n"
			"    cache-period = 3600\n"
			"}\n"
			"session-report { enable = false }\n"
			"thread-nb    = 1\n"
			"thread-queue = 2048\n", f );
	fclose( f );

	probe_conf_t *conf = conf_load_from_file( path );
	unlink( path );
	assert( conf != NULL );
	return conf;
}

//the context the real _receive_message() works on
probe_context_t *get_context(){
	static probe_context_t context;
	if( context.config == NULL )
		context.config = _load_test_conf();
	return &context;
}

//the processing child's restart decision lives in agency.c, which is not
// included: no parameter triggers a restart here
bool dynamic_conf_need_to_restart_to_update( int ident ){
	(void) ident;
	return false;
}

//the bus delivers the message to its subscribers and the first effective
// reply wins, like the blocking publish of mmt_bus.c does. Delivered
// here to the real monitor subscriber - the pid it receives means no
// processing child is running - and to a simulated second subscriber
// that refuses 'stack-type' updates, like a block that exists only in
// the other process: that keeps a refused verdict to check on every build
mmt_bus_code_t mmt_bus_publish( const char *message, size_t message_size, uint16_t *reply_code ){
	if( reply_code == NULL )
		return MMT_BUS_SUCCESS;

	static pid_t child_pid = -1;
	*reply_code = _receive_message( message, message_size, &child_pid );

	if( *reply_code == DYN_CONF_CMD_REPLY_OK ){
		const command_t *cmd = (const command_t *) message;
		if( cmd->id == DYN_CONF_CMD_UPDATE ){
			size_t nb = conf_get_identities( NULL );
			command_param_t params[ nb ];
			nb = parse_command_parameters( cmd->parameter,
					cmd->parameter_length, params, nb );
			for( size_t i=0; i<nb; i++ )
				if( params[i].ident == CONF_ATT__STACK_TYPE )
					*reply_code = DYN_CONF_CMD_REPLY_ERROR;
		}
	}
	return MMT_BUS_SUCCESS;
}

//the remaining bus functions are referenced by dynamic_conf.c but never
// called by the legs
bool mmt_bus_create(){ return true; }
bool mmt_bus_subscribe( bus_subscriber_callback_t cb, void *user_data ){
	(void) cb; (void) user_data;
	return true;
}
void mmt_bus_subcriber_check(){}
void mmt_bus_release(){}

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

	//"update{...}" is the documented form (docs/dynamic_conf.md); the
	// values use the configuration file's spellings - ONLINE, uppercase
	_send_command( "update{\ninput.mode=ONLINE\n}\0", 28, reply, sizeof( reply ));
	assert( strstr( reply, "Successfully processed the command: update" ) != NULL );

	_send_command( "updateXYZ{}\0", 12, reply, sizeof( reply ));
	assert( strstr( reply, "Does not support" ) != NULL );

	//a multi-line valid update still works
	_send_command( "update{\ninput.mode=ONLINE\nprobe-id=7\n}\0", 39,
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

//a refused UPDATE replies an error, not "0 Successfully": the real
//subscriber returns DYN_CONF_CMD_REPLY_ERROR through the blocking
//publish and the server maps it to CMD_INTERNAL_ERROR (issue #40 - on
//the unfixed code the fire-and-forget publish acknowledged everything).
//conf_validate_data_value() refuses a non-numeric value for a number
//parameter as a syntax error, while enum-like parameters keep taking
//their names.
static void test_update_refused_reply( void ){
	char reply[ BUFFER_SIZE ];
#define SEND( cmd ) \
	_send_command( cmd, strlen( cmd ) + 1, reply, sizeof( reply ))

	//a subscriber refusing a parameter ends the publish with
	// DYN_CONF_CMD_REPLY_ERROR: the client gets an internal error - the
	// unfixed code acknowledged it ('0 Successfully ...')
	SEND( "update{\nstack-type=3\n}\0" );
	assert( reply[0] == '3' && reply[1] == ' ' ); //CMD_INTERNAL_ERROR

#if defined( FTP_RECONSTRUCT_MODULE )
	//a parameter of a CFGF_MULTI block the configuration file left out
	// is refused by the real subscriber the same way: no
	// 'reconstruct-data ftp' block exists in the test conf
	SEND( "update{\nreconstruct-data.ftp.enable=true\n}\0" );
	assert( reply[0] == '3' && reply[1] == ' ' ); //CMD_INTERNAL_ERROR
#elif defined( HTTP_RECONSTRUCT_MODULE )
	SEND( "update{\nreconstruct-data.http.enable=true\n}\0" );
	assert( reply[0] == '3' && reply[1] == ' ' ); //CMD_INTERNAL_ERROR
#endif

	//a non-numeric value for a number parameter is refused at
	// validation, as a syntax error: on the unfixed code
	// conf_validate_data_value()'s 'return 0' accepted it and atoi()
	// silently wrote a truncated number
	SEND( "update{\nstats-period=12x\n}\0" );
	assert( reply[0] == '1' && reply[1] == ' ' ); //CMD_SYNTAX_ERROR
	assert( strstr( reply, "Expect a number" ) != NULL );

	//an enum-like parameter still takes its names, not a number: this
	// one passes validation and is applied by the real override
	SEND( "update{\noutput.format=JSON\n}\0" );
	assert( strstr( reply, "Successfully processed the command: update" ) != NULL );
	assert( get_context()->config->outputs.format == OUTPUT_FORMAT_JSON );

	//an unknown enum name is refused at validation and names the
	// accepted values
	SEND( "update{\noutput.format=XML\n}\0" );
	assert( reply[0] == '1' && reply[1] == ' ' ); //CMD_SYNTAX_ERROR
	assert( strstr( reply, "expect" ) != NULL );

	//'on' is not an input.mode name either: refused at validation
	SEND( "update{\ninput.mode=on\n}\0" );
	assert( reply[0] == '1' && reply[1] == ' ' ); //CMD_SYNTAX_ERROR
#undef SEND
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
	test_update_refused_reply();
	test_eof_disconnects();
	test_sigpipe_survives();
	test_long_descriptor_rejected();

	printf( "dynconf-reply: all assertions passed\n" );
	return 0;
}
