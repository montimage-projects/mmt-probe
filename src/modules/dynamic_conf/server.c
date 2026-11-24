/*
 * server.c
 *
 *  Created on: May 16, 2018
 *          by: Huu Nghia Nguyen
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <execinfo.h>

#include "server.h"
#include "mmt_bus.h"
#include "command.h"

#include "../../lib/log.h"
#include "../../lib/tools.h"
#include "../../lib/memory.h"
#include "../../lib/limit.h"
#include "../../lib/string_builder.h"
#include "../../configure_override.h"

//we allocate buffer to be able to stock at least one command
#define BUFFER_SIZE        ( sizeof( command_t) )
#define LENGTH( string )   (sizeof( string ) - 1 )
//a command is the whole received string: "startXYZ" is not "start"
#define IS_CMD( buf, cmd ) (0 == strcmp( buf, cmd ))
//the update command prefixes its parameters, glued on: "update{...}"
#define IS_CMD_PREFIX( buf, cmd ) (0 == strncmp( buf, cmd, LENGTH( cmd ) ))

#define NEW_LINE '\n'

/**
 * Write all len bytes of message to sock.
 * The loop stops at the first error: a -1 return is retried only on EINTR
 * and is never added to the index, so the loop always terminates.
 * @return the number of bytes written
 */
static inline size_t _write_all( int sock, const char *message, size_t len ){
	size_t written = 0;
	while( written < len ){
		ssize_t ret = write( sock, message + written, len - written );
		if( ret == -1 && errno == EINTR )
			continue;
		if( ret <= 0 )
			break;
		written += ret;
	}
	return written;
}

/**
 * Response to control client in form: code description
 * @param sock
 * @param code
 * @param format
 */
__attribute__((format (printf, 3, 4)))
static inline void _reply( int sock, uint16_t code, const char *format, ... ){
	char message[ BUFFER_SIZE ];
	//snprintf and vsnprintf report the length they would have written:
	// bound it to what really landed in message (a negative return counts
	// as nothing written), so offset never moves past the buffer
	size_t offset = bounded_snprintf_len( BUFFER_SIZE,
			snprintf( message, BUFFER_SIZE, "%d ", code));
	va_list args;
	va_start( args, format );
	offset += bounded_snprintf_len( BUFFER_SIZE - offset,
			vsnprintf( message + offset, BUFFER_SIZE - offset, format, args));
	va_end( args );

	_write_all( sock, message, offset );
}

size_t parse_command_parameters( const char *buffer, size_t buffer_size, command_param_t * lst, size_t size ){
	size_t ret = 0, offset = 0;
	uint16_t ident, data_len;
	const char *data;
	while( offset < buffer_size && ret < size ){
		//a parameter header is 4 bytes: identity, then data length
		if( offset + 4 > buffer_size )
			break;
		//1. The first 2bytes is identity
		assign_2bytes( &ident, &buffer[ offset ]);
		offset += 2;
		//2. The next 2bytes is data length
		assign_2bytes( &data_len, &buffer[ offset ]);
		offset += 2;
		//the data value must fit in what remains of the message
		if( offset + data_len > buffer_size )
			break;
		//3. data
		data = &buffer[offset];

		//processing this parameter
		lst[ret].ident = ident;
		lst[ret].data_len = data_len;
		lst[ret].data = data;

		//jump to the next parameter
		offset += data_len;
		ret ++;
	}
	DEBUG("Got %zu parameters", ret );
	return ret;
}

/**
 * After executing this function, we get the parameters of update command on `parameter` variable.
 * Each parameter is stocked in format:
 * - the first 2bytes represents identity of the parameter (see the list in `conf_print_identities_list`)
 * - the next 2bytes represents length of data value
 * - the next x bytes represents data value. The data value is always ended by '\0'.
 *     For example, x=5 if data value is 'true\0' (4 effective bytes + 1 byte for '\0')
 *
 * Example, given buffer = "{input.mode=online\n}"
 * => parameter = "xxyyonline\0", in which,
 *  - xx is 2 bytes whose value is 10 representing "input.mode"
 *  - yy is 2 bytes whose value is  7 representing 6 bytes of 'online' and 1  byte of '\0'
 * @param buffer
 * @param buffer_len
 * @param parameter
 * @param param_size
 * @param sock
 * @return - 0 if there exist syntax error in one of the parameters
 *         - otherwise, number of bytes being used to stock the parameters
 *
 *
 */
static inline int _parse_update_parameters( char *buffer, size_t buffer_len, char *parameter, size_t param_size, int sock ){
	char *ident_str, *val_str;
	const char *str_ptr;
	const identity_t *ident;
	uint16_t val, val_len, len;
	int i;

	printf( "Update parameter: %s", buffer );

	//0. no parameter?
	if( buffer_len == 0 ){
		_reply( sock, CMD_SYNTAX_ERROR, "The update command must contain at least one parameter\n");
		return 0;
	}

	//exclude null byte
	if( buffer[ buffer_len-1] == '\0' )
		buffer_len -= 1;

	//1. must surround by { and }
	if( buffer_len < 2 || buffer[0] != '{' || buffer[ buffer_len - 1 ] != '}' ){
		_reply( sock, CMD_SYNTAX_ERROR, "Parameters of update command must be surrounded by { and }");
		return 0;
	}
	buffer ++; //jump over {
	buffer_len -= 2; //exclude { and }

	//the body is a list of NEW_LINE-ended "name=value" lines, surrounded
	// by a leading and a final NEW_LINE: "update{}" has no body at all and
	// "update{\n}" holds only the newlines - reject an empty or truncated
	// body before the scans below run on an exhausted buffer
	if( buffer_len < 2 || buffer[0] != NEW_LINE
			|| buffer[ buffer_len - 1 ] != NEW_LINE ){
		_reply( sock, CMD_SYNTAX_ERROR, "The update command must contain at least one parameter ended by \\n\n" );
		return 0;
	}
	//a '}' only terminates the command: one inside the body is malformed
	if( memchr( buffer, '}', buffer_len ) != NULL ){
		_reply( sock, CMD_SYNTAX_ERROR, "Parameters of update command must not contain '}'\n" );
		return 0;
	}
	buffer[ buffer_len ] = '\0'; //well null-terminated

	//jump over the leading NEW_LINE
	buffer ++;
	buffer_len -= 1;

	//2. check parameters
	//every scan below stays inside the parameter body: a malformed line
	// stops at `end`, never past the buffer
	char *end = buffer + buffer_len;

	ident_str = buffer;
	val_str   = ident_str;

	size_t offset = 0;
	do{
		//val_str = 'input.mode=online\nabc.xyz=12\n'

		//we need to jump over the first = character
		while( val_str < end && *val_str != NEW_LINE && *val_str != '=' )
			val_str ++;

		//not found = character
		if( val_str >= end || *val_str == NEW_LINE ){
			if( val_str < end )
				*val_str = '\0'; //terminate ident_str to be able to used in the next _reply
			_reply( sock, CMD_SYNTAX_ERROR, "Parameter and its value (%s) must be separated by '='\n", ident_str );
			return 0;
		}

		//We have (*val_str == '='): the name cannot be empty
		if( val_str == ident_str ){
			_reply( sock, CMD_SYNTAX_ERROR, "Empty parameter name in update command\n" );
			return 0;
		}
		*val_str = '\0'; //null-ended for ident_str;
		//jump over '\0' above
		val_str ++;

		//now ident_str is a string with null-terminated.
		// We will check whether it is existing in our list (see the list in `conf_print_identities_list`)
		ident = conf_get_identity_from_string( ident_str );
		//not found or not supported yet
		if( ident == NULL || ident->data_type == NO_SUPPORT ){
			_reply( sock, CMD_SYNTAX_ERROR, "Does not support parameter '%s'\n", ident_str );
			return 0;
		}

		//count the length of data value
		val_len = 0;
		while( val_str + val_len < end && val_str[ val_len ] != NEW_LINE )
			val_len ++;

		//the value must end by \n inside the body - checked above, so
		// reaching `end` here can only come from a malformed line
		if( val_str + val_len >= end ){
			_reply( sock, CMD_SYNTAX_ERROR, "The last parameter of update command must ended by \\n\n" );
			return 0;
		}

		//value is empty
		if( val_len == 0 ){
			_reply( sock, CMD_SYNTAX_ERROR, "Expect value for '%s'\n", ident_str );
			return 0;
		}

		//ended val_str by '\0'
		val_str[ val_len ] = '\0';
		val_len ++; //take into account '\0'

		//check value depending on data type of parameter
		str_ptr = conf_validate_data_value(ident, val_str);
		if( str_ptr != NULL ){
			_reply( sock, CMD_SYNTAX_ERROR, "%s", str_ptr );
			return 0;
		}


		DEBUG("%s=%s", ident_str, val_str );
		//stock into parameter

		//ensure that we have enough place to stock this parameter
		if( offset + 2 + 2 + val_len > param_size ){
			_reply( sock, CMD_SYNTAX_ERROR, "Huge data value for parameters\n");
			return 0;
		}

		//First 2bytes contains identity of parameter
		val = ident->val;
		assign_2bytes( &parameter[offset], &val );
		offset += 2;
		//next 2bytes contains value length
		assign_2bytes( &parameter[offset], &val_len );
		offset += 2;
		//next x bytes contains value data
		memcpy( &parameter[offset], val_str, val_len );
		offset += val_len;


		//next parameter
		val_str  += val_len; //to the next
		ident_str = val_str;

	}while( val_str < end ); //reach to the end of the parameter body

	//3. everything are ok
	return offset;
}

static inline void _reply_list_of_update_parameters( int sock ){
	int i;
	size_t size, written = 0, total_bytes_to_write = 0;
	const char *data_type_strings[] = {
			"",
			"boolean",
			"uint16_t",
			"uint32_t",
			"string",
			"string"
	};
	char message[ BUFFER_SIZE ];

	const identity_t *identities;
	size_t nb_parameters = conf_get_identities( &identities );

	//number of elements
	size = bounded_snprintf_len( BUFFER_SIZE,
			snprintf( message, BUFFER_SIZE, "%zu\n", nb_parameters - 1 )); //-NO_SUPPORT

	total_bytes_to_write = size;
	written = _write_all( sock, message, size );

	for( i=0; i<nb_parameters; i++ )
		if( identities[i].data_type !=NO_SUPPORT  ){
			size = bounded_snprintf_len( BUFFER_SIZE,
					snprintf( message, BUFFER_SIZE, "%s (%s)\n", identities[i].ident, data_type_strings[identities[i].data_type]));
			total_bytes_to_write += size;
			written += _write_all( sock, message, size );
		}
	if( written != total_bytes_to_write )
		log_write( LOG_ERR, "Error while writing response (%zu < %zu bytes)", written, total_bytes_to_write );
}

static int socket_fd = 0;
static struct sockaddr_un address;


#define CMD_START_STR   "start"
#define CMD_STOP_STR    "stop"
#define CMD_UPDATE_STR  "update"
#define CMD_LS_STR      "ls"

static inline void _processing( int sock ) {
	int ret;
	char buffer[ BUFFER_SIZE ];
	uint16_t reply_code;
	const char *cmd_str = NULL;
	command_t command;
	int buffer_len = 0, i;
	buffer[0] = '\0';

	do {
		ret = read( sock, buffer + buffer_len, BUFFER_SIZE - buffer_len );

		//error
		if( ret == -1 ){
			log_write( LOG_INFO, "error while reading socket: %d %s", errno, strerror(errno) );
			goto _finish;
		}
		else if( ret == 0 ){
			//EOF with nothing received: the peer is gone - end the
			// connection instead of spinning on read() forever
			if( buffer_len == 0 )
				goto _finish;
			//no more data
			else
				goto _process_command;
		}
		buffer_len += ret;

		if( buffer_len >= BUFFER_SIZE )
			goto _process_command;

		//whether the buffer contain '\0' => end of a command
		for( i=0; i<ret; i++ )
			if( buffer[buffer_len-ret+i] == '\0' ){
				buffer_len = buffer_len-ret+i + 1;
				goto _process_command;
			}
	} while( true );

	_process_command:

	if( buffer_len == 0 ){
		_reply(sock, CMD_SYNTAX_ERROR, "Does not support the command: %s\n", buffer);
		goto _finish;
	}

	buffer[buffer_len-1] = '\0'; //well terminate the string

	log_write( LOG_INFO, "received command [%s]", buffer );

	//ls
	if (IS_CMD(buffer, CMD_LS_STR) ) {
		_reply_list_of_update_parameters(sock);
		goto _finish;
	} else //start
	if (IS_CMD(buffer, CMD_START_STR) ) {
		command.id = DYN_CONF_CMD_START;
		command.parameter_length = 0;
		cmd_str = CMD_START_STR;
	} else //stop
	if (IS_CMD(buffer, CMD_STOP_STR) ) {
		command.id = DYN_CONF_CMD_STOP;
		command.parameter_length = 0;
		cmd_str = CMD_STOP_STR;
	} else //update: its parameters are glued to the command - "update{...}"
	if (IS_CMD_PREFIX(buffer, CMD_UPDATE_STR "{")) {
		ret = _parse_update_parameters(buffer + LENGTH(CMD_UPDATE_STR),
				buffer_len - LENGTH(CMD_UPDATE_STR), command.parameter,
				sizeof(command.parameter), sock);

		//syntax error. We notified the error inside _parse_update_parameters function
		if (ret == 0)
			goto _finish;

		command.parameter_length = ret;
		command.id = DYN_CONF_CMD_UPDATE;
		cmd_str = CMD_UPDATE_STR;
	} else {
		_reply(sock, CMD_SYNTAX_ERROR, "Does not support the command: %s\n", buffer);
		goto _finish;
	}

	log_write( LOG_INFO, "Publish command id %d (%s)", command.id, cmd_str);

	//4: 2bytes of id + 2bytes of paramter_length
	ret = mmt_bus_publish((char *) &command, 4 + command.parameter_length,
			NULL);

	switch (ret) {
	case MSG_BUS_OLD_MSG_NO_CONSUME:
		_reply(sock, MSG_BUS_OLD_MSG_NO_CONSUME,
				"Old message is not consumed. Need to wait then resend again.");
		break;
	case MMT_BUS_SUCCESS:
		_reply(sock, CMD_SUCCESS, "Successfully processed the command: %s\n",
				cmd_str);
		break;
	}

	_finish:
	close( sock );
}

//the first termination signal this process received: a second one - a
// repeat or a different, forwarded one - must exit it immediately (same
// convention as signal_handler() in src/main.c)
static volatile sig_atomic_t server_stop_signal = 0;

/**
 * Report a termination signal from inside _signal_handler(), where the
 * logger - syslog - cannot be used: it is not async-signal-safe and a
 * signal interrupting it inside a lock would deadlock the drain (the
 * monitor's forwarded signal can arrive while a previous one is being
 * handled). Only write() to stderr is used, as in
 * _report_termination_signal() of src/main.c. The text keeps the
 * "Received signal <n>" marker the logger produced.
 */
static void _report_termination_signal( int sig ){
	static const char prefix[] = "mmt-probe: Received signal ";
	static const char suffix[] = ". Exit dynamic configuration server.\n";
	char num[ 4 ];
	size_t i = 0;
	//append the signal number: snprintf() is not async-signal-safe
	if( sig > 99 ) num[ i++ ] = '0' + ( sig / 100 ) % 10;
	if( sig > 9  ) num[ i++ ] = '0' + ( sig / 10 ) % 10;
	num[ i++ ] = '0' + sig % 10;
	if( write( STDERR_FILENO, prefix, sizeof( prefix ) - 1 ) < 0 ){}
	if( write( STDERR_FILENO, num, i ) < 0 ){}
	if( write( STDERR_FILENO, suffix, sizeof( suffix ) - 1 ) < 0 ){}
}

/**
 * Report a second signal from inside a signal handler - the process then
 * exits immediately. write() only, for the same reason as above.
 */
static void _report_second_signal( int sig ){
	static const char prefix[] = "mmt-probe: Received signal ";
	static const char suffix[] = " while processing other one. Exit immediately.\n";
	char num[ 4 ];
	size_t i = 0;
	//append the signal number: snprintf() is not async-signal-safe
	if( sig > 99 ) num[ i++ ] = '0' + ( sig / 100 ) % 10;
	if( sig > 9  ) num[ i++ ] = '0' + ( sig / 10 ) % 10;
	num[ i++ ] = '0' + sig % 10;
	if( write( STDERR_FILENO, prefix, sizeof( prefix ) - 1 ) < 0 ){}
	if( write( STDERR_FILENO, num, i ) < 0 ){}
	if( write( STDERR_FILENO, suffix, sizeof( suffix ) - 1 ) < 0 ){}
}

/**
 * Report a fatal signal from inside a signal handler. Only
 * async-signal-safe primitives are used: a single write() to stderr for
 * the one-line message, then backtrace_symbols_fd() which writes the
 * backtrace directly to stderr - unlike backtrace_symbols() it does not
 * allocate memory, so this still works when the crash happened inside the
 * allocator (see _report_crash_signal() in src/main.c). The text keeps
 * the "Segv signal received on control process!" marker the logger
 * produced.
 */
static void _report_crash_signal(){
	static const char msg[] =
		"mmt-probe: Segv signal received on control process!\n";
	if( write( STDERR_FILENO, msg, sizeof( msg ) - 1 ) < 0 ){}

	void *frames[ 16 ];
	int nb_frames = backtrace( frames, 16 );
	backtrace_symbols_fd( frames, nb_frames, STDERR_FILENO );
}

/**
 * This signal handler ensures clean exits of the control process.
 * Only async-signal-safe calls may run here - write(), close(), unlink(),
 * _exit(), backtrace_symbols_fd() - never the logger (syslog) nor malloc,
 * exactly as signal_handler() in src/main.c.
 * @param type
 */
static void _signal_handler( int type ){
	//a second signal while draining - e.g., a group-wide kill plus the
	// monitor's forward - exits right now, without touching the logger
	// which the interrupted code may hold a lock of
	if( server_stop_signal != 0 ){
		_report_second_signal( type );
		EXIT_NORMALLY();
	}

	switch( type ){
	case SIGINT:
	case SIGTERM:

		server_stop_signal = type;
		_report_termination_signal( type );
		close( socket_fd );
		unlink( address.sun_path );

		//intend to exit
		EXIT_NORMALLY();

		break;

	case SIGSEGV:
		_report_crash_signal();

		//Auto restart when segmentation fault
		EXIT_TOBE_RESTARTED();

		break;

	case SIGRES:
		{
			static const char restart_msg[] =
				"mmt-probe: Restart signal received! Cleaning up before restarting!\n";
			if( write( STDERR_FILENO, restart_msg, sizeof( restart_msg ) - 1 ) < 0 ){}
		}
		EXIT_TOBE_RESTARTED();
	}
}

bool dynamic_conf_server_start_processing( const char* unix_domain_descriptor ){
	int  newsock_fd;
	struct sockaddr_un cli_addr;
	socklen_t sock_len = sizeof( cli_addr );

	//resolve the backtrace machinery now, before the signal handler is
	// installed: the first backtrace() call lazily loads libgcc_s (dlopen +
	// malloc, not async-signal-safe) - inside a crash handler that could
	// deadlock or fault before the process dies by the signal (same as in
	// _main_processing(), src/main.c)
	{
		void *frames[ 1 ];
		(void) backtrace( frames, 1 );
	}

	//default signal to exit
	signal( SIGINT,  _signal_handler );
	signal( SIGTERM, _signal_handler );
	signal( SIGSEGV, _signal_handler );
	signal(SIGRES,   _signal_handler);
	//a client closing the connection before the reply must not kill this
	// process by SIGPIPE: write() then fails with EPIPE and is dropped
	signal( SIGPIPE, SIG_IGN );
	//use UNIX socket
	if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		ABORT( "Error when opening socket: %s", strerror( errno ) );
		return false;
	}

	memset(&address, 0, sizeof( address ));
	address.sun_family = AF_UNIX;
	//the descriptor is config-controlled: one that does not fit into
	// sun_path with its terminating '\0' is rejected here, at start-up,
	// instead of leaving sun_path unterminated for bind() and unlink()
	const size_t descriptor_len = strlen( unix_domain_descriptor );
	if( descriptor_len >= sizeof( address.sun_path )){
		//a signal death by ABORT would be re-created by the monitor over
		// the same bad config, about once a second: report the error once
		// and stop the probe for good
		log_write( LOG_ERR, "dynamic-config.descriptor is too long: %zu characters (maximum %zu). Aborted",
				descriptor_len, sizeof( address.sun_path ) - 1 );
		fprintf( stderr, "dynamic-config.descriptor is too long: %zu characters (maximum %zu). Aborted\n",
				descriptor_len, sizeof( address.sun_path ) - 1 );
		EXIT_NO_RESTART();
	}
	memcpy( address.sun_path, unix_domain_descriptor, descriptor_len + 1 );
	unlink( address.sun_path ); //remove the existing file

	if (bind(socket_fd, (struct sockaddr *)&address, strlen(address.sun_path) + sizeof(address.sun_family)) == -1) {
		ABORT("Error when binding dynamic configuration server: %s", strerror( errno ) );
		return false;
	}

	//only one connection at a time
	if (listen(socket_fd, 1) == -1) {
		ABORT("Error when listening dynamic configuration server: %s", strerror( errno ) );
		return false;
	}

	log_write( LOG_INFO, "Dynamic configuration server is listening on %s", unix_domain_descriptor );
	printf("MMT-Probe is listening control commands on UNIX domain socket at %s", unix_domain_descriptor );

	while( true ){
		//Accept actual connection from the client
		newsock_fd = accept(socket_fd, (struct sockaddr *) &cli_addr, &sock_len);
		ASSERT( newsock_fd >= 0, "Error when accepting: %s", strerror( errno ) );

		log_write(LOG_INFO, "Dynamic configuration server received a connection");

		//processing the connection
		//only one client is served at a time
		_processing( newsock_fd );
	}
	return true;
}
