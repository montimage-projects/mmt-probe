/*
 * main.c
 *
 *  Created on: Dec 12, 2017
 *          by: Huu Nghia
 *
 * This is main of MMT-Probe.
 * It will create 2 children processes:
 *   + processing process: this this main processing of MMT-Probe
 *   + control process: it receives control commands via an UNIX socket, check them, then broadcast them.
 *                      It is created only if DYNAMIC_CONFIG_MODULE is defined.
 * There are totally 3 processes: 2 children + dispatcher (main).
 * The dispatch monitors their children, and re-create a child if it has crashed.
 * The dispatch receives also a command from the control process to start or stop the processing process.
 *
 */
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>   // stat
#include <stdbool.h>    // bool type

#include "lib/log.h"
#include "lib/version.h"
#include "lib/tools.h"
#include "lib/malloc.h"
#include "lib/memory.h"
#include "lib/version.h"
#include "lib/limit.h"
#include "context.h"
#include "configure_override.h"
#include "modules/routine/routine.h"

#ifdef DPDK_MODULE
#include "modules/packet_capture/dpdk/dpdk_capture.h"
#endif

#ifdef PCAP_MODULE
#include "modules/packet_capture/pcap/pcap_capture.h"
#endif

#ifdef SECURITY_MODULE
#include "modules/security/security.h"
#endif

#ifdef DYNAMIC_CONFIG_MODULE
#include "modules/dynamic_conf/dynamic_conf.h"
#endif

#if defined DPDK_MODULE && defined PCAP_MODULE
#error("Either DPDK_MODULE or PCAP_MODULE is defined but must not all of them")
#endif

#ifdef DEBUG_MODE
	#warning "The debug compile option is reserved only for debugging"
#endif

#ifndef MMT_BASE
	#define MMT_BASE "/opt/mmt"
#endif

/*
 * Default configuration file: either in the current folder or in /opt/mmt/probe
 * The former has a higher priority
 */
#define DEFAULT_CONFIG_FILE     "./mmt-probe.conf"
#define DEFAULT_CONFIG_FILE_OPT MMT_BASE "/probe/mmt-probe.conf"

static void _print_usage(const char * prg_name) {
	printf("%s [<Option>]\n", prg_name);
	printf("Option:\n");
	printf("\t-v               : Print version information, then exits.\n");
	printf("\t-c <config file> : Gives the path to the configuration file (default: %s, %s).\n",
				DEFAULT_CONFIG_FILE, DEFAULT_CONFIG_FILE_OPT);
IF_ENABLE_PCAP(
	printf("\t-t <trace file>  : Gives the trace file for offline analyse.\n");
)
	printf("\t-i <interface>   : Gives the interface name for live traffic analysis.\n");
	printf("\t-X attr=value    : Override configuration attributes.\n");
	printf("\t                    For example \"-X file-output.enable=true -Xfile-output.output-dir=/tmp/\" will enable output to file and change output directory to /tmp.\n");
	printf("\t                    This parameter can appear several times.\n");
	printf("\t                    An option that takes a name (see -x) takes the same names as in the configuration file, not a number: output.format takes %s.\n", CONF_OUTPUT_FORMAT_VALUES );
	printf("\t                    A boolean option takes true, in lower case: any other value means false.\n");
	printf("\t-x               : Prints list of configuration attributes being able to be used with -X, with their type or accepted values, then exits.\n");
	printf("\t-h               : Prints this help, then exits.\n");
}

/**
 * Free a string pointer before clone data to it
 */
static inline void _override_string_conf( char **conf, const char*new_val ){
	free( *conf );
	*conf = strdup( new_val );
}

bool _is_file_exists (const char *filename) {
	struct stat buffer;
	return (stat (filename, &buffer) == 0);
}

/**
 * 1) Parse options from execution command line to get location of configuration file.
 * 2) Load configuration from the file
 * 3) Override the configuration parameters, that was loaded from file, by the ones given from execution command line
 * @param argc
 * @param argv
 * @return
 */
static inline probe_conf_t* _parse_options( int argc, char ** argv ) {
	int opt, optcount = 0;
	int val;
#ifdef DPDK_MODULE
	const char *options = "c:i:vhxX:"; //not allow -t to analyze pcap files
#else
	const char *options = "c:t:i:vhxX:";
#endif
	const char *config_file = NULL;
	probe_conf_t *conf = NULL;

	extern char *optarg;
	extern int optind;

	char *string_att, *string_val;

	//first parser round to get configuration file
	while ((opt = getopt(argc, argv, options )) != EOF) {
		switch (opt) {
		case 'c':
			config_file = optarg;
			break;
		case 'v':
			printf("Version:\n");
			printf( "- MMT-Probe %s\n", get_version());
			printf( "- MMT-DPI %s\n", mmt_version() );
			IF_ENABLE_SECURITY(
					printf( "- MMT-Security %s\n", security_get_version() );
			)
			printf("- Modules: %s\n", MODULES_LIST );
			printf("- MMT_BASE: %s\n", MMT_BASE );
			exit( EXIT_SUCCESS );
		case 'h':
			_print_usage(argv[0]);
			exit( EXIT_SUCCESS );
		case 'x':
			conf_print_identities_list();
			exit( EXIT_SUCCESS );
		}
	}

	//user given
	if( config_file ){
		conf = conf_load_from_file( config_file );
		if( conf == NULL )
			abort();
	}else{
		// load ./mmt-probe.conf if it is existing
		if( _is_file_exists( DEFAULT_CONFIG_FILE) ){
			config_file = DEFAULT_CONFIG_FILE;
			conf = conf_load_from_file( config_file );
			if( conf == NULL )
				abort();
		} else {
			//try again to read config from /opt/mmt/probe/mmt-probe.conf
			config_file = DEFAULT_CONFIG_FILE_OPT;
			conf = conf_load_from_file( config_file );
			if( conf == NULL )
				abort();
		}
	}

	log_write( LOG_INFO, "Loaded configuration from '%s'", config_file );

	//reset getopt function
	optind = 0;
	//override some options inside the configuration
	while ((opt = getopt(argc, argv, options)) != EOF) {
		switch (opt) {
		//trace file
		case 't':
			_override_string_conf( &conf->input->input_source, optarg );
			//switch to offline mode
			conf->input->input_mode = OFFLINE_ANALYSIS;
			break;
			//input interface
		case 'i':
			_override_string_conf( &conf->input->input_source, optarg );
			//switch to online mode
			conf->input->input_mode = ONLINE_ANALYSIS;
			break;

		case 'X':
			//example: -X file-output.enable=true
			//we will separate the phrase "file-output.enable=true" into 2
			// to expect:
			//   string_att = "file-output.enable"
			//   string_val = "true"
			string_att = optarg;
			string_val = optarg;
			while( *string_val != '\0' ){
				//separated by = character
				if( *string_val == '=' ){
					*string_val = '\0'; //NULL ended for attribute
					//jump to the part after = character
					string_val ++;
					break;
				}
				string_val ++;
			}
			//not found = character
			if( *string_val == '\0' )
				log_write( LOG_WARNING, "Input parameter '%s' is not well-formatted (must be in format parameter=value). Ignored it.", string_att );

			switch( conf_override_element(conf, string_att, string_val) ){
			case 0:
				log_write( LOG_INFO, "Overridden value of configuration parameter '%s' by '%s'", string_att, string_val );
				break;
			case 1: //value is incorrect
				fprintf(stderr, "Unexpected parameter value %s\n", string_val );
				exit( 1 );
				break;
			case -1:  //ident is incorrect
				fprintf(stderr, "Unknown parameter identity %s\n", string_att );
				exit( 1 );
				break;
			default: break;
			}

		}
	}

	if( conf_validate(conf) ){
		abort();
	}

	return conf;
}

static inline void _stop_modules( probe_context_t *context){
	IF_ENABLE_PCAP(
		pcap_capture_stop(context);
	)

}

//global context of MMT-Probe
probe_context_t *get_context(){
	static probe_context_t context;
	return &context;
}

static volatile sig_atomic_t main_processing_signal = 0;
//the first crash signal received: if the crash reporter itself faults, the
// handler is re-entered - the process must then still die by the first signal
static volatile sig_atomic_t first_crash_signal = 0;

/**
 * Report a fatal signal from inside a signal handler. Only async-signal-safe
 * primitives are used: a single write() to stderr for the one-line message,
 * then backtrace_symbols_fd() which writes the backtrace directly to stderr -
 * unlike backtrace_symbols() it does not allocate memory, so this still works
 * when the crash happened inside the allocator (a malloc/free call here could
 * deadlock on a held arena lock and prevent the crash exit).
 */
static void _report_crash_signal( int sig ){
	static const char prefix[] = "mmt-probe: crash signal received: ";
	char msg[ sizeof( prefix ) - 1 + 10 + 1 ];
	size_t i = 0;
	for( const char *c = prefix; *c != '\0'; c ++ )
		msg[ i++ ] = *c;
	//append the signal number: snprintf() is not async-signal-safe
	i += append_uint_dec( msg + i, sig );
	msg[ i++ ] = '\n';
	//best effort: nothing sensible to do if the write fails
	if( write( STDERR_FILENO, msg, i ) < 0 ){}

	void *frames[ 16 ];
	int nb_frames = backtrace( frames, 16 );
	backtrace_symbols_fd( frames, nb_frames, STDERR_FILENO );
}

/**
 * Report a termination signal from inside a signal handler, where the
 * logger - syslog - cannot be used: it is not async-signal-safe and a
 * signal interrupting it inside a lock would deadlock the drain (the
 * monitor's forwarded signal can arrive while a previous one is being
 * handled). Only write() to stderr is used, as in _report_crash_signal().
 * The text keeps the "Received SIG<name>" markers the logger produced.
 */
static void _report_termination_signal( const char *name ){
	static const char prefix[] = "mmt-probe: Received SIG";
	static const char suffix[] = ". Main processing process is releasing resource ...\n";
	//the whole line is composed in one buffer and emitted by a single
	// write(): several writes could interleave on the shared descriptor
	// with the report of another process signalled at the same instant
	// (a group-wide kill) and break the markers docker-logs scrapers match
	char msg[ sizeof( prefix ) - 1 + 8 + sizeof( suffix ) - 1 ];
	size_t i = 0;
	const char *c;
	for( c = prefix; *c != '\0'; c ++ )
		msg[ i++ ] = *c;
	//a signal name is a few characters; the buffer leaves room for 8
	for( c = name; *c != '\0' && c - name < 8; c ++ )
		msg[ i++ ] = *c;
	for( c = suffix; *c != '\0'; c ++ )
		msg[ i++ ] = *c;
	if( write( STDERR_FILENO, msg, i ) < 0 ){}
}

/**
 * Report a second signal from inside a signal handler - the process then
 * exits immediately. write() only, for the same reason as above.
 */
static void _report_second_signal( int sig ){
	static const char prefix[] = "mmt-probe: Received signal ";
	static const char suffix[] = " while processing other one. Exit immediately.\n";
	//one buffer, one write(): see _report_termination_signal()
	char msg[ sizeof( prefix ) - 1 + 10 + sizeof( suffix ) - 1 ];
	size_t i = 0;
	const char *c;
	for( c = prefix; *c != '\0'; c ++ )
		msg[ i++ ] = *c;
	i += append_uint_dec( msg + i, sig );
	for( c = suffix; *c != '\0'; c ++ )
		msg[ i++ ] = *c;
	if( write( STDERR_FILENO, msg, i ) < 0 ){}
}

/**
 * This signal handler ensures clean exits.
 * Note: calling printf() from a signal handler is not safe since printf() is not async-signal-safe,
 *      and neither is the logger (syslog): they are not used here - only write() to stderr and
 *      pcap_breakloop(), which libpcap documents as signal-handler-safe.
 */
void signal_handler(int type) {
	//this handler returns to the interrupted code on the termination and
	// restart arms below: errno must be left as it was found - a libc call
	// inside the handler, e.g., a best-effort write() that fails, would
	// otherwise clobber it. The crash arms never reach the restore: they
	// _exit or die by the signal first.
	int saved_errno = errno;

	//remember signal type in order to restart its process
	main_processing_signal = type;

	probe_context_t *context = get_context();
	if(  context->is_exiting ){
		//a crash signal while shutting down is still a crash:
		// in offline mode there is no monitor process, so die by the signal
		if( context->config->input->input_mode == OFFLINE_ANALYSIS )
			switch( type ){
			case SIGSEGV:
			case SIGBUS:
			case SIGFPE:
			case SIGILL:
			case SIGABRT:
				if( first_crash_signal == 0 ){
					first_crash_signal = type;
					_report_crash_signal( type );
				}
				EXIT_BY_SIGNAL( first_crash_signal );
			}
		//a second termination signal asks to exit right now - e.g., a
		// group-wide kill plus the monitor's forward - without touching the
		// logger, which the interrupted code may hold a lock of
		_report_second_signal( type );
		EXIT_NORMALLY();
	}

	switch( type ){
	case SIGINT:
		_report_termination_signal( "INT" );
		context->is_exiting = true;

		_stop_modules( context );
		break;

	case SIGTERM:
		_report_termination_signal( "TERM" );
		context->is_exiting = true;

		_stop_modules( context );
		break;

		//crash signals, e.g., segmentation fault
	case SIGSEGV:
	case SIGBUS:
	case SIGFPE:
	case SIGILL:
		//a nested crash while reporting skips the report and dies by the
		// first signal - the reporter itself may fault on a corrupted stack
		if( first_crash_signal == 0 ){
			first_crash_signal = type;
			_report_crash_signal( type );
		}

		//Auto restart when crashing in online mode: the monitor process
		// re-creates the processing process when it exits non-zero.
		//In offline mode there is no monitor process: re-raise the signal so
		// callers see a signal death (128 + signum as seen from a shell).
		if( context->config->input->input_mode == OFFLINE_ANALYSIS )
			EXIT_BY_SIGNAL( first_crash_signal );
		else
			EXIT_TOBE_RESTARTED();
		break;

		//abort signal may be generated by calling abort() function.
		//In the code, this function is called when some parameters are not well configured or not enough memory.
		//In such a case, in online mode, the child exits with the do-not-restart status so the monitor
		// stops the probe without restarting it and gives control to user to update the parameters (#10).
		//In offline mode, an abort is a crash: re-raise SIGABRT so callers see a signal death.
	case SIGABRT:
		if( context->config->input->input_mode == OFFLINE_ANALYSIS ){
			if( first_crash_signal == 0 ){
				first_crash_signal = type;
				_report_crash_signal( type );
			}
			EXIT_BY_SIGNAL( first_crash_signal );
		}else{
			static const char abort_msg[] =
				"mmt-probe: Abort signal received! Cleaning up before exiting!\n";
			if( write( STDERR_FILENO, abort_msg, sizeof( abort_msg ) - 1 ) < 0 ){}
			EXIT_NO_RESTART();
		}
		break;
	case SIGRES:
		{
			static const char restart_msg[] =
				"mmt-probe: Restart signal received! Cleaning up before restarting!\n";
			if( write( STDERR_FILENO, restart_msg, sizeof( restart_msg ) - 1 ) < 0 ){}
		}
		_stop_modules( context );
	}

	//every path that falls through the switch returns to the interrupted
	// code: restore the errno saved on entry (see above)
	errno = saved_errno;
}

//need to clean resource before exiting each process
static void _clean_resource(){
	probe_context_t *context = get_context();
	IF_ENABLE_DYNAMIC_CONFIG(
		if( context->config->dynamic_conf->is_enable )
			dynamic_conf_release();
	)
	conf_release( context->config );
	log_close();
}

#ifdef STATIC_LINK
//this function is implemented inside libmmt_tcpip.a
extern void init_tcpip_plugin();

static inline void _load_tcp_plugin(){
	//check if ip proto has been loaded?
	//This can happen when MMT-Probe is compiled using STATIC_LINK param
	//  but we still have libmmt_tcpip.so in ./plugins/ or /opt/mmt/plugins folders.
	//In such a case,  the libmmt_tcpi.so will be loaded by init_extraction function.
	//So we do not need to load the internal library that has been embedded inside probe by static link.
	//In other words, we do not need to call init_tcpip_plugin function as it will
	//   cause errors when the library is loaded doubly.
	const char *name = get_protocol_name_by_id( PROTO_IP );
	if( name == NULL ){
		init_tcpip_plugin();
		log_write( LOG_INFO, "Use internal mmt_tcpip that has been embedded inside MMT-Probe");
	}else{
		log_write( LOG_INFO, "Use external mmt_tcpip that has been packaged inside libmmt_tcpip.so");
	}
}
#endif

static struct {
	uint32_t type;
	uint32_t offset;
} stack = {1, 0}; //1: Ethernet, 0: no offset => protocol Ethernet is started immediately at the first byte

static classified_proto_t _stack_classification(ipacket_t * ipacket) {
	classified_proto_t retval;
	retval.offset   = stack.offset;
	retval.proto_id = stack.type;
	retval.status   = Classified;
	return retval;
}

bool _init_protocol_stack(uint32_t stack_type, uint32_t stack_offset ){
	switch( stack_type ){
	//these stack are already registered in DPI
	case 1:   //Ethernet
	case 624: //Linux cooked capture
	case 800: //ieee802154
		//Use the function that is registered in DPI
		// => the function "_stack_classification" will no be called
		return true;
	default:
		//for the other stack, we need to register it to DPI
		//We use protocol ID as the stack number
		stack.type   = stack_type;
		stack.offset = stack_offset;
		return register_protocol_stack( stack_type, "Dynamic-Stack", _stack_classification);
	}
}


/**
 * This is the main processing process of MMT-Probe.
 * Every packets processing are done here.
 * argc and argv are the ones from main()
 * @return
 */
static int _main_processing( int argc, char** argv ){
	//resolve the backtrace machinery now, before any signal handler is
	// installed: the first backtrace() call lazily loads libgcc_s (dlopen +
	// malloc, not async-signal-safe) — inside a crash handler that could
	// deadlock or fault before the process dies by the signal
	{
		void *frames[ 1 ];
		(void) backtrace( frames, 1 );
	}

	//must not handle SIGUSR1 as it is used by mmt_bus
	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGBUS,  signal_handler);
	signal(SIGFPE,  signal_handler);
	signal(SIGILL,  signal_handler);
	signal(SIGABRT, signal_handler);
	signal(SIGRES,  signal_handler);

	int ret = 0;

	probe_context_t *context = get_context();

#ifdef DPDK_MODULE
	char *dpdk_argv[ 100 ];
	int dpdk_argc = string_split( context->config->input->dpdk_options, " ", &dpdk_argv[1], 100-1 );

	//the first parameter is normally program name
	dpdk_argv[0] = LOG_IDENT;
	dpdk_argc   += 1;

	ret = rte_eal_init( dpdk_argc, dpdk_argv );
	if (ret < 0)
		rte_exit_failure( "Error while EAL initialization" );
#endif

	IF_ENABLE_SECURITY(
		if( context->config->reports.security != NULL && context->config->reports.security->is_enable )
			security_open( context->config->reports.security->excluded_rules );
	)

	log_write( LOG_INFO, "MMT-Probe v%s is running on pid %d",
			get_version(),
			getpid() );
	log_write( LOG_INFO, "Modules: " MODULES_LIST );

	//when libmmt_tcpip is statically linked into mmt-probe,
	// we need to fire its bootstrap function to initialize its protocol list
	//(the function is fired automatically when the lib is dynamically loaded)
#ifdef STATIC_LINK
	_load_tcp_plugin();
#endif

	log_write( LOG_INFO, "MMT-DPI %s", mmt_version() );

	//a statistic output
	const uint16_t output_id = 0;
	context->output = output_alloc_init( output_id, &context->config->outputs, context->config->probe_id, context->config->input->input_source, true );

	if( !_init_protocol_stack( context->config->stack_type, context->config->stack_offset )  ){
		log_write( LOG_ERR, "Cannot initialize stack-type=%d! Exiting!", context->config->stack_type );
		return EXIT_FAILURE;
	}

	//other stubs, such as, system usage report
	routine_t *routine = routine_create_and_start( context );

#ifdef DPDK_MODULE
	dpdk_capture_start( context );
#else
	pcap_capture_start( context );
#endif

	IF_ENABLE_SECURITY(
		if( context->config->reports.security != NULL && context->config->reports.security->is_enable )
			security_close();
	)

	routine_stop_and_release( routine );
	//we free the output here only in SMP mode
	// because in non-SMP mode, this output is used also by a worker
	// the worker will free the output once MMT-Probe terminated
	//=> avoid double free
	if( IS_SMP_MODE(context) )
		output_release( context->output );

	//depending on signal received, exit using different value to notify the monitor process
	switch( main_processing_signal ){
	case SIGINT:
	case SIGTERM:
		EXIT_NORMALLY();
		break;
	case SIGRES:
		EXIT_TOBE_RESTARTED();
		break;
	}

	return EXIT_SUCCESS;
}


/**
 * this function will create 2 children processes:
 *  - processing process: performs main jobs realising by _main_processing
 *  - control process: receives control commands via UNIX domain socket and broadcast the commands to
 *  the 2 other processes (parent - or the monitor process, and the processing process)
 * The parent process - or the monitor process - monitors its children to recreate them if need, e.g., when they was crashed.
 * The parent can also stop or start the processing process depending on command received from the control process.
 * @param argc
 * @param argv
 * @return
 */

//special process id (value of pid_t)
#define PID_NEED_TO_CREATE 0
#define PID_NEED_TO_STOP  -1
#define ANY_CHILD_PROCESS -1

//the last termination signal the monitor process received: SIGINT or SIGTERM
static volatile sig_atomic_t monitor_stop_signal = 0;

/**
 * The monitor process forwards termination signals to its children (#7):
 * docker stop or systemctl stop signals the monitor only, which must relay
 * them so the children can flush their reports and exit cleanly. The handler
 * only records the signal - the monitor loop then forwards it with kill() to
 * each live child, which covers a child forked while the handler ran and
 * keeps the handler trivially async-signal-safe.
 */
static void _monitor_signal_handler( int sig ){
	//this handler returns to the interrupted code: keep errno as it was
	// found (nothing here can set it today, but a future call could)
	int saved_errno = errno;
	monitor_stop_signal = sig;
	errno = saved_errno;
}

/**
 * @return the processing child's fate: its exit status, 0 when a termination
 *  signal killed it - that is the shutdown that was asked for - or
 *  128 + signum when it died of another signal
 */
static int _create_sub_processes( int argc, char** argv ){
	pid_t child_pid;
	pid_t children_pids[ 2 ] = {PID_NEED_TO_CREATE, PID_NEED_TO_CREATE};
	int nb_children_processes = 1; //by default, only one sub-process for the main processing
	int  status, i;
	bool stopping = false;      //a termination signal was received: nothing is (re)created any more
	int  forwarded_signal = 0;  //the signal that was forwarded to the children
	//the exit status the monitor reports
	int  monitor_exit_status = EXIT_SUCCESS;

	probe_context_t *context = get_context();

	IF_ENABLE_DYNAMIC_CONFIG(
			if( context->config->dynamic_conf->is_enable ){
				//take into account control process
				nb_children_processes = 2;
				dynamic_conf_alloc_and_init( & children_pids[0] );
			}
	)

	//an infinity loop to monitor the children processes: restart when it has been crashed
	while( true ){

		//0. a termination signal ends the probe: it is forwarded to every live
		// child (the handler only recorded it - a child forked while it ran is
		// reached here), then the monitor just waits for them. A different
		// second signal is forwarded too - the children treat a second signal
		// as "exit immediately" - while a repeated one is not sent again.
		if( monitor_stop_signal != 0 && monitor_stop_signal != forwarded_signal ){
			stopping = true;
			forwarded_signal = monitor_stop_signal;
			log_write( LOG_INFO, "Received signal %d. Stopping MMT-Probe ...", forwarded_signal );
			for( i=0; i<nb_children_processes; i++ ){
				if( children_pids[ i ] > 0 )
					kill( children_pids[ i ], forwarded_signal );
				else
					children_pids[ i ] = PID_NEED_TO_STOP;
			}
		}

		//1. create a child process for main processing
		if( ! stopping && children_pids[ 0 ] == PID_NEED_TO_CREATE ){
			//the child inherits the monitor's flag-only handler until it
			// resets its dispositions: a forwarded signal caught in between
			// would just set the flag in the child - which never reads it -
			// and the monitor would wait on it forever. Blocking the signals
			// around the fork makes the child inherit the blocked mask, so a
			// signal stays pending until the child's reset is done.
			sigset_t block_set, prev_set;
			sigemptyset( &block_set );
			sigaddset( &block_set, SIGINT );
			sigaddset( &block_set, SIGTERM );
			sigprocmask( SIG_BLOCK, &block_set, &prev_set );
			//duplicate the current process into 2 different processes
			child_pid = fork();
			sigprocmask( SIG_SETMASK, &prev_set, NULL );

			if( child_pid < 0 ) {
				ABORT( "Fork error: %s", strerror(errno) );
				exit( EXIT_FAILURE );
			}

			if (child_pid == 0) {
				//we are in child process: the monitor's dispositions were
				// inherited - reset them so a forwarded signal kills this
				// child by default until _main_processing installs its own
				// handlers (the monitor counts that death as the requested stop)
				signal( SIGINT,  SIG_DFL );
				signal( SIGTERM, SIG_DFL );
				sigprocmask( SIG_SETMASK, &prev_set, NULL );

				log_write( LOG_INFO, "Create a new sub-process %d for main processing", getpid() );

				IF_ENABLE_DYNAMIC_CONFIG(
					if( context->config->dynamic_conf->is_enable )
						dynamic_conf_agency_start() ;
				)

				int child_ret = _main_processing( argc, argv );

				//clean resource
				_clean_resource();

				//the child exits with _main_processing()'s status (#10): a
				// non-zero return is a start-up error - e.g., a bad parameter
				// value or an input the probe cannot use - that a restart
				// would not fix, so the monitor is told to stop the child
				// without restarting it
				exit( child_ret == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_STATUS_NO_RESTART );
			}

			//in parent process
			children_pids[0] = child_pid;
		}

		//2. create a control process for dynamic configuration
		//this process receives external commands via an UNIX domain socket, then send them to the main processing
#ifdef DYNAMIC_CONFIG_MODULE
		if( ! stopping && context->config->dynamic_conf->is_enable && children_pids[ 1 ] == PID_NEED_TO_CREATE ){
			children_pids[1] = dynamcic_conf_create_new_process_to_receive_command( context->config->dynamic_conf->descriptor, _clean_resource );
		}
#endif

		//nothing remains to be waited for: every child is dead and none is due
		// to be (re)created - while stopping, markers left by a control command
		// do not count
		int nb_pending_children = 0;
		for( i=0; i<nb_children_processes; i++ )
			if( children_pids[ i ] > 0
			 || ( ! stopping && children_pids[ i ] == PID_NEED_TO_CREATE ))
				nb_pending_children ++;
		if( nb_pending_children == 0 )
			break;

		//3. check if a child has terminated
		//while stopping only terminations matter and waitpid blocks until one
		// happens; otherwise it does not block (WNOHANG)
		child_pid = waitpid( ANY_CHILD_PROCESS, &status, stopping ? 0 : WNOHANG );

		if( child_pid == -1 ){
			//a signal interrupted the wait: nothing was reaped
			if( errno == EINTR )
				goto _next_iteration;
			ABORT( "Cannot wait for children: %s", strerror( errno ) );
		}

		//no child changes its state
		if( child_pid == 0 )
			goto _next_iteration;

		log_write( LOG_INFO, "Child process %d return code: %d", child_pid, status );

		//which child terminated
		int child_index = -1;
		for( i=0; i<nb_children_processes; i++ )
			if( child_pid == children_pids[i] ){
				child_index = i;
				break;
			}

		//the processing child's fate gives the monitor's exit status
		if( child_index == 0 ){
			if( WIFEXITED( status ) )
				monitor_exit_status = WEXITSTATUS( status );
			else if( WIFSIGNALED( status )
					&& WTERMSIG( status ) != SIGINT && WTERMSIG( status ) != SIGTERM )
				monitor_exit_status = 128 + WTERMSIG( status );
			//a death by SIGINT or SIGTERM is the shutdown that was asked for
		}

		//4. parent will check to re-create a new instance of a child if it was
		// killed by a crash - a signal death or the EXIT_TOBE_RESTARTED status.
		// While stopping, or when the child exits cleanly or with the
		// do-not-restart status, it stays dead.
		int child_state;
		if( stopping
		 || ( WIFEXITED( status )
		  && ( WEXITSTATUS( status ) == EXIT_SUCCESS
		    || WEXITSTATUS( status ) == EXIT_STATUS_NO_RESTART )))
			child_state = PID_NEED_TO_STOP;
		else //mark to re-create this child
			child_state = PID_NEED_TO_CREATE;

		//update status of the child
		if( child_index >= 0 )
			children_pids[ child_index ] = child_state;

		//5. the do-not-restart status stops the whole probe: tell the other
		// children to terminate too
		if( ! stopping
		 && WIFEXITED( status ) && WEXITSTATUS( status ) == EXIT_STATUS_NO_RESTART ){
			stopping = true;
			forwarded_signal = SIGTERM;
			log_write( LOG_INFO, "Child process %d reported a start-up error. Stopping MMT-Probe ...", child_pid );
			for( i=0; i<nb_children_processes; i++ ){
				if( children_pids[ i ] > 0 )
					kill( children_pids[ i ], SIGTERM );
				else
					children_pids[ i ] = PID_NEED_TO_STOP;
			}
		}

		_next_iteration:
		IF_ENABLE_DYNAMIC_CONFIG(
			//we need to check periodically if there are new commands that have been broadcasted by the control process
			if( context->config->dynamic_conf->is_enable )
				dynamic_conf_check();
		)

		//avoid exhaustively resource when having dense consecutive restarts: restart, crash, restart, crash, ...
		//no restart happens while stopping: no need to wait
		if( ! stopping )
			sleep( 1 );
	}

	return monitor_exit_status;
}


int main( int argc, char** argv ){

	//the monitor process does not ignore Ctrl+C and SIGTERM: it records them
	// to forward them to its children, which handle them (#7). In offline and
	// debug modes _main_processing installs its own handlers below instead.
	signal( SIGINT,  _monitor_signal_handler );
	signal( SIGTERM, _monitor_signal_handler );
	log_open();

	IF_ENABLE_DEBUG(
		log_write( LOG_WARNING, "Must not run debug mode in production environment" );
	)

	//DPI initialization
	if( !init_extraction() ) { // general ixE initialization
		log_write( LOG_ERR, "MMT Extraction engine initialization error! Exiting!");
		return EXIT_FAILURE;
	}

	//read configuration from file and execution parameters
	probe_context_t *context = get_context();
	//initialize: fill zero
	memset( context, 0, sizeof( probe_context_t) );

	//MMT-Probe is running.
	//This variable is false only when user want to stop MMT-Probe by sending SIGINT signal, e.g., pressing Ctrl+C
	context->is_exiting = false;
	context->config = _parse_options(argc, argv);
	if( conf_validate( context->config ) > 0 )
		return EXIT_FAILURE;

	int processing_ret = EXIT_SUCCESS;
#ifdef DEBUG_MODE
	processing_ret = _main_processing( argc, argv );
#else
	//if MMT-Probe is used to check pcap offline
	// => no need to created sub processes
	if( context->config->input->input_mode == OFFLINE_ANALYSIS ){
		processing_ret = _main_processing( argc, argv );
	}else{
		processing_ret = _create_sub_processes( argc, argv );
	}
#endif

	//a failure inside the processing process, e.g., a bad parameter value,
	// must not be reported as a success
	if( processing_ret != EXIT_SUCCESS )
		return processing_ret;

	//end
	close_extraction();

	log_write(LOG_INFO, "Exit normally MMT-Probe");
	_clean_resource();

	printf("Bye\n");
	return EXIT_SUCCESS;
}
