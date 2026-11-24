/*
 * report_overflow_test.c - Regression test for issue #9
 *
 * The report writers accumulate the "would-be written" lengths reported by
 * snprintf-style functions (snprintf, vsnprintf, mmt_attr_sprintf) into their
 * offsets. A report longer than the destination buffer moved the offset past
 * the end of the buffer, so the following writes landed out of bounds.
 *
 * This test drives the writers with buffers that cannot contain a whole
 * report. On the unfixed code it overflows the buffers (ASan reports a
 * stack-buffer-overflow); on the fixed code the report is truncated safely.
 *
 * It includes the report writers' sources directly as their statistics
 * structures are private to the .c files.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

//only the file and stdout channels are exercised by this driver: compile the
//optional output channels out so the binary does not need their libraries
#undef KAFKA_MODULE
#undef MONGODB_MODULE
#undef REDIS_MODULE
#undef MQTT_MODULE
#undef SOCKET_MODULE

//this branch builds output.c with an optional STIX alert format; compile it
//out so the driver needs neither libuuid nor the STIX sources
#undef STIX_FORMAT

#include "../../src/lib/limit.h"
#include "../../src/modules/output/file/file_output.c"
#include "../../src/modules/output/output.c"
#include "../../src/modules/dpi/report/event_based_report.c"
#include "../../src/modules/dpi/report/session_report_rtp.c"
#include "../../src/modules/dpi/report/session_report_gtp.c"

//bounded_snprintf_len maps a snprintf-style return value to the number of
//bytes really appended in the destination buffer
static void test_bounded_snprintf_len( void ){
	assert( bounded_snprintf_len( 10, -1 ) == 0 ); //error: nothing written
	assert( bounded_snprintf_len( 10,  0 ) == 0 );
	assert( bounded_snprintf_len( 10,  3 ) == 3 ); //everything fitted
	assert( bounded_snprintf_len( 10,  9 ) == 9 ); //fits exactly, no room for '\0'
	assert( bounded_snprintf_len( 10, 10 ) == 9 ); //truncated: 9 bytes + '\0'
	assert( bounded_snprintf_len( 10, 50 ) == 9 ); //truncated
	assert( bounded_snprintf_len(  1,  5 ) == 0 ); //room for '\0' only
	assert( bounded_snprintf_len(  0,  5 ) == 0 ); //empty destination
}

//_print_ip_session_report appends each app report at message + valid, then
//writes message[valid] = '\0'. A writer returning its would-be length moves
//valid past the end of the buffer.
static void test_rtp_report_truncated( void ){
	char message[ MAX_LENGTH_REPORT_MESSAGE + 1 ];
	int valid = MAX_LENGTH_REPORT_MESSAGE - 10; //the report is almost full

	session_stat_t session_stat;
	memset( &session_stat, 0, sizeof( session_stat ));
	session_stat.app_type = SESSION_STAT_TYPE_APP_RTP;

	session_rtp_stat_t rtp;
	memset( &rtp, 0, sizeof( rtp ));
	rtp.packets_nb     = 1000000;
	rtp.jitter         = 4294967295U; //10 digits: a long enough report
	rtp.nb_order_error = 50000;
	rtp.nb_lost        = 12345;
	rtp.nb_loss_bursts = 678;
	session_stat.apps.rtp = &rtp;

	valid += print_rtp_report( message + valid, MAX_LENGTH_REPORT_MESSAGE + 1 - valid,
			NULL, &session_stat, NULL );

	//this is the write _print_ip_session_report does after the switch: it is
	//out-of-bounds when the writer returned its would-be length
	message[ valid ] = '\0';
	assert( valid <= MAX_LENGTH_REPORT_MESSAGE );
	assert( strlen( message + MAX_LENGTH_REPORT_MESSAGE - 10 ) == (size_t) valid - ( MAX_LENGTH_REPORT_MESSAGE - 10 ));
}

//print_gtp_report appends the list of TEIDs then ']' and '\0' unconditionally:
//all these writes must stay inside the destination buffer
static void test_gtp_report_truncated( void ){
	char message[ 64 ];

	session_stat_t session_stat;
	memset( &session_stat, 0, sizeof( session_stat ));
	session_stat.app_type = SESSION_STAT_TYPE_APP_GTP;

	session_gtp_stat_t gtp;
	memset( &gtp, 0, sizeof( gtp ));
	gtp.ip_version  = 4;
	gtp.ip_src.ipv4 = 0x08080808;
	gtp.ip_dst.ipv4 = 0x08080404;
	//6 TEIDs of 10 digits fill the buffer well before the list is closed
	int i;
	for( i=0; i<MAX_NB_TEID; i++ )
		gtp.teids[i] = 4294967295U;
	session_stat.apps.gtp = &gtp;

	int ret = print_gtp_report( message, sizeof( message ), NULL, &session_stat, NULL );

	assert( ret >= 0 && ret < (int) sizeof( message ));
	assert( strlen( message ) == (size_t) ret );
}

//an app report that fits entirely must be written as before
static void test_gtp_report_complete( void ){
	char message[ 512 ];

	session_stat_t session_stat;
	memset( &session_stat, 0, sizeof( session_stat ));
	session_stat.app_type = SESSION_STAT_TYPE_APP_GTP;

	session_gtp_stat_t gtp;
	memset( &gtp, 0, sizeof( gtp ));
	gtp.ip_version  = 4;
	gtp.ip_src.ipv4 = 0x08080808;
	gtp.ip_dst.ipv4 = 0x08080404;
	gtp.teids[0]    = 1234;
	gtp.teids[1]    = 5678;
	session_stat.apps.gtp = &gtp;

	int ret = print_gtp_report( message, sizeof( message ), NULL, &session_stat, NULL );

	assert( ret > 0 && ret < (int) sizeof( message ));
	assert( strlen( message ) == (size_t) ret );
	assert( strcmp( message, "\"8.8.8.8\",\"8.4.4.8\",[1234,5678]" ) == 0 );
}

//output._write surrounds a report by '[' and ']' to output it as JSON (or to
//MongoDB): the wrap must fit a whole report, and a longer message must be
//truncated rather than overflow new_msg
static void test_output_json_wrap( void ){
	file_output_conf_t file_conf;
	memset( &file_conf, 0, sizeof( file_conf )); //file channel disabled

	output_conf_t conf;
	memset( &conf, 0, sizeof( conf ));
	conf.is_enable = true;
	conf.format    = OUTPUT_FORMAT_JSON;
	conf.file      = &file_conf;

	output_t *output = output_alloc_init( 0, &conf, 0, "test", false );
	assert( output != NULL );

	//the reports are written to stdout: send them to /dev/null to keep the
	//output of this driver readable
	FILE *devnull = fopen( "/dev/null", "w" );
	assert( devnull != NULL );
	fflush( stdout );
	int stdout_copy = dup( fileno( stdout ));
	int rc1 = dup2( fileno( devnull ), fileno( stdout ));
	assert( stdout_copy >= 0 && rc1 >= 0 );

	//a body of N, N-1 or N-2 bytes fills the report to its limit
	char body[ MAX_LENGTH_REPORT_MESSAGE + 1 ];
	memset( body, 'A', MAX_LENGTH_REPORT_MESSAGE );
	struct timeval ts = { .tv_sec = 1234, .tv_usec = 0 };
	int sizes[] = { MAX_LENGTH_REPORT_MESSAGE,
			MAX_LENGTH_REPORT_MESSAGE - 1,
			MAX_LENGTH_REPORT_MESSAGE - 2 };
	int i;
	for( i=0; i<3; i++ ){
		body[ sizes[i] ] = '\0';
		int ret = output_write_report( output, CONF_OUTPUT_CHANNEL_STDOUT,
				DUMMY_REPORT_TYPE, &ts, body );
		assert( ret == 1 );
	}

	fflush( stdout );
	int rc2 = dup2( stdout_copy, fileno( stdout ));
	assert( rc2 >= 0 );
	close( stdout_copy );
	fclose( devnull );

	output_release( output );
}

//_process_ieee802154_src_dst wrote "" and returned 2 without looking at the
//room left in the buffer: at a full report that wrote past the buffer and
//moved the caller's offset out of bounds
static void test_ieee802154_attr_truncated( void ){
	char message[ MAX_LENGTH_REPORT_MESSAGE + 1 ];

	//the report is exactly full: nothing may be written
	int ret0 = _process_ieee802154_src_dst( message + MAX_LENGTH_REPORT_MESSAGE, 0,
			PROTO_IEEE802154, IEEE802154_SRC_ADDRESS_EXTENDED, NULL );
	assert( ret0 == 0 );

	//room for the closing '\0' only
	int ret1 = _process_ieee802154_src_dst( message + MAX_LENGTH_REPORT_MESSAGE, 1,
			PROTO_IEEE802154, IEEE802154_DST_ADDRESS_EXTENDED, NULL );
	assert( ret1 == 0 );
	assert( message[ MAX_LENGTH_REPORT_MESSAGE ] == '\0' );

	//a fitting buffer still gets ""
	char buf[8];
	int ret2 = _process_ieee802154_src_dst( buf, sizeof( buf ), PROTO_IEEE802154,
			IEEE802154_SRC_ADDRESS_EXTENDED, NULL );
	assert( ret2 == 2 );
	assert( strcmp( buf, "\"\"" ) == 0 );
}

int main( void ){
	test_bounded_snprintf_len();
	test_rtp_report_truncated();
	test_gtp_report_truncated();
	test_gtp_report_complete();
	test_output_json_wrap();
	test_ieee802154_attr_truncated();

	printf( "report-overflow: all assertions passed\n" );
	return 0;
}
