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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//only the file and stdout channels are exercised by this driver: compile the
//optional output channels out so the binary does not need their libraries
#undef KAFKA_MODULE
#undef MONGODB_MODULE
#undef REDIS_MODULE
#undef MQTT_MODULE
#undef SOCKET_MODULE

//the probe always builds with -DNDEBUG, so assert() would compile to nothing
//here: CHECK always evaluates its condition, prints file:line and the
//failing condition on stderr, and exits non-zero
#define CHECK( cond ) do { \
	if( !(cond) ){ \
		fprintf( stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond ); \
		exit( 1 ); \
	} \
} while( 0 )

#include "../../src/lib/limit.h"
#include "../../src/modules/output/file/file_output.c"
#include "../../src/modules/output/output.c"
#include "../../src/modules/dpi/report/event_based_report.c"
#include "../../src/modules/dpi/report/session_report_rtp.c"
#include "../../src/modules/dpi/report/session_report_gtp.c"

//bounded_snprintf_len maps a snprintf-style return value to the number of
//bytes really appended in the destination buffer
static void test_bounded_snprintf_len( void ){
	CHECK( bounded_snprintf_len( 10, -1 ) == 0 ); //error: nothing written
	CHECK( bounded_snprintf_len( 10,  0 ) == 0 );
	CHECK( bounded_snprintf_len( 10,  3 ) == 3 ); //everything fitted
	CHECK( bounded_snprintf_len( 10,  9 ) == 9 ); //fits exactly, no room for '\0'
	CHECK( bounded_snprintf_len( 10, 10 ) == 9 ); //truncated: 9 bytes + '\0'
	CHECK( bounded_snprintf_len( 10, 50 ) == 9 ); //truncated
	CHECK( bounded_snprintf_len(  1,  5 ) == 0 ); //room for '\0' only
	CHECK( bounded_snprintf_len(  0,  5 ) == 0 ); //empty destination
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
	CHECK( valid <= MAX_LENGTH_REPORT_MESSAGE );
	CHECK( strlen( message + MAX_LENGTH_REPORT_MESSAGE - 10 ) == (size_t) valid - ( MAX_LENGTH_REPORT_MESSAGE - 10 ));
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

	CHECK( ret >= 0 && ret < (int) sizeof( message ));
	CHECK( strlen( message ) == (size_t) ret );
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
	gtp.ip_dst.ipv4 = 0x08040408;
	gtp.teids[0]    = 1234;
	gtp.teids[1]    = 5678;
	session_stat.apps.gtp = &gtp;

	int ret = print_gtp_report( message, sizeof( message ), NULL, &session_stat, NULL );

	CHECK( ret > 0 && ret < (int) sizeof( message ));
	CHECK( strlen( message ) == (size_t) ret );
	//0x08040408 is palindromic: append_ipv4 reads the address byte by byte,
	//so it prints "8.4.4.8" on both little- and big-endian hosts
	CHECK( strcmp( message, "\"8.8.8.8\",\"8.4.4.8\",[1234,5678]" ) == 0 );
}

//the reports are written to stdout: redirect it to a temporary capture file
//so the emitted bytes can be checked, not only the return value. Returns the
//capture file and stores a copy of the real stdout fd in *stdout_copy for
//capture_restore()
static FILE *capture_begin( int *stdout_copy ){
	FILE *cap = tmpfile();
	CHECK( cap != NULL );
	fflush( stdout );
	*stdout_copy = dup( fileno( stdout ));
	CHECK( *stdout_copy >= 0
			&& dup2( fileno( cap ), fileno( stdout )) >= 0 );
	return cap;
}

//flush the captured writes, put the real stdout back and rewind the capture
//file so the emitted bytes can be read from its start
static void capture_restore( FILE *cap, int stdout_copy ){
	fflush( stdout );
	CHECK( dup2( stdout_copy, fileno( stdout )) >= 0 );
	close( stdout_copy );
	rewind( cap );
}

//read one emitted line from the capture file: it must be exactly
//'[' + <len bytes of expect> + ']' + '\n'
static void check_emitted( FILE *cap, const char *expect, size_t len ){
	CHECK( fgetc( cap ) == '[' );
	size_t i;
	for( i=0; i<len; i++ )
		CHECK( fgetc( cap ) == (unsigned char) expect[ i ] );
	CHECK( fgetc( cap ) == ']' );
	CHECK( fgetc( cap ) == '\n' );
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
	CHECK( output != NULL );

	//the reports are written to stdout: capture them to check what is
	//really emitted, not only the return value
	int stdout_copy;
	FILE *cap = capture_begin( &stdout_copy );

	//a body of N, N-1 or N-2 bytes fills the report to its limit: each call
	//emits the report prefix and the part of the body that fits, bracketed.
	//A reverted wrap fix cannot be observed through these lines: the
	//out-of-bounds ']' and '\0' land contiguously past new_msg, so fprintf
	//emits the same bytes — only ASan sees that overflow. The direct _write
	//calls below are what give the cap a red without ASan
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
		CHECK( ret == 1 );
	}

	//output_write_report bounds its message at MAX_LENGTH_REPORT_MESSAGE, so
	//the truncation cap inside _write is reachable only by calling _write
	//directly (this driver includes output.c): an overlong message must emit
	//only its first MAX_LENGTH_REPORT_MESSAGE bytes between the brackets.
	//Without the cap the emitted line carries more body bytes than that, so
	//this check fires without ASan when the overwrite reaches stdout
	char overlong[ 2 * MAX_LENGTH_REPORT_MESSAGE + 1 ];
	for( i=0; i < (int) sizeof( overlong ) - 1; i++ )
		overlong[i] = 'a' + i % 26;
	int overs[] = { MAX_LENGTH_REPORT_MESSAGE + 1,
			2 * MAX_LENGTH_REPORT_MESSAGE };
	for( i=0; i<2; i++ ){
		overlong[ overs[i] ] = '\0';
		CHECK( _write( output, CONF_OUTPUT_CHANNEL_STDOUT, overlong, false ) == 1 );
	}

	capture_restore( cap, stdout_copy );

	//the three reports emit the same line: '[' + the CSV prefix + as many
	//body bytes as fit a full report + ']' + '\n'
	char report[ MAX_LENGTH_REPORT_MESSAGE ];
	int m = snprintf( report, sizeof( report ), "%d,0,\"test\",%ld.%06ld,",
			DUMMY_REPORT_TYPE, (long) ts.tv_sec, (long) ts.tv_usec );
	CHECK( m > 0 && m < (int) sizeof( report ));
	memset( report + m, 'A', sizeof( report ) - m );
	for( i=0; i<3; i++ )
		check_emitted( cap, report, sizeof( report ));

	//the direct _write calls emit the first MAX_LENGTH_REPORT_MESSAGE bytes
	//of the message inside the brackets, whatever its real length
	check_emitted( cap, overlong, MAX_LENGTH_REPORT_MESSAGE );
	check_emitted( cap, overlong, MAX_LENGTH_REPORT_MESSAGE );

	//nothing else may have been written
	CHECK( fgetc( cap ) == EOF );

	fclose( cap );
	output_release( output );
}

#ifdef STIX_FORMAT
//with STIX_FORMAT kept in, a SECURITY_REPORT_TYPE report is first offered to
//construct_alert_stix_format, which writes its bundle into the same
//message[ MAX_LENGTH_REPORT_MESSAGE ] buffer as the CSV row. A bundle that
//fits is sent through the JSON wrap of output._write; a bundle that does not
//fit, or a body that is not an alert, falls back to the bounded CSV row.
//This function compiles only on branches that ship
//src/modules/output_format/stix_format.c (intact-new-features does; main
//does not — it would need both the source and libuuid): it is dead code on
//main, kept so this driver file stays identical across branches.
static void test_output_stix_alert( void ){
	file_output_conf_t file_conf;
	memset( &file_conf, 0, sizeof( file_conf )); //file channel disabled

	output_conf_t conf;
	memset( &conf, 0, sizeof( conf ));
	conf.is_enable = true;
	conf.format    = OUTPUT_FORMAT_JSON;
	conf.file      = &file_conf;

	output_t *output = output_alloc_init( 0, &conf, 0, "test", false );
	CHECK( output != NULL );

	//the reports are written to stdout: capture them so the emitted bytes
	//can be checked — a bundle line in the capture proves the STIX path
	//inside output_write_report really ran (a dead path, e.g. an out_size
	//too small for any bundle, emits only CSV fallback rows)
	int stdout_copy;
	FILE *cap = capture_begin( &stdout_copy );

	struct timeval ts = { .tv_sec = 1234, .tv_usec = 0 };
	const char *trace = "{\"event_1\":{\"timestamp\":1682506925.089123,"
			"\"attributes\":[[\"ip.src\",\"10.0.0.1\"],[\"ip.dst\",\"10.0.0.2\"]]}}";
	char body[ 2 * MAX_LENGTH_REPORT_MESSAGE ];
	char desc[ MAX_LENGTH_REPORT_MESSAGE ];
	char bundle[ MAX_LENGTH_REPORT_MESSAGE + 1 ];
	memset( desc, 'A', sizeof( desc ));

	//the description is the only sizeable part of a bundle: sweep its length
	//across the point where the bundle stops fitting the report buffer —
	//both the STIX output and the CSV fallback must be observed. Keep going
	//a few iterations past the first fallback so an over-large out_size at
	//the construct_alert_stix_format call site provably writes past the
	//report buffer under ASan, not only up to its last valid byte
	int stix = 0, fallback = 0;
	int i;
	for( i=0; i<(int) sizeof( desc ) && fallback < 5; i += 7 ){
		int n = snprintf( body, sizeof( body ),
				"20,\"detected\",\"attack\",\"%.*s\",%s", i, desc, trace );
		CHECK( n > 0 && n < (int) sizeof( body ));
		if( construct_alert_stix_format( body, &ts, 0, "test",
				bundle, MAX_LENGTH_REPORT_MESSAGE ))
			stix = 1;
		else
			fallback ++;
		CHECK( output_write_report( output, CONF_OUTPUT_CHANNEL_STDOUT,
				SECURITY_REPORT_TYPE, &ts, body ) == 1 );
	}

	//a body at the report limit, alert-shaped or not, always falls back to
	//the bounded CSV row
	memset( body, 'A', MAX_LENGTH_REPORT_MESSAGE );
	int sizes[] = { MAX_LENGTH_REPORT_MESSAGE,
			MAX_LENGTH_REPORT_MESSAGE - 1,
			MAX_LENGTH_REPORT_MESSAGE - 2 };
	for( i=0; i<3; i++ ){
		body[ sizes[i] ] = '\0';
		CHECK( output_write_report( output, CONF_OUTPUT_CHANNEL_STDOUT,
				SECURITY_REPORT_TYPE, &ts, body ) == 1 );
	}

	capture_restore( cap, stdout_copy );

	//the capture must contain a real STIX bundle: the first emitted line is
	//a fitting alert, wrapped by _write's brackets
	long capsize;
	CHECK( fseek( cap, 0, SEEK_END ) == 0 && ( capsize = ftell( cap )) > 0 );
	rewind( cap );
	char *emitted = malloc( capsize + 1 );
	CHECK( emitted != NULL );
	CHECK( fread( emitted, 1, capsize, cap ) == (size_t) capsize );
	emitted[ capsize ] = '\0';
	CHECK( emitted[0] == '[' );
	CHECK( emitted[ capsize-2 ] == ']' && emitted[ capsize-1 ] == '\n' );
	CHECK( strstr( emitted, "\"type\": \"bundle\"" ) != NULL );
	free( emitted );
	fclose( cap );

	CHECK( stix && fallback );

	output_release( output );
}
#endif

//_process_ieee802154_src_dst wrote "" and returned 2 without looking at the
//room left in the buffer: at a full report that wrote past the buffer and
//moved the caller's offset out of bounds
static void test_ieee802154_attr_truncated( void ){
	char message[ MAX_LENGTH_REPORT_MESSAGE + 1 ];

	//the report is exactly full: nothing may be written
	int ret0 = _process_ieee802154_src_dst( message + MAX_LENGTH_REPORT_MESSAGE, 0,
			PROTO_IEEE802154, IEEE802154_SRC_ADDRESS_EXTENDED, NULL );
	CHECK( ret0 == 0 );

	//room for the closing '\0' only
	int ret1 = _process_ieee802154_src_dst( message + MAX_LENGTH_REPORT_MESSAGE, 1,
			PROTO_IEEE802154, IEEE802154_DST_ADDRESS_EXTENDED, NULL );
	CHECK( ret1 == 0 );
	CHECK( message[ MAX_LENGTH_REPORT_MESSAGE ] == '\0' );

	//a fitting buffer still gets ""
	char buf[8];
	int ret2 = _process_ieee802154_src_dst( buf, sizeof( buf ), PROTO_IEEE802154,
			IEEE802154_SRC_ADDRESS_EXTENDED, NULL );
	CHECK( ret2 == 2 );
	CHECK( strcmp( buf, "\"\"" ) == 0 );
}

int main( void ){
	test_bounded_snprintf_len();
	test_rtp_report_truncated();
	test_gtp_report_truncated();
	test_gtp_report_complete();
	test_output_json_wrap();
#ifdef STIX_FORMAT
	test_output_stix_alert();
#endif
	test_ieee802154_attr_truncated();

	printf( "report-overflow: all checks passed\n" );
	return 0;
}
