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

#include "../../src/lib/limit.h"
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

int main( void ){
	test_bounded_snprintf_len();
	test_rtp_report_truncated();
	test_gtp_report_truncated();
	test_gtp_report_complete();

	printf( "report-overflow: all assertions passed\n" );
	return 0;
}
