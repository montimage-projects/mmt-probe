/* udp_gen.c - flood UDP datagrams to a loopback address so the online
 * double-signal check of test/online_signals.sh has live sessions to
 * drain when the signal lands.
 *
 * Build for the container image: cc -O2 -static -o udp_gen udp_gen.c
 * Run inside the container:    udp_gen 127.0.0.1 40000
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

/* datagrams cycle over this many destination ports so the worker holds
 * that many live sessions at signal time */
#define NB_PORTS 64

int main( int argc, char **argv ){
	const char *ip       = argc > 1 ? argv[ 1 ] : "127.0.0.1";
	int         base_prt = argc > 2 ? atoi( argv[ 2 ] ) : 40000;
	if( base_prt <= 0 || base_prt + NB_PORTS > 65535 )
		return 2;

	int fd = socket( AF_INET, SOCK_DGRAM, 0 );
	if( fd < 0 )
		return 2;

	struct sockaddr_in dst = {
		.sin_family = AF_INET,
	};
	if( inet_pton( AF_INET, ip, &dst.sin_addr ) != 1 )
		return 2;

	char payload[ 256 ];
	for( int i = 0; i < (int) sizeof( payload ); i ++ )
		payload[ i ] = (char) ( i & 0xFF );

	int port = base_prt;
	for( ;; ){
		dst.sin_port = htons( port );
		sendto( fd, payload, sizeof( payload ), 0,
				(struct sockaddr *) &dst, sizeof( dst ));
		port = port == base_prt + NB_PORTS - 1 ? base_prt : port + 1;
	}
	//never returns: killed by the test driver
}
