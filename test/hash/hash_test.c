/*
 * hash_test.c - Regression test for the zero-length key path of hash.c.
 *
 * An occupied slot can legitimately hold {key_len = 0, key = NULL}: a
 * query report with an empty group-by makes _get_string_values() return 0
 * and mmt_memdup(msg, 0) return NULL, which hash_add stores as-is. A later
 * hash_search reaching that slot ran memcmp(key, NULL, 0): the pointer
 * arguments of memcmp are declared nonnull, so the call is undefined
 * behaviour even at length 0. The fix treats all zero-length keys as
 * equal and skips the compare.
 *
 * Built with -fsanitize=address,undefined, so this driver is red on the
 * unfixed hash.c (UBSan: null pointer passed to memcmp) and green on the
 * fixed one; the assertions themselves hold on both.
 */

//the default build adds -DNDEBUG, which would compile every assert below
// out and turn this driver into a no-op
#undef NDEBUG

#include <assert.h>
#include <stdio.h>

//hash.c is self-contained (libc only); include it directly so it is
// compiled with the same sanitizers as this file
#include "../../src/lib/hash.c"

int main( void ){
	hash_t *t = hash_create();
	int d1 = 1, d2 = 2, d3 = 3;
	const char key[] = "abc";

	assert( t != NULL );

	//the empty key: a legitimate {key_len = 0, key = NULL} slot
	assert( hash_add( t, 0, NULL, &d1 ));
	//must be found without reaching memcmp: UBSan reports the unfixed code
	assert( hash_search( t, 0, NULL ) == &d1 );

	//a second empty key lands in another slot (hash_add does no duplicate
	// check; the callers search-then-add); the empty key stays findable
	assert( hash_add( t, 0, NULL, &d2 ));
	assert( hash_search( t, 0, NULL ) != NULL );

	//ordinary keys are unaffected by the zero-length shortcut
	assert( hash_add( t, sizeof( key ), (void *) key, &d3 ));
	assert( hash_search( t, sizeof( key ), key ) == &d3 );
	assert( hash_search( t, 3, "zzz" ) == NULL );

	hash_free( t );
	printf( "hash: all assertions passed\n" );
	return 0;
}
