/*
 * alloc.h
 *
 *  Created on: Dec 13, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_LIB_MEMORY_H_
#define SRC_LIB_MEMORY_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h> //for uint64_t PRIu64
#include <stdbool.h>
#include "optimization.h"
#include "log.h"
#include "limit.h"
#include "unit.h"
#include "tools.h"

static ALWAYS_INLINE void assign_16bytes( void *dest, const void *source){
	memcpy( dest, source, 16 );
}

static ALWAYS_INLINE void assign_8bytes( void *dest, const void *source){
	memcpy( dest, source, 8 );
}

/**
 * Assign 6 bytes from #source to #dest
 * @param dest
 * @param source
 */

static ALWAYS_INLINE void assign_6bytes( void *dest, const void *source){
	memcpy( dest, source, 6 );
}

static ALWAYS_INLINE void assign_4bytes( void *dest, const void *source){
	memcpy( dest, source, 4 );
}

static ALWAYS_INLINE void assign_2bytes( void *dest, const void *source){
	memcpy( dest, source, 2 );
}

#endif /* SRC_LIB_MEMORY_H_ */
