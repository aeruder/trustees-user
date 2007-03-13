/* A simple dynamic array implementation
 * GPL
 * Andrew Ruder Copyright 2007 andy@aeruder.net
 */

typedef struct {
	unsigned capacity;
	void **items;
	unsigned *lengths;
	unsigned len;
} dynarray;

/* Initialize/cleanup */
dynarray *dynarray_init(unsigned capacity);
void dynarray_free(dynarray *array);

/* Add items */
void dynarray_push(dynarray *array, const void *item, unsigned len);
void dynarray_unshift(dynarray *array, const void *item, unsigned len);

/* Remove items */
void *dynarray_pop(dynarray *array, unsigned *len);
void *dynarray_shift(dynarray *array, unsigned *len);

/* Query information */
unsigned dynarray_length(dynarray *array);
unsigned dynarray_capacity(dynarray *array);

/* Reorganize items */
void dynarray_rotate_left(dynarray *array);
void dynarray_rotate_right(dynarray *array);
