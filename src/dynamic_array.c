#include <stdlib.h>
#include <string.h>
#include "dynamic_array.h"

/* Initialize/cleanup */
dynarray *dynarray_init(unsigned capacity)
{
	dynarray *x;
	
	x = calloc(1, sizeof(dynarray));
	x->items = malloc(capacity * sizeof(void *));
	x->lengths = malloc(capacity * sizeof(unsigned));
	x->capacity = capacity;
	return x;
}

void dynarray_free(dynarray *array)
{
	void *item;

	while ((item = dynarray_shift(array, 0))) free(item);

	free(array->items);
	free(array->lengths);
	free(array);
}

/* Add items */
void dynarray_push(dynarray *array, const void *item, unsigned len)
{
	void *buffer = calloc(1, len+1);
	memcpy(buffer, item, len);

	if (array->len >= array->capacity) {
		array->capacity *= 2;
		array->items = realloc(array->items, array->capacity * sizeof(void *));
		array->lengths = realloc(array->lengths, array->capacity * sizeof(unsigned));
	}

	array->items[array->len] = buffer;
	array->lengths[array->len] = len;
	array->len += 1;
}

void dynarray_unshift(dynarray *array, const void *item, unsigned len)
{
	dynarray_push(array, item, len);
	dynarray_rotate_right(array);
}

/* Remove items */
void *dynarray_pop(dynarray *array, unsigned *len)
{
	if (!array->len) return 0;
	array->len -= 1;
	if (len) *len = array->lengths[array->len]; 
	return array->items[array->len];
}

void *dynarray_shift(dynarray *array, unsigned *len)
{
	dynarray_rotate_left(array);
	return dynarray_pop(array, len);
}

/* Query information */
unsigned dynarray_length(dynarray *array)
{
	return array->len;
}
unsigned dynarray_capacity(dynarray *array)
{
	return array->capacity;
}

/* Reorganize items */
void dynarray_rotate_left(dynarray *array)
{
	void *firstitem;
	unsigned firstlen;

	if (array->len <= 1) return;

	firstitem = array->items[0];
	firstlen = array->lengths[0];
	memmove(array->items, array->items + 1, sizeof(void *) * (array->len - 1));
	memmove(array->lengths, array->lengths + 1, sizeof(unsigned) * (array->len - 1));
	array->items[array->len - 1] = firstitem;
	array->lengths[array->len - 1] = firstlen;
}

void dynarray_rotate_right(dynarray *array)
{
	void *lastitem;
	unsigned lastlen;

	if (array->len <= 1) return;

	lastitem = array->items[0];
	lastlen = array->lengths[0];
	memmove(array->items + 1, array->items, sizeof(void *) * (array->len - 1));
	memmove(array->lengths + 1, array->lengths, sizeof(unsigned) * (array->len - 1));

	array->items[0] = lastitem;
	array->lengths[0] = lastlen;
}
