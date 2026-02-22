#include "ringbuffer.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     /* usleep */
#include <stdio.h>      /* for debug if needed */
#include <stdbool.h>

int ringbuffer_init(RingBuffer *rb, size_t size, const char *name)
{
    if (rb == NULL || size == 0) return -1;
    rb->size = size;
    rb->itemsize = sizeof(float);
    rb->buffer = (float*)malloc(size * rb->itemsize);
    if (!rb->buffer) return -1;
    atomic_init(&rb->head, 0);
    atomic_init(&rb->tail, 0);
    rb->blockingPush = false;
    rb->blockingPop = false;
    rb->blockingNap = 1000; /* default 1ms */
    rb->name = name ? strdup(name) : NULL;
    return 0;
}

void ringbuffer_destroy(RingBuffer *rb)
{
    if (!rb) return;
    free(rb->buffer);
    rb->buffer = NULL;
    free(rb->name);
    rb->name = NULL;
}

/* NOTE: casts to signed long for distance computations like the C++ original */
size_t ringbuffer_items_available_for_write(RingBuffer *rb)
{
    long head = (long)atomic_load_explicit(&rb->head, memory_order_acquire);
    long tail = (long)atomic_load_explicit(&rb->tail, memory_order_acquire);
    long pointerspace = head - tail; /* signed */
    if (pointerspace > 0) return (size_t)pointerspace;
    else return (size_t)(pointerspace + (long)rb->size);
}

size_t ringbuffer_items_available_for_read(RingBuffer *rb)
{
    long head = (long)atomic_load_explicit(&rb->head, memory_order_acquire);
    long tail = (long)atomic_load_explicit(&rb->tail, memory_order_acquire);
    long pointerspace = tail - head; /* signed */
    if (pointerspace >= 0) return (size_t)pointerspace;
    else return (size_t)(pointerspace + (long)rb->size);
}

void ringbuffer_push_may_block(RingBuffer *rb, bool block) { rb->blockingPush = block; }
void ringbuffer_pop_may_block(RingBuffer *rb, bool block)  { rb->blockingPop  = block; }
void ringbuffer_set_blocking_nap(RingBuffer *rb, unsigned long nap_us) { rb->blockingNap = nap_us; }

size_t ringbuffer_push(RingBuffer *rb, const float *data, size_t n)
{
    if (n == 0) return 0;
    size_t space = ringbuffer_items_available_for_write(rb);

    if (rb->blockingPush) {
        while ((space = ringbuffer_items_available_for_write(rb)) < n) {
            usleep(rb->blockingNap);
        }
    }

    if (space == 0) return 0;
    size_t n_to_write = n <= space ? n : space;

    size_t current_tail = atomic_load_explicit(&rb->tail, memory_order_acquire);
    if (current_tail + n_to_write <= rb->size) {
        /* fits in a single chunk */
        memcpy(rb->buffer + current_tail, data, n_to_write * rb->itemsize);
    } else {
        size_t first_chunk = rb->size - current_tail;
        memcpy(rb->buffer + current_tail, data, first_chunk * rb->itemsize);
        memcpy(rb->buffer, data + first_chunk, (n_to_write - first_chunk) * rb->itemsize);
    }
    size_t new_tail = (current_tail + n_to_write) % rb->size;
    atomic_store_explicit(&rb->tail, new_tail, memory_order_release);
    return n_to_write;
}

size_t ringbuffer_pop(RingBuffer *rb, float *data, size_t n)
{
    if (n == 0) return 0;
    size_t space = ringbuffer_items_available_for_read(rb);

    if (rb->blockingPop) {
        while ((space = ringbuffer_items_available_for_read(rb)) < n) {
            usleep(rb->blockingNap);
        }
    }

    if (space == 0) return 0;
    size_t n_to_read = n <= space ? n : space;

    size_t current_head = atomic_load_explicit(&rb->head, memory_order_acquire);
    if (current_head + n_to_read <= rb->size) {
        memcpy(data, rb->buffer + current_head, n_to_read * rb->itemsize);
    } else {
        size_t first_chunk = rb->size - current_head;
        memcpy(data, rb->buffer + current_head, first_chunk * rb->itemsize);
        memcpy(data + first_chunk, rb->buffer, (n_to_read - first_chunk) * rb->itemsize);
    }
    size_t new_head = (current_head + n_to_read) % rb->size;
    atomic_store_explicit(&rb->head, new_head, memory_order_release);
    return n_to_read;
}

bool ringbuffer_is_lock_free(RingBuffer *rb)
{
    /* atomic_is_lock_free takes pointer to atomic object */
    return atomic_is_lock_free(&rb->head) && atomic_is_lock_free(&rb->tail);
}
