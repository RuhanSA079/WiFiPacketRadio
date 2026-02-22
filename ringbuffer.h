#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include <stddef.h>
#include <stdatomic.h>
#include <stdbool.h>

typedef struct RingBuffer {
    size_t size;                /* number of items (not bytes) */
    float *buffer;              /* storage */
    atomic_size_t head;         /* read index */
    atomic_size_t tail;         /* write index */
    size_t itemsize;            /* == sizeof(float) */
    bool blockingPush;
    bool blockingPop;
    unsigned long blockingNap;  /* microseconds to sleep when blocking */
    char *name;
} RingBuffer;

/* initialize; returns 0 on success, -1 on failure */
int ringbuffer_init(RingBuffer *rb, size_t size, const char *name);

/* destroy (free memory) */
void ringbuffer_destroy(RingBuffer *rb);

/* items available for write (space) */
size_t ringbuffer_items_available_for_write(RingBuffer *rb);

/* items available for read */
size_t ringbuffer_items_available_for_read(RingBuffer *rb);

/* set blocking behaviour */
void ringbuffer_push_may_block(RingBuffer *rb, bool block);
void ringbuffer_pop_may_block(RingBuffer *rb, bool block);
void ringbuffer_set_blocking_nap(RingBuffer *rb, unsigned long nap_us);

/* push up to n floats from data; returns number actually written */
size_t ringbuffer_push(RingBuffer *rb, const float *data, size_t n);

/* pop up to n floats into data; returns number actually read */
size_t ringbuffer_pop(RingBuffer *rb, float *data, size_t n);

/* are the atomics lock free? (C equivalent of isLockFree()) */
bool ringbuffer_is_lock_free(RingBuffer *rb);

#endif /* RINGBUFFER_H */
