/* rtskb.h
 *
 * RTnet - real-time networking subsystem
 * Copyright (C) 2002 Ulrich Marx <marx@kammer.uni-hannover.de>,
 *               2003, 2004 Jan Kiszka <jan.kiszka@web.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#ifndef __RTSKB_H_
#define __RTSKB_H_

#ifdef __KERNEL__

#include <linux/skbuff.h>

#include <rtnet_internal.h>


/***

rtskb Management - A Short Introduction
---------------------------------------

1. rtskbs (Real-Time Socket Buffers)

A rtskb consists of a management structure (struct rtskb) and a fixed-sized
(RTSKB_SIZE) data buffer. It is used to store network packets on their way from
the API routines through the stack to the NICs or vice versa. rtskbs are
allocated as one chunk of memory which contains both the managment structure
and the buffer memory itself.


2. rtskb Queues

A rtskb queue is described by struct rtskb_queue. A queue can contain an
unlimited number of rtskbs in an ordered way. A rtskb can either be added to
the head (rtskb_queue_head()) or the tail of a queue (rtskb_queue_tail()). When
a rtskb is removed from a queue (rtskb_dequeue()), it is always taken from the
head. Queues are normally spin lock protected unless the __variants of the
queuing functions are used.


3. Prioritized rtskb Queues

A prioritized queue contains a number of normal rtskb queues within an array.
The array index of a sub-queue correspond to the priority of the rtskbs within
this queue. For enqueuing a rtskb (rtskb_prio_queue_head()), its priority field
is evaluated and the rtskb is then placed into the appropriate sub-queue. When
dequeuing a rtskb, the first rtskb of the first non-empty sub-queue with the
highest priority is returned. The current implementation supports 32 different
priority levels, the lowest if defined by QUEUE_MIN_PRIO, the highest by
QUEUE_MAX_PRIO.


4. rtskb Pools

As rtskbs must not be allocated by a normal memory manager during runtime,
preallocated rtskbs are kept ready in several pools. Most packet producers
(NICs, sockets, etc.) have their own pools in order to be independent of the
load situation of other parts of the stack.

When a pool is created (rtskb_pool_init()), the required rtskbs are allocated
from a Linux slab cache. Pools can be extended (rtskb_pool_extend()) or
shrinked (rtskb_pool_shrink()) during runtime. When shutting down the
program/module, every pool has to be released (rtskb_pool_release()). All these
commands demand to be executed within a non real-time context.

To support real-time pool manipulation, a tunable number of rtskbs can be
preallocated in a dedicated pool. When every a real-time-safe variant of the
commands mentioned above is used (postfix: _rt), rtskbs are taken from or
returned to that real-time pool. Note that real-time and non real-time commands
must not be mixed up when manipulating a pool.

Pools are organized as normal rtskb queues (struct rtskb_queue). When a rtskb
is allocated (alloc_rtskb()), it is actually dequeued from the pool's queue.
When freeing a rtskb (kfree_rtskb()), the rtskb is enqueued to its owning pool.
rtskbs can be exchanged between pools (rtskb_acquire()). In this case, the
passed rtskb switches over to from its owning pool to a given pool, but only if
this pool can pass an empty rtskb from its own queue back.


5. rtskb Chains

To ease the defragmentation of larger IP packets, several rtskbs can form a
chain. For these purposes, the first rtskb (and only the first!) provides a
pointer to the last rtskb in the chain. When enqueuing the first rtskb of a
chain, the whole chain is automatically placed into the destined queue. But,
to dequeue a complete chain specialized calls are required (postfix: _chain).
While chains also get freed en bloc (kfree_rtskb()) when passing the first
rtskbs, it is not possible to allocate a chain from a pool (alloc_rtskb()); a
newly allocated rtskb is always reset to a "single rtskb chain". Furthermore,
the acquisition of complete chains is NOT supported (rtskb_acquire()).


6. Capturing Support (Optional)

When incoming or outgoing packets are captured, the assigned rtskb needs to be
shared between the stack, the driver, and the capturing service. In contrast to
many other network layers, RTnet does not create a new rtskb head and
re-references the payload. Instead, additional fields at the end of the rtskb
structure are use for sharing a rtskb with a capturing service. If the sharing
bit (RTSKB_CAP_SHARED) in cap_flags is set, the rtskb will not be return to the
owning pool upon the first call of kfree_rtskb. This call will only reset the
bit so that the second call can then return the rtskb as normal. cap_start and
cap_len can be used to mirror the dimension of the full packet. This is
required because the data and len fields will be modified while walking through
the stack. cap_next allows to add a rtskb to a separate queue which is
independent of any queue described in 2.

Certain setup tasks for capturing packets can not become part of a capturing
module, they have to be embedded into the stack. For this purpose, several
inline functions are provided. rtcap_mark_incoming() is used to save the packet
dimension right before it is modifed by the stack. rtcap_report_incoming()
calls the capturing handler if present in order to let it process the received
rtskb (e.g. acquire it, mark it as shared, and enqueue it).

Outgoing rtskb have to be captured by adding a hook function to the chain of
hard_start_xmit functions of a device. To measure the delay caused by RTmac
between the request and the actual transmission, a time stamp can be taken using
rtcap_mark_rtmac_enqueue(). This function is typically called by RTmac
disciplines when they add a rtskb to their internal transmission queue. In such
a case, the RTSKB_CAP_RTMAC_STAMP bit is set in cap_flags to indicate that the
cap_rtmac_stamp field now contains valid data.

 ***/


#define RTSKB_CAP_SHARED        1   /* rtskb shared between stack and RTcap */
#define RTSKB_CAP_RTMAC_STAMP   2   /* cap_rtmac_stamp is valid             */


struct rtskb_queue;
struct rtsocket;
struct rtnet_device;

/***
 *  rtskb - realtime socket buffer
 */
struct rtskb {
    struct rtskb        *next;      /* used for queuing rtskbs */
    struct rtskb        *chain_end; /* marks the end of a rtskb chain starting
                                       with this very rtskb */
    struct rtskb_queue  *pool;      /* owning pool */

    unsigned int        priority;

    struct rtsocket     *sk;        /* assigned socket */
    struct rtnet_device *rtdev;     /* source or destination device */

    /* transport layer */
    union
    {
        struct tcphdr   *th;
        struct udphdr   *uh;
        struct icmphdr  *icmph;
        struct iphdr    *ipihdr;
        unsigned char   *raw;
    } h;

    /* network layer */
    union
    {
        struct iphdr    *iph;
        struct arphdr   *arph;
        unsigned char   *raw;
    } nh;

    /* link layer */
    union
    {
        struct ethhdr   *ethernet;
        unsigned char   *raw;
    } mac;

    unsigned short      protocol;
    unsigned char       pkt_type;

    unsigned char       ip_summed;
    unsigned int        csum;

    struct rt_rtable    *dst;

    unsigned int        len;
    unsigned int        data_len;
    unsigned int        buf_len;

    unsigned char       *buf_start;
    unsigned char       *buf_end;

    unsigned char       *data;
    unsigned char       *tail;
    unsigned char       *end;
    rtos_time_t         time_stamp; /* arrival or transmission (RTcap) time */

#ifdef CONFIG_RTNET_RTCAP
    int                 cap_flags;  /* see RTSKB_CAP_xxx                    */
    struct rtskb        *cap_next;  /* used for capture queue               */
    unsigned char       *cap_start; /* start offset for capturing           */
    unsigned int        cap_len;    /* capture length of this rtskb         */
    rtos_time_t         cap_rtmac_stamp; /* RTmac enqueuing time            */
#endif
};

struct rtskb_queue {
    struct rtskb        *first;
    struct rtskb        *last;
    rtos_spinlock_t     lock;
#ifdef CONFIG_RTNET_CHECKED
    int                 pool_balance;
#endif
};

#define QUEUE_MAX_PRIO          0
#define QUEUE_MIN_PRIO          31

struct rtskb_prio_queue {
    rtos_spinlock_t     lock;
    __u32               usage;  /* bit array encoding non-empty sub-queues */
    struct rtskb_queue  queue[QUEUE_MIN_PRIO+1];
};


/* default values for the module parameter */
#define DEFAULT_RTSKB_CACHE_SIZE    0       /* default number of cached rtskbs for new pools */
#define DEFAULT_GLOBAL_RTSKBS       0       /* default number of rtskb's in global pool */
#define DEFAULT_DEVICE_RTSKBS       16      /* default additional rtskbs per network adapter */
#define DEFAULT_SOCKET_RTSKBS       16      /* default number of rtskb's in socket pools */

#define ALIGN_RTSKB_STRUCT_LEN      SKB_DATA_ALIGN(sizeof(struct rtskb))
#define RTSKB_SIZE                  1544    /* maximum needed by pcnet32-rt */

extern unsigned int socket_rtskbs;      /* default number of rtskb's in socket pools */

extern unsigned int rtskb_pools;        /* current number of rtskb pools      */
extern unsigned int rtskb_pools_max;    /* maximum number of rtskb pools      */
extern unsigned int rtskb_amount;       /* current number of allocated rtskbs */
extern unsigned int rtskb_amount_max;   /* maximum number of allocated rtskbs */

#ifdef CONFIG_RTNET_CHECKED
extern void rtskb_over_panic(struct rtskb *skb, int len, void *here);
extern void rtskb_under_panic(struct rtskb *skb, int len, void *here);
#endif

extern struct rtskb *alloc_rtskb(unsigned int size, struct rtskb_queue *pool);
#define dev_alloc_rtskb(len, pool)  alloc_rtskb(len, pool)

extern void kfree_rtskb(struct rtskb *skb);
#define dev_kfree_rtskb(a)  kfree_rtskb(a)


/***
 *  rtskb_queue_init - initialize the queue
 *  @queue
 */
static inline void rtskb_queue_init(struct rtskb_queue *queue)
{
    rtos_spin_lock_init(&queue->lock);
    queue->first = NULL;
    queue->last  = NULL;
}

/***
 *  rtskb_prio_queue_init - initialize the prioritized queue
 *  @prioqueue
 */
static inline void rtskb_prio_queue_init(struct rtskb_prio_queue *prioqueue)
{
    memset(prioqueue, 0, sizeof(struct rtskb_prio_queue));
    rtos_spin_lock_init(&prioqueue->lock);
}

/***
 *  rtskb_queue_empty
 *  @queue
 */
static inline int rtskb_queue_empty(struct rtskb_queue *queue)
{
    return (queue->first == NULL);
}

/***
 *  rtskb__prio_queue_empty
 *  @queue
 */
static inline int rtskb_prio_queue_empty(struct rtskb_prio_queue *prioqueue)
{
    return (prioqueue->usage == 0);
}

/***
 *  __rtskb_queue_head - insert a buffer at the queue head (w/o locks)
 *  @queue: queue to use
 *  @skb: buffer to queue
 */
static inline void __rtskb_queue_head(struct rtskb_queue *queue,
                                      struct rtskb *skb)
{
    struct rtskb *chain_end = skb->chain_end;

    chain_end->next = queue->first;

    if (queue->first == NULL)
        queue->last = chain_end;
    queue->first = skb;
}

/***
 *  rtskb_queue_head - insert a buffer at the queue head (lock protected)
 *  @queue: queue to use
 *  @skb: buffer to queue
 */
static inline void rtskb_queue_head(struct rtskb_queue *queue, struct rtskb *skb)
{
    unsigned long flags;

    rtos_spin_lock_irqsave(&queue->lock, flags);
    __rtskb_queue_head(queue, skb);
    rtos_spin_unlock_irqrestore(&queue->lock, flags);
}

/***
 *  rtskb_prio_queue_head - insert a buffer at the prioritized queue head
 *  @queue: queue to use
 *  @skb: buffer to queue
 */
static inline void rtskb_prio_queue_head(struct rtskb_prio_queue *prioqueue,
                                         struct rtskb *skb)
{
    unsigned long flags;

    RTNET_ASSERT(skb->priority <= 31, skb->priority = 31;);

    rtos_spin_lock_irqsave(&prioqueue->lock, flags);
    __rtskb_queue_head(&prioqueue->queue[skb->priority], skb);
    __set_bit(skb->priority, &prioqueue->usage);
    rtos_spin_unlock_irqrestore(&prioqueue->lock, flags);
}

/***
 *  __rtskb_queue_tail - insert a buffer at the queue tail (w/o locks)
 *  @queue: queue to use
 *  @skb: buffer to queue
 */
static inline void __rtskb_queue_tail(struct rtskb_queue *queue,
                                      struct rtskb *skb)
{
    struct rtskb *chain_end = skb->chain_end;

    chain_end->next = NULL;

    if (queue->first == NULL)
        queue->first = skb;
    else
        queue->last->next = skb;
    queue->last = chain_end;
}

/***
 *  rtskb_queue_tail - insert a buffer at the queue tail (lock protected)
 *  @queue: queue to use
 *  @skb: buffer to queue
 */
static inline void rtskb_queue_tail(struct rtskb_queue *queue, struct rtskb *skb)
{
    unsigned long flags;

    rtos_spin_lock_irqsave(&queue->lock, flags);
    __rtskb_queue_tail(queue, skb);
    rtos_spin_unlock_irqrestore(&queue->lock, flags);
}

/***
 *  rtskb_prio_queue_tail - insert a buffer at the prioritized queue tail
 *  @prioqueue: queue to use
 *  @skb: buffer to queue
 */
static inline void rtskb_prio_queue_tail(struct rtskb_prio_queue *prioqueue,
                                         struct rtskb *skb)
{
    unsigned long flags;

    RTNET_ASSERT(skb->priority <= 31, skb->priority = 31;);

    rtos_spin_lock_irqsave(&prioqueue->lock, flags);
    __rtskb_queue_tail(&prioqueue->queue[skb->priority], skb);
    __set_bit(skb->priority, &prioqueue->usage);
    rtos_spin_unlock_irqrestore(&prioqueue->lock, flags);
}

/***
 *  __rtskb_dequeue - remove from the head of the queue (w/o locks)
 *  @queue: queue to remove from
 */
static inline struct rtskb *__rtskb_dequeue(struct rtskb_queue *queue)
{
    struct rtskb *result;

    if ((result = queue->first) != NULL) {
        queue->first = result->next;
        result->next = NULL;
    }

    return result;
}

/***
 *  rtskb_dequeue - remove from the head of the queue (lock protected)
 *  @queue: queue to remove from
 */
static inline struct rtskb *rtskb_dequeue(struct rtskb_queue *queue)
{
    unsigned long flags;
    struct rtskb *result;

    rtos_spin_lock_irqsave(&queue->lock, flags);
    result = __rtskb_dequeue(queue);
    rtos_spin_unlock_irqrestore(&queue->lock, flags);

    return result;
}

/***
 *  rtskb_prio_dequeue - remove from the head of the prioritized queue
 *  @prioqueue: queue to remove from
 */
static inline struct rtskb *rtskb_prio_dequeue(struct rtskb_prio_queue *prioqueue)
{
    unsigned long flags;
    int prio;
    struct rtskb *result = NULL;
    struct rtskb_queue *sub_queue;

    rtos_spin_lock_irqsave(&prioqueue->lock, flags);
    if (prioqueue->usage) {
        prio      = ffz(~prioqueue->usage);
        sub_queue = &prioqueue->queue[prio];
        result    = __rtskb_dequeue(sub_queue);
        if (rtskb_queue_empty(sub_queue))
            __change_bit(prio, &prioqueue->usage);
    }
    rtos_spin_unlock_irqrestore(&prioqueue->lock, flags);

    return result;
}

/***
 *  __rtskb_dequeue_chain - remove a chain from the head of the queue
 *                          (w/o locks)
 *  @queue: queue to remove from
 */
static inline struct rtskb *__rtskb_dequeue_chain(struct rtskb_queue *queue)
{
    struct rtskb *result;
    struct rtskb *chain_end;

    if ((result = queue->first) != NULL) {
        chain_end = result->chain_end;
        queue->first = chain_end->next;
        chain_end->next = NULL;
    }

    return result;
}

/***
 *  rtskb_dequeue_chain - remove a chain from the head of the queue
 *                        (lock protected)
 *  @queue: queue to remove from
 */
static inline struct rtskb *rtskb_dequeue_chain(struct rtskb_queue *queue)
{
    unsigned long flags;
    struct rtskb *result;

    rtos_spin_lock_irqsave(&queue->lock, flags);
    result = __rtskb_dequeue_chain(queue);
    rtos_spin_unlock_irqrestore(&queue->lock, flags);

    return result;
}

/***
 *  rtskb_prio_dequeue_chain - remove a chain from the head of the
 *                             prioritized queue
 *  @prioqueue: queue to remove from
 */
static inline
    struct rtskb *rtskb_prio_dequeue_chain(struct rtskb_prio_queue *prioqueue)
{
    unsigned long flags;
    int prio;
    struct rtskb *result = NULL;
    struct rtskb_queue *sub_queue;

    rtos_spin_lock_irqsave(&prioqueue->lock, flags);
    if (prioqueue->usage) {
        prio      = ffz(~prioqueue->usage);
        sub_queue = &prioqueue->queue[prio];
        result    = __rtskb_dequeue_chain(sub_queue);
        if (rtskb_queue_empty(sub_queue))
            __change_bit(prio, &prioqueue->usage);
    }
    rtos_spin_unlock_irqrestore(&prioqueue->lock, flags);

    return result;
}

/***
 *  rtskb_queue_purge - clean the queue
 *  @queue
 */
static inline void rtskb_queue_purge(struct rtskb_queue *queue)
{
    struct rtskb *skb;
    while ( (skb=rtskb_dequeue(queue))!=NULL )
        kfree_rtskb(skb);
}

static inline int rtskb_is_nonlinear(const struct rtskb *skb)
{
    return skb->data_len;
}

static inline int rtskb_headlen(const struct rtskb *skb)
{
    return skb->len - skb->data_len;
}

static inline void rtskb_reserve(struct rtskb *skb, unsigned int len)
{
    skb->data+=len;
    skb->tail+=len;
}

#define RTSKB_LINEAR_ASSERT(rtskb) \
    RTNET_ASSERT(!rtskb_is_nonlinear(rtskb), BUG();)

static inline unsigned char *__rtskb_put(struct rtskb *skb, unsigned int len)
{
    unsigned char *tmp=skb->tail;
    RTSKB_LINEAR_ASSERT(skb);
    skb->tail+=len;
    skb->len+=len;
    return tmp;
}

static inline unsigned char *rtskb_put(struct rtskb *skb, unsigned int len)
{
    unsigned char *tmp=skb->tail;
    RTSKB_LINEAR_ASSERT(skb);
    skb->tail+=len;
    skb->len+=len;

    RTNET_ASSERT(skb->tail <= skb->buf_end,
        rtskb_over_panic(skb, len, current_text_addr()););

    return tmp;
}

static inline unsigned char *__rtskb_push(struct rtskb *skb, unsigned int len)
{
    skb->data-=len;
    skb->len+=len;
    return skb->data;
}

static inline unsigned char *rtskb_push(struct rtskb *skb, unsigned int len)
{
    skb->data-=len;
    skb->len+=len;

    RTNET_ASSERT(skb->data >= skb->buf_start,
        rtskb_under_panic(skb, len, current_text_addr()););

    return skb->data;
}

static inline char *__rtskb_pull(struct rtskb *skb, unsigned int len)
{
    skb->len-=len;
    if (skb->len < skb->data_len)
        BUG();
    return skb->data+=len;
}

static inline unsigned char *rtskb_pull(struct rtskb *skb, unsigned int len)
{
    if (len > skb->len)
        return NULL;

    return __rtskb_pull(skb,len);
}

static inline void rtskb_trim(struct rtskb *skb, unsigned int len)
{
    if (skb->len>len) {
        skb->len = len;
        skb->tail = skb->data+len;
    }
}

static inline struct rtskb *rtskb_padto(struct rtskb *rtskb, unsigned int len)
{
    RTNET_ASSERT(len <= (unsigned int)(rtskb->buf_end + 1 - rtskb->data),
                 return NULL;);

    memset(rtskb->data + rtskb->len, 0, len - rtskb->len);

    return rtskb;
}

extern struct rtskb_queue global_pool;

extern unsigned int rtskb_pool_init(struct rtskb_queue *pool,
                                    unsigned int initial_size);
extern unsigned int rtskb_pool_init_rt(struct rtskb_queue *pool,
                                       unsigned int initial_size);
extern void rtskb_pool_release(struct rtskb_queue *pool);
extern void rtskb_pool_release_rt(struct rtskb_queue *pool);

extern unsigned int rtskb_pool_extend(struct rtskb_queue *pool,
                                      unsigned int add_rtskbs);
extern unsigned int rtskb_pool_extend_rt(struct rtskb_queue *pool,
                                         unsigned int add_rtskbs);
extern unsigned int rtskb_pool_shrink(struct rtskb_queue *pool,
                                      unsigned int rem_rtskbs);
extern unsigned int rtskb_pool_shrink_rt(struct rtskb_queue *pool,
                                         unsigned int rem_rtskbs);
extern int rtskb_acquire(struct rtskb *rtskb, struct rtskb_queue *comp_pool);

extern int rtskb_pools_init(void);
extern void rtskb_pools_release(void);

extern unsigned int rtskb_copy_and_csum_bits(const struct rtskb *skb,
                                             int offset, u8 *to, int len,
                                             unsigned int csum);
extern void rtskb_copy_and_csum_dev(const struct rtskb *skb, u8 *to);


#ifdef CONFIG_RTNET_RTCAP

extern rtos_spinlock_t rtcap_lock;
extern void (*rtcap_handler)(struct rtskb *skb);

static inline void rtcap_mark_incoming(struct rtskb *skb)
{
    skb->cap_start = skb->data;
    skb->cap_len   = skb->len;
}

static inline void rtcap_report_incoming(struct rtskb *skb)
{
    unsigned long flags;


    rtos_spin_lock_irqsave(&rtcap_lock, flags);
    if (rtcap_handler != NULL)
        rtcap_handler(skb);

    rtos_spin_unlock_irqrestore(&rtcap_lock, flags);
}

static inline void rtcap_mark_rtmac_enqueue(struct rtskb *skb)
{
    /* rtskb start and length are probably not valid yet */
    skb->cap_flags |= RTSKB_CAP_RTMAC_STAMP;
    rtos_get_time(&skb->cap_rtmac_stamp);
}

#else /* ifndef CONFIG_RTNET_RTCAP */

#define rtcap_mark_incoming(skb)
#define rtcap_report_incoming(skb)
#define rtcap_mark_rtmac_enqueue(skb)

#endif /* CONFIG_RTNET_RTCAP */


#endif /* __KERNEL__ */

#endif  /* __RTSKB_H_ */
