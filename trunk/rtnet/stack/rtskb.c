/***
 *
 *  stack/rtskb.c - rtskb implementation for rtnet
 *
 *  Copyright (C) 2002      Ulrich Marx <marx@fet.uni-hannover.de>,
 *                2003-2005 Jan Kiszka <jan.kiszka@web.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <net/checksum.h>

#include <rtdev.h>
#include <rtnet_internal.h>
#include <rtskb.h>

static unsigned int global_rtskbs    = DEFAULT_GLOBAL_RTSKBS;
static unsigned int rtskb_cache_size = DEFAULT_RTSKB_CACHE_SIZE;
module_param(global_rtskbs, uint, 0444);
module_param(rtskb_cache_size, uint, 0444);
MODULE_PARM_DESC(global_rtskbs, "Number of realtime socket buffers in global pool");
MODULE_PARM_DESC(rtskb_cache_size, "Number of cached rtskbs for creating pools in real-time");


/* Linux slab pool for rtskbs */
static kmem_cache_t *rtskb_slab_pool;

/* preallocated rtskbs for real-time pool creation */
static struct rtskb_queue rtskb_cache;

/* pool of rtskbs for global use */
struct rtskb_queue global_pool;

/* pool statistics */
unsigned int rtskb_pools=0;
unsigned int rtskb_pools_max=0;
unsigned int rtskb_amount=0;
unsigned int rtskb_amount_max=0;

#ifdef CONFIG_RTNET_ADDON_RTCAP
/* RTcap interface */
rtdm_lock_t rtcap_lock;
void (*rtcap_handler)(struct rtskb *skb) = NULL;
#endif



/***
 *  rtskb_copy_and_csum_bits
 */
unsigned int rtskb_copy_and_csum_bits(const struct rtskb *skb, int offset,
                                      u8 *to, int len, unsigned int csum)
{
    int copy;
    int pos = 0;

    /* Copy header. */
    if ((copy = skb->len-offset) > 0) {
        if (copy > len)
            copy = len;
        csum = csum_partial_copy_nocheck(skb->data+offset, to, copy, csum);
        if ((len -= copy) == 0)
            return csum;
        offset += copy;
        to += copy;
        pos = copy;
    }

    RTNET_ASSERT(len == 0, );
    return csum;
}


/***
 *  rtskb_copy_and_csum_dev
 */
void rtskb_copy_and_csum_dev(const struct rtskb *skb, u8 *to)
{
    unsigned int csum;
    unsigned int csstart;

    if (skb->ip_summed == CHECKSUM_HW) {
        csstart = skb->h.raw - skb->data;

        if (csstart > skb->len)
            BUG();
    } else
        csstart = skb->len;

    memcpy(to, skb->data, csstart);

    csum = 0;
    if (csstart != skb->len)
        csum = rtskb_copy_and_csum_bits(skb, csstart, to+csstart, skb->len-csstart, 0);

    if (skb->ip_summed == CHECKSUM_HW) {
        unsigned int csstuff = csstart + skb->csum;

        *((unsigned short *)(to + csstuff)) = csum_fold(csum);
    }
}



#ifdef CONFIG_RTNET_CHECKED
/**
 *  skb_over_panic - private function
 *  @skb: buffer
 *  @sz: size
 *  @here: address
 *
 *  Out of line support code for rtskb_put(). Not user callable.
 */
void rtskb_over_panic(struct rtskb *skb, int sz, void *here)
{
    rtdm_printk("RTnet: rtskb_put :over: %p:%d put:%d dev:%s\n", here,
                skb->len, sz, (skb->rtdev) ? skb->rtdev->name : "<NULL>");
}



/**
 *  skb_under_panic - private function
 *  @skb: buffer
 *  @sz: size
 *  @here: address
 *
 *  Out of line support code for rtskb_push(). Not user callable.
 */
void rtskb_under_panic(struct rtskb *skb, int sz, void *here)
{
    rtdm_printk("RTnet: rtskb_push :under: %p:%d put:%d dev:%s\n", here,
                skb->len, sz, (skb->rtdev) ? skb->rtdev->name : "<NULL>");
}
#endif /* CONFIG_RTNET_CHECKED */



/***
 *  alloc_rtskb - allocate an rtskb from a pool
 *  @size: required buffer size (to check against maximum boundary)
 *  @pool: pool to take the rtskb from
 */
struct rtskb *alloc_rtskb(unsigned int size, struct rtskb_queue *pool)
{
    struct rtskb *skb;


    RTNET_ASSERT(size <= SKB_DATA_ALIGN(RTSKB_SIZE), return NULL;);

    skb = rtskb_dequeue(pool);
    if (!skb)
        return NULL;
#ifdef CONFIG_RTNET_CHECKED
    pool->pool_balance--;
    skb->chain_len = 1;
#endif

    /* Load the data pointers. */
    skb->data = skb->buf_start;
    skb->tail = skb->buf_start;
    skb->end  = skb->buf_start + size;

    /* Set up other states */
    skb->chain_end = skb;
    skb->len = 0;
    skb->pkt_type = PACKET_HOST;
    skb->xmit_stamp = NULL;

#ifdef CONFIG_RTNET_ADDON_RTCAP
    skb->cap_flags = 0;
#endif

    return skb;
}



/***
 *  kfree_rtskb
 *  @skb    rtskb
 */
void kfree_rtskb(struct rtskb *skb)
{
#ifdef CONFIG_RTNET_ADDON_RTCAP
    rtdm_lockctx_t  context;
    struct rtskb    *comp_skb;
    struct rtskb    *next_skb;
    struct rtskb    *chain_end;
#endif


    RTNET_ASSERT(skb != NULL, return;);
    RTNET_ASSERT(skb->pool != NULL, return;);

#ifdef CONFIG_RTNET_ADDON_RTCAP
    next_skb  = skb;
    chain_end = skb->chain_end;

    do {
        skb      = next_skb;
        next_skb = skb->next;

        rtdm_lock_get_irqsave(&rtcap_lock, context);

        if (skb->cap_flags & RTSKB_CAP_SHARED) {
            skb->cap_flags &= ~RTSKB_CAP_SHARED;

            comp_skb  = skb->cap_comp_skb;
            skb->pool = xchg(&comp_skb->pool, skb->pool);

            rtdm_lock_put_irqrestore(&rtcap_lock, context);

            rtskb_queue_tail(comp_skb->pool, comp_skb);
#ifdef CONFIG_RTNET_CHECKED
            comp_skb->pool->pool_balance++;
#endif
        }
        else {
            rtdm_lock_put_irqrestore(&rtcap_lock, context);

            skb->chain_end = skb;
            rtskb_queue_tail(skb->pool, skb);
#ifdef CONFIG_RTNET_CHECKED
            skb->pool->pool_balance++;
#endif
        }

    } while (chain_end != skb);

#else  /* CONFIG_RTNET_ADDON_RTCAP */

    rtskb_queue_tail(skb->pool, skb);
#ifdef CONFIG_RTNET_CHECKED
    skb->pool->pool_balance += skb->chain_len;
#endif

#endif /* CONFIG_RTNET_ADDON_RTCAP */
}



/***
 *  rtskb_pool_init
 *  @pool: pool to be initialized
 *  @initial_size: number of rtskbs to allocate
 *  return: number of actually allocated rtskbs
 */
unsigned int rtskb_pool_init(struct rtskb_queue *pool,
                             unsigned int initial_size)
{
    unsigned int i;

    rtskb_queue_init(pool);
#ifdef CONFIG_RTNET_CHECKED
    pool->pool_balance = 0;
#endif

    i = rtskb_pool_extend(pool, initial_size);

    rtskb_pools++;
    if (rtskb_pools > rtskb_pools_max)
        rtskb_pools_max = rtskb_pools;

    return i;
}



/***
 *  rtskb_pool_init_rt
 *  @pool: pool to be initialized
 *  @initial_size: number of rtskbs to allocate
 *  return: number of actually allocated rtskbs
 */
unsigned int rtskb_pool_init_rt(struct rtskb_queue *pool,
                                unsigned int initial_size)
{
    unsigned int i;

    rtskb_queue_init(pool);
#ifdef CONFIG_RTNET_CHECKED
    pool->pool_balance = 0;
#endif

    i = rtskb_pool_extend_rt(pool, initial_size);

    rtskb_pools++;
    if (rtskb_pools > rtskb_pools_max)
        rtskb_pools_max = rtskb_pools;

    return i;
}



/***
 *  __rtskb_pool_release
 *  @pool: pool to release
 */
void __rtskb_pool_release(struct rtskb_queue *pool)
{
    struct rtskb *skb;


    while ((skb = rtskb_dequeue(pool)) != NULL) {
        kmem_cache_free(rtskb_slab_pool, skb);
        rtskb_amount--;
    }

    rtskb_pools--;
}



/***
 *  __rtskb_pool_release_rt
 *  @pool: pool to release
 */
void __rtskb_pool_release_rt(struct rtskb_queue *pool)
{
    struct rtskb *skb;


    while ((skb = rtskb_dequeue(pool)) != NULL) {
        skb->chain_end = skb;
        rtskb_queue_tail(&rtskb_cache, skb);
        rtskb_amount--;
    }

    rtskb_pools--;
}



unsigned int rtskb_pool_extend(struct rtskb_queue *pool,
                               unsigned int add_rtskbs)
{
    unsigned int i;
    struct rtskb *skb;


    RTNET_ASSERT(pool != NULL, return -EINVAL;);

    for (i = 0; i < add_rtskbs; i++) {
        /* get rtskb from slab pool */
        if (!(skb = kmem_cache_alloc(rtskb_slab_pool, GFP_KERNEL))) {
            printk(KERN_ERR "RTnet: rtskb allocation from slab pool failed\n");
            break;
        }

        /* fill the header with zero */
        memset(skb, 0, sizeof(struct rtskb));

        skb->chain_end = skb;
        skb->pool = pool;
        skb->buf_start = ((unsigned char *)skb) + ALIGN_RTSKB_STRUCT_LEN;
#ifdef CONFIG_RTNET_CHECKED
        skb->buf_end = skb->buf_start + SKB_DATA_ALIGN(RTSKB_SIZE) - 1;
#endif

        rtskb_queue_tail(pool, skb);

        rtskb_amount++;
        if (rtskb_amount > rtskb_amount_max)
            rtskb_amount_max = rtskb_amount;
    }

    return i;
}



unsigned int rtskb_pool_extend_rt(struct rtskb_queue *pool,
                                  unsigned int add_rtskbs)
{
    unsigned int i;
    struct rtskb *skb;


    RTNET_ASSERT(pool != NULL, return -EINVAL;);

    for (i = 0; i < add_rtskbs; i++) {
        /* get rtskb from rtskb cache */
        if (!(skb = rtskb_dequeue(&rtskb_cache))) {
            rtdm_printk("RTnet: rtskb allocation from real-time cache "
                        "failed\n");
            break;
        }

        /* most of the initialization has been done upon cache creation */
        skb->chain_end = skb;
        skb->pool = pool;

        rtskb_queue_tail(pool, skb);

        rtskb_amount++;
        if (rtskb_amount > rtskb_amount_max)
            rtskb_amount_max = rtskb_amount;
    }

    return i;
}



unsigned int rtskb_pool_shrink(struct rtskb_queue *pool,
                               unsigned int rem_rtskbs)
{
    unsigned int    i;
    struct rtskb    *skb;


    for (i = 0; i < rem_rtskbs; i++) {
        if ((skb = rtskb_dequeue(pool)) == NULL)
            break;

        kmem_cache_free(rtskb_slab_pool, skb);
        rtskb_amount--;
    }

    return i;
}



unsigned int rtskb_pool_shrink_rt(struct rtskb_queue *pool,
                                  unsigned int rem_rtskbs)
{
    unsigned int    i;
    struct rtskb    *skb;


    for (i = 0; i < rem_rtskbs; i++) {
        if ((skb = rtskb_dequeue(pool)) == NULL)
            break;
        skb->chain_end = skb;

        rtskb_queue_tail(&rtskb_cache, skb);
        rtskb_amount--;
    }

    return i;
}



/* Note: acquires only the first skb of a chain! */
int rtskb_acquire(struct rtskb *rtskb, struct rtskb_queue *comp_pool)
{
    struct rtskb *comp_rtskb = rtskb_dequeue(comp_pool);


    if (!comp_rtskb)
        return -ENOMEM;
#ifdef CONFIG_RTNET_CHECKED
    comp_pool->pool_balance--;
#endif

    comp_rtskb->chain_end = comp_rtskb;
    comp_rtskb->pool = rtskb->pool;
    rtskb_queue_tail(comp_rtskb->pool, comp_rtskb);
#ifdef CONFIG_RTNET_CHECKED
    comp_rtskb->chain_len = 1;
    comp_rtskb->pool->pool_balance++;
#endif
    rtskb->pool = comp_pool;

    return 0;
}



int rtskb_pools_init(void)
{
    rtskb_slab_pool = kmem_cache_create("rtskb_slab_pool",
        ALIGN_RTSKB_STRUCT_LEN + SKB_DATA_ALIGN(RTSKB_SIZE),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    if (rtskb_slab_pool == NULL)
        return -ENOMEM;

    /* create the rtskb cache like a normal pool */
    if (rtskb_pool_init(&rtskb_cache, rtskb_cache_size) < rtskb_cache_size)
        goto err_out1;

    /* reset the statistics (cache is accounted separately) */
    rtskb_pools      = 0;
    rtskb_pools_max  = 0;
    rtskb_amount     = 0;
    rtskb_amount_max = 0;

    /* create the global rtskb pool */
    if (rtskb_pool_init(&global_pool, global_rtskbs) < global_rtskbs)
        goto err_out2;

#ifdef CONFIG_RTNET_ADDON_RTCAP
    rtdm_lock_init(&rtcap_lock);
#endif

    return 0;

err_out2:
    rtskb_pool_release(&global_pool);
    rtskb_pool_release(&rtskb_cache);

err_out1:
    kmem_cache_destroy(rtskb_slab_pool);

    return -ENOMEM;
}



void rtskb_pools_release(void)
{
    rtskb_pool_release(&global_pool);
    rtskb_pool_release(&rtskb_cache);

    if (kmem_cache_destroy(rtskb_slab_pool) != 0)
        printk(KERN_CRIT "RTnet: rtskb memory leakage detected "
               "- reboot required!\n");
}


EXPORT_SYMBOL(rtskb_copy_and_csum_bits);
EXPORT_SYMBOL(rtskb_copy_and_csum_dev);

EXPORT_SYMBOL(alloc_rtskb);
EXPORT_SYMBOL(kfree_rtskb);

EXPORT_SYMBOL(rtskb_pool_init);
EXPORT_SYMBOL(__rtskb_pool_release);
EXPORT_SYMBOL(global_pool);

EXPORT_SYMBOL(rtskb_acquire);

#ifdef CONFIG_RTNET_CHECKED
EXPORT_SYMBOL(rtskb_over_panic);
EXPORT_SYMBOL(rtskb_under_panic);
#endif

#ifdef CONFIG_RTNET_ADDON_RTCAP
EXPORT_SYMBOL(rtcap_lock);
EXPORT_SYMBOL(rtcap_handler);
#endif
