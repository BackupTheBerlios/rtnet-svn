/* rtmac_cleanup.c
 *
 * rtmac - real-time networking medium access control subsystem
 * Copyright (C) 2002 Marc Kleine-Budde <kleine-budde@gmx.de>
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

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/module.h>

#include <rtai.h>

#include <rtnet.h>
#include <tdma.h>


/*
 * delete rt specific stuff
 * - rtskb queues
 *   * tx
 *   * master
 * - timer
 * - lists
 *   * rt_add_list
 *   * rt_list
 * - realtime task
 */
void tdma_cleanup_master_rt(struct rtmac_tdma *tdma)
{
	struct rtskb *skb;

	/*
	 * packets are not queued into rtmac any longer
	 */
	tdma->flags.mac_active = 0;

	/*
	 * shutdown realtime task
	 */
	tdma_task_shutdown(tdma);

	/*
	 * delete sema
	 * if a sending task is waiting due to maximum length of tx queue,
	 * it will become runable and send skb into queue
	 */
	rt_sem_delete(&tdma->free);
	rt_sem_delete(&tdma->full);

	
	/*
	 * if we have some packets in tx queue send them
	 */
	TDMA_DEBUG(2, "RTmac: tdma: "__FUNCTION__"() tx_queue length=%d\n", tdma->tx_queue.qlen);
	while (tdma->tx_queue.qlen >= 1) {
		skb = rtskb_dequeue(&tdma->tx_queue);

		rtdev_xmit(skb);

		TDMA_DEBUG(2, "RTmac: tdma: "__FUNCTION__"() tx_queue length=%d\n", tdma->tx_queue.qlen);
	}

	//FIXME: send master queue contens, or clear semas.....warscheinlich 2.
	//rtskb_queue_purge(&tdma->master_queue);

	/*
	 * delete timers, and init timers
	 */
	del_timer(&tdma->task_change_timer);
	del_timer(&tdma->rt_add_timer);
	del_timer(&tdma->master_wait_timer);
	del_timer(&tdma->master_sent_conf_timer);
	del_timer(&tdma->master_sent_test_timer);

	init_timer(&tdma->task_change_timer);
	init_timer(&tdma->rt_add_timer);
	init_timer(&tdma->master_wait_timer);
	init_timer(&tdma->master_sent_conf_timer);
	init_timer(&tdma->master_sent_test_timer);


	/*
	 * delete (if there are) entries in rt- and rt-add-list
	 */
	{
		struct list_head *lh, *next;
		struct tdma_rt_add_entry *rt_add_entry;
		struct tdma_rt_entry *rt_entry;

		list_for_each_safe(lh, next, &tdma->rt_add_list) {
			rt_add_entry = list_entry(lh, struct tdma_rt_add_entry, list);

			list_del(&rt_add_entry->list);
			rt_free(rt_add_entry);
		}

		list_for_each_safe(lh, next, &tdma->rt_list) {
			rt_entry = list_entry(lh, struct tdma_rt_entry, list);

			list_del(&rt_entry->list);
			rt_free(rt_entry);
		}
	}

	/*
	 * re-init lists
	 *
	 */
	INIT_LIST_HEAD(&tdma->rt_add_list);
	INIT_LIST_HEAD(&tdma->rt_list);
	INIT_LIST_HEAD(&tdma->rt_list_rate);


	/*
	 * re-init semas
	 */
	rt_sem_init(&tdma->free, TDMA_MAX_TX_QUEUE);
	rt_sem_init(&tdma->full, 0);

	/*
	 * not it should be save to remove module
	 */
	MOD_DEC_USE_COUNT;

	return;
}



void tdma_cleanup_master_rt_check(struct rtmac_tdma *tdma)
{
	if (tdma->flags.mac_active != 0)
		rt_printk("RTmac: tdma: BUG! "__FUNCTION__"() flags.mac_active != 0\n");

	if (tdma->tx_queue.qlen != 0)
		rt_printk("RTmac: tdma: BUG! "__FUNCTION__"() tx_queue length != 0\n");

	if (list_len(&tdma->rt_add_list) != 0)
		rt_printk("RTmac: tdma: BUG! "__FUNCTION__"() rt_add_list length != 0\n");

	if (list_len(&tdma->rt_list) != 0)
		rt_printk("RTmac: tdma: BUG! "__FUNCTION__"() rt_list length != 0\n");
}



void tdma_cleanup_client_rt(struct rtmac_tdma *tdma)
{
	struct rtskb *skb;

	/*
	 * packets are not queued into rtmac any longer
	 */
	tdma->flags.mac_active = 0;

	/*
	 * shutdown realtime task
	 */
	tdma_task_shutdown(tdma);

	/*
	 * delete sema
	 * if a sending task is waiting due to maximum length of tx queue,
	 * it will become runable and send skb into queue
	 */
	rt_sem_delete(&tdma->free);
	rt_sem_delete(&tdma->full);

	/*
	 * if we have some packets in tx queue send them
	 */
	TDMA_DEBUG(2, "RTmac: tdma: "__FUNCTION__"() tx_queue length=%d\n", tdma->tx_queue.qlen);
	while (tdma->tx_queue.qlen >= 1) {
		skb = rtskb_dequeue(&tdma->tx_queue);

		rtdev_xmit(skb);

		TDMA_DEBUG(2, "RTmac: tdma: "__FUNCTION__"() tx_queue length=%d\n", tdma->tx_queue.qlen);
	}

	/*
	 * delete timers, and init timers
	 */
	del_timer(&tdma->client_sent_ack_timer);

	init_timer(&tdma->client_sent_ack_timer);

	/*
	 * delete (if there are) entries in rt_list_rate
	 */
	{
		struct list_head *lh, *next;
		struct tdma_rt_entry *rt_entry;

		list_for_each_safe(lh, next, &tdma->rt_list_rate) {
			rt_entry = list_entry(lh, struct tdma_rt_entry, list_rate);

			list_del(&rt_entry->list_rate);
			rt_free(rt_entry);
		}
	}

	/*
	 * re-init semas
	 */
	rt_sem_init(&tdma->free, TDMA_MAX_TX_QUEUE);
	rt_sem_init(&tdma->full, 0);

	/*
	 * not it should be save to remove module
	 */
	MOD_DEC_USE_COUNT;

	return;
}
