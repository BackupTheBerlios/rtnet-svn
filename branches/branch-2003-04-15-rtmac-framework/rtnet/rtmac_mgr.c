/* rtmac_mgr.c
 *
 * Copyright (C) 2003 Hans-Peter Bock <hpbock-at-avaapgh.de>
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

/****
 * Please have a look at the OpenOffice file Documentation/structure.sxi
 * to easier understand what this code does.
 */

#include "rtmac_mgr.h"

struct rtnet_mgr rt_wakeup_manager;
struct rtnet_mgr proxy_wakeup_manager;

/****
 * Realtime txqueue wakeup manager.
 *
 * Waits blocking for a wakeup message in its mailbox and calls the rtdevice
 * specific wakeup function (if one is registered) after a message arrived.
 * After processing the realtime txqueue, a wakeup message is sent to the
 * proxy wakeup manager.
 */
void rt_wakeup_manager_task (int mgr_id) {
        struct rtnet_msg msg;
	struct rtnet_mgr *mgr = (struct rtnet_mgr *)mgr_id;

        rt_printk("RTnet: Realtime txqueue wakeup manager started. (%p)\n", rt_whoami());
        while(1) {
                rt_mbx_receive(&(mgr->mbx), &msg, sizeof(struct rtnet_msg));
                if ((msg.msg_type==WAKEUP) && (msg.rtdev)) {
			if (msg.rtdev->rt_wakeup_xmit) {
				msg.rtdev->rt_wakeup_xmit(msg.rtdev);
			}
		}
		// The next call should depend on the not yet specified returncode of rt_wakeup_xmit().
		rt_mbx_send_if(&(proxy_wakeup_manager.mbx), &msg, sizeof (struct rtnet_msg));
	}
}


/****
 * Initialize the realtime txqueue wakeup manager and its mailbox.
 */
int rt_wakeup_mgr_init (struct rtnet_mgr *mgr) {
	int ret = 0;

	if ( (ret=rt_mbx_init (&(mgr->mbx), sizeof(struct rtnet_msg))) )
		return ret;
	if ( (ret=rt_task_init(&(mgr->task), &rt_wakeup_manager_task, (int)mgr, 4096, RTNET_RT_WAKEUP_PRIORITY, 0, 0)) )
		goto rt_mbox_err;
	if ( (ret=rt_task_resume(&(mgr->task))) )
		goto rt_task_err;

	return (ret);

 rt_task_err:
	rt_task_delete(&(mgr->task));
 rt_mbox_err:
	rt_mbx_delete(&(mgr->mbx));
	return (ret);
}


/****
 * Delete the realtime txqueue wakeup manager and its mailbox.
 */
void rt_wakeup_mgr_delete (struct rtnet_mgr *mgr) {
	rt_task_suspend(&(mgr->task));
	rt_task_delete(&(mgr->task));
	rt_mbx_delete(&(mgr->mbx));
}


/****
 * Proxy txqueue wakeup manager.
 *
 * Waits blocking for a wakeup message in its mailbox and calls the rtdevice
 * specific wakeup function (if one is registered) after a message arrived.
 */
void proxy_wakeup_manager_task (int mgr_id) {
        struct rtnet_msg msg;
	struct rtnet_mgr *mgr = (struct rtnet_mgr *)mgr_id;

        rt_printk("RTnet: Proxy txqueue wakeup manager started. (%p)\n", rt_whoami());
        while(1) {
                rt_mbx_receive(&(mgr->mbx), &msg, sizeof(struct rtnet_msg));
                if ((msg.msg_type==WAKEUP) && (msg.rtdev)) {
			if (msg.rtdev->rt_wakeup_xmit) {
				msg.rtdev->proxy_wakeup_xmit(msg.rtdev);
			}
		}
	}
}


/****
 * Initialize the proxy txqueue wakeup manager and its mailbox.
 *
 * This is inefficient since this code is nearly the same as
 * the code in function rt_wakeup_mgr_init().
 */
int proxy_wakeup_mgr_init (struct rtnet_mgr *mgr) {
	int ret = 0;

	if ( (ret=rt_mbx_init (&(mgr->mbx), sizeof(struct rtnet_msg))) )
		return ret;
	if ( (ret=rt_task_init(&(mgr->task), &proxy_wakeup_manager_task, (int)mgr, 4096, RTNET_PROXY_WAKEUP_PRIORITY, 0, 0)) )
		goto rt_mbox_err;
	if ( (ret=rt_task_resume(&(mgr->task))) )
		goto rt_task_err;

	return (ret);

 rt_task_err:
	rt_task_delete(&(mgr->task));
 rt_mbox_err:
	rt_mbx_delete(&(mgr->mbx));
	return (ret);
}


/****
 * Delete proxy txqueue wakeup manager and its mailbox.
 *
 * This is inefficient since this code is exactly the same as
 * the code in function rt_wakeup_mgr_delete() 
 * and rt_rtdev_mgr_delete().
 */
void proxy_wakeup_mgr_delete (struct rtnet_mgr *mgr) {
	rt_task_suspend(&(mgr->task));
	rt_task_delete(&(mgr->task));
	rt_mbx_delete(&(mgr->mbx));
}
