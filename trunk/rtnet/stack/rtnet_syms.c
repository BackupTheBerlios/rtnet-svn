/***
 *
 *  rtnet/rtnet_syms.c - export kernel symbols
 *
 *  Copyright (C) 1999      Lineo, Inc
 *                1999,2002 David A. Schleef <ds@schleef.org>
 *                2002      Ulrich Marx <marx@kammer.uni-hannover.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include <rtnet.h>
#include <rtskb.h>
#include <rtnet_chrdev.h>
#include <rtnet_rtpc.h>
#include <rtnet_socket.h>
#include <rtdev_mgr.h>
#include <stack_mgr.h>
#include <ethernet/eth.h>
#include <ipv4/arp.h>
#include <ipv4/ip_input.h>
#include <ipv4/route.h>
#include <ipv4/protocol.h>


/****************************************************************************
 * stack_mgr.c                                                              *
 ****************************************************************************/
EXPORT_SYMBOL(rtdev_add_pack);
EXPORT_SYMBOL(rtdev_remove_pack);

EXPORT_SYMBOL(rtnetif_rx);
EXPORT_SYMBOL(rt_mark_stack_mgr);
EXPORT_SYMBOL(rtnetif_tx);

EXPORT_SYMBOL(rt_stack_connect);
EXPORT_SYMBOL(rt_stack_disconnect);

EXPORT_SYMBOL(rt_packets);
EXPORT_SYMBOL(rt_packets_lock);


/****************************************************************************
 * rtdev_mgr.c                                                              *
 ****************************************************************************/
EXPORT_SYMBOL(rtnetif_err_rx);
EXPORT_SYMBOL(rtnetif_err_tx);

EXPORT_SYMBOL(rt_rtdev_connect);
EXPORT_SYMBOL(rt_rtdev_disconnect);


/****************************************************************************
 * rtdev.c                                                                  *
 ****************************************************************************/
EXPORT_SYMBOL(rt_alloc_etherdev);
EXPORT_SYMBOL(rtdev_free);

EXPORT_SYMBOL(rtdev_alloc_name);

EXPORT_SYMBOL(rt_register_rtnetdev);
EXPORT_SYMBOL(rt_unregister_rtnetdev);

EXPORT_SYMBOL(rtdev_add_register_hook);
EXPORT_SYMBOL(rtdev_del_register_hook);

EXPORT_SYMBOL(rtdev_get_by_name);
EXPORT_SYMBOL(rtdev_get_by_index);
EXPORT_SYMBOL(rtdev_get_by_hwaddr);
EXPORT_SYMBOL(rtdev_get_loopback);

EXPORT_SYMBOL(rtdev_xmit);

#ifdef CONFIG_RTNET_PROXY
EXPORT_SYMBOL(rtdev_xmit_proxy);
#endif

EXPORT_SYMBOL(rt_hard_mtu);


/****************************************************************************
 * rtnet_chrdev.c                                                             *
 ****************************************************************************/
EXPORT_SYMBOL(rtnet_register_ioctls);
EXPORT_SYMBOL(rtnet_unregister_ioctls);


/****************************************************************************
 * rtnet_module.c                                                             *
 ****************************************************************************/
EXPORT_SYMBOL(rtnet_proc_root);
EXPORT_SYMBOL(STACK_manager);
EXPORT_SYMBOL(RTDEV_manager);


/****************************************************************************
 * ethernet/eth.c                                                           *
 ****************************************************************************/
EXPORT_SYMBOL(rt_eth_header);
EXPORT_SYMBOL(rt_eth_type_trans);


/****************************************************************************
 * ipv4/arp.c                                                               *
 ****************************************************************************/
EXPORT_SYMBOL(rt_arp_send);


/****************************************************************************
 * ipv4/route.c                                                             *
 ****************************************************************************/
EXPORT_SYMBOL(rt_ip_route_add_host);
EXPORT_SYMBOL(rt_ip_route_del_host);
EXPORT_SYMBOL(rt_ip_route_output);
EXPORT_SYMBOL(rt_ip_route_del_all);


/****************************************************************************
 * ipv4/ip_input.c                                                          *
 ****************************************************************************/
#ifdef CONFIG_RTNET_PROXY
EXPORT_SYMBOL(rt_ip_register_fallback);
#endif


/****************************************************************************
 * ipv4/protocol.c                                                          *
 ****************************************************************************/
EXPORT_SYMBOL(rt_inet_aton);


/****************************************************************************
 * rtskb.c                                                                  *
 ****************************************************************************/
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

#ifdef CONFIG_RTNET_RTCAP
EXPORT_SYMBOL(rtcap_lock);
EXPORT_SYMBOL(rtcap_handler);
#endif


/****************************************************************************
 * packet                                                                   *
 ****************************************************************************/
EXPORT_SYMBOL(rt_eth_aton);


/****************************************************************************
 * rtnet_rtpc.c                                                             *
 ****************************************************************************/
EXPORT_SYMBOL(rtpc_dispatch_call);
EXPORT_SYMBOL(rtpc_complete_call);
EXPORT_SYMBOL(rtpc_complete_call_nrt);
