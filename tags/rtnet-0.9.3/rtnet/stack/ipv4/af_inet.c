/***
 *
 *  ipv4/af_inet.c
 *
 *  rtnet - real-time networking subsystem
 *  Copyright (C) 1999, 2000 Zentropic Computing, LLC
 *                2002       Ulrich Marx <marx@kammer.uni-hannover.de>
 *                2004, 2005 Jan Kiszka <jan.kiszka@web.de>
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

#include <linux/module.h>
#include <asm/uaccess.h>

#include <ipv4_chrdev.h>
#include <rtnet_internal.h>
#include <rtnet_rtpc.h>
#include <ipv4/arp.h>
#include <ipv4/icmp.h>
#include <ipv4/ip_output.h>
#include <ipv4/protocol.h>
#include <ipv4/route.h>
#include <ipv4/udp.h>


MODULE_LICENSE("GPL");

struct route_solicit_params {
    struct rtnet_device *rtdev;
    __u32               ip_addr;
};

#ifdef CONFIG_PROC_FS
struct proc_dir_entry *ipv4_proc_root;
#endif


static int route_solicit_handler(struct rt_proc_call *call)
{
    struct route_solicit_params *param;
    struct rtnet_device         *rtdev;


    param = rtpc_get_priv(call, struct route_solicit_params);
    rtdev = param->rtdev;

    if ((rtdev->flags & IFF_UP) == 0)
        return -ENODEV;

    rt_arp_solicit(rtdev, param->ip_addr);

    return 0;
}



static void cleanup_route_solicit(void *priv_data)
{
    struct route_solicit_params *param;


    param = (struct route_solicit_params *)priv_data;
    rtdev_dereference(param->rtdev);
}



static int ping_handler(struct rt_proc_call *call)
{
    struct ipv4_cmd *cmd;
    int             err;


    cmd = rtpc_get_priv(call, struct ipv4_cmd);

    rt_icmp_queue_echo_request(call);

    err = rt_icmp_send_echo(cmd->args.ping.ip_addr, cmd->args.ping.id,
                            cmd->args.ping.sequence, cmd->args.ping.msg_size);
    if (err < 0) {
        rt_icmp_dequeue_echo_request(call);
        return err;
    }

    return -CALL_PENDING;
}



static void ping_complete_handler(struct rt_proc_call *call, void *priv_data)
{
    struct ipv4_cmd *cmd;
    struct ipv4_cmd *usr_cmd = (struct ipv4_cmd *)priv_data;


    if (rtpc_get_result(call) < 0)
        return;

    cmd = rtpc_get_priv(call, struct ipv4_cmd);
    usr_cmd->args.ping.ip_addr = cmd->args.ping.ip_addr;
    usr_cmd->args.ping.rtt     = cmd->args.ping.rtt;
}



static int ipv4_ioctl(struct rtnet_device *rtdev, unsigned int request,
                      unsigned long arg)
{
    struct ipv4_cmd             cmd;
    struct route_solicit_params params;
    int                         ret;


    ret = copy_from_user(&cmd, (void *)arg, sizeof(cmd));
    if (ret != 0)
        return -EFAULT;

    switch (request) {
        case IOC_RT_HOST_ROUTE_ADD:
            if (down_interruptible(&rtdev->nrt_lock))
                return -ERESTARTSYS;

            ret = rt_ip_route_add_host(cmd.args.addhost.ip_addr,
                                       cmd.args.addhost.dev_addr, rtdev);

            up(&rtdev->nrt_lock);
            break;

        case IOC_RT_HOST_ROUTE_SOLICIT:
            if (down_interruptible(&rtdev->nrt_lock))
                return -ERESTARTSYS;

            rtdev_reference(rtdev);
            params.rtdev   = rtdev;
            params.ip_addr = cmd.args.solicit.ip_addr;

            /* We need the rtpc wrapping because rt_arp_solicit can block on a
             * real-time semaphore in the NIC's xmit routine. */
            ret = rtpc_dispatch_call(route_solicit_handler, 0, &params,
                                     sizeof(params), NULL,
                                     cleanup_route_solicit);

            up(&rtdev->nrt_lock);
            break;

        case IOC_RT_HOST_ROUTE_DELETE:
        case IOC_RT_HOST_ROUTE_DELETE_DEV:
            ret = rt_ip_route_del_host(cmd.args.delhost.ip_addr, rtdev);
            break;

#ifdef CONFIG_RTNET_RTIPV4_NETROUTING
        case IOC_RT_NET_ROUTE_ADD:
            ret = rt_ip_route_add_net(cmd.args.addnet.net_addr,
                                      cmd.args.addnet.net_mask,
                                      cmd.args.addnet.gw_addr);
            break;

        case IOC_RT_NET_ROUTE_DELETE:
            ret = rt_ip_route_del_net(cmd.args.delnet.net_addr,
                                      cmd.args.delnet.net_mask);
            break;
#endif /* CONFIG_RTNET_RTIPV4_NETROUTING */

        case IOC_RT_PING:
            ret = rtpc_dispatch_call(ping_handler, cmd.args.ping.timeout, &cmd,
                                     sizeof(cmd), ping_complete_handler, NULL);
            if (ret >= 0) {
                if (copy_to_user((void *)arg, &cmd, sizeof(cmd)) != 0)
                    ret = -EFAULT;
            }
            if (ret < 0)
                rt_icmp_cleanup_echo_requests();
            break;

        default:
            ret = -ENOTTY;
    }

    return ret;
}



unsigned long rt_inet_aton(const char *ip)
{
    int p, n, c;
    union { unsigned long l; char c[4]; } u;
    p = n = 0;
    while ((c = *ip++)) {
        if (c != '.') {
            n = n*10 + c-'0';
        } else {
            if (n > 0xFF) {
                return 0;
            }
            u.c[p++] = n;
            n = 0;
        }
    }
    u.c[3] = n;
    return u.l;
}



static void rt_ip_ifup(struct rtnet_device *rtdev,
                       struct rtnet_core_cmd *up_cmd)
{
    struct rtnet_device *tmp;
    int                 i;


    rt_ip_route_del_all(rtdev); /* cleanup routing table */

    if (up_cmd->args.up.ip_addr != 0xFFFFFFFF) {
        rtdev->local_ip     = up_cmd->args.up.ip_addr;
        rtdev->broadcast_ip = up_cmd->args.up.broadcast_ip;
    }

    if (rtdev->local_ip != 0) {
        if (rtdev->flags & IFF_LOOPBACK) {
            for (i = 0; i < MAX_RT_DEVICES; i++)
                if ((tmp = rtdev_get_by_index(i)) != NULL) {
                    rt_ip_route_add_host(tmp->local_ip,
                                         rtdev->dev_addr, rtdev);
                    rtdev_dereference(tmp);
                }
        } else if ((tmp = rtdev_get_loopback()) != NULL) {
            rt_ip_route_add_host(rtdev->local_ip,
                                 tmp->dev_addr, tmp);
            rtdev_dereference(tmp);
        }

        if (rtdev->flags & IFF_BROADCAST)
            rt_ip_route_add_host(up_cmd->args.up.broadcast_ip,
                                 rtdev->broadcast, rtdev);
    }
}



static void rt_ip_ifdown(struct rtnet_device *rtdev)
{
    rt_ip_route_del_all(rtdev);
}



static struct rtdev_event_hook  rtdev_hook = {
    register_device:    NULL,
    unregister_device:  NULL,
    ifup:               rt_ip_ifup,
    ifdown:             rt_ip_ifdown
};

static struct rtnet_ioctls ipv4_ioctls = {
    service_name:       "IPv4",
    ioctl_type:         RTNET_IOC_TYPE_IPV4,
    handler:            ipv4_ioctl
};

static struct rtdm_device ipv4_device = {
    struct_version:     RTDM_DEVICE_STRUCT_VER,

    device_flags:       RTDM_PROTOCOL_DEVICE,
    context_size:       sizeof(struct rtsocket),

    protocol_family:    PF_INET,
    socket_type:        SOCK_DGRAM,

    socket_rt:          rt_inet_socket,
    socket_nrt:         rt_inet_socket,

    /* default is UDP */
    ops: {
        close_rt:       rt_udp_close,
        close_nrt:      rt_udp_close,
        ioctl_rt:       rt_udp_ioctl,
        ioctl_nrt:      rt_udp_ioctl,
        recvmsg_rt:     rt_udp_recvmsg,
        sendmsg_rt:     rt_udp_sendmsg,
#ifdef CONFIG_RTNET_RTDM_SELECT
        poll_rt:        rt_udp_poll,
        /* there should be only the function poll() */
        pollwait_rt:    rt_udp_pollwait,
        pollfree_rt:    rt_udp_pollfree,
#endif /* CONFIG_RTNET_RTDM_SELECT */
    },

    device_class:       RTDM_CLASS_NETWORK,
    device_sub_class:   RTDM_SUBCLASS_RTNET,
    driver_name:        "rtipv4",
    driver_version:     RTNET_RTDM_VER,
    peripheral_name:    "Real-Time IPv4 Datagram Socket Interface",
    provider_name:      rtnet_rtdm_provider_name,

    proc_name:          "INET_DGRAM"
};


int __init rt_ipv4_proto_init(void)
{
    int i;
    int result;


    /* Network-Layer */
    rt_ip_init();
    rt_arp_init();

    /* Transport-Layer */
    for (i=0; i<MAX_RT_INET_PROTOCOLS; i++)
        rt_inet_protocols[i]=NULL;

    rt_icmp_init();
    rt_udp_init();

#ifdef CONFIG_PROC_FS
    ipv4_proc_root = create_proc_entry("ipv4", S_IFDIR, rtnet_proc_root);
    if (!ipv4_proc_root) {
        /*ERRMSG*/printk("RTnet: unable to initialize /proc entry (ipv4)\n");
        return -1;
    }
#endif /* CONFIG_PROC_FS */

    if ((result = rt_ip_routing_init()) < 0)
        goto err1;
    if ((result = rtnet_register_ioctls(&ipv4_ioctls)) < 0)
        goto err2;
    if ((result = rtdm_dev_register(&ipv4_device)) < 0)
        goto err3;

    rtdev_add_event_hook(&rtdev_hook);

    return 0;

  err3:
    rtnet_unregister_ioctls(&ipv4_ioctls);

  err2:
    rt_ip_routing_release();

  err1:
#ifdef CONFIG_PROC_FS
    remove_proc_entry("ipv4", rtnet_proc_root);
#endif /* CONFIG_PROC_FS */

    rt_udp_release();
    rt_icmp_release();
    rt_arp_release();
    rt_ip_release();

    return result;
}


void __exit rt_ipv4_proto_release(void)
{
    rtdev_del_event_hook(&rtdev_hook);
    rtdm_dev_unregister(&ipv4_device, 1000);
    rtnet_unregister_ioctls(&ipv4_ioctls);
    rt_ip_routing_release();

#ifdef CONFIG_PROC_FS
    remove_proc_entry("ipv4", rtnet_proc_root);
#endif

    /* Transport-Layer */
    rt_udp_release();
    rt_icmp_release();

    /* Network-Layer */
    rt_arp_release();
    rt_ip_release();
}


module_init(rt_ipv4_proto_init);
module_exit(rt_ipv4_proto_release);


EXPORT_SYMBOL(rt_inet_aton);
