/***
 *
 *  examples/frag_ip/frag_ip.c
 *
 *  sends fragmented IP packets to another frag_ip instance
 *
 *  Copyright (C) 2003, 2004 Jan Kiszka <jan.kiszka@web.de>
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
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>

#include <rtnet_sys.h>
#include <rtnet.h>

static char *dest_ip_s = "127.0.0.1";
static unsigned int size = 65505;
static unsigned int add_rtskbs = 75;

MODULE_PARM(dest_ip_s, "s");
MODULE_PARM(size, "i");
MODULE_PARM(add_rtskbs, "i");
MODULE_PARM_DESC(dest_ip_s, "destination IP address");
MODULE_PARM_DESC(size, "message size (0-65505)");
MODULE_PARM_DESC(add_rtskbs, "number of additional rtskbs (default: 75)");

#ifdef CONFIG_RTOS_STARTSTOP_TIMER
static int start_timer = 0;
MODULE_PARM(start_timer, "i");
MODULE_PARM_DESC(start_timer, "set to non-zero to start scheduling timer");
#endif

MODULE_LICENSE("GPL");

#define CYCLE       1000*1000*1000   /* 1 s */
rtos_task_t rt_xmit_task;
rtos_task_t rt_recv_task;

#define PORT        37000

static struct sockaddr_in dest_addr;

static int sock;

static char buffer_out[64*1024];
static char buffer_in[64*1024];



void send_msg(void *arg)
{
    int ret;
    struct msghdr msg;
    struct iovec iov[2];
    unsigned short msgsize = size;


    while(1) {
        iov[0].iov_base = &msgsize;
        iov[0].iov_len  = sizeof(msgsize);
        iov[1].iov_base = buffer_out;
        iov[1].iov_len  = size;

        memset(&msg, 0, sizeof(msg));
        msg.msg_name    = &dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov     = iov;
        msg.msg_iovlen  = 2;

        rtos_print("Sending message of %d+2 bytes\n", size);
        ret = rt_dev_sendmsg(sock, &msg, 0);
        if (ret != (int)(sizeof(msgsize) + size))
            rtos_print(" rt_dev_sendmsg() = %d!\n", ret);

        rtos_task_wait_period(&rt_xmit_task);
    }
}



void recv_msg(void *arg)
{
    int ret;
    struct msghdr msg;
    struct iovec iov[2];
    unsigned short msgsize = size;
    struct sockaddr_in addr;


    while(1) {
        iov[0].iov_base = &msgsize;
        iov[0].iov_len  = sizeof(msgsize);
        iov[1].iov_base = buffer_in;
        iov[1].iov_len  = size;

        memset(&msg, 0, sizeof(msg));
        msg.msg_name    = &addr;
        msg.msg_namelen = sizeof(addr);
        msg.msg_iov     = iov;
        msg.msg_iovlen  = 2;

        ret = rt_dev_recvmsg(sock, &msg, 0);
        if (ret <= 0) {
            rtos_print(" rt_dev_recvmsg() = %d\n", ret);
            return;
        } else {
            unsigned long ip = ntohl(addr.sin_addr.s_addr);

            rtos_print("received packet from %lu.%lu.%lu.%lu, length: %d+2, "
                "encoded length: %d,\n flags: %X, content %s\n", ip >> 24,
                (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                ret-sizeof(msgsize), msgsize, msg.msg_flags,
                (memcmp(buffer_in, buffer_out, ret-sizeof(msgsize)) == 0) ?
                    "ok" : "corrupted");
        }
    }
}



int init_module(void)
{
    int ret;
    unsigned int i;
    struct sockaddr_in local_addr;
    unsigned long dest_ip = rt_inet_aton(dest_ip_s);

    if (size > 65505)
        size = 65505;

    printk("destination ip address %s=%08x\n", dest_ip_s,
           (unsigned int)dest_ip);
    printk("size %d\n", size);
#ifdef CONFIG_RTOS_STARTSTOP_TIMER
    printk("start timer %d\n", start_timer);
#endif

    /* fill output buffer with test pattern */
    for (i = 0; i < sizeof(buffer_out); i++)
        buffer_out[i] = i & 0xFF;

    /* create rt-socket */
    sock = rt_dev_socket(AF_INET,SOCK_DGRAM,0);
    if (sock < 0) {
        printk(" rt_dev_socket() = %d!\n", sock);
        return sock;
    }

    /* extend the socket pool */
    ret = rt_dev_ioctl(sock, RTNET_RTIOC_EXTPOOL, &add_rtskbs);
    if (ret != (int)add_rtskbs) {
        printk(" rt_dev_ioctl(RT_IOC_SO_EXTPOOL) = %d\n", ret);
        rt_dev_close(sock);
        return -1;
    }

    /* bind the rt-socket to a port */
    memset(&local_addr, 0, sizeof(struct sockaddr_in));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(PORT);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    ret = rt_dev_bind(sock, (struct sockaddr *)&local_addr,
                      sizeof(struct sockaddr_in));
    if (ret < 0) {
        printk(" rt_dev_bind() = %d!\n", ret);
        rt_dev_close(sock);
        return ret;
    }

    /* set destination address */
    memset(&dest_addr, 0, sizeof(struct sockaddr_in));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    dest_addr.sin_addr.s_addr = dest_ip;

#ifdef CONFIG_RTOS_STARTSTOP_TIMER
    if (start_timer) {
        rtos_timer_start_oneshot();
    }
#endif

    ret = rtos_task_init(&rt_recv_task, recv_msg, 0, 9);
    if (ret != 0)
    {
        printk(" rtos_task_init(recv) = %d!\n", ret);
        rt_dev_close(sock);
        return ret;
    }

    ret = rtos_task_init_periodic(&rt_xmit_task, send_msg, 0, 10, CYCLE);
    if (ret != 0) {
        printk(" rtos_task_init_periodic(xmit) = %d!\n", ret);
        rt_dev_close(sock);
        rtos_task_delete(&rt_recv_task);
        return ret;
    }

    return 0;
}



void cleanup_module(void)
{
#ifdef CONFIG_RTOS_STARTSTOP_TIMER
    if (start_timer)
        rtos_timer_stop();
#endif

    /* Important: First close the socket! */
    while (rt_dev_close(sock) == -EAGAIN) {
        printk("frag-ip: Socket busy - waiting...\n");
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(1*HZ); /* wait a second */
    }

    rtos_task_delete(&rt_xmit_task);
    rtos_task_delete(&rt_recv_task);
}
