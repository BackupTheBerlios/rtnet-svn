/***
 *
 *  rtmac/examples/event/rt_event.c
 *
 *  Example for tdma-based RTmac, global time and cycle based
 *  packet transmission.
 *
 *  Copyright (C) 2003, 2004 Jan Kiszka <Jan.Kiszka@Uweb.de>
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
#include <asm/io.h>
#include <net/ip.h>

#include <rtnet_config.h>

#include <rtai.h>
#include <rtai_sched.h>

#ifdef HAVE_RTAI_SEM_H
#include <rtai_sem.h>
#endif

#include <rtnet.h>
#include <rtmac.h>

#define PAR_DATA        io
#define PAR_STATUS      io+1
#define PAR_CONTROL     io+2

#define SER_DATA        io
#define SER_IER         io+1
#define SER_IIR         io+2
#define SER_LCR         io+3
#define SER_MCR         io+4
#define SER_LSR         io+5
#define SER_MSR         io+6

#define SYNC_PORT       40000
#define REPORT_PORT     40001

#define MODE_PAR        0
#define MODE_SER        1


static int mode = MODE_PAR;
static int io  = 0x378;
static int irq = 7;
MODULE_PARM(mode, "i");
MODULE_PARM(io, "i");
MODULE_PARM(irq, "i");

static char* rtmac_dev = "TDMA0";
static char* my_ip     = "";
static char* dest_ip   = "10.255.255.255";
MODULE_PARM(rteth_dev, "s");
MODULE_PARM(my_ip, "s");
MODULE_PARM(dest_ip, "s");

MODULE_LICENSE("GPL");

static unsigned long        irq_count = 0;
static int                  tdma;
static int                  sock;
static struct sockaddr_in   dest_addr;
static RT_TASK              task;
static SEM                  event_sem;
static RTIME                time_stamp;


void irq_handler(void)
{
    time_stamp = rt_get_time_ns();

    if (mode == MODE_SER) {
        /* clear irq sources */
        while ((inb(SER_IIR) & 0x01) == 0) {
            inb(SER_LSR);
            inb(SER_DATA);
            inb(SER_MSR);
        }

        /* only trigger on rising CTS edge if using a serial port */
        if ((inb(SER_MSR) & 0x10) == 0)
            return;
    }

    irq_count++;
    rt_sem_signal(&event_sem);
}



void event_handler(int arg)
{
    struct {
        RTIME         time_stamp;
        unsigned long count;
    } packet;
    int wait_on = RTMAC_WAIT_ON_DEFAULT;


    while (1) {
        rt_sem_wait(&event_sem);


        ioctl_rt(tdma, RTMAC_RTIOC_TIMEOFFSET, &packet.time_stamp);

        rt_disable_irq(irq);

        packet.time_stamp += time_stamp;
        packet.count      = irq_count;

        rt_enable_irq(irq);

        ioctl_rt(tdma, RTMAC_RTIOC_WAITONCYCLE, &wait_on);


        if (sendto_rt(sock, &packet, sizeof(packet), 0,
                      (struct sockaddr*)&dest_addr,
                      sizeof(struct sockaddr_in)) < 0)
            break;
    }
}



void sync_callback(struct rtdm_dev_context *dummy, void* arg)
{
    struct msghdr      msg;


    irq_count = 0;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name       = NULL;
    msg.msg_namelen    = 0;
    msg.msg_iov        = NULL;
    msg.msg_iovlen     = 0;
    msg.msg_control    = NULL;
    msg.msg_controllen = 0;

    recvmsg_rt(sock, &msg, 0);
}



int init_module(void)
{
    unsigned int            nonblock = 1;
    struct sockaddr_in      local_addr;
    struct rtnet_callback   callback = {sync_callback, NULL};


    printk("rt_event is using the following parameters:\n"
           "    mode    = %s\n"
           "    io      = 0x%04X\n"
           "    irq     = %d\n"
           "    my_ip   = %s\n"
           "    dest_ip = %s\n",
           (mode == MODE_PAR) ? "parallel port" : "serial port",
           io, irq, my_ip, dest_ip);


    tdma = open_rt(rtmac_dev, O_RDONLY);
    if (tdma < 0) {
        printk("ERROR: RTmac/TDMA not loaded!\n");
        return -ENODEV;
    }


    sock = socket_rt(AF_INET,SOCK_DGRAM,0);

    memset(&local_addr, 0, sizeof(struct sockaddr_in));
    local_addr.sin_family      = AF_INET;
    local_addr.sin_port        = htons(SYNC_PORT);
    local_addr.sin_addr.s_addr =
        (strlen(my_ip) != 0) ? rt_inet_aton(my_ip) : INADDR_ANY;
    bind_rt(sock, (struct sockaddr*)&local_addr, sizeof(struct sockaddr_in));

    /* switch to non-blocking */
    ioctl_rt(sock, RTNET_RTIOC_NONBLOCK, &nonblock);

    memset(&dest_addr, 0, sizeof(struct sockaddr_in));
    dest_addr.sin_family      = AF_INET;
    dest_addr.sin_port        = htons(REPORT_PORT);
    dest_addr.sin_addr.s_addr = rt_inet_aton(dest_ip);

    ioctl_rt(sock, RTNET_RTIOC_CALLBACK, &callback);


    rt_task_init(&task, event_handler, 0, 4096, 10, 0, NULL);
    rt_sem_init(&event_sem, 0);


    if (rt_request_global_irq(irq, irq_handler) != 0) {
        printk("ERROR: irq not available!\n");
        rt_task_delete(&task);
        rt_sem_delete(&event_sem);
        return -EINVAL;
    }

    if (mode == MODE_PAR) {
        /* trigger interrupt on Acknowledge pin (10) */
        outb(0x10, PAR_CONTROL);
    }
    else {
        /* don't forget to specify io and irq (e.g. 0x3F8 / 4) */

        outb(0x00, SER_LCR);
        outb(0x00, SER_IER);

        /* clear irq sources */
        while ((inb(SER_IIR) & 0x01) == 0) {
            printk("Loop init\n");
            inb(SER_LSR);
            inb(SER_DATA);
            inb(SER_MSR);
        }

        /* enable RTS output and set OUT2 */
        outb(0x0A, SER_MCR);

        /* trigger interrupt on modem status line change */
        outb(0x00, SER_LCR);
        outb(0x0D, SER_IER);
    }

    rt_startup_irq(irq);
    rt_enable_irq(irq);


    rt_task_resume(&task);

    return 0;
}



void cleanup_module(void)
{
    rt_disable_irq(irq);
    rt_shutdown_irq(irq);
    rt_free_global_irq(irq);

    while (close_rt(sock) == -EAGAIN) {
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(1*HZ); /* wait a second */
    }

    while (close_rt(tdma) == -EAGAIN) {
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(1*HZ); /* wait a second */
    }

    rt_sem_delete(&event_sem);
    rt_task_delete(&task);
}
