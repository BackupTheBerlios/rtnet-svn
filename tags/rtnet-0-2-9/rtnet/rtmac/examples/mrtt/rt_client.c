/***
 *
 *  examples/rtt/rt_client.c
 *
 *  client part - sends packet, receives echo, passes them by fifo to userspace app
 *
 *  based on Ulrich Marx's module, adopted to rtmac
 *
 *  Copyright (C) 2002 Ulrich Marx <marx@kammer.uni-hannover.de>
 *                2002 Marc Kleine-Budde <kleine-budde@gmx.de>
 *
 *  rtnet - real-time networking example
 *  rtmac - real-time media access control example
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

#include <net/ip.h>

#include <rtai.h>
#include <rtai_sched.h>
#include <rtai_fifos.h>

#include <rtnet.h>

#define MIN_LENGTH_IPv4 7
#define MAX_LENGTH_IPv4 15
static char *local_ip_s  = "127.0.0.1";
static char *broadcast_ip_s = "127.0.0.1";
static int cycle = 1*1000*1000; // = 1 s

struct mrtt_rx_packet {
	long long	rx;
	long long	tx;
	u32		ip_addr;
};

MODULE_PARM (local_ip_s ,"s");
MODULE_PARM (broadcast_ip_s,"s");
MODULE_PARM (cycle, "i");
MODULE_PARM_DESC (local_ip_s, "rt_echo_client: lokal ip-address");
MODULE_PARM_DESC (broadcast_ip_s, "rt_echo_client: broadcast ip-address");
MODULE_PARM_DESC (cycle, "cycletime in us");

#define TIMERTICKS	1000	// 1 us
RT_TASK rt_task;

#define RCV_PORT	35999
#define SRV_PORT	36000

static struct sockaddr_in broadcast_addr;
static struct sockaddr_in local_addr;

static int sock;

#define BUFSIZE 1500
static char buffer[BUFSIZE];
static RTIME tx_time;
static RTIME rx_time;

SEM tx_sem;

#define PRINT 0

void *process(void * arg)
{
	int ret = 0;

	while(1) {
                /* get time        */
                tx_time = rt_get_time_ns();

                /* send the time   */    
		ret=rt_socket_sendto(sock, &tx_time, sizeof(RTIME), 0, (struct sockaddr *) &broadcast_addr, sizeof(struct sockaddr_in));

	        /* wait one period */ 
	        rt_task_wait_period();
	}
}



int echo_rcv(int s,void *arg)
{
	int			ret=0;
	struct msghdr		msg;
	struct iovec		iov;
	struct sockaddr_in	addr;
	struct mrtt_rx_packet	rx_packet;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &buffer;
	iov.iov_len = BUFSIZE;

	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	ret = rt_socket_recvmsg(sock, &msg, 0);

	if ( (ret>0) && (msg.msg_namelen==sizeof(struct sockaddr_in)) ) {
		struct sockaddr_in *sin = msg.msg_name;
		
		/* get the time    */
		rx_time = rt_get_time_ns();
		memcpy(&tx_time, buffer, sizeof(RTIME));

		rx_packet.rx = rx_time;
		rx_packet.tx = tx_time;
		rx_packet.ip_addr = sin->sin_addr.s_addr;

		rtf_put(PRINT, &rx_packet, sizeof(struct mrtt_rx_packet));
	}

	return 0;
}


int init_module(void)
{
	int ret;

	unsigned long local_ip  = rt_inet_aton(local_ip_s);
	unsigned long broadcast_ip = rt_inet_aton(broadcast_ip_s);

	rtf_create(PRINT, 40000);
	rt_sem_init(&tx_sem, 0);

	rt_printk ("local     ip address %s=%8x\n", local_ip_s, local_ip);
	rt_printk ("broadcast ip address %s=%8x\n", broadcast_ip_s, broadcast_ip);

	/* create rt-socket */
	sock=rt_socket(AF_INET,SOCK_DGRAM,0);
	
	/* bind the rt-socket to local_addr */	
	memset(&local_addr, 0, sizeof(struct sockaddr_in));
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(RCV_PORT);
	local_addr.sin_addr.s_addr = local_ip;
	ret=rt_socket_bind(sock, (struct sockaddr *) &local_addr, sizeof(struct sockaddr_in));

	/* set server-addr */
	memset(&broadcast_addr, 0, sizeof(struct sockaddr_in));
	broadcast_addr.sin_family = AF_INET;
	broadcast_addr.sin_port = htons(SRV_PORT);
	broadcast_addr.sin_addr.s_addr = broadcast_ip;

	// set up receiving
	rt_socket_callback(sock, echo_rcv, NULL);
	
	rt_set_oneshot_mode();
	start_rt_timer(TIMERTICKS);

        ret=rt_task_init(&rt_task,(void *)process,0,4096,10,0,NULL);
        ret=rt_task_make_periodic_relative_ns( &rt_task, 10 * 1000*1000, cycle * 1000);

	return ret;
}




void cleanup_module(void)
{
        /* stop timer         */ 
  	stop_rt_timer();

        /* rt_task_delete     */ 
  	rt_task_delete(&rt_task);

        /* close th rt-socket */
  	rt_socket_close(sock);

	rt_sem_delete(&tx_sem);

	/* destroy the fifo   */
	rtf_destroy(PRINT);
}
