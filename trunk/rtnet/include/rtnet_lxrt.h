/* rtnet_lxrt.h
 *
 * rtnet_lxrt - real-time networking in usermode
 *
 * Copyright (C) 2002 Ulrich Marx <marx@fet.uni-hannover.de>
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
#ifndef __LX_RTNET_H__
#define __LX_RTNET_H__

#include <rtai_declare.h>

#define LxRTNET_IDX             7

#define RT_SOCKET               0
#define RT_SOCKET_CLOSE         1
#define RT_SOCKET_BIND          2
#define RT_SOCKET_CONNECT       3
#define RT_SOCKET_ACCEPT        4
#define RT_SOCKET_LISTEN        5
#define RT_SOCKET_SEND          6
#define RT_SOCKET_RECV          7
#define RT_SOCKET_SENDTO        8
#define RT_SOCKET_RECVFROM      9
#define RT_SOCKET_SENDMSG       10
#define RT_SOCKET_RECVMSG       11
#define RT_SOCKET_WRITE	        12
#define RT_SOCKET_READ	        13
#define RT_SOCKET_WRITEV        14
#define RT_SOCKET_READV         15
#define RT_SOCKET_GETSOCKNAME   16
#define RT_SOCKET_SETSOCKOPT    17

/* not implemented yet (will they ever be?) */
#define RT_SSOCKET              40
#define RT_SSOCKET_CLOSE        41
#define RT_SSOCKET_BIND         42
#define RT_SSOCKET_CONNECT      43
#define RT_SSOCKET_ACCEPT       44
#define RT_SSOCKET_LISTEN       45
#define RT_SSOCKET_SEND         46
#define RT_SSOCKET_RECV         47
#define RT_SSOCKET_SENDTO       48
#define RT_SSOCKET_RECVFROM     49
#define RT_SSOCKET_SENDMSG      50
#define RT_SSOCKET_RECVMSG      51
#define RT_SSOCKET_WRITE        52
#define RT_SSOCKET_READ         53
#define RT_SSOCKET_WRITEV       54
#define RT_SSOCKET_READV        55
#define RT_SSOCKET_GETSOCKNAME  56
#define RT_SSOCKET_SETSOCKOPT   57


extern int rt_socket_init(int family, int type, int protocol);
extern int rt_socket_close(int s);
extern int rt_socket_bind(int s, struct sockaddr *my_addr, socklen_t addrlen);
extern int rt_socket_connect(int s, const struct sockaddr *addr, socklen_t addrlen);
extern int rt_socket_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
extern int rt_socket_listen(int s, int backlog);
extern int rt_socket_send(int s, const void *msg, size_t len, int flags);
extern int rt_socket_recv(int s,void *buf, size_t len, int flags);
extern int rt_socket_sendto(int s, const void *msg, size_t len, int flags,
                            const struct sockaddr *to, socklen_t tolen);
extern int rt_socket_recvfrom(int s, void *buf, size_t len, int flags,
                              struct sockaddr *from, socklen_t *fromlen);
extern int rt_socket_sendmsg(int s, const struct msghdr *msg, int flags);
extern int rt_socket_recvmsg(int s, struct msghdr *msg, int flags);
extern int rt_socket_getsockname(int s, struct sockaddr *addr, socklen_t addrlen);
extern int rt_socket_setsockopt(int s, int level, int optname,
                                const void *optval, socklen_t optlen);

#define rt_bind                 rt_socket_bind
#define rt_listen               rt_socket_listen
#define rt_connect              rt_socket_connect
#define rt_accept               rt_socket_accept
#define rt_close                rt_socket_close
#define rt_sendto               rt_socket_sendto
#define rt_recvfrom             rt_socket_recvfrom
#define rt_setsockopt           rt_socket_setsockopt

#ifndef __KERNEL__

#include <stdarg.h>
#include <rtai_lxrt.h>

extern union rtai_lxrt_t rtai_lxrt(short int dynx, short int lsize, int srq, void *arg);

#define SIZARG sizeof(arg)

DECLARE int rt_socket(int family, int type, int protocol)
{
    struct { int family; int type; int protocol; } arg = { family, type, protocol };
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET, &arg).i[LOW];
}

DECLARE int rt_socket_close(int fd)
{
    struct { int fd; } arg = { fd };
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_CLOSE, &arg).i[LOW];
}

DECLARE int rt_socket_bind(int fd, struct sockaddr *addr, int addr_len)
{
    struct {int fd; struct sockaddr *addr; int addr_len; } arg = { fd, addr, addr_len };
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_BIND, &arg).i[LOW];
}

DECLARE int rt_socket_connect(int fd, struct sockaddr *addr, int addr_len)
{
    struct {int fd; struct sockaddr *addr; int addr_len; } arg = { fd, addr, addr_len };
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_CONNECT, &arg).i[LOW];
}

DECLARE int rt_socket_accept(int fd, struct sockaddr *addr, int *addr_len)
{
    struct {int fd; struct sockaddr *addr; int *addr_len; } arg = { fd, addr, addr_len };
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_ACCEPT, &arg).i[LOW];
}

DECLARE int rt_socket_listen(int fd, int backlog)
{
    struct {int fd; int backlog; } arg = { fd, backlog };
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_LISTEN, &arg).i[LOW];
}

DECLARE int rt_socket_send(int fd, void *buf, int len, unsigned int flags)
{
    struct {int fd; void *buf; int len; unsigned int flags;} arg = { fd, buf, len, flags };
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_SEND, &arg).i[LOW];
}

DECLARE int rt_socket_recv(int fd, void *buf, int len, unsigned int flags)
{
    struct {int fd; void *buf; int len; unsigned int flags;} arg = { fd, buf, len, flags };
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_RECV, &arg).i[LOW];
}

DECLARE int rt_socket_sendto(int fd, void *buf, int len, unsigned int flags, struct sockaddr *to, int tolen)
{
    struct {int fd; void *buf; int len; unsigned int flags; struct sockaddr *to; int tolen;} arg
        = {fd, buf, len, flags, to, tolen};
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_SENDTO, &arg).i[LOW];
}

DECLARE int rt_socket_recvfrom(int fd, void *buf, int len, unsigned int flags, struct sockaddr *from, int *fromlen)
{
    fd = fd; buf=buf; len=len; flags=flags; from=from, fromlen=fromlen;
#warning function not yet implemented!
    return 0;
}

DECLARE int rt_socket_sendmsg(int fd, struct msghdr *msg, unsigned int flags)
{
    struct {int fd; struct msghdr *msg; unsigned int flags;} arg = {fd, msg, flags};
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_SENDMSG, &arg).i[LOW];
}

DECLARE int rt_socket_recvmsg(int fd, struct msghdr *msg, unsigned int flags)
{
    fd=fd; msg=msg; flags=flags;
#warning function not yet implemented!
    return 0;
}

DECLARE int rt_socket_getsockname(int fd, struct sockaddr *addr, int addr_len)
{
    struct {int fd; struct sockaddr *addr; int addr_len;} arg = {fd, addr, addr_len};
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_GETSOCKNAME, &arg).i[LOW];
}

DECLARE int rt_socket_setsockopt(int fd, int level, int optname, const void *optval, int optlen)
{
    struct {int fd; int level; int optname; const void *optval; int optlen;} arg = {fd, level, optname, optval, optlen};
    return (int)rtai_lxrt(LxRTNET_IDX, SIZARG, RT_SOCKET_SETSOCKOPT, &arg).i[LOW];
}

#endif	/* __KERNEL__ */
#endif	/* __LX_RTNET_H_ */
