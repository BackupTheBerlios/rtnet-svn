/* rtmac_mgr.h
 *
 * Copyright (C) 2003 Hans-Peter Bock <hpbock@avaapgh.de>
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

#ifndef __RTMAC_MGR__
#define __RTMAC_MGR__

#include <rtnet.h>

extern struct rtnet_mgr rt_wakeup_manager;
extern struct rtnet_mgr proxy_wakeup_manager;

extern int rt_wakeup_mgr_init (struct rtnet_mgr *mgr);
extern void rt_wakeup_mgr_delete (struct rtnet_mgr *mgr);
extern int proxy_wakeup_mgr_init (struct rtnet_mgr *mgr);
extern void proxy_wakeup_mgr_delete (struct rtnet_mgr *mgr);

#endif /* __RTMAC_MGR__ */
