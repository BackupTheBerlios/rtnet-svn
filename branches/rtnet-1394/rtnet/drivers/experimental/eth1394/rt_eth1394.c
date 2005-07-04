/* rtfirewire/highlevel/eth1394/rt_eth1394.c
 *
* Ehernet Emulation on RT-FireWire.
 *
 * Copyright (C)  2005 Zhang Yuchen <y.zhang-4@student.utwente.nl>
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
 #include <linux/module.h>
 #include <linux/config.h>
 #include <linux/init.h>
 
 #include <rt_eth1394.h>
 #include <highlevel.h> 
 
 #include <rtnet_port.h>
 
 #define driver_name	"Eth1394"
 
 #define ARPHRD_IEEE1394	24//stolen from linux/if_arp.h
 
 #define ETH1394_PRINT_G(level, fmt, args...) \
	rtos_print(level "%s: " fmt, driver_name, ## args)

#define ETH1394_PRINT(level, dev_name, fmt, args...) \
	rtos_print(level "%s: %s: " fmt, driver_name, dev_name, ## args)

#define ETH1394_DEBUG 1
#ifdef ETH1394_DEBUG
#define DEBUGP(fmt, args...) \
	rtos_print(KERN_ERR "%s:%s[%d]: " fmt "\n", driver_name, __FUNCTION__, __LINE__, ## args)
#else
#define DEBUGP(fmt, args...)
#endif
	
#define TRACE() rtos_print(KERN_ERR "%s:%s[%d] ---- TRACE\n", driver_name, __FUNCTION__, __LINE__)

/* Change this to IEEE1394_SPEED_S100 to make testing easier */
#define ETH1394_SPEED_DEF	0x03 /*IEEE1394_SPEED_MAX*/

/* For now, this needs to be 1500, so that XP works with us */
#define ETH1394_DATA_LEN	1500/*ETH_DATA_LEN*/

 static const u16 eth1394_speedto_maxpayload[] = {
/*     S100, S200, S400, S800, S1600, S3200 */
	512, 1024, 2048, 4096,  4096,  4096
};

static inline void eth1394_register_limits(int nodeid, u16 maxpayload,
					     unsigned char sspd, u64 eui, u64 fifo,
					     struct eth1394_priv *priv)
{
	
	if (nodeid < 0 || nodeid >= ALL_NODES) {
		ETH1394_PRINT_G (KERN_ERR, "Cannot register invalid nodeid %d\n", nodeid);
		return;
	}

	priv->maxpayload[nodeid]	= maxpayload;
	priv->sspd[nodeid]		= sspd;
	priv->fifo[nodeid]		= fifo;
	priv->eui[nodeid]		= eui;

	priv->maxpayload[ALL_NODES] = min(priv->maxpayload[ALL_NODES], maxpayload);
	priv->sspd[ALL_NODES] = min(priv->sspd[ALL_NODES], sspd);

	return;
}
 
 static int eth1394_write(void *host, int srcid, int destid,
			   quadlet_t *data, u64 addr, size_t len, u16 flags)
{
	return -1;
}
 
 
 /* Function for incoming 1394 packets */
static struct hpsb_address_ops eth1394_op = {
	.write =	eth1394_write,
};

static struct hpsb_highlevel eth1394_highlevel;
	

static void eth1394_reset_priv (struct rtnet_device *dev, int set_mtu)
{
	unsigned long flags;
	int i;
	struct eth1394_priv *priv = (struct eth1394_priv *)dev->priv;
	void *host = priv->host;
	int phy_id = get_nodeid(host);
	u64 guid = get_guid(host);
	u16 maxpayload = get_maxpayload(host);

	rtos_spin_lock_irqsave (&priv->lock, flags);
	/* Clear the speed/payload/offset tables */
	memset (priv->maxpayload, 0, sizeof (priv->maxpayload));
	memset (priv->sspd, 0, sizeof (priv->sspd));
	memset (priv->fifo, 0, sizeof (priv->fifo));

	priv->sspd[ALL_NODES] = ETH1394_SPEED_DEF;
	priv->maxpayload[ALL_NODES] = eth1394_speedto_maxpayload[priv->sspd[ALL_NODES]];

	priv->bc_state = ETHER1394_BC_CHECK;

	/* Register our limits now */
	eth1394_register_limits(phy_id, maxpayload,
				  get_sspd(host,phy_id, phy_id),
				  guid, ETHER1394_REGION_ADDR, priv);

	/* We'll use our maxpayload as the default mtu */
	if (set_mtu) {
		dev->mtu = min(ETH1394_DATA_LEN, (int)(priv->maxpayload[phy_id] -
			       (sizeof(union eth1394_hdr) + ETHER1394_GASP_OVERHEAD)));

		/* Set our hardware address while we're at it */
		*(u64*)dev->dev_addr = guid;
		*(u64*)dev->broadcast = ~0x0ULL;
	}

	rtos_spin_unlock_irqrestore (&priv->lock, flags);

	for (i = 0; i < ALL_NODES; i++) {
		struct list_head *lh, *n;

		rtos_spin_lock_irqsave(&priv->pdg[i].lock, flags);
		if (!set_mtu) {
			list_for_each_safe(lh, n, &priv->pdg[i].list) {
				//~ purge_partial_datagram(lh);
			}
		}
		INIT_LIST_HEAD(&(priv->pdg[i].list));
		priv->pdg[i].sz = 0;
		rtos_spin_unlock_irqrestore(&priv->pdg[i].lock, flags);
	}
}


static int eth1394_add_host (void *host)
{
	int i, retval;
	struct host_info *hi = NULL;
	
	//*******RTnet********
	struct rtnet_device *dev = NULL;
	//
	struct eth1394_priv *priv;

	/* We should really have our own alloc_hpsbdev() function in
	 * net_init.c instead of calling the one for ethernet then hijacking
	 * it for ourselves.  That way we'd be a real networking device. */
	
	//******RTnet******
	
	dev = rt_alloc_etherdev(sizeof (struct eth1394_priv));
	if (dev == NULL) {
		ETH1394_PRINT_G (KERN_ERR, "Out of memory trying to allocate "
				 "etherdevice for IEEE 1394 device\n");
		retval=-ENOMEM;     
		goto free_dev;
        }
	rtdev_alloc_name(dev, "rteth%d");
	memset(dev->priv, 0, sizeof(struct eth1394_priv));
	rt_rtdev_connect(dev, &RTDEV_manager);
	RTNET_SET_MODULE_OWNER(dev);
	
	//dev->init = eth1394_init_dev;

	dev->vers = RTDEV_VERS_2_0;
	//~ dev->open = eth1394_open;
	//~ dev->hard_start_xmit = eth1394_tx;
	//~ dev->stop = eth1394_stop;
	//~ dev->hard_header = eth1394_header;
	dev->flags		= IFF_BROADCAST | IFF_MULTICAST;
	dev->addr_len		= ETH1394_ALEN;
	dev->hard_header_len 	= ETH1394_HLEN;
	dev->type		= ARPHRD_IEEE1394;
	
	//rtdev->do_ioctl = NULL;
	priv = (struct eth1394_priv *)dev->priv;
	
	//the pool maynot be needed
	if (rtskb_pool_init(&priv->skb_pool, RX_RING_SIZE*2) < RX_RING_SIZE*2) {
    		retval=-ENOMEM;
    		goto free_pool;

	}
	
	rtos_spin_lock_init(&priv->lock);
	priv->host = host;

	for (i = 0; i < ALL_NODES; i++) {
                rtos_spin_lock_init(&priv->pdg[i].lock);
		INIT_LIST_HEAD(&priv->pdg[i].list);
		priv->pdg[i].sz = 0;
	}
  
	hi = hpsb_create_hostinfo(&eth1394_highlevel, host, sizeof(*hi));
	if (hi == NULL) {
		ETH1394_PRINT_G (KERN_ERR, "Out of memory trying to create "
				 "hostinfo for IEEE 1394 device\n");
		retval=-ENOMEM;
		goto free_hi;
        }
        
	retval=rt_register_rtnetdev(dev);
	
	if(retval) 
	{
		ETH1394_PRINT (KERN_ERR, dev->name, "Error registering network driver\n");
    		goto free_hi;
	}

	ETH1394_PRINT (KERN_ERR, dev->name, "IEEE-1394 IPv4 over 1394 Ethernet\n");

 	hi->host = host;
	hi->dev = dev;
	
	eth1394_reset_priv (dev, 1);
	/* Ignore validity in hopes that it will be set in the future.  It'll
	 * be checked when the eth device is opened. */
	priv->broadcast_channel = get_bcchannel(host);

	//~ priv->iso = hpsb_iso_recv_init(host, 16 * 4096, 16, priv->broadcast_channel,
				       //~ 1, eth1394_iso);
	if (priv->iso == NULL) {
		priv->bc_state = ETHER1394_BC_CLOSED;
	}
	
	hpsb_register_addrspace(&eth1394_highlevel, host, &eth1394_op, ETHER1394_REGION_ADDR,
				 ETHER1394_REGION_ADDR_END);
	
	return 0;

free_hi:
	hpsb_destroy_hostinfo(&eth1394_highlevel, host);  
free_pool:
	rtskb_pool_release(&priv->skb_pool);
free_dev:
	rtdev_free(dev);

	return retval;
}

static void eth1394_remove_host (void *host)
{
	struct host_info *hi = hpsb_get_hostinfo(&eth1394_highlevel, host);

	if (hi != NULL) {
		struct eth1394_priv *priv = (struct eth1394_priv *)hi->dev->priv;

		//~ eth1394_iso_shutdown(priv);

		if (hi->dev) {
			rtskb_pool_release(&priv->skb_pool);
			rt_stack_disconnect(hi->dev);
			rt_unregister_rtnetdev (hi->dev);
			rtdev_free(hi->dev);
		}
	}
	return;
}

static void eth1394_host_reset (void *host)
{
	struct host_info *hi = hpsb_get_hostinfo(&eth1394_highlevel, host);
	struct rtnet_device *dev;

	/* This can happen for hosts that we don't use */
	if (hi == NULL)
		return;

	dev = hi->dev;

	/* Reset our private host data, but not our mtu */
	rtnetif_stop_queue (dev);
	eth1394_reset_priv (dev, 0);
	rtnetif_wake_queue (dev);
}


/* Ieee1394 highlevel driver functions */
static struct hpsb_highlevel eth1394_highlevel = {
	.name =		driver_name,
	.add_host =	eth1394_add_host,
	.remove_host =	eth1394_remove_host,
	.host_reset =	eth1394_host_reset,
};
 
 
 static int eth1394_init(void)
 {
	hpsb_register_highlevel(&eth1394_highlevel);
	 
	return 0;	
 }
 
 static void eth1394_exit(void)
 {
	hpsb_unregister_highlevel(&eth1394_highlevel);
 }

 module_init(eth1394_init);
 module_exit(eth1394_exit);

 MODULE_LICENSE("GPL");

  