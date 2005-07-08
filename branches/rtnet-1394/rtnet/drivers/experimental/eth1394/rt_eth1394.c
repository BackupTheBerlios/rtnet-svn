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

struct fragment_info {
	struct list_head list;
	int offset;
	int len;
};

struct partial_datagram {
	struct list_head list;
	u16 dgl;
	u16 dg_size;
	u16 ether_type;
	struct rtskb *skb;
	char *pbuf;
	struct list_head frag_info;
};

 static const u16 eth1394_speedto_maxpayload[] = {
/*     S100, S200, S400, S800, S1600, S3200 */
	512, 1024, 2048, 4096,  4096,  4096
};

static kmem_cache_t *packet_task_cache;

static struct hpsb_highlevel eth1394_highlevel;

/* Use common.lf to determine header len */
static const int hdr_type_len[] = {
	sizeof (struct eth1394_uf_hdr),
	sizeof (struct eth1394_ff_hdr),
	sizeof (struct eth1394_sf_hdr),
	sizeof (struct eth1394_sf_hdr)
};

/* The max_partial_datagrams parameter is the maximum number of fragmented
 * datagrams per node that eth1394 will keep in memory.  Providing an upper
 * bound allows us to limit the amount of memory that partial datagrams
 * consume in the event that some partial datagrams are never completed.  This
 * should probably change to a sysctl item or the like if possible.
 */
MODULE_PARM(max_partial_datagrams, "i");
MODULE_PARM_DESC(max_partial_datagrams,
		 "Maximum number of partially received fragmented datagrams "
		 "(default = 25).");
static int max_partial_datagrams = 25;


static int ether1394_header(struct rtskb *skb, struct rtnet_device *dev,
			    unsigned short type, void *daddr, void *saddr,
			    unsigned len);
static int ether1394_rebuild_header(struct rtskb *skb);
static int ether1394_header_parse(struct rtskb *skb, unsigned char *haddr);
static int ether1394_header_cache(struct neighbour *neigh, struct hh_cache *hh);
static void ether1394_header_cache_update(struct hh_cache *hh,
					  struct rtnet_device *dev,
					  unsigned char * haddr);
static int ether1394_mac_addr(struct rtnet_device *dev, void *p);

static inline void purge_partial_datagram(struct list_head *old);
static int ether1394_tx(struct rtskb *skb, struct rtnet_device *dev);
static void ether1394_iso(struct hpsb_iso *iso);

static int ether1394_do_ioctl(struct rtnet_device *dev, struct ifreq *ifr, int cmd);

static void eth1394_iso_shutdown(struct eth1394_priv *priv)
{
	priv->bc_state = ETHER1394_BC_CLOSED;

	if (priv->iso != NULL) {
		//~ if (!in_interrupt())
			hpsb_iso_shutdown(priv->iso);
		priv->iso = NULL;
	}
}

static int ether1394_init_bc(struct rtnet_device *dev)
{
	struct eth1394_priv *priv = (struct eth1394_priv *)dev->priv;

	/* First time sending?  Need a broadcast channel for ARP and for
	 * listening on */
	if (priv->bc_state == ETHER1394_BC_CHECK) {
		quadlet_t bc;

		/* Get the local copy of the broadcast channel and check its
		 * validity (the IRM should validate it for us) */

		bc = priv->host->csr.broadcast_channel;

		if ((bc & 0xc0000000) != 0xc0000000) {
			/* broadcast channel not validated yet */
			ETH1394_PRINT(KERN_WARNING, dev->name,
				      "Error BROADCAST_CHANNEL register valid "
				      "bit not set, can't send IP traffic\n");

			eth1394_iso_shutdown(priv);

			return -EAGAIN;
		}
		if (priv->broadcast_channel != (bc & 0x3f)) {
			/* This really shouldn't be possible, but just in case
			 * the IEEE 1394 spec changes regarding broadcast
			 * channels in the future. */

			eth1394_iso_shutdown(priv);

			//~ if (in_interrupt())
				//~ return -EAGAIN;

			priv->broadcast_channel = bc & 0x3f;
			ETH1394_PRINT(KERN_INFO, dev->name,
				      "Changing to broadcast channel %d...\n",
				      priv->broadcast_channel);

			priv->iso = hpsb_iso_recv_init(priv->host, 16 * 4096,
						       16, priv->broadcast_channel,
						       1, ether1394_iso);
			if (priv->iso == NULL) {
				ETH1394_PRINT(KERN_ERR, dev->name,
					      "failed to change broadcast "
					      "channel\n");
				return -EAGAIN;
			}
		}
		if (hpsb_iso_recv_start(priv->iso, -1, (1 << 3), -1) < 0) {
			ETH1394_PRINT(KERN_ERR, dev->name,
				      "Could not start data stream reception\n");

			eth1394_iso_shutdown(priv);

			return -EAGAIN;
		}
		priv->bc_state = ETHER1394_BC_OPENED;
	}
    
	return 0;
}

static int ether1394_open (struct rtnet_device *dev)
{
	struct eth1394_priv *priv = (struct eth1394_priv *)dev->priv;
	unsigned long flags;
	int ret;

	/* Something bad happened, don't even try */
	if (priv->bc_state == ETHER1394_BC_CLOSED)
	{
		return -EAGAIN;
	}
	rtos_spin_lock_irqsave(&priv->lock, flags);
	ret = ether1394_init_bc(dev);
	rtos_spin_unlock_irqrestore(&priv->lock, flags);

	if (ret)
		return ret;
	rt_stack_connect(dev,&STACK_manager);
	rtnetif_start_queue (dev);
	return 0;
}

static int ether1394_stop (struct rtnet_device *dev)
{
	rtnetif_stop_queue (dev);
	rt_stack_disconnect(dev);
	return 0;
}

/* Return statistics to the caller */
static struct net_device_stats *ether1394_stats (struct rtnet_device *dev)
{
	return &(((struct eth1394_priv *)dev->priv)->stats);
}

/* this should not happen in real-time context */
static void ether1394_tx_timeout (struct rtnet_device *dev)
{
	//~ ETH1394_PRINT (KERN_ERR, dev->name, "Timeout, resetting host %s\n",
		       //~ ((struct eth1394_priv *)(dev->priv))->host->driver->name);

	//~ highlevel_host_reset (((struct eth1394_priv *)(dev->priv))->host);

	//~ rtnetif_wake_queue (dev);
	return;
}

static int ether1394_change_mtu(struct rtnet_device *dev, int new_mtu)
{
	struct eth1394_priv *priv = (struct eth1394_priv *)dev->priv;
	int phy_id = get_nodeid(priv->host);

	if ((new_mtu < 68) || (new_mtu > min(ETH1394_DATA_LEN, (int)(priv->maxpayload[phy_id] -
					     (sizeof(union eth1394_hdr) + ETHER1394_GASP_OVERHEAD)))))
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}


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
	dev->open = eth1394_open;
	dev->hard_start_xmit = eth1394_tx;
	dev->stop = eth1394_stop;
	dev->hard_header = eth1394_header;
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
	priv->broadcast_channel = ETH1394_BC_CHANNEL;

	//initialize the isoconfig
	priv->isoconfig.data_buf_size = 16 * 4096;
	priv->isoconfig.buf_packets = 16;
	priv->isoconfig.channel = ETH1394_BC_CHANNEL;
	priv->isoconfig.irqinterval = 1;
	priv->isoconfig.callback = eth1394_iso;
	priv->isoconfig.arg = (void *)dev;
	
	retval = hpsb_listen_channel(&eth1394_highlevel,host,&priv->isoconfig);
	if(retval)
	{
		ETH1394_PRINT(KERN_ERR, dev->name, "Error starting broadcast channel\n");
		priv->bc_state = ETHER1394_BC_CLOSED;
		goto unregister_dev;
	}
		
	hpsb_register_addrspace(&eth1394_highlevel, host, &eth1394_op, ETHER1394_REGION_ADDR,
				 ETHER1394_REGION_ADDR_END);
	
	return 0;
	
unregister_dev:
	rt_unregister_rtnetdev(dev);
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

		eth1394_iso_shutdown(priv);

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

/******************************************
 * HW Header net device functions
 ******************************************/
/* These functions have been adapted from net/ethernet/eth.c */


/* Create a fake MAC header for an arbitrary protocol layer.
 * saddr=NULL means use device source address
 * daddr=NULL means leave destination address (eg unresolved arp). */
static int ether1394_header(struct rtskb *skb, struct rtnet_device *dev,
			    unsigned short type, void *daddr, void *saddr,
			    unsigned len)
{
	struct eth1394hdr *eth = (struct eth1394hdr *)rtskb_push(skb, ETH1394_HLEN);

	eth->h_proto = htons(type);

	if (dev->flags & (IFF_LOOPBACK|IFF_NOARP)) 
	{
		memset(eth->h_dest, 0, dev->addr_len);
		return(dev->hard_header_len);
	}

	if (daddr)
	{
		memcpy(eth->h_dest,daddr,dev->addr_len);
		return dev->hard_header_len;
	}
	
	return -dev->hard_header_len;

}


/* Rebuild the faked MAC header. This is called after an ARP
 * (or in future other address resolution) has completed on this
 * rtskb. We now let ARP fill in the other fields.
 *
 * This routine CANNOT use cached dst->neigh!
 * Really, it is used only when dst->neigh is wrong.
 */
static int ether1394_rebuild_header(struct rtskb *skb)
{
	struct eth1394hdr *eth = (struct eth1394hdr *)skb->data;
	struct rtnet_device *dev = skb->rtdev;

	switch (eth->h_proto)
	{
#ifdef CONFIG_INET
	case __constant_htons(ETH_P_IP):
 		return arp_find((unsigned char*)&eth->h_dest, skb);
#endif	
	default:
		rtos_print(KERN_DEBUG
		       "%s: unable to resolve type %X addresses.\n", 
		       dev->name, (int)eth->h_proto);
		break;
	}

	return 0;
}

static int ether1394_header_parse(struct rtskb *skb, unsigned char *haddr)
{
	struct rtnet_device *dev = skb->rtdev;
	memcpy(haddr, dev->dev_addr, ETH1394_ALEN);
	return ETH1394_ALEN;
}


static int ether1394_header_cache(struct neighbour *neigh, struct hh_cache *hh)
{
	unsigned short type = hh->hh_type;
	struct eth1394hdr *eth = (struct eth1394hdr*)(((u8*)hh->hh_data) + 6);
	struct rtnet_device *dev = neigh->dev;

	if (type == __constant_htons(ETH_P_802_3)) {
		return -1;
	}

	eth->h_proto = type;
	memcpy(eth->h_dest, neigh->ha, dev->addr_len);
	
	hh->hh_len = ETH1394_HLEN;
	return 0;
}

/* Called by Address Resolution module to notify changes in address. */
static void ether1394_header_cache_update(struct hh_cache *hh,
					  struct rtnet_device *dev,
					  unsigned char * haddr)
{
	memcpy(((u8*)hh->hh_data) + 6, haddr, dev->addr_len);
}

static int ether1394_mac_addr(struct rtnet_device *dev, void *p)
{
	if (rtnetif_running(dev))
		return -EBUSY;

	/* Not going to allow setting the MAC address, we really need to use
	 * the real one suppliled by the hardware */
	 return -EINVAL;
}
 


/******************************************
 * Datagram reception code
 ******************************************/

/* Copied from net/ethernet/eth.c */
static inline u16 ether1394_type_trans(struct rtskb *skb,
				       struct rtnet_device *dev)
{
	struct eth1394hdr *eth;
	unsigned char *rawp;

	skb->mac.raw = skb->data;
	rtskb_pull (skb, ETH1394_HLEN);
	eth = (struct eth1394hdr*)skb->mac.raw;

	if (*eth->h_dest & 1) {
		if (memcmp(eth->h_dest, dev->broadcast, dev->addr_len)==0)
			skb->pkt_type = PACKET_BROADCAST;
#if 0
		else
			skb->pkt_type = PACKET_MULTICAST;
#endif
	} else {
		if (memcmp(eth->h_dest, dev->dev_addr, dev->addr_len))
			skb->pkt_type = PACKET_OTHERHOST;
        }

	if (ntohs (eth->h_proto) >= 1536)
		return eth->h_proto;

	rawp = skb->data;

        if (*(unsigned short *)rawp == 0xFFFF)
		return htons (ETH_P_802_3);

        return htons (ETH_P_802_2);
}

/* Parse an encapsulated IP1394 header into an ethernet frame packet.
 * We also perform ARP translation here, if need be.  */
static inline u16 ether1394_parse_encap(struct rtskb *skb,
					struct rtnet_device *dev,
					nodeid_t srcid, nodeid_t destid,
					u16 ether_type)
{
	struct eth1394_priv *priv = (struct eth1394_priv *)dev->priv;
	u64 dest_hw;
	unsigned short ret = 0;

	/* Setup our hw addresses. We use these to build the
	 * ethernet header.  */
	if (destid == (LOCAL_BUS | ALL_NODES))
		dest_hw = ~0ULL;  /* broadcast */
	else
		dest_hw = priv->eui[NODEID_TO_NODE(destid)];

	/* If this is an ARP packet, convert it. First, we want to make
	 * use of some of the fields, since they tell us a little bit
	 * about the sending machine.  */
	if (ether_type == __constant_htons (ETH_P_ARP)) {
		unsigned long flags;
		struct eth1394_arp *arp1394 = (struct eth1394_arp*)skb->data;
		struct arphdr *arp = (struct arphdr *)skb->data;
		unsigned char *arp_ptr = (unsigned char *)(arp + 1);
		u64 fifo_addr = (u64)ntohs(arp1394->fifo_hi) << 32 |
			ntohl(arp1394->fifo_lo);
		u8 host_max_rec = (be32_to_cpu(priv->host->csr.rom[2]) >>
				   12) & 0xf;
		u8 max_rec = min(host_max_rec, (u8)(arp1394->max_rec));
		u16 maxpayload = min(eth1394_speedto_maxpayload[arp1394->sspd],
				     (u16)(1 << (max_rec + 1)));


		/* Update our speed/payload/fifo_offset table */
		rtos_spin_lock_irqsave (&priv->lock, flags);
		ether1394_register_limits(NODEID_TO_NODE(srcid), maxpayload,
					  arp1394->sspd, arp1394->s_uniq_id,
					  fifo_addr, priv);
		rtos_spin_unlock_irqrestore (&priv->lock, flags);

		/* Now that we're done with the 1394 specific stuff, we'll
		 * need to alter some of the data.  Believe it or not, all
		 * that needs to be done is sender_IP_address needs to be
		 * moved, the destination hardware address get stuffed
		 * in and the hardware address length set to 8.
		 *
		 * IMPORTANT: The code below overwrites 1394 specific data
		 * needed above data so keep the call to
		 * ether1394_register_limits() before munging the data for the
		 * higher level IP stack. */

		arp->ar_hln = 8;
		arp_ptr += arp->ar_hln;		/* skip over sender unique id */
		*(u32*)arp_ptr = arp1394->sip;	/* move sender IP addr */
		arp_ptr += arp->ar_pln;		/* skip over sender IP addr */

		if (arp->ar_op == 1)
			/* just set ARP req target unique ID to 0 */
			memset(arp_ptr, 0, ETH1394_ALEN);
		else
			memcpy(arp_ptr, dev->dev_addr, ETH1394_ALEN);
	}

	/* Now add the ethernet header. */
	if (dev->hard_header (skb, dev, __constant_ntohs (ether_type),
			      &dest_hw, NULL, skb->len) >= 0)
		ret = ether1394_type_trans(skb, dev);

	return ret;
}

static inline int fragment_overlap(struct list_head *frag_list, int offset, int len)
{
	struct list_head *lh;
	struct fragment_info *fi;

	list_for_each(lh, frag_list) {
		fi = list_entry(lh, struct fragment_info, list);

		if ( ! ((offset > (fi->offset + fi->len - 1)) ||
		       ((offset + len - 1) < fi->offset)))
			return 1;
	}
	return 0;
}

static inline struct list_head *find_partial_datagram(struct list_head *pdgl, int dgl)
{
	struct list_head *lh;
	struct partial_datagram *pd;

	list_for_each(lh, pdgl) {
		pd = list_entry(lh, struct partial_datagram, list);
		if (pd->dgl == dgl)
			return lh;
	}
	return NULL;
}

/* Assumes that new fragment does not overlap any existing fragments */
static inline int new_fragment(struct list_head *frag_info, int offset, int len)
{
	struct list_head *lh;
	struct fragment_info *fi, *fi2, *new;

	list_for_each(lh, frag_info) {
		fi = list_entry(lh, struct fragment_info, list);
		if ((fi->offset + fi->len) == offset) {
			/* The new fragment can be tacked on to the end */
			fi->len += len;
			/* Did the new fragment plug a hole? */
			fi2 = list_entry(lh->next, struct fragment_info, list);
			if ((fi->offset + fi->len) == fi2->offset) {
				/* glue fragments together */
				fi->len += fi2->len;
				list_del(lh->next);
				kfree(fi2);
			}
			return 0;
		} else if ((offset + len) == fi->offset) {
			/* The new fragment can be tacked on to the beginning */
			fi->offset = offset;
			fi->len += len;
			/* Did the new fragment plug a hole? */
			fi2 = list_entry(lh->prev, struct fragment_info, list);
			if ((fi2->offset + fi2->len) == fi->offset) {
				/* glue fragments together */
				fi2->len += fi->len;
				list_del(lh);
				kfree(fi);
			}
			return 0;
		} else if (offset > (fi->offset + fi->len)) {
			break;
		} else if ((offset + len) < fi->offset) {
			lh = lh->prev;
			break;
		}
	}

	new = kmalloc(sizeof(struct fragment_info), GFP_ATOMIC);
	if (!new) 
		return -ENOMEM;

	new->offset = offset;
	new->len = len;

	list_add(&new->list, lh);

	return 0;
}

static inline int new_partial_datagram(struct rtnet_device *dev,
				       struct list_head *pdgl, int dgl,
				       int dg_size, char *frag_buf,
				       int frag_off, int frag_len)
{
	struct partial_datagram *new;
	struct eth1394_priv *priv = (struct eth1394_priv *)dev->priv;

	new = kmalloc(sizeof(struct partial_datagram), GFP_ATOMIC);
	if (!new)
		return -ENOMEM;

	INIT_LIST_HEAD(&new->frag_info);

	if (new_fragment(&new->frag_info, frag_off, frag_len) < 0) {
		kfree(new);
		return -ENOMEM;
	}

	new->dgl = dgl;
	new->dg_size = dg_size;

	new->skb = dev_alloc_rtskb(dg_size + dev->hard_header_len + 15,&priv->skb_pool);
	if (!new->skb) {
		struct fragment_info *fi = list_entry(new->frag_info.next,
						      struct fragment_info,
						      list);
		kfree(fi);
		kfree(new);
		return -ENOMEM;
	}

	rtskb_reserve(new->skb, (dev->hard_header_len + 15) & ~15);
	new->pbuf = rtskb_put(new->skb, dg_size);
	memcpy(new->pbuf + frag_off, frag_buf, frag_len);

	list_add(&new->list, pdgl);

	return 0;
}

static inline int update_partial_datagram(struct list_head *pdgl, struct list_head *lh,
					  char *frag_buf, int frag_off, int frag_len)
{
	struct partial_datagram *pd = list_entry(lh, struct partial_datagram, list);

	if (new_fragment(&pd->frag_info, frag_off, frag_len) < 0) {
		return -ENOMEM;
	}

	memcpy(pd->pbuf + frag_off, frag_buf, frag_len);

	/* Move list entry to beginnig of list so that oldest partial
	 * datagrams percolate to the end of the list */
	list_del(lh);
	list_add(lh, pdgl);

	return 0;
}

static inline void purge_partial_datagram(struct list_head *old)
{
	struct partial_datagram *pd = list_entry(old, struct partial_datagram, list);
	struct list_head *lh, *n;

	list_for_each_safe(lh, n, &pd->frag_info) {
		struct fragment_info *fi = list_entry(lh, struct fragment_info, list);
		list_del(lh);
		kfree(fi);
	}
	list_del(old);
	kfree_rtskb(pd->skb);
	kfree(pd);
}

static inline int is_datagram_complete(struct list_head *lh, int dg_size)
{
	struct partial_datagram *pd = list_entry(lh, struct partial_datagram, list);
	struct fragment_info *fi = list_entry(pd->frag_info.next,
					      struct fragment_info, list);

	return (fi->len == dg_size);
}




/* Packet reception. We convert the IP1394 encapsulation header to an
 * ethernet header, and fill it with some of our other fields. This is
 * an incoming packet from the 1394 bus.  */
static int ether1394_data_handler(struct rtnet_device *dev, int srcid, int destid,
				  char *buf, int len)
{
	struct rtskb *skb;
	unsigned long flags;
	struct eth1394_priv *priv;
	union eth1394_hdr *hdr = (union eth1394_hdr *)buf;
	u16 ether_type = 0;  /* initialized to clear warning */
	int hdr_len;

	priv = (struct eth1394_priv *)dev->priv;

	/* First, did we receive a fragmented or unfragmented datagram? */
	hdr->words.word1 = ntohs(hdr->words.word1);

	hdr_len = hdr_type_len[hdr->common.lf];
	
	if (hdr->common.lf == ETH1394_HDR_LF_UF) {
		//rtos_print("a single datagram has been received\n");
		/* An unfragmented datagram has been received by the ieee1394
		 * bus. Build an skbuff around it so we can pass it to the
		 * high level network layer. */

		skb = dev_alloc_rtskb(len + dev->hard_header_len + 15,&priv->skb_pool);
		if (!skb) {
			HPSB_PRINT (KERN_ERR, "ether1394 rx: low on mem\n");
			priv->stats.rx_dropped++;
			return -1;
		}
		rtskb_reserve(skb, (dev->hard_header_len + 15) & ~15);
		memcpy(rtskb_put(skb, len - hdr_len), buf + hdr_len, len - hdr_len);
		ether_type = hdr->uf.ether_type;
	} else {
		rtos_print("a datagram fragment has been received\n");
		/* A datagram fragment has been received, now the fun begins. */
		struct list_head *pdgl, *lh;
		struct partial_datagram *pd;
		int fg_off;
		int fg_len = len - hdr_len;
		int dg_size;
		int dgl;
		int retval;
		int sid = NODEID_TO_NODE(srcid);
                struct pdg_list *pdg = &(priv->pdg[sid]);

		hdr->words.word3 = ntohs(hdr->words.word3);
		/* The 4th header word is reserved so no need to do ntohs() */

		if (hdr->common.lf == ETH1394_HDR_LF_FF) {
			ether_type = hdr->ff.ether_type;
			dgl = hdr->ff.dgl;
			dg_size = hdr->ff.dg_size + 1;
			fg_off = 0;
		} else {
			hdr->words.word2 = ntohs(hdr->words.word2);
			dgl = hdr->sf.dgl;
			dg_size = hdr->sf.dg_size + 1;
			fg_off = hdr->sf.fg_off;
		}
		rtos_spin_lock_irqsave(&pdg->lock, flags);

		pdgl = &(pdg->list);
		lh = find_partial_datagram(pdgl, dgl);

		if (lh == NULL) {
			if (pdg->sz == max_partial_datagrams) {
				/* remove the oldest */
				purge_partial_datagram(pdgl->prev);
				pdg->sz--;
			}
            
			retval = new_partial_datagram(dev, pdgl, dgl, dg_size,
						      buf + hdr_len, fg_off,
						      fg_len);
			if (retval < 0) {
				rtos_spin_unlock_irqrestore(&pdg->lock, flags);
				goto bad_proto;
			}
			pdg->sz++;
			lh = find_partial_datagram(pdgl, dgl);
		} else {
			struct partial_datagram *pd;

			pd = list_entry(lh, struct partial_datagram, list);

			if (fragment_overlap(&pd->frag_info, fg_off, fg_len)) {
				/* Overlapping fragments, obliterate old
				 * datagram and start new one. */
				purge_partial_datagram(lh);
				retval = new_partial_datagram(dev, pdgl, dgl,
							      dg_size,
							      buf + hdr_len,
							      fg_off, fg_len);
				if (retval < 0) {
					pdg->sz--;
					rtos_spin_unlock_irqrestore(&pdg->lock, flags);
					goto bad_proto;
				}
			} else {
				retval = update_partial_datagram(pdgl, lh,
								 buf + hdr_len,
								 fg_off, fg_len);
				if (retval < 0) {
					/* Couldn't save off fragment anyway
					 * so might as well obliterate the
					 * datagram now. */
					purge_partial_datagram(lh);
					pdg->sz--;
					rtos_spin_unlock_irqrestore(&pdg->lock, flags);
					goto bad_proto;
				}
			} /* fragment overlap */
		} /* new datagram or add to existing one */

		pd = list_entry(lh, struct partial_datagram, list);

		if (hdr->common.lf == ETH1394_HDR_LF_FF) {
			pd->ether_type = ether_type;
		}

		if (is_datagram_complete(lh, dg_size)) {
			ether_type = pd->ether_type;
			pdg->sz--;
			//skb = skb_get(pd->skb);
			skb = pd->skb;
			purge_partial_datagram(lh);
			rtos_spin_unlock_irqrestore(&pdg->lock, flags);
		} else {
			/* Datagram is not complete, we're done for the
			 * moment. */
			rtos_spin_unlock_irqrestore(&pdg->lock, flags);
			return 0;
		}
	} /* unframgented datagram or fragmented one */

	/* Write metadata, and then pass to the receive level */
	skb->rtdev = dev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;	/* don't check it */

	/* Parse the encapsulation header. This actually does the job of
	 * converting to an ethernet frame header, aswell as arp
	 * conversion if needed. ARP conversion is easier in this
	 * direction, since we are using ethernet as our backend.  */
	skb->protocol = ether1394_parse_encap(skb, dev, srcid, destid,
					      ether_type);


	rtos_spin_lock_irqsave(&priv->lock, flags);
	if (!skb->protocol) {
		priv->stats.rx_errors++;
		priv->stats.rx_dropped++;
		//dev_kfree_skb_any(skb);
		kfree_rtskb(skb);
		goto bad_proto;
	}

	/*if (netif_rx(skb) == NET_RX_DROP) {
		priv->stats.rx_errors++;
		priv->stats.rx_dropped++;
		goto bad_proto;
	}*/
	
	rtnetif_rx(skb);

	/* Statistics */
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += skb->len;
	rt_mark_stack_mgr(dev);

bad_proto:
	if (rtnetif_queue_stopped(dev))
		rtnetif_wake_queue(dev);
	rtos_spin_unlock_irqrestore(&priv->lock, flags);

	//dev->last_rx = jiffies;

	return 0;
}


 static int eth1394_write(void *host, int srcid, int destid,
			   quadlet_t *data, u64 addr, size_t len, u16 flags)
{
	struct host_info *hi = hpsb_get_hostinfo(&eth1394_highlevel, host);

	if (hi == NULL) {
		ETH1394_PRINT_G(KERN_ERR, "Could not find net device for host %s\n",
				host->driver->name);
		return RCODE_ADDRESS_ERROR;
	}

	if (ether1394_data_handler(hi->dev, srcid, destid, (char*)data, len))
		return RCODE_ADDRESS_ERROR;
	else
		return RCODE_COMPLETE;
}

static void eth1394_iso(void *dev_opaque, void *iso)
{
	quadlet_t *data;
	char *buf;
	struct rtnet_device *dev = (struct rtnet_device *)dev_opaque;
	unsigned int len;
	u32 specifier_id;
	u16 source_id;
	int i;
	int nready;
	struct hpsb_iso_packet_info *info;

	
	nready = hpsb_iso_n_ready(iso);
	for (i = 0; i < nready; i++) {
		info = get_isopacketinfo(iso,i);
		data = (quadlet_t*) (info->buf);

		/* skip over GASP header */
		buf = (char *)data + 8;
		len = info->len - 8;

		specifier_id = (((be32_to_cpu(data[0]) & 0xffff) << 8) |
				((be32_to_cpu(data[1]) & 0xff000000) >> 24));
		source_id = be32_to_cpu(data[0]) >> 16;

		if (specifier_id != ETHER1394_GASP_SPECIFIER_ID) {
			/* This packet is not for us */
			continue;
		}
		ether1394_data_handler(dev, source_id, LOCAL_BUS | ALL_NODES,
				       buf, len);
	}

	hpsb_iso_recv_release_packets(iso, i);

	//dev->last_rx = jiffies;
}

/******************************************
 * Datagram transmission code
 ******************************************/

/* Convert a standard ARP packet to 1394 ARP. The first 8 bytes (the entire
 * arphdr) is the same format as the ip1394 header, so they overlap.  The rest
 * needs to be munged a bit.  The remainder of the arphdr is formatted based
 * on hwaddr len and ipaddr len.  We know what they'll be, so it's easy to
 * judge.  
 *
 * Now that the EUI is used for the hardware address all we need to do to make
 * this work for 1394 is to insert 2 quadlets that contain max_rec size,
 * speed, and unicast FIFO address information between the sender_unique_id
 * and the IP addresses.
 */
static inline void ether1394_arp_to_1394arp(struct rtskb *skb,
					    struct rtnet_device *dev)
{
	struct eth1394_priv *priv = (struct eth1394_priv *)(dev->priv);
	u16 phy_id = NODEID_TO_NODE(priv->host->node_id);

	struct arphdr *arp = (struct arphdr *)skb->data;
	unsigned char *arp_ptr = (unsigned char *)(arp + 1);
	struct eth1394_arp *arp1394 = (struct eth1394_arp *)skb->data;

	/* Believe it or not, all that need to happen is sender IP get moved
	 * and set hw_addr_len, max_rec, sspd, fifo_hi and fifo_lo.  */
	arp1394->hw_addr_len	= 16;
	arp1394->sip		= *(u32*)(arp_ptr + ETH1394_ALEN);
	arp1394->max_rec	= (be32_to_cpu(priv->host->csr.rom[2]) >> 12) & 0xf;
	arp1394->sspd		= priv->sspd[phy_id];
	arp1394->fifo_hi	= htons (priv->fifo[phy_id] >> 32);
	arp1394->fifo_lo	= htonl (priv->fifo[phy_id] & ~0x0);

	return;
}

/* We need to encapsulate the standard header with our own. We use the
 * ethernet header's proto for our own. */
static inline unsigned int ether1394_encapsulate_prep(unsigned int max_payload,
						      int proto,
						      union eth1394_hdr *hdr,
						      u16 dg_size, u16 dgl)
{ 
	unsigned int adj_max_payload = max_payload - hdr_type_len[ETH1394_HDR_LF_UF];
	//rtos_print("adj_max_payload=%d\n",adj_max_payload);
	//rtos_print("dg_size=%d\n",dg_size);

	/* Does it all fit in one packet? */
	if (dg_size <= adj_max_payload) {
		hdr->uf.lf = ETH1394_HDR_LF_UF;
		hdr->uf.ether_type = proto;
	} else {
		hdr->ff.lf = ETH1394_HDR_LF_FF;
		hdr->ff.ether_type = proto;
		hdr->ff.dg_size = dg_size - 1;
		hdr->ff.dgl = dgl;
		adj_max_payload = max_payload - hdr_type_len[ETH1394_HDR_LF_FF];
	}
	return((dg_size + (adj_max_payload - 1)) / adj_max_payload);
}

static inline unsigned int ether1394_encapsulate(struct rtskb *skb,
						 unsigned int max_payload,
						 union eth1394_hdr *hdr)
{
	union eth1394_hdr *bufhdr;
	int ftype = hdr->common.lf;
	int hdrsz = hdr_type_len[ftype];
	unsigned int adj_max_payload = max_payload - hdrsz;

	switch(ftype) {
	case ETH1394_HDR_LF_UF:
		bufhdr = (union eth1394_hdr *)rtskb_push(skb, hdrsz);
		bufhdr->words.word1 = htons(hdr->words.word1);
		bufhdr->words.word2 = hdr->words.word2;
		break;

	case ETH1394_HDR_LF_FF:
		bufhdr = (union eth1394_hdr *)rtskb_push(skb, hdrsz);
		bufhdr->words.word1 = htons(hdr->words.word1);
		bufhdr->words.word2 = hdr->words.word2;
		bufhdr->words.word3 = htons(hdr->words.word3);
		bufhdr->words.word4 = 0;

		/* Set frag type here for future interior fragments */
		hdr->common.lf = ETH1394_HDR_LF_IF;
		hdr->sf.fg_off = 0;
		break;
		
	default:
		hdr->sf.fg_off += adj_max_payload;
		bufhdr = (union eth1394_hdr *)rtskb_pull(skb, adj_max_payload);
		if (max_payload >= skb->len)
			hdr->common.lf = ETH1394_HDR_LF_LF;
		bufhdr->words.word1 = htons(hdr->words.word1);
		bufhdr->words.word2 = htons(hdr->words.word2);
		bufhdr->words.word3 = htons(hdr->words.word3);
		bufhdr->words.word4 = 0;
	}

	return min(max_payload, skb->len);
}

static inline struct hpsb_packet *ether1394_alloc_common_packet(struct hpsb_host *host)
{
	struct hpsb_packet *p;

	p = alloc_hpsb_packet(0);
	if (p) {
		p->host = host;
		p->data = NULL;
		p->generation = get_hpsb_generation(host);
		p->type = hpsb_async;
	}
	return p;
}

static inline int ether1394_prep_write_packet(struct hpsb_packet *p,
					      struct hpsb_host *host,
					      nodeid_t node, u64 addr,
					      void * data, int tx_len)
{
	p->node_id = node;
	p->data = NULL;

	p->tcode = TCODE_WRITEB;
	p->header[1] = (host->node_id << 16) | (addr >> 32);
	p->header[2] = addr & 0xffffffff;

	p->header_size = 16;
	p->expect_response = 1;

	if (hpsb_get_tlabel(p)) {
		ETH1394_PRINT_G(KERN_ERR, "No more tlabels left while sending "
				"to node " NODE_BUS_FMT "\n", NODE_BUS_ARGS(host, node));
		return -1;
	}		
	p->header[0] = (p->node_id << 16) | (p->tlabel << 10)
		| (1 << 8) | (TCODE_WRITEB << 4);

	p->header[3] = tx_len << 16;
	p->data_size = tx_len + (tx_len % 4 ? 4 - (tx_len % 4) : 0);
	p->data = (quadlet_t*)data;

	return 0;
}

static inline void ether1394_prep_gasp_packet(struct hpsb_packet *p,
					      struct eth1394_priv *priv,
					      struct rtskb *skb, int length)
{
	p->header_size = 4;
	p->tcode = TCODE_STREAM_DATA;

	p->header[0] = (length << 16) | (3 << 14)
		| ((priv->broadcast_channel) << 8)
		| (TCODE_STREAM_DATA << 4);
	p->data_size = length;
	p->data = ((quadlet_t*)skb->data) - 2;
	p->data[0] = cpu_to_be32((priv->host->node_id << 16) |
				      ETHER1394_GASP_SPECIFIER_ID_HI);
	p->data[1] = cpu_to_be32((ETHER1394_GASP_SPECIFIER_ID_LO << 24) |
				      ETHER1394_GASP_VERSION);

	/* Setting the node id to ALL_NODES (not LOCAL_BUS | ALL_NODES)
	 * prevents hpsb_send_packet() from setting the speed to an arbitrary
	 * value based on packet->node_id if packet->node_id is not set. */
	p->node_id = ALL_NODES;
	p->speed_code = priv->sspd[ALL_NODES];
}

static inline void ether1394_free_packet(struct hpsb_packet *packet)
{
	if (packet->tcode != TCODE_STREAM_DATA)
		hpsb_free_tlabel(packet);
	packet->data = NULL;
	free_hpsb_packet(packet);
}

static void ether1394_complete_cb(void *__ptask);

static int ether1394_send_packet(struct packet_task *ptask, unsigned int tx_len)
{
	struct eth1394_priv *priv = ptask->priv;
	struct hpsb_packet *packet = NULL;

	packet = ether1394_alloc_common_packet(priv->host);
	if (!packet)
		return -1;

	if (ptask->tx_type == ETH1394_GASP) {
		int length = tx_len + (2 * sizeof(quadlet_t));

		ether1394_prep_gasp_packet(packet, priv, ptask->skb, length);
	} else if (ether1394_prep_write_packet(packet, priv->host,
					       ptask->dest_node,
					       ptask->addr, ptask->skb->data,
					       tx_len)) {
		free_hpsb_packet(packet);
		return -1;
	}
	
	ptask->packet = packet;
	hpsb_set_packet_complete_task(ptask->packet, ether1394_complete_cb,
				      ptask);

	if (!hpsb_send_packet(packet)) {
		ether1394_free_packet(packet);
		return -1;
	}

	return 0;
}


/* Task function to be run when a datagram transmission is completed */
static inline void ether1394_dg_complete(struct packet_task *ptask, int fail)
{
	struct rtskb *skb = ptask->skb;
	struct rtnet_device *dev = skb->rtdev;
	struct eth1394_priv *priv = (struct eth1394_priv *)dev->priv;
        unsigned long flags;
		
	/* Statistics */
	rtos_spin_lock_irqsave(&priv->lock, flags);
	if (fail) {
		priv->stats.tx_dropped++;
		priv->stats.tx_errors++;
	} else {
		priv->stats.tx_bytes += skb->len;
		priv->stats.tx_packets++;
	}
	rtos_spin_unlock_irqrestore(&priv->lock, flags);

	//dev_kfree_skb_any(skb);
	kfree_rtskb(skb);
	kmem_cache_free(packet_task_cache, ptask);
}


/* Callback for when a packet has been sent and the status of that packet is
 * known */
static void ether1394_complete_cb(void *__ptask)
{
	struct packet_task *ptask = (struct packet_task *)__ptask;
	struct hpsb_packet *packet = ptask->packet;
	int fail = 0;

	if (packet->tcode != TCODE_STREAM_DATA)
		fail = hpsb_packet_success(packet);

	ether1394_free_packet(packet);

	ptask->outstanding_pkts--;
	if (ptask->outstanding_pkts > 0 && !fail)
	{
		int tx_len;

		/* Add the encapsulation header to the fragment */
		tx_len = ether1394_encapsulate(ptask->skb, ptask->max_payload,
					       &ptask->hdr);
		if (ether1394_send_packet(ptask, tx_len))
			ether1394_dg_complete(ptask, 1);
	} else {
		ether1394_dg_complete(ptask, fail);
	}
}



/* Transmit a packet (called by kernel) */
static int ether1394_tx (struct rtskb *skb, struct rtnet_device *dev)
{
	
	//int kmflags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
	int kmflags = GFP_ATOMIC;
	struct eth1394hdr *eth;
	struct eth1394_priv *priv = (struct eth1394_priv *)dev->priv;
	int proto;
	unsigned long flags;
	nodeid_t dest_node;
	eth1394_tx_type tx_type;
	int ret = 0;
	unsigned int tx_len;
	unsigned int max_payload;
	u16 dg_size;
	u16 dgl;
	struct packet_task *ptask;
	struct node_entry *ne;
	
	
	//~ ptask = kmem_cache_alloc(packet_task_cache, kmflags);
	//~ if (ptask == NULL) {
		//~ ret = -ENOMEM;
		//~ goto fail;
	//~ }
	struct list_head *l;
	struct packet_task* ptask,p;
	list_for_each(l, &ptask_list){
		p=list_entry(l, struct packet_task, lh);
		if(p->packet == NULL){
			ptask = p;
			break;
		}
	}
	if(ptask==NULL)
		return -EBUSY;
	
	
	rtos_spin_lock_irqsave (&priv->lock, flags);
	if (priv->bc_state == ETHER1394_BC_CLOSED) {
		ETH1394_PRINT(KERN_ERR, dev->name,
			      "Cannot send packet, no broadcast channel available.\n");
		ret = -EAGAIN;
		rtos_spin_unlock_irqrestore (&priv->lock, flags);
		goto fail;
	}

	if ((ret = ether1394_init_bc(dev))) {
		rtos_spin_unlock_irqrestore (&priv->lock, flags);
		goto fail;
	}


	rtos_spin_unlock_irqrestore (&priv->lock, flags);
	//if ((skb = skb_share_check (skb, kmflags)) == NULL) {
	//	ret = -ENOMEM;
	//	goto fail;
	//}

	/* Get rid of the fake eth1394 header, but save a pointer */
	eth = (struct eth1394hdr*)skb->data;
	rtskb_pull(skb, ETH1394_HLEN);


	ne = hpsb_guid_get_entry(be64_to_cpu(*(u64*)eth->h_dest));
	if (!ne)
		dest_node = LOCAL_BUS | ALL_NODES;
	else
		dest_node = ne->nodeid;

	proto = eth->h_proto;

	/* If this is an ARP packet, convert it */
	if (proto == __constant_htons (ETH_P_ARP))
		ether1394_arp_to_1394arp (skb, dev);

	max_payload = priv->maxpayload[NODEID_TO_NODE(dest_node)];

	/* This check should be unnecessary, but we'll keep it for safety for
	 * a while longer. */
	if (max_payload < 512) {
		ETH1394_PRINT(KERN_WARNING, dev->name,
			      "max_payload too small: %d   (setting to 512)\n",
			      max_payload);
		max_payload = 512;
	}

	/* Set the transmission type for the packet.  ARP packets and IP
	 * broadcast packets are sent via GASP. */
	if (memcmp(eth->h_dest, dev->broadcast, ETH1394_ALEN) == 0 ||
	    proto == __constant_htons(ETH_P_ARP) ||
	    (proto == __constant_htons(ETH_P_IP) &&
	     IN_MULTICAST(__constant_ntohl(skb->nh.iph->daddr)))) {
		tx_type = ETH1394_GASP;
                max_payload -= ETHER1394_GASP_OVERHEAD;
	} else {
		tx_type = ETH1394_WRREQ;
	}

	dg_size = skb->len;

	rtos_spin_lock_irqsave (&priv->lock, flags);
	dgl = priv->dgl[NODEID_TO_NODE(dest_node)];
	if (max_payload < dg_size + hdr_type_len[ETH1394_HDR_LF_UF])
		priv->dgl[NODEID_TO_NODE(dest_node)]++;
	rtos_spin_unlock_irqrestore (&priv->lock, flags);

	ptask->hdr.words.word1 = 0;
	ptask->hdr.words.word2 = 0;
	ptask->hdr.words.word3 = 0;
	ptask->hdr.words.word4 = 0;
	ptask->skb = skb;
	ptask->priv = priv;
	ptask->tx_type = tx_type;

	if (tx_type != ETH1394_GASP) {
		u64 addr;

		/* This test is just temporary until ConfigROM support has
		 * been added to eth1394.  Until then, we need an ARP packet
		 * after a bus reset from the current destination node so that
		 * we can get FIFO information. */
		if (priv->fifo[NODEID_TO_NODE(dest_node)] == 0ULL) {
			ret = -EAGAIN;
			goto fail;
		}

		rtos_spin_lock_irqsave(&priv->lock, flags);
		addr = priv->fifo[NODEID_TO_NODE(dest_node)];
		rtos_spin_unlock_irqrestore(&priv->lock, flags);

		ptask->addr = addr;
		ptask->dest_node = dest_node;
	}

	ptask->tx_type = tx_type;
	ptask->max_payload = max_payload;
	ptask->outstanding_pkts = ether1394_encapsulate_prep(max_payload, proto,
							     &ptask->hdr, dg_size,
							     dgl);

	/* Add the encapsulation header to the fragment */
	tx_len = ether1394_encapsulate(skb, max_payload, &ptask->hdr);
	//dev->trans_start = jiffies;
	if (ether1394_send_packet(ptask, tx_len))
		goto fail;
	
	rtnetif_wake_queue(dev);
	return 0;
fail:
	if (ptask)
		kmem_cache_free(packet_task_cache, ptask);

	if (skb != NULL)
		dev_kfree_rtskb(skb);

	rtos_spin_lock_irqsave (&priv->lock, flags);
	priv->stats.tx_dropped++;
	priv->stats.tx_errors++;
	rtos_spin_unlock_irqrestore (&priv->lock, flags);

	if (rtnetif_queue_stopped(dev))
		rtnetif_wake_queue(dev);

	return 0;  /* returning non-zero causes serious problems */
}

static int ether1394_do_ioctl(struct rtnet_device *dev, struct ifreq *ifr, int cmd)
{
	switch(cmd) {
		case SIOCETHTOOL:
			return ether1394_ethtool_ioctl(dev, (void *) ifr->ifr_data);

		case SIOCGMIIPHY:		/* Get address of MII PHY in use. */
		case SIOCGMIIREG:		/* Read MII PHY register. */
		case SIOCSMIIREG:		/* Write MII PHY register. */
		default:
			return -EOPNOTSUPP;
	}

	return 0;
}

static int ether1394_ethtool_ioctl(struct rtnet_device *dev, void *useraddr)
{
	u32 ethcmd;

	if (get_user(ethcmd, (u32 *)useraddr))
		return -EFAULT;

	switch (ethcmd) {
		case ETHTOOL_GDRVINFO: {
			struct ethtool_drvinfo info = { ETHTOOL_GDRVINFO };
			strcpy (info.driver, driver_name);
			strcpy (info.version, "$Rev: 1043 $");
			/* FIXME XXX provide sane businfo */
			strcpy (info.bus_info, "ieee1394");
			if (copy_to_user (useraddr, &info, sizeof (info)))
				return -EFAULT;
			break;
		}
		case ETHTOOL_GSET:
		case ETHTOOL_SSET:
		case ETHTOOL_NWAY_RST:
		case ETHTOOL_GLINK:
		case ETHTOOL_GMSGLVL:
		case ETHTOOL_SMSGLVL:
		default:
			return -EOPNOTSUPP;
	}

	return 0;
}

 
 
 /* Function for incoming 1394 packets */
static struct hpsb_address_ops eth1394_op = {
	.write =	eth1394_write,
};


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

  