#ifndef _RTNET_PORT_H_
#define _RTNET_PORT_H_

#include "../rtmac_mgr.h"

static inline void rtnetif_start_queue(struct rtnet_device *rtdev)
{
	clear_bit(__LINK_STATE_XOFF, &rtdev->dev->state);
}

static inline void rtnetif_wake_queue(struct rtnet_device *rtdev)
{
	if (test_and_clear_bit(__LINK_STATE_XOFF, &rtdev->dev->state)) {
		struct rtnet_msg msg = {
			.msg_type = WAKEUP,
			.rtdev    = rtdev
		};
		rt_mbx_send_if(&(rt_wakeup_manager.mbx), &msg, sizeof (struct rtnet_msg));
	}
}

static inline void rtnetif_stop_queue(struct rtnet_device *rtdev)
{
	set_bit(__LINK_STATE_XOFF, &rtdev->dev->state);
}

static inline int rtnetif_queue_stopped(struct rtnet_device *rtdev)
{
	return test_bit(__LINK_STATE_XOFF, &rtdev->dev->state);
}

static inline int rtnetif_running(struct rtnet_device *rtdev)
{
	return test_bit(__LINK_STATE_START, &rtdev->dev->state);
}

#endif
