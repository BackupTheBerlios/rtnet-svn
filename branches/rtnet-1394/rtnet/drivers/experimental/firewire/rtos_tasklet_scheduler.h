/***************************************************************************
                          rtos_tasklet_scheduler.h  -  description
                             -------------------
    begin                : Wed Jan 5 2005
    copyright            : (C) 2005 by Zhang Yuchen
    email                : y.zhang-4@student.utwente.nl
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <rtnet_port.h>
 
struct rtos_tasklet_queue {
	struct tasklet_struct *head;
	struct tasklet_struct *last;
	rtos_spinlock_t lock;
};

struct rtos_tasklet_scheduler {
	rtos_event_sem_t sem;
	struct rtos_tasklet_queue tasklet_queue;
	rtos_task_t task;
};

extern void rtos_tasklet_schedule(struct tasklet_struct *tasklet);

extern void rtos_trigger_bh(void);
