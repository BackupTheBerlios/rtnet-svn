/***************************************************************************
                          rtos.tasklet_scheduler.c  -  description
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>

//******** RTnet **********
#include <rtnet_port.h>
#include <rtos_tasklet_scheduler.h>
//
static int priority=RTOS_HIGHEST_RT_PRIORITY+RTOS_LOWER_PRIORITY;
static int debug=0;

#define PRINT(fmt, args...); \
if(debug)\
rtos_print(KERN_INFO "rtos_tasklet_scheduler:" fmt,## args);\

#define TASKLETS_NOT_FINISHED 1
#define SCHED_IS_RUNNING 1


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhang Yuchen (y.zhang-4@student.utwente.nl)");
MODULE_PARM(priority,"i");
MODULE_PARM(debug,"i");
MODULE_PARM_DESC(priority,"realtime task priority for rtos_tasklet_scheduler");
MODULE_PARM_DESC(debug,"debug level: 0 nodebug, 1 debug");

static struct rtos_tasklet_scheduler *scheduler;

void rtos_tasklet_schedule(struct tasklet_struct *tasklet)
{
	//to prevent concurrent access from other cpus in SMP system
	rtos_spin_lock(&scheduler->tasklet_queue.lock);
		
	if (!scheduler->tasklet_queue.head)
	{
		scheduler->tasklet_queue.head=tasklet;
		scheduler->tasklet_queue.last=tasklet;
	}
	else{
	scheduler->tasklet_queue.last->next=tasklet;
	scheduler->tasklet_queue.last=tasklet;
	}
	tasklet->next=NULL;
	
	rtos_spin_unlock(&scheduler->tasklet_queue.lock);
}

void rtos_trigger_bh(void)
{
	rtos_event_sem_signal(&scheduler->sem);
}

void do_schedulertask(void)
{
	struct tasklet_struct *tasklet;
	unsigned long flags;

	PRINT("rtos_tasklet_scheduler started!\n");
	do{
    	PRINT("in the loop\n");
    	rtos_event_sem_wait(&scheduler->sem);
		PRINT("semaphore released\n");
		do{
			rtos_spin_lock_irqsave(&scheduler->tasklet_queue.lock, flags);
			/*fetch the tasklet from head of tasklet_queue*/
			tasklet=scheduler->tasklet_queue.head;

			if(tasklet==NULL)
			{
				PRINT("NULL pointer to tasklet!!!\n");
				rtos_spin_unlock_irqrestore(&scheduler->tasklet_queue.lock, flags);
				goto waitforsem;
			}
			
			/*point the head to next tasklet*/
			scheduler->tasklet_queue.head=tasklet->next;
			
			rtos_spin_unlock_irqrestore(&scheduler->tasklet_queue.lock,flags);
			
			/*execute the function of tasklet*/
			tasklet->func(tasklet->data);

			/*if(scheduler->tasklet_queue.head==NULL)
			{
				rtos_print(KERN_INFO "no more tasklet in queue\n");
				break;
			}*/
		}while(TASKLETS_NOT_FINISHED);
waitforsem:	
	}while(SCHED_IS_RUNNING);
}


static int __init rtos_tasklet_scheduler_init(void)
{

	scheduler=kmalloc(sizeof(struct rtos_tasklet_scheduler),GFP_KERNEL);
	if(!scheduler)
	{
		rtos_print("rtos tasklet sheduler allocatoin failed!!!\n");
		return -ENOMEM;
	}

	/*initialize the tasklet queue*/
	scheduler->tasklet_queue.head=NULL;
	scheduler->tasklet_queue.last=NULL;
	rtos_spin_lock_init(&scheduler->tasklet_queue.lock);

	/*initialize the scheduler*/
	rtos_event_sem_init(&scheduler->sem);

	/*start the task*/
	return rtos_task_init(&scheduler->task, do_schedulertask, (int)scheduler,
                          priority);
}

static void __exit rtos_tasklet_scheduler_exit(void)
{
	rtos_task_delete(&scheduler->task);
	rtos_event_sem_delete(&scheduler->sem);
	kfree(scheduler);
}

module_init(rtos_tasklet_scheduler_init);
module_exit(rtos_tasklet_scheduler_exit);

EXPORT_SYMBOL(rtos_tasklet_schedule);
EXPORT_SYMBOL(rtos_trigger_bh);




