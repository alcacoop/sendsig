/*
 *
 * Module: sendsig
 * Description: A small hack to kill crazy real time processes
 *
 * Copyright 2010, Alca Società Cooperativa
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/init.h>
#include <asm/siginfo.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <asm/cputime.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>


/* ACTIONS ON USER INPUT*/
#define NOACT_PID 0
#define ADD_PID 1
#define REMOVE_PID 2

static struct dentry *file;

struct sendsig_struct {
  pid_t pid;
  struct task_struct *task;
  struct timer_list timer;
  cputime_t last_cputime;
  ushort count;
  unsigned long secs;
  struct list_head list;
};


static ssize_t count_digits(unsigned long);
static void my_thread_group_cputime(struct task_struct *, struct task_cputime *);
static ushort thread_group_cpu_share(struct sendsig_struct *);
static struct task_struct *get_check_task(pid_t );
static void signal_send(struct task_struct *);
static void timer_function(unsigned long);
static ssize_t register_pid(pid_t);
static struct sendsig_struct * get_check_by_pid(pid_t);
static void release_check(struct sendsig_struct *);
static void free_sendsig_resources(void);
static bool remove_pid(pid_t);
static ushort get_sendsig_action(char *);


static inline ssize_t count_digits(unsigned long num)
{
  ssize_t len = 1;
  unsigned long n = num;

  while (n /= 10)
    len++;

  return len;
}

static inline ushort get_sendsig_action(char *sign) 
{
  ushort action = NOACT_PID;

  if (*sign == '+')
    action = ADD_PID;
  else if(*sign == '-')
    action = REMOVE_PID;

  return action;
}
