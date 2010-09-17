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

#include "sendsig.h"

#define MOD_AUTHOR "Domenico Delle Side <domenico.delleside@alcacoop.it>"
#define MOD_DESC "Small kernel module to check a process' cpu usage and kill it if too high"

/* safe defaults for the module params */
#define SIG_TO_SEND 9
#define MAX_CPU_SHARE 90
#define WAIT_TIMEOUT 10
#define MAX_CHECKS 6 

static int sig_to_send = SIG_TO_SEND;
static ushort max_cpu_share = MAX_CPU_SHARE;
static ushort wait_timeout = WAIT_TIMEOUT;
static ushort max_checks = MAX_CHECKS;

module_param(sig_to_send, int, 0000);
MODULE_PARM_DESC(sig_to_send, " The signal code you want to send (default: SIGKILL, 9)");
module_param(max_cpu_share, ushort, 0000);
MODULE_PARM_DESC(max_cpu_share, " The maximum cpu share admissible for the process, a value between 0 and 100 (default: 90)");
module_param(wait_timeout, ushort, 0000);
MODULE_PARM_DESC(wait_timeout, " The number of seconds to wait between each check (default: 10)");
module_param(max_checks, ushort, 0000);
MODULE_PARM_DESC(max_checks, " The number of checks after which the signal is sent (default: 6)");


static struct sendsig_struct check_tasks;


/* 
   This function is not exported to modules by the kernel, so let's
   re-define it there. Taken from
   LINUX_SOURCE/kernel/posix-cpu-timers.c. Kudos to its author.
*/

static void my_thread_group_cputime(struct task_struct *tsk, struct task_cputime *times)
{
        struct signal_struct *sig;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
	struct task_struct *t;
	struct sighand_struct *sighand;

	*times = INIT_CPUTIME;

	rcu_read_lock();
	sighand = rcu_dereference(tsk->sighand);
	if (!sighand)
		goto out;

	sig = tsk->signal;

	t = tsk;
	do {
		times->utime = cputime_add(times->utime, t->utime);
		times->stime = cputime_add(times->stime, t->stime);
		times->sum_exec_runtime += t->se.sum_exec_runtime;

		t = next_thread(t);
	} while (t != tsk);

	times->utime = cputime_add(times->utime, sig->utime);
	times->stime = cputime_add(times->stime, sig->stime);
	times->sum_exec_runtime += sig->sum_sched_runtime;
out:
	rcu_read_unlock();
#else
	int i;
	struct task_cputime *tot;

	sig = tsk->signal;
	if (unlikely(!sig) || !sig->cputime.totals) {
		times->utime = tsk->utime;
		times->stime = tsk->stime;
		times->sum_exec_runtime = tsk->se.sum_exec_runtime;
		return;
	}
	times->stime = times->utime = cputime_zero;
	times->sum_exec_runtime = 0;
	for_each_possible_cpu(i) {
		tot = per_cpu_ptr(tsk->signal->cputime.totals, i);
		times->utime = cputime_add(times->utime, tot->utime);
		times->stime = cputime_add(times->stime, tot->stime);
		times->sum_exec_runtime += tot->sum_exec_runtime;
	}
#endif
}


static ushort thread_group_cpu_share(struct sendsig_struct *check) 
{
  struct task_cputime times;
  cputime_t num_load, div_load, total_time;
  ushort share;

  my_thread_group_cputime(check->task, &times);  
  total_time = cputime_add(times.utime, times.stime);
  /*
    last_cputime == 0 means that the timer_function has been called
    for the first time and we have to collect info before doing any
    check.
  */
  if (unlikely(check->last_cputime == 0)) {
    share = 0;
    printk(KERN_INFO "sendsig: timer initialization for pid %d completed\n", check->pid);
  } else {
    /*
      Let's compute the share of cpu usage for the last WAIT_TIMEOUT
      seconds
    */
    num_load = cputime_sub(total_time, check->last_cputime) * 100;
    div_load = jiffies_to_cputime(wait_timeout * HZ);
    share = (ushort)cputime_div(num_load, div_load);
    
    printk(KERN_DEBUG "sendsig: computed cpu share for process %d: %d\n", 
	   check->pid, share);
  }
  /*
    Update last_cputime
  */
  check->last_cputime = total_time;

  return share;
}


/*
 * Given a pid, returns the corresponding struct task_struct defined
 * in kernel space
 */
static struct task_struct *get_check_task(pid_t pid) 
{
  struct task_struct *task;
  struct pid *struct_pid = NULL;
  
  rcu_read_lock();

  struct_pid = find_get_pid(pid);
  task = pid_task(struct_pid, PIDTYPE_PID);

  rcu_read_unlock();

  if(unlikely(task == NULL)){
    printk(KERN_INFO "sendsig: no process with pid %d found\n", pid);
    return NULL;
  }

  return task;
}


/*
 * Setup the necessary things to send a signal to a signal to a
 * process, identified by its task_struct
 */
static void signal_send(struct task_struct *task)
{
    struct siginfo info;

  /*
    initialize the signal structure
  */
  memset(&info, 0, sizeof(struct siginfo));
  info.si_signo = sig_to_send;
  info.si_code = SI_KERNEL;
  /*
    send the signal to the process
  */
  send_sig_info(sig_to_send, &info, task);
}


/*
 * Take the nessary timed actions to check each registerd process and
 * check its status
 */
static void timer_function(unsigned long data)
{ 
  ushort cpu_share; 
  struct sendsig_struct *check = (struct sendsig_struct *)data;
  pid_t pid = check->pid;

  if (unlikely(!pid_alive(check->task))) {
    release_check(check);
    printk(KERN_INFO "sendsig: cannot find pid %d. Is the process still active? Timer removed\n", pid);
    return;
  }

  cpu_share = thread_group_cpu_share(check);

  if (cpu_share >= max_cpu_share) {
    check->count++;
    printk(KERN_INFO "sendsig: current cpu share for pid %d over limit of %d (check #%d)\n", 
	   pid, max_cpu_share, check->count);

/* the ratio is: if the process has a cpu share higher than
   max_cpu_share for more than max_checks * wait_timeout seconds, then
   we'll send the signal sig_to_send to it
 */    
    if (check->count >= max_checks) {
      /*
	sending the signal to the process
      */
      signal_send(check->task);
      /*
	remove the timer
      */ 
      release_check(check);
      printk(KERN_INFO "sendsig: sent signal to process %d, timer removed\n", pid);
      return;
    } 
  } else {
    /*
      if the process is being good, let's reset its counter
    */
    check->count = 0;
  }  
  /*
    update the timer
  */
  mod_timer(&check->timer, jiffies + wait_timeout * HZ); 

  return;
}


/* 
 * Given a pid, return NULL if it is not registered in check_tasks,
 * its sendsig_struct otherwise
 */
static struct sendsig_struct * get_check_by_pid(pid_t pid) 
{
  struct sendsig_struct *c, *r;
  r = NULL;

  list_for_each_entry(c, &check_tasks.list, list) {
    if (c->pid == pid)
      r = c;
  }

  return r;
}


/*
 * free all resources associated with a given check task
 */
static void release_check(struct sendsig_struct *check)
{
  del_timer(&(check->timer));
  list_del(&(check->list));
  kfree(check);  
}

/*
 * Release all resources used by the module
 */
static void free_sendsig_resources(void)
{
  struct sendsig_struct *c, *n;

  list_for_each_entry_safe(c, n, &check_tasks.list, list) {
    release_check(c);
  }
}


/*
 * Given a pid, register it in the list of check tasks
 */
static ssize_t register_pid(pid_t pid) 
{
  struct sendsig_struct *sendsig;

  /*
   * Alca Società Cooperativa has been started up by good persons, so
   * we don't want to check two times the same process!
   */
  if(get_check_by_pid(pid) != NULL) {
    printk(KERN_INFO "sendsig: pid %d is already being checked\n", pid);
    return -EBUSY;
  }


  if (unlikely(!(sendsig = kmalloc(sizeof(struct sendsig_struct), GFP_KERNEL)))) {
    printk(KERN_ERR "sendsig: unable to allocate memory\n");
    return -ENOMEM;
  }

  sendsig->pid = pid;
  /*
   * get the task struct to check
   */
  sendsig->task = get_check_task(pid);


  /*
   * don't try to check non-existent processes
   */
  if (unlikely(sendsig->task == NULL)) {
    printk(KERN_INFO "sendsig: can't check non-existent process, exiting\n");
    return -ESRCH;
  }
  /*
   * start time of this pid
   */
  sendsig->secs = get_seconds();
  /*
   * update to zero the value of the last cputime usage
   */
  sendsig->last_cputime = 0;
  /*
   * update to zero the value of the check counter
   */
  sendsig->count = 0;
  /* 
   * install the new timer
   */
  init_timer(&sendsig->timer);
  sendsig->timer.function = timer_function;
  sendsig->timer.expires = jiffies + wait_timeout*HZ;
  sendsig->timer.data = (unsigned long)sendsig;
  add_timer(&sendsig->timer);

  /*
   * add sendsig to the check_tasks linked list 
   */
  list_add(&(sendsig->list), &(check_tasks.list));
  
  printk(KERN_INFO "sendsig: got pid = %d. Checking it every %i seconds, after timer initialization\n", 
	 pid, wait_timeout);

  return 1;
}

/*
 * Remove a pid from the list of check tasks, freing the used
 * resources
 */
static bool remove_pid(pid_t pid) 
{
  struct sendsig_struct *rem;

  if (!(rem = get_check_by_pid(pid))) {
    printk(KERN_INFO "sendsig: unable to find pid %d\n", pid);
    return false;
  }

  release_check(rem);
  printk(KERN_INFO "sendsig: pid %d has been removed\n", pid);
  
  return true;
}


static ssize_t debugfs_on_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
  char mybuf[11];
  ssize_t ret;
  ushort action = NOACT_PID;
  pid_t pid;

  if(unlikely(count > 11))
    return -EINVAL;

  copy_from_user(mybuf, buf, count);
  action = get_sendsig_action(mybuf);

  if (action != NOACT_PID)
    sscanf(&mybuf[1], "%d", &pid);

  switch(action) {

  case ADD_PID:
    if (!(ret = register_pid(pid))) {
      printk(KERN_INFO "Unable to add pid %d\n", pid);
      return ret;
    }
    break;

  case REMOVE_PID:
    if (!(ret = remove_pid(pid))) {
      printk(KERN_INFO "Unable to remove pid %d\n", pid);
      return ret;
    }
    break;

  default:
    printk("sendsig: bad argument\n");
    return -EINVAL;
  }
  
  return count;
}


static ssize_t debugfs_on_read(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos) 
{
  struct sendsig_struct *t;
  char *out, *tmp;
  ssize_t buflen = 1;
  ssize_t ret = 0;
  

  if (list_empty(&(check_tasks.list))) {
    return simple_read_from_buffer(buf, count, ppos, "No pid registered\n", 18);
  } 

    list_for_each_entry(t, &check_tasks.list, list) {
      buflen += count_digits(t->secs)
	+ count_digits((unsigned long)t->count)
	+ count_digits((unsigned long)t->pid)
	+ sizeof(t->task->comm)
	+ 4; /* to take into account 3 spaces and a \n*/
    }

    if (unlikely(!(out = kcalloc(buflen, sizeof(char), GFP_KERNEL)))) {
      printk(KERN_ERR "sendsig: unable to allocate memory\n");
      return -ENOMEM;
    }
    
    tmp = out;

    list_for_each_entry(t, &check_tasks.list, list) {
      sprintf(tmp, "%d %s %lu %d\n", t->pid, t->task->comm,
	      t->secs, t->count);
      tmp += strlen(tmp) + 1;
    }

    ret = simple_read_from_buffer(buf, count, ppos, out, buflen);
    kfree(out);

    return ret;
}


static const struct file_operations sendsig_fops = {
  .read  = debugfs_on_read,
  .write = debugfs_on_write,
  .owner = THIS_MODULE,
};


static int __init sendsig_module_init(void)
{
  INIT_LIST_HEAD(&check_tasks.list);
  if (!(file = debugfs_create_file("sendsig", 0200, NULL, NULL, &sendsig_fops)))
    printk(KERN_ERR "sendsig: unable to create interface file in debugfs\n");
  else
    printk(KERN_INFO "sendsig: module loaded\n");

  return 0;
}


static void __exit sendsig_module_exit(void)
{
  /*
   * freeing all used resources
   */
  if (!list_empty(&(check_tasks.list)))
    free_sendsig_resources();

  debugfs_remove(file);
  printk("sendsig: module unloaded\n");
}


module_init(sendsig_module_init);
module_exit(sendsig_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_DESCRIPTION(MOD_DESC);
