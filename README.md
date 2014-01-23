S E N D S I G
=============


I N T R O D U C T I O N
-----------------------

This module, maybe, is stupid. It does an easy task in a very
complicated fashion.  But it seems to work.

The need for such a module arises from a problem with a real time
process; it sometimes reaches a share of cpu of 100% and no userspace
strategy has shown to be useful in killing it automagically.

So the idea: writing a kernel module that, given a pid, is able to
send a signal to it if a specific condition on the share of cpu used
by the process is met.

The sendsig module will check every WAIT_TIMEOUT seconds if the
process you want to monitor has a share of cpu greater than or equal
to MAX_CPU_SHARE. If the process is in this situation for MAX_CHECK
consecutive checks, sendsig will send a SIG_TO_SEND signal to
it. Additionally, these parameters could be tuned up to fit everyone
needs by setting them in the command line of the module, eg:

insmod sendsig max_cpu_share=60 wait_timeout=5 max_checks=5 sig_to_send=9

See "modinfo sendsig" for more details.

C O M P I L I N G
-----------------

* cd sendsig
* make
* make install (as root)


U S A G E
---------

* Load the module as you prefer
* echo PID_YOU_WANT_TO_CHECK > DEBUGFS_MOUNTPOINT/sendsig
* pray
