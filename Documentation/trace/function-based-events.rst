=====================
Function based events
=====================

.. Copyright 2018 VMware Inc.
..   Author:   Steven Rostedt <srostedt@goodmis.org>
..  License:   The GNU Free Documentation License, Version 1.2
..               (dual licensed under the GPL v2)


Introduction
============

Static events are extremely useful for analyzing the happenings of
inside the Linux kernel. But there are times where events are not
available, either due to not being in control of the kernel, or simply
because a maintainer refuses to have them in their subsystem.

The function tracer is a way trace within a subsystem without trace events.
But it only provides information of when a function was hit and who
called it. Combining trace events with the function tracer allows
for dynamically creating trace events where they do not exist at
function entry. They provide more information than the function
tracer can provide, as they can read the parameters of a function
or simply read an address. This makes it possible to create a
trace point at any function that the function tracer can trace, and
read the parameters of the function.


Usage
=====

Simply writing an ASCII string into a file called "function_events"
in the tracefs file system will create the function based events.
Note, this file is only writable by root.

 # mount -t tracefs nodev /sys/kernel/tracing
 # cd /sys/kernel/tracing
 # echo 'do_IRQ()' > function_events

The above will create a trace event on the do_IRQ function call.
As no parameters were specified, it will not trace anything other
than the function and the parent. This is the minimum function
based event.

 # ls events/functions/do_IRQ
enable  filter  format  hist  id  trigger

Even though the above function based event does not record much more
than the function tracer does, it does become a full fledge event.
This can be used by the histogram infrastructure, and triggers.

 # cat events/functions/do_IRQ/format
name: do_IRQ
ID: 1304
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __parent_ip;	offset:8;	size:8;	signed:0;
	field:unsigned long __ip;	offset:16;	size:8;	signed:0;

print fmt: "%pS->%pS()", REC->__ip, REC->__parent_ip

The above shows that the format is very close to the function trace
except that it displays the parent function followed by the called
function.


Number of arguments
===================

The number of arguments that can be specified is dependent on the
architecture. An architecture may not allow any arguments, or it
may limit to just three or six. If more arguments are used than
supported, it will fail with -EINVAL.

Parameters
==========

Adding parameters creates fields within the events. The format is
as follows:

 # echo EVENT > function_events

 EVENT := <function> '(' ARGS ')'

 Where <function> is any function that the function tracer can trace.

 ARGS := ARG | ARG ',' ARGS | ''

 ARG := TYPE FIELD

 TYPE := ATOM

 ATOM := 'u8' | 'u16' | 'u32' | 'u64' |
         's8' | 's16' | 's32' | 's64' |
         'char' | 'short' | 'int' | 'long' | 'size_t'

 FIELD := <name>

 Where <name> is a unique string starting with an alphabetic character
 and consists only of letters and numbers and underscores.


Simple arguments
================

Looking at kernel code, we can see something like:

 v4.15: net/ipv4/ip_input.c:

int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)

If we are only interested in the first argument (skb):

 # echo 'ip_rcv(u64 skb, u64 dev)' > function_events

 # echo 1 > events/functions/ip_rcv/enable
 # cat trace
     <idle>-0     [003] ..s3  2119.041935: __netif_receive_skb_core->ip_rcv(skb=18446612136982403072, dev=18446612136968273920)
     <idle>-0     [003] ..s3  2119.041944: __netif_receive_skb_core->ip_rcv(skb=18446612136982403072, dev=18446612136968273920)
     <idle>-0     [003] ..s3  2119.288337: __netif_receive_skb_core->ip_rcv(skb=18446612136982403072, dev=18446612136968273920)
     <idle>-0     [003] ..s3  2119.288960: __netif_receive_skb_core->ip_rcv(skb=18446612136982403072, dev=18446612136968273920)
