/**
 * Clean up script for segfaults
 */


#include <stdlib.h>
#include <stdio.h>
#include <tracefs.h>

// kprobe definitions
#define K_SYSTEM NULL
#define K_EVENT_SYS "kprobes"
#define K_EVENT "getnameprobe"
#define K_ADDR "getname"
#define K_FORMAT "+0(+0($retval)):string"
#define K_MAX_PROBES 0
#define FORCE_DESTROY_KPROBE false
#define K_FIELD "arg1"

int main (void)
{
	struct tracefs_dynevent *kprobe_event;
	
	kprobe_event = tracefs_kretprobe_alloc(K_SYSTEM, K_EVENT,
				K_ADDR, K_FORMAT, K_MAX_PROBES);

	tracefs_dynevent_destroy(kprobe_event, FORCE_DESTROY_KPROBE);
	tracefs_dynevent_free(kprobe_event);
}
