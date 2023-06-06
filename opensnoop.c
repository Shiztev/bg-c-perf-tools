/**
 * @file opensnoop.c
 * @author Stevie Alvarez (steviea@google.com)
 * @brief Trace open() syscalls and the respective file.
 * @version 0.1
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <stdlib.h>
#include <string.h>
#include <tracefs.h>

// see docs.kernel.org/trace/kprobetrace.html for probe point formatting
// kprobe definitions
#define KPROBE_SYS "kprobes"
#define K_SYSTEM NULL
#define K_EVENT "getnameprobe"
#define K_ADDR "getname"
#define K_FORMAT "+0(+0($retval)):string"

// event definitions
#define EVENT_SYS "syscalls"
#define OPENAT "sys_exit_openat"
#define OPEN "sys_exit_open"

// Instance constants
#define INST_NAME "opensnoop"

/**
 * Verify that all required events are avaiable for use.
 *
 * Returns:
 *	a boolean indicating success (0) or failure.
 */
bool ensure_events_exist(void)
{
	char **systems; 
	char **events;
	int s, e;
	bool open_exists, openat_exists, getnameprobe_exists;

	open_exists = false;
	openat_exists = false;
	getnameprobe_exists = false;

	systems = tracefs_event_systems(NULL);
	if (!systems) {
		// ERROR
	}

	s = -1;
	while (systems[++s]) {
		events = tracefs_system_events(NULL, systems[s]);
		if (!events) {
			continue;
		}

		e = -1;
		if (!strcmp(systems[s], K_SYSTEM)) {
			// check for K_EVENT
			// TODO: refactor
			while (events[++e]) {
				if (!strcmp(events[e], K_EVENT)) {
					getnameprobe_exists = true;
				}
			}
		} else if (!strcmp(systems[s], EVENT_SYS)) {
			// check for OPEN or OPENAT
			while (events[++e]) {
				if (!strcmp(events[e], OPEN)) {
					open_exists = true;
				} else if (!strcmp(events[e], OPENAT)) {
					openat_exists = true;
				}
			}
		}
		tracefs_list_free(events);
	}
	tracefs_list_free(systems);

	return !(getnameprobe_exists && open_exists && openat_exists);
}

int main(int argc, char const *argv[])
{
	struct tracefs_dynevent *kprobe_event;
	struct tracefs_instance *inst;
	int events_exist;

	events_exist = ensure_events_exist();
	printf("%d\n", events_exist);
	if (!events_exist) {
		// ERROR
	} 

	// create kprobe -> avaiable in instances
	kprobe_event = tracefs_kprobe_alloc(K_SYSTEM, K_EVENT,
				K_ADDR, K_FORMAT);
	if (!kprobe_event) {
		// ERROR
	}

	// create instance
	inst = tracefs_instance_create(INST_NAME);

	// enable events
	// tracefs_event_enable to enable events
	

	// read data

	//struct tep_handle *tep = tep_alloc();
	//if (!tep_handle) {
		// ERROR
	//}



	// clean up
	//tep_free(tep);
	tracefs_instance_destroy(inst);
	tracefs_dynevent_free(kprobe_event);

	return EXIT_SUCCESS;
}

