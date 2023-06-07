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
#include <stdio.h>
#include <string.h>
#include <tracefs.h>

// see docs.kernel.org/trace/kprobetrace.html for probe point formatting
// kprobe definitions
#define K_SYSTEM NULL
#define K_EVENT_SYS "kprobes"
#define K_EVENT "getnameprobe"
#define K_ADDR "getname"
#define K_FORMAT "+0(+0($retval)):string"
#define K_MAX_PROBES 0

// Event definitions
#define EVENT_SYS "syscalls"
#define OPENAT "sys_exit_openat"
#define OPEN "sys_exit_open"

// Instance definitions
#define INST_NAME "opensnoop"

/**
 * Verify that all required events are avaiable for use.
 *
 * Returns:
 *	a boolean indicating success (true) or failure.
 */
bool ensure_events_exist()
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
		return EXIT_FAILURE;
	}

	s = 0;
	while (systems[s]) {
		e = 0;
		events = tracefs_system_events(NULL, systems[s]);
		if (events) {
			while (events[e]) {
				// check if event exists
				if (!strcmp(systems[s], K_EVENT_SYS) && !strcmp(events[e], K_EVENT)) {
					getnameprobe_exists = true;
				} else if (!strcmp(systems[s], EVENT_SYS) && !strcmp(events[e], OPEN)) {
					open_exists = true;
				} else if (!strcmp(systems[s], EVENT_SYS) && !strcmp(events[e], OPENAT)) {
					openat_exists = true;
				}
				e++;
			}
		}
		tracefs_list_free(events);
		s++;
	}

	// clean up
	tracefs_list_free(systems);
	return !(open_exists && openat_exists && getnameprobe_exists);
}

int main(int argc, char const *argv[])
{
	struct tracefs_dynevent *kprobe_event;
	struct tracefs_instance *inst;
	char *output;
	int events_dne;

	// create kprobe -> avaiable in instances
	kprobe_event = tracefs_kretprobe_alloc(K_SYSTEM, K_EVENT,
				K_ADDR, K_FORMAT, K_MAX_PROBES);
	if (!kprobe_event) {
		// ERROR creating dynevent descriptor
		fprintf(stderr, "error: unable to create %s kretprobe dynamic event description\n", K_ADDR);
		return EXIT_FAILURE;
	}

	// events_dne = 0 on success
	events_dne = tracefs_dynevent_create(kprobe_event);
	if (events_dne) {
		// ERROR creating kprobe dynamic event
		output = tracefs_error_last(NULL);
		fprintf(stderr, "error: unable to create %s kretprobe dynmaic event\n%s\b",
				K_ADDR, output);
		tracefs_dynevent_free(kprobe_event);
		return EXIT_FAILURE;
	}

	events_dne = ensure_events_exist();
	if (events_dne) {
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

