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
#include <tracefs.h>

// see docs.kernel.org/trace/kprobetrace.html for probe point formatting
#define SYSTEM NULL
#define EVENT "getnameprobe"
#define ADDR "getname"
#define FORMAT "+0(+0($retval)):string"

// Instance constants
#define INST_NAME "opensnoop"

/**
 * Verify that all required events are avaiable for use.
 *
 * Returns:
 *	an integer indicating success (0) or failure.
 */
int ensure_events_exist()
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

	s = 0;
	while (systems[s]) {
		e = 0;
		events = tracefs_system_events(NULL, systems[s]);
		if (events) {
			while (events[e]) {
				// check if event exists
				printf("%s: %s\n", systems[s], events[e]);
				e++;
			}
		}
		tracefs_list_free(events);
		s++;
	}

	// clean up
	tracefs_list_free(systems);
	return EXIT_SUCCESS;
}

int main(int argc, char const *argv[])
{
	struct tracefs_dynevent *kprobe_event;
	struct tracefs_instance *inst;
	int events_exist;

	events_exist = ensure_events_exist();
	if (!events_exist) {
		// ERROR
	} 

	// create kprobe -> avaiable in instances
	kprobe_event = tracefs_kprobe_alloc(SYSTEM, EVENT,
				ADDR, FORMAT);
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

