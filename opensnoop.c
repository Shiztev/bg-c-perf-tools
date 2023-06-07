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
#include <errno.h>
#include <tracefs.h>

// see docs.kernel.org/trace/kprobetrace.html for probe point formatting
// kprobe definitions
#define K_SYSTEM NULL
#define K_EVENT_SYS "kprobes"
#define K_EVENT "getnameprobe"
#define K_ADDR "getname"
#define K_FORMAT "+0(+0($retval)):string"
#define K_MAX_PROBES 0
#define FORCE_DESTROY_KPROBE false

// Event definitions
#define EVENT_SYS "syscalls"
#define OPENAT "sys_exit_openat"
#define OPEN "sys_exit_open"

// Instance definitions
#define INST_NAME "opensnoop"

extern int errno;

bool enable_event(void *inst, char *system, char *event)
{
	int check;
	check = tracefs_event_enable(inst, system, event);
	if (check) {
		perror(NULL);
		fprintf(stderr, "(errno %d) events/%s/%s does not exist\n", errno, system, event);
	}
	return check;
}

/**
 * Ensures necessary events exist and are the only events enabled.
 */
bool enable_necessary_events(void *inst)
{
	int check, kprobe_e, open_e, openat_e;
	// disable all events and attempt to enable necessary events
	check = tracefs_event_disable(inst, NULL, NULL);
	if (check) {
		perror(NULL);
		fprintf(stderr, "(errno %d) unable to disable all events\n", errno);
		return EXIT_FAILURE;
	}

	kprobe_e = enable_event(inst, K_EVENT_SYS, K_EVENT);
	open_e = enable_event(inst, EVENT_SYS, OPEN);
	openat_e = enable_event(inst, EVENT_SYS, OPENAT);
	return (kprobe_e || open_e || openat_e);
}

/**
 * Destroy and free tracefs instance.
 */
int cleanup_instance(void *inst)
{
	int events_check;
	events_check = tracefs_instance_destroy(inst);
	tracefs_instance_free(inst);

	if (events_check) {
		fprintf(stderr, "error: failed to destroy %s tracefs instance", INST_NAME);
	}
	inst = NULL;
	return events_check;
}

/**
 * Destroy and free kprobe dynamic event.
 */
int cleanup_kprobe(void *kprobe_event)
{
	int events_check;
	events_check = tracefs_dynevent_destroy(kprobe_event, FORCE_DESTROY_KPROBE);
	tracefs_dynevent_free(kprobe_event);

	if (events_check) {
		fprintf(stderr, "error: failed to destroy %s kprobe dynamic event", K_ADDR);
	}
	kprobe_event = NULL;
	return events_check;
}

/**
 * Clean up tracefs instance and kprobe event.
 */
int cleanup(void *inst, void *kprobe_event)
{
	int inst_failure = cleanup_instance(inst);
	int kprobe_failure = cleanup_kprobe(kprobe_event);
	return (inst_failure || kprobe_failure);
}

int main(int argc, char const *argv[])
{
	struct tracefs_dynevent *kprobe_event;
	struct tracefs_instance *inst;
	char *output;
	int events_check;
	int return_check;

	// create kprobe -> avaiable in instances
	kprobe_event = tracefs_kretprobe_alloc(K_SYSTEM, K_EVENT,
				K_ADDR, K_FORMAT, K_MAX_PROBES);
	if (!kprobe_event) {
		// ERROR creating dynevent descriptor
		fprintf(stderr, "error: unable to create %s kretprobe dynamic event description\n", K_ADDR);
		return EXIT_FAILURE;
	}


	// create instance
	inst = tracefs_instance_create(INST_NAME);
	if (!inst) {
		// ERROR
		fprintf(stderr, "error: unable to instantiate %s tracsfs instance\n", INST_NAME);
		cleanup_kprobe(kprobe_event);
		return EXIT_FAILURE;
	}

	// events_check = 0 on success
	events_check = tracefs_dynevent_create(kprobe_event);
	if (events_check) {
		// ERROR creating kprobe dynamic event
		output = tracefs_error_last(NULL);
		fprintf(stderr, "error: unable to create %s kretprobe dynmaic event\n%s\b",
				K_ADDR, output);
		cleanup(inst, kprobe_event);
		return EXIT_FAILURE;
	}

	//events_check = ensure_events_exist_enabled(inst);
	events_check = enable_necessary_events(inst);
	if (events_check) {
		// ERROR
		fprintf(stderr, "error: not all required events exist!");
		cleanup(inst, kprobe_event);
		return EXIT_FAILURE;
	} 

	// enable events
	// tracefs_event_enable to enable events
	

	// read data


	// clean up
	return_check = cleanup_instance(inst);
	events_check = cleanup_kprobe(kprobe_event);

	return (return_check || events_check);
}

