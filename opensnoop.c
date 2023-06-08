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
#include <signal.h>
#include <fcntl.h>
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
#define TRACE "trace"
#define PIPE_FLAGS 0 //O_NONBLOCK

extern int errno;
struct tracefs_instance *inst = NULL;

/**
 * Enable indicated event under the provided instance.
 */
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
 * Returns 0 on success.
 */
int cleanup_instance(void *inst)
{
	int events_check;
	events_check = tracefs_instance_destroy(inst);
	tracefs_instance_free(inst);

	if (events_check) {
		fprintf(stderr, "error: failed to destroy " INST_NAME " tracefs instance\n");
	}
	inst = NULL;
	return events_check;
}

/**
 * Destroy and free kprobe dynamic event.
 * Returns 0 on success.
 */
int cleanup_kprobe(void *kprobe_event)
{
	int events_check;
	events_check = tracefs_dynevent_destroy(kprobe_event,
			FORCE_DESTROY_KPROBE);
	tracefs_dynevent_free(kprobe_event);

	if (events_check) {
		fprintf(stderr,"error: failed to destroy " K_ADDR " kprobe dynamic event\n");
	}
	kprobe_event = NULL;
	return events_check;
}

/**
 * Clean up tracefs instance and kprobe event.
 * Returns 0 on success.
 */
int cleanup(void *inst, void *kprobe_event)
{
	int inst_failure = cleanup_instance(inst);
	int kprobe_failure = cleanup_kprobe(kprobe_event);
	return (inst_failure || kprobe_failure);
}

/**
 * Clean up instance, kprobe event, and print an error message.
 * Always returns EXIT_FAILURE.
 */
int clean_failure(void *inst, void *kprobe_event, char *output)
{
	fprintf(stderr, "%s\n", output);
	cleanup(inst, kprobe_event);
	return EXIT_FAILURE;
}

/**
 * Clear the trace buffer and turn the trace on.
 * Returns 0 on success.
 */
int turn_trace_on(void *inst)
{
	int check;

	check = tracefs_trace_off(inst);
	if (check) {
		fprintf(stderr, "error: unable to clear the trace buffer\n");
		return EXIT_FAILURE;
	}

	check = tracefs_trace_on(inst);
	if (check) {
		fprintf(stderr, "error: unable to enable tracing\n");
	}
	return check;
}

void stop(int sig)
{
	tracefs_trace_pipe_stop(inst);
}

ssize_t read_trace_data(void *inst)
{
	ssize_t pipe_check;
	signal(SIGINT, stop);
	pipe_check = tracefs_trace_pipe_print(inst, PIPE_FLAGS);
	signal(SIGINT, SIG_DFL);

	// TODO: sscanf to parse each line?

	return pipe_check;
}

int main(int argc, char const *argv[])
{
	struct tracefs_dynevent *kprobe_event;
	char *output;
	ssize_t pipe_check;
	int check;

	// create kprobe -> avaiable in instances
	kprobe_event = tracefs_kretprobe_alloc(K_SYSTEM, K_EVENT,
				K_ADDR, K_FORMAT, K_MAX_PROBES);
	if (!kprobe_event) {
		// ERROR creating dynevent descriptor
		fprintf(stderr, "error: unable to create " K_ADDR " kretprobe dynamic event description\n");
		return EXIT_FAILURE;
	}

	// create instance
	inst = tracefs_instance_create(INST_NAME);
	if (!inst) {
		// ERROR
		fprintf(stderr, "error: unable to instantiate " INST_NAME " tracsfs instance\n");
		cleanup_kprobe(kprobe_event);
		return EXIT_FAILURE;
	}

	// check = 0 on success
	check = tracefs_dynevent_create(kprobe_event);
	if (check) {
		// ERROR creating kprobe dynamic event
		output = tracefs_error_last(NULL);
		clean_failure(inst, kprobe_event, 
				"error: unable to create " K_ADDR " kretprobe dynmaic event");
		fprintf(stderr, "%s\n", output);
		free(output);
		return EXIT_FAILURE;
	}

	// ensure necessary events are the only events enabled
	check = enable_necessary_events(inst);
	if (check) {
		return clean_failure(inst, kprobe_event,
				"error: unable to enable only necessary events");
	} 

	// TODO: prompt user to start tracing, inform them ctrl+c ends tracing
	scanf("To stop tracing, press CTRL+C\nHit enter when ready to start tracing: %s",
			&output);
	printf("\n");

	// clean trace and turn it on (optimize with tracefs_trace_on_fd)
	check = turn_trace_on(inst);
	if (check) {
		cleanup(inst, kprobe_event);
		return EXIT_FAILURE;
	}

	// read data
	pipe_check = read_trace_data(inst);
	if (pipe_check == -1) {
		fprintf(stderr, "error: error during trace pipe printing\n");
	}

	// clean up
	check = tracefs_trace_off(inst);
	if (check) {
		return clean_failure(inst, kprobe_event,
				"error: unable to disable tracing");
	}
	check = cleanup(inst, kprobe_event);
	return check;
}

