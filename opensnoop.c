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
#include <event-parse.h>
#include <trace-seq.h>

// see docs.kernel.org/trace/kprobetrace.html for probe point formatting
// kprobe definitions
#define K_SYSTEM NULL
#define K_EVENT_SYS "kprobes"
#define K_EVENT "getnameprobe"
#define K_ADDR "getname"
#define K_FORMAT "+0(+0($retval)):string"
#define K_MAX_PROBES 0
#define FORCE_DESTROY_KPROBE false
#define K_FIELD "arg1"

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

/**
 * Halts trace pipe streaming to stdout.
 * Created specifically for terminating trace pipe stream via SIGINT.
 */
void stop(int sig)
{
	tracefs_trace_pipe_stop(inst);
}

/**
 * Read data from trace pipe.
 * 
 * Prerequisite:
 *	Trace must be cleaned and turned on.
 */
ssize_t read_trace_pipe_data(void *inst)
{
	ssize_t pipe_check;
	signal(SIGINT, stop);
	pipe_check = tracefs_trace_pipe_print(inst, PIPE_FLAGS);
	signal(SIGINT, SIG_DFL);

	// TODO: sscanf to parse each line?

	return pipe_check;
}

/**
 * Halts iteration of raw events. 
 * Created specifically for terminating raw event iteration via SIGINT.
 */
static void stop_iter(int s)
{
	tracefs_iterate_stop(inst);
}

static int callback(struct tep_event *event, struct tep_record *record,
			int cpu, void *data)
{
	struct trace_seq seq;
	struct tep_format_field *field;
	char *filename;
	int len;

	if (!seq.buffer) {
		trace_seq_init(&seq);
	}

	field = tep_find_any_field(event, K_FIELD);
	if (!field) {
		fprintf(stderr, "error: field " K_FIELD " does not exist for %s\n",
				event->name);
		return EXIT_FAILURE;
	}
	//tep_print_field_content(&seq, record->data, record->size, field);
	
	filename = tep_get_field_raw(&seq, event, K_FIELD, record, &len, 0);
	printf("%s\n", filename);



	/*
	if (trace_seq_do_printf(&seq) < 0) {
		fprintf(stderr, "error: unable to print seq\n");
		return EXIT_FAILURE;
	}
	*/

	// clean up
	trace_seq_destroy(&seq);
	return EXIT_SUCCESS;
}

/**
 * Callback function for iterating events which doesn't do anything.
 */
static int callback_blank(struct tep_event *event, struct tep_record *record,
			int cpu, void *data)
{
	return EXIT_SUCCESS;
}

/**
 * Iterate over event data.
 *
 * Prerequisite:
 *	Trace must be cleaned and turned on.
 */
void read_event_data(void *inst, void *kprobe_event)
{
	struct tep_handle *tep;
	const char *systems[] = {K_EVENT_SYS, NULL};

	tep = tracefs_local_events_system(NULL, systems);
	if (!tep) {
		fprintf(stderr, "error: unable to create tep handle for " K_EVENT_SYS " event system\n");
		return;
	}

	// sig must run tracefs_iterate_stop(inst);
	signal(SIGINT, stop_iter);
	tracefs_follow_event(tep, inst, K_EVENT_SYS, K_EVENT, callback, NULL);
        tracefs_iterate_raw_events(tep, inst, NULL, 0, callback_blank, NULL);
	signal(SIGINT, SIG_DFL);

	// clean up
	tep_free(tep);
}

int main(int argc, char const *argv[])
{
	struct tracefs_dynevent *kprobe_event;
	char *output;
	int check;
	char input;

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

	// prompt user to start tracing
	printf("To stop tracing, press CTRL+C\nHit enter when you're ready to start tracing: ");
	scanf("%c", &input);
	printf("\n");

	// clean trace and turn it on (optimize with tracefs_trace_on_fd)
	check = turn_trace_on(inst);
	if (check) {
		cleanup(inst, kprobe_event);
		return EXIT_FAILURE;
	}

	// read data
	read_event_data(inst, kprobe_event);

	// clean up
	check = tracefs_trace_off(inst);
	if (check) {
		return clean_failure(inst, kprobe_event,
				"error: unable to disable tracing");
	}
	check = cleanup(inst, kprobe_event);
	return check;
}

