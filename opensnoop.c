/**
 * @file opensnoop.c
 * @author Stevie Alvarez (steviea@google.com)
 * @brief Trace files accessed by open() syscalls via kprobes.
 * @version 0.1
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
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
#define K_FILENAME_FIELD "arg1"
#define K_PID_FIELD "common_pid"

// Instance definitions
#define INST_NAME "opensnoop"
#define ERR_ON 1
#define EVENT_READ_WAIT 1
#define PID_SPACING -7
#define PID_HEADER "PID"
#define F_HEADER "FILE"

extern int errno;
struct tracefs_instance *inst = NULL;
static bool iter_events = true;

/**
 * Print error message and system error message.
 */
static void print_err(const char *loc, char *msg)
{
	if (errno) {
	perror(loc);
	}
	fprintf(stderr, "(errno %d) %s\n", errno, msg);
}

/**
 * Enable event under the provided instance.
 */
static bool enable_event(void *inst, char *system, char *event)
{
	int check;

	check = tracefs_event_enable(inst, system, event);
	if (check) {
		perror("Enable Event");
		fprintf(stderr, "(errno %d) events/%s/%s does not exist",
				errno, system, event);
	}
	return check;
}

/**
 * Ensures necessary events exist and are the only events enabled.
 */
static bool enable_necessary_events(void *inst)
{
	int check, kprobe_e;

	// disable all events and attempt to enable necessary events
	check = tracefs_event_disable(inst, NULL, NULL);
	if (check) {
		print_err("Initial Disable Events",
				"unable to disable events to clean "
				"environment");
		return EXIT_FAILURE;
	}
	
	kprobe_e = enable_event(inst, K_EVENT_SYS, K_EVENT);
	return kprobe_e;
}

/**
 * Destroy and free tracefs instance.
 * Returns 0 on success.
 */
static int cleanup_instance(void *inst)
{
	int events_check;

	events_check = tracefs_instance_destroy(inst);
	tracefs_instance_free(inst);
	if (events_check) {
		print_err("Instance Clean Up", "unable to destroy " INST_NAME
				" tracefs instance");
	}

	inst = NULL;
	return events_check;
}

/**
 * Destroy and free kprobe dynamic event.
 * Returns 0 on success.
 */
static int cleanup_kprobe(void *kprobe_event)
{
	int events_check;

	events_check = tracefs_dynevent_destroy(kprobe_event,
			FORCE_DESTROY_KPROBE);
	tracefs_dynevent_free(kprobe_event);
	if (events_check) {
		print_err(K_EVENT " kprobe Clean Up", "unable to destroy "
				K_ADDR " kprobe dynamic event");
	}

	kprobe_event = NULL;
	return events_check;
}

/**
 * Clean up tracefs instance and kprobe event.
 * Returns 0 on success.
 */
static int cleanup(void *inst, void *kprobe_event)
{
	int inst_failure = cleanup_instance(inst);
	int kprobe_failure = cleanup_kprobe(kprobe_event);
	return (inst_failure || kprobe_failure);
}

/**
 * Clear the trace buffer and turn the trace on.
 * Returns 0 on success.
 */
static int turn_trace_on(void *inst)
{
	int check;

	check = tracefs_trace_off(inst);
	if (check) {
		print_err("Turn Tracing Off", 
				"unable to clear the trace buffer before "
				"running");
		return EXIT_FAILURE;
	}

	check = tracefs_trace_on(inst);
	if (check) {
		print_err("Turn Tracing Off", "unable to enable tracing");
	}
	return check;
}

/**
 * Print content stored in a trace_seq* instance.
 * Returns 0 on success.
 */
static int print_seq(void *seq) {
	if (trace_seq_do_printf(seq) < 0) {
		print_err("Print Sequence",
				"unable to print sequence information");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * Halts iteration of raw events. 
 * Created specifically for terminating raw event iteration via SIGINT.
 */
static void stop_iter(int s)
{
	iter_events = false;
	tracefs_iterate_stop(inst);
}

/**
 * Callback function for filename kprobe event.
 * Prints the name of the file that was opened and the PID responsible for
 * opening it. 
 *
 * Returns EXIT_SUCCESS on success and EXIT_FAILURE on errors.
 */
static int callback(struct tep_event *event, struct tep_record *record,
			int cpu, void *data)
{
	struct tep_format_field *field;
	struct trace_seq *seq = data;
	char *filename;
	unsigned long long pid;
	int len, err;

	// ensure non-common filename field exists
	field = tep_find_any_field(event, K_FILENAME_FIELD);
	if (!field) {
		print_err("Validate kprobe",
				"field " K_FILENAME_FIELD " does not exist for "
				K_ADDR " kprobe event");
		return EXIT_FAILURE;
	}
	
	// fetch filename
	filename = tep_get_field_raw(seq, event, K_FILENAME_FIELD, record,
			&len, ERR_ON);
	if (!filename) {
		print_err("Fetch Filename", "invalid filename received");
		return EXIT_FAILURE;
	}
	
	// fetch pid
	err = tep_get_common_field_val(seq, event, K_PID_FIELD, record, &pid,
			ERR_ON);
	if (err) {
		print_seq(seq);
		return EXIT_FAILURE;
	}
	printf("%*lld%s\n", PID_SPACING, pid, filename);

	// print any errors
	if (print_seq(seq)) {
		return EXIT_FAILURE;
	}

	// clean up
	trace_seq_reset(seq);
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
static void read_event_data(void *inst, void *kprobe_event)
{
	struct tep_handle *tep;
	const char *systems[] = {K_EVENT_SYS, NULL};
	struct trace_seq seq;

	tep = tracefs_local_events_system(NULL, systems);
	if (!tep) {
		print_err("Create " K_EVENT_SYS " System TEP", 
				"unable to create tep handle for " 
				K_EVENT_SYS " event system");
		return;
	}
	trace_seq_init(&seq);

	// sig must run tracefs_iterate_stop(inst);
	signal(SIGINT, stop_iter);
	tracefs_follow_event(tep, inst, K_EVENT_SYS, K_EVENT, callback, &seq);
	while (iter_events) {
		tracefs_iterate_raw_events(tep, inst, NULL, 0, callback_blank,
				NULL);
		sleep(EVENT_READ_WAIT);
	}
	signal(SIGINT, SIG_DFL);

	// clean up
	trace_seq_reset(&seq);
	trace_seq_destroy(&seq);
	tep_free(tep);
}

/**
 * Print tracefs error message.
 */
static void print_tracefs_err()
{
	char *output;
	output = tracefs_error_last(inst);
	fprintf(stderr, "tracefs err: %s\n", output);
	free(output);
}

int main(int argc, char const *argv[])
{
	struct tracefs_dynevent *kprobe_event;
	int check;
	char input;

	// create kprobe -> avaiable in instances
	kprobe_event = tracefs_kretprobe_alloc(K_SYSTEM, K_EVENT,
				K_ADDR, K_FORMAT, K_MAX_PROBES);
	if (!kprobe_event) {
		// ERROR creating dynevent descriptor
		print_err(K_EVENT " kretprobe Alloc", "unable to create "
				K_ADDR " kretprobe dynamic event description");
		print_tracefs_err();
		return EXIT_FAILURE;
	}

	// create instance
	inst = tracefs_instance_create(INST_NAME);
	if (!inst) {
		// ERROR
		print_err(INST_NAME " Instance Create", "unable to instantiate "
				INST_NAME " tracsfs instance");
		cleanup_kprobe(kprobe_event);
		return EXIT_FAILURE;
	}

	// check = 0 on success
	check = tracefs_dynevent_create(kprobe_event);
	if (check) {
		// ERROR creating kprobe dynamic event
		print_err(K_ADDR " dynevent Create", "unable to create " K_ADDR
				" kretprobe dynmaic event");
		print_tracefs_err();
		return EXIT_FAILURE;
	}

	// ensure necessary events are the only events enabled
	check = enable_necessary_events(inst);
	if (check) {
		fprintf(stderr, "unable to enable only necessary events\n");
		cleanup(inst, kprobe_event);
		return EXIT_FAILURE;
	} 

	// prompt user to start tracing
	printf("To stop tracing, press CTRL+C\nHit enter when you're ready to start tracing: ");
	scanf("%c", &input);
	printf("\n%*s%s\n", PID_SPACING, PID_HEADER, F_HEADER);

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
		print_err("Turning Trace Off", "unable to disable tracing");
		cleanup(inst, kprobe_event);
		return EXIT_FAILURE;
	}
	check = cleanup(inst, kprobe_event);
	return check;
}

