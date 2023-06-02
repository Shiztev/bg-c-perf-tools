/**
 * @file pflat.c
 * @author Stevie Alvarez (steviea@google.com)
 * @brief Calculate the latency of page faults.
 * @version 0.1
 * @date 2023-06-02
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <tracefs.h>
#include <event-parse.h>
#include <trace-seq.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define PF_NAME "page_fault_lat"
#define SYNTH_OP "synthetic"

/**
 * @brief Create a synthetic event to measure latency of page faults.
 * 
 * @param tep Tep handle that lies within scope
 * @return struct tracefs_synth* must be freed
 */
struct tracefs_synth *make_event(struct tep_handle *tep)
{
  struct tracefs_synth *synth;

  synth = tracefs_synth_alloc(tep, PF_NAME,
                        NULL, "mmap_lock_start_locking",
                        NULL, "mmap_lock_released",
                        "common_pid", "common_pid",
                        "pid");

  // microsecond time difference
  tracefs_synth_add_compare_field(synth, TRACEFS_TIMESTAMP_USECS,
                          TRACEFS_TIMESTAMP_USECS,
                          TRACEFS_SYNTH_DELTA_END, "delta");
  return synth;
}

static int callback(struct tep_event *event, struct tep_record *record,
                int cpu, void *data)
{
  static struct trace_seq s;

  if (!s.buffer)
    trace_seq_init(&s);
  trace_seq_reset(&s);
  tep_print_event(event->tep, &s, record, "%s\n", TEP_PRINT_INFO);
  trace_seq_do_printf(&s);
  return 0;
}

int main(int argc, char const *argv[])
{
  struct tracefs_synth *synth;
  struct tep_handle *tep;
  int val;
  int seconds;

  // options
  if (!(argc == 2)) {
    fprintf(stderr, "usage: pflat SECONDS\n");
    return EXIT_FAILURE;
  }
  seconds = atoi(argv[1]);

  // set up event handler and synth page fault event
  tep = tracefs_local_events(NULL);
  synth = make_event(tep);
  val = tracefs_synth_create(synth);
  tracefs_fill_local_events(NULL, tep, NULL);

  // enable and trace event
  val = tracefs_follow_event(tep, NULL, SYNTH_OP, PF_NAME, callback, NULL);
  tracefs_event_enable(NULL, SYNTH_OP, PF_NAME);
  sleep(seconds);
  tracefs_event_disable(NULL, SYNTH_OP, PF_NAME);

  tracefs_iterate_raw_events(tep, NULL, NULL, 0, NULL, NULL);


  // clean up
  tep_free(tep);
  tracefs_synth_destroy(synth);
  tracefs_synth_free(synth);
  return EXIT_SUCCESS;
}
