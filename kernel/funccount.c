/**
 * @file funccount.c
 * @author Stevie Alvarez (steviea@google.com)
 * @brief Counts the number of times a kernel function is called.
 * @version 0.1
 * @date 2023-06-01
 * 
 * @copyright Copyright (c) 2023
 * 
 */


#include <tracefs.h>
#include <stdlib.h>
#include <stdio.h>

#define NAME "funccount_traceinst"
#define F_PROFILE_E "function_profile_enabled"


void test_tracing_dir(void)
{
  const char *dir = tracefs_tracing_dir();
  char **systems = tracefs_event_systems(dir);

  int num_sys = tracefs_list_size(systems);
  for (int i = 0; i < num_sys; i++) {
    printf("%s\n", systems[i]);
  }
}

/**
 * @brief Counts the number of times a specified kernel function is called.
 * 
 * @param argc Argument count
 * @param argv Argument list
 * @return int Success code
 */
int main(int argc, char const *argv[])
{
  struct tracefs_instance *inst;
  int check;

  // options?

  inst = tracefs_instance_create(NULL);
  if (!inst) {
    printf("unable to create tracefs instance %s", NAME);
    return EXIT_FAILURE;
  }

  char *f = tracefs_instance_get_file(inst, F_PROFILE_E);
  bool exists = tracefs_file_exists(inst, f);
  printf("%d %s", exists, f);

  test_tracing_dir();


  // turn function_profile_enabled off and back on
  // char *f_profile_e_loc = tracefs_instance_get_file(inst, F_PROFILE_E);
  // check = tracefs_instance_file_write(inst, f_profile_e_loc, "0");
  // check = tracefs_instance_file_write(inst, f_profile_e_loc, "1");
  // for each trace_stat/function*
    // skip header
    // for each function call entry
      // if it matches provided pattern, update count

  // <regex.h> to verify which entries you want


  tracefs_instance_free(inst);
  

  /*check = tracefs_instance_destroy(inst);
  if (!check) {
    printf("unable to destroy tracefs instance %s", NAME);
    return EXIT_FAILURE;
  }
  */

  return EXIT_SUCCESS;
}
