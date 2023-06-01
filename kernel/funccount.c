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

#define NAME "funccount_traceinst"

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

  inst = tracefs_instance_create(NAME);
  if (!inst) {
    // error
  }

  // turn function_profile_enabled off and back on
  // for each trace_stat/function*
    // skip header
    // for each function call entry
      // if it matches provided pattern, update count

  // <regex.h> to verify which entries you want

  check = tracefs_instance_destroy(inst);
  if (!check) {
    // error
  }

  return 0;
}
