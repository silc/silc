/* SilcStack tests */

#include "silc.h"

#define NUM_ALLS 300

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcStack stack;
  void *ptr, *ptr2;
  int i;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_quick(TRUE);
    silc_log_set_debug_string("*stack*");
  }

  SILC_LOG_DEBUG(("Allocating stack of default size (1024 bytes)"));
  stack = silc_stack_alloc(0);
  if (!stack)
    goto err;
  silc_stack_stats(stack);

  SILC_LOG_DEBUG(("Allocating 2048 bytes from stack"));
  ptr = silc_smalloc(stack, 2048);
  if (!ptr)
    goto err;
  silc_stack_stats(stack);

  SILC_LOG_DEBUG(("Freeing the stack"));
  silc_stack_free(stack);

  SILC_LOG_DEBUG(("Allocating stack of default size (1024 bytes)"));
  stack = silc_stack_alloc(0);
  if (!stack)
    goto err;
  silc_stack_stats(stack);

  SILC_LOG_DEBUG(("Pushing and allocating %d times", NUM_ALLS));
  if (!silc_stack_push(stack, NULL))
    goto err;
  for (i = 0; i < NUM_ALLS; i++) {
    ptr2 = silc_smalloc(stack, (i + 1) * 7);
    if (!ptr2)
      goto err;
  }
  silc_stack_stats(stack);
  silc_stack_pop(stack);
  SILC_LOG_DEBUG(("Popping"));
  silc_stack_stats(stack);

  SILC_LOG_DEBUG(("Pushing and allocating %d times", NUM_ALLS));
  if (!silc_stack_push(stack, NULL))
    goto err;
  for (i = 0; i < NUM_ALLS; i++) {
    ptr2 = silc_smalloc(stack, (i + 1) * 7);
    if (!ptr2)
      goto err;
  }
  silc_stack_stats(stack);
  silc_stack_pop(stack);
  SILC_LOG_DEBUG(("Popping"));
  silc_stack_stats(stack);

  SILC_LOG_DEBUG(("Pushing %d times", NUM_ALLS / 2));
  for (i = 0; i < NUM_ALLS / 2; i++) {
    if (!silc_stack_push(stack, NULL))
      goto err;
    ptr2 = silc_smalloc(stack, (i + 1) * 7);
    if (!ptr2)
      goto err;
  }
  silc_stack_stats(stack);
  SILC_LOG_DEBUG(("Popping %d times", NUM_ALLS / 2));
  for (i = 0; i < NUM_ALLS / 2; i++)
    silc_stack_pop(stack);
  silc_stack_stats(stack);

  SILC_LOG_DEBUG(("Pushing and reallocating %d times", NUM_ALLS / 10));
  ptr2 = NULL;
  if (!silc_stack_push(stack, NULL))
    goto err;
  for (i = 0; i < NUM_ALLS / 10; i++) {
    ptr2 = silc_srealloc(stack, (i * 7), ptr2, (i + 1) * 7);
    if (!ptr2)
      goto err;
  }
  silc_stack_stats(stack);
  silc_stack_pop(stack);
  SILC_LOG_DEBUG(("Popping"));
  silc_stack_stats(stack);

  SILC_LOG_DEBUG(("Freeing the stack"));
  silc_stack_free(stack);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
