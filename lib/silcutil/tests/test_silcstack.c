/* SilcStack tests */

#include "silc.h"

#define NUM_ALLS 300

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcStack stack, child, child2;
  void *ptr, *ptr2;
  int i;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_quick(TRUE);
    silc_log_set_debug_string("*stack*");
  }

  SILC_LOG_DEBUG(("Allocating stack of default size (1024 bytes)"));
  stack = silc_stack_alloc(0, NULL);
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
  stack = silc_stack_alloc(0, NULL);
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

  SILC_LOG_DEBUG(("Creating child stack"));
  child = silc_stack_alloc(8192, stack);
  if (!child)
    goto err;
  SILC_LOG_DEBUG(("Pushing %d times", NUM_ALLS / 2));
  for (i = 0; i < NUM_ALLS / 2; i++) {
    if (!silc_stack_push(child, NULL))
      goto err;
    ptr2 = silc_smalloc(child, (i + 1) * 7);
    if (!ptr2)
      goto err;
  }
  silc_stack_stats(child);
  SILC_LOG_DEBUG(("Popping %d times", NUM_ALLS / 2));
  for (i = 0; i < NUM_ALLS / 2; i++)
    silc_stack_pop(child);
  silc_stack_stats(child);

  SILC_LOG_DEBUG(("Pushing and reallocating %d times", NUM_ALLS / 10));
  ptr2 = NULL;
  if (!silc_stack_push(child, NULL))
    goto err;
  for (i = 0; i < NUM_ALLS / 10; i++) {
    ptr2 = silc_srealloc(child, (i * 7), ptr2, (i + 1) * 7);
    if (!ptr2)
      goto err;
  }
  ptr = silc_smalloc(child, 100000);
  silc_stack_stats(child);
  silc_stack_pop(child);
  SILC_LOG_DEBUG(("Popping"));
  silc_stack_stats(child);
  silc_stack_stats(stack);
  silc_stack_free(child);
  silc_stack_stats(stack);

  SILC_LOG_DEBUG(("Creating child stack"));
  child = silc_stack_alloc(8192, stack);
  if (!child)
    goto err;
  SILC_LOG_DEBUG(("Pushing %d times", NUM_ALLS / 10));
  for (i = 0; i < NUM_ALLS / 10; i++) {
    if (!silc_stack_push(child, NULL))
      goto err;
    ptr2 = silc_smalloc(child, (i + 1) * 7);
    if (!ptr2)
      goto err;
  }
  silc_stack_stats(child);
  SILC_LOG_DEBUG(("Popping %d times", NUM_ALLS / 10));
  for (i = 0; i < NUM_ALLS / 10; i++)
    silc_stack_pop(child);
  silc_stack_stats(child);

  SILC_LOG_DEBUG(("Pushing and reallocating %d times", NUM_ALLS / 10));
  ptr2 = NULL;
  if (!silc_stack_push(child, NULL))
    goto err;
  for (i = 0; i < NUM_ALLS / 10; i++) {
    ptr2 = silc_srealloc(child, (i * 7), ptr2, (i + 1) * 7);
    if (!ptr2)
      goto err;
  }
  SILC_LOG_DEBUG(("Allocate child from child"));
  child2 = silc_stack_alloc(0, child);
  ptr = silc_smalloc(child2, 500000);
  silc_stack_stats(child2);
  silc_stack_free(child2);
  silc_stack_stats(child);
  silc_stack_pop(child);
  SILC_LOG_DEBUG(("Popping"));
  silc_stack_stats(child);
  silc_stack_stats(stack);
  silc_stack_free(child);
  silc_stack_stats(stack);

  SILC_LOG_DEBUG(("Current alignment: %d", silc_stack_get_alignment(stack)));
  SILC_LOG_DEBUG(("Set alignemtn to 16"));
  silc_stack_set_alignment(stack, 16);
  SILC_LOG_DEBUG(("Current alignment: %d", silc_stack_get_alignment(stack)));
  SILC_LOG_DEBUG(("Allocate 1 byte"));
  ptr = silc_smalloc(stack, 1);
  SILC_LOG_DEBUG(("Allocate 1 byte, check alignment"));
  ptr2 = silc_smalloc(stack, 1);
  if (ptr2 - ptr < 16) {
    SILC_LOG_DEBUG(("Bad alignment"));
    goto err;
  }
  SILC_LOG_DEBUG(("Alignment (ptr, ptr2) is %d", ptr2 - ptr));
  SILC_LOG_DEBUG(("Allocate 1 byte, check alignment"));
  ptr2 = silc_smalloc(stack, 1);
  if (ptr2 - ptr < 32) {
    SILC_LOG_DEBUG(("Bad alignment"));
    goto err;
  }
  SILC_LOG_DEBUG(("Alignment (ptr, ptr2) is %d", ptr2 - ptr));

  SILC_LOG_DEBUG(("Freeing the stack"));
  silc_stack_free(stack);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
