/* SilcDir tests */

#include "silc.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcDir dir;
  SilcDirEntry entry;
  SilcDirEntryStat status;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*dir*,*errno*");
  }

  dir = silc_dir_open("/etc/");
  if (!dir)
    goto err;

  printf("%s:\n", silc_dir_name(dir));
  while ((entry = silc_dir_read(dir, &status)))
    printf(
     "%c%c%c%c%c%c%c%c%c%c %3d %4d %4d %8lu %04d-%02d-%02d %02d:%02d %s\n",
	status->mode & SILC_DIR_ENTRY_IFDIR ? 'd' : '-',
	status->mode & SILC_DIR_ENTRY_IRUSR ? 'r' : '-',
	status->mode & SILC_DIR_ENTRY_IWUSR ? 'w' : '-',
	status->mode & SILC_DIR_ENTRY_IXUSR ? 'x' : '-',
	status->mode & SILC_DIR_ENTRY_IRGRP ? 'r' : '-',
	status->mode & SILC_DIR_ENTRY_IWGRP ? 'w' : '-',
	status->mode & SILC_DIR_ENTRY_IXGRP ? 'x' : '-',
	status->mode & SILC_DIR_ENTRY_IROTH ? 'r' : '-',
	status->mode & SILC_DIR_ENTRY_IWOTH ? 'w' : '-',
	status->mode & SILC_DIR_ENTRY_IXOTH ? 'x' : '-',
	status->nlink, status->uid, status->gid, status->size,
	status->last_mod.year, status->last_mod.month, status->last_mod.day,
	status->last_mod.hour, status->last_mod.minute,
	silc_dir_entry_name(entry));

  fflush(stdout);

  silc_dir_close(dir);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
