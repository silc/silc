/****f* Robodoc/RB_Panic [2.0d]
 * NAME
 *   RB_Panic -- Shout panic, free resources, and shut down.
 * SYNOPSIS
 *   RB_Panic (cause, add_info)
 *   RB_Panic (char *, char *)
 * FUNCTION
 *   Prints an error message.
 *   Frees all resources used by robodoc.
 *   Terminates program.
 * INPUTS
 *   cause    - pointer to a string which describes the
 *              cause of the error.
 *   add_info - pointer to a string with additional information.
 * SEE ALSO
 *   RB_Close_The_Shop ()
 * SOURCE
 */

  void RB_Panic (char *cause, char *add_info)
  {
    printf ("Robodoc: Error, %s\n",cause) ;
    printf ("         %s\n", add_info) ;
    printf ("Robodoc: Panic Fatal error, closing down...\n") ;
    RB_Close_The_Shop () ; /* Free All Resources */
    exit(100) ;
  }

/*******/
