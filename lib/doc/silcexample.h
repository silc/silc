/****h* silcexample/SilcExampleAPI
 *
 * DESCRIPTION
 *
 * This is example API providing the examples of how API items may appear
 * in the Toolkit Reference Manual.  This example includes all aspects of
 * a reference, however, note that all API items that appear in the manual
 * may not include all of the information that are presented here.
 *
 ***/

/****d* silcexample/SilcExampleAPI/SilcExampleType
 *
 * NAME
 *
 *    typedef enum { ... } SilcExampleTyle;
 *
 * DESCRIPTION
 *
 *    Example type definition with the actual source code.
 *
 * SOURCE
 */
/* Source code from the actual header file is appended */
typedef enum {
  SILC_EXAMPLE_1,
  SILC_EXAMPLE_2,
  SILC_EXAMPLE_3,
} SilcExampleType;
/***/

/****s* silcexample/SilcExampleAPI/SilcExampleStruct
 *
 * NAME
 *
 *    typedef struct { ... } SilcExampleStruct;
 *
 * DESCRIPTION
 *
 *    Example structure definition.
 *
 ***/

/****f* silcexample/SilcExampleAPI/silc_example_function
 *
 * SYNOPSIS
 *
 *    bool silc_example_function(SilcExampleType type);
 *
 * DESCRIPTION
 *
 *    Description of the silc_example_function.
 *
 * NOTES
 *
 *    There may be additional notes that programmers should be aware of
 *    for this function.
 *
 * EXAMPLE
 *
 *    if (!silc_example_function(SILC_EXAMPLE_1))
 *      SILC_LOG_ERROR(("Error occurred during example function"));
 *
 * SEE ALSO
 *
 *    SilcExampleType, SILC_LOG_ERROR, SilcExampleStruct
 *
 ***/
