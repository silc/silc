<?php
/*

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  This is the detailed page generator. This generates the actual data
  that is shown plus index at the right side. 

*/
?>

<div align="center">
<table cellpadding=2 cellspacing=0 border=0 width="99%" align=center>
<tr>
<td valign=top>
<font face="Helvetica,Arial,Sans-serif" size="+1">

<?php
/* Get the actual data for the page */
require "$page";
?>

</font>
</td>

<td bgcolor="#dddddd">
<table bgcolor="#dddddd" cellpadding=4 cellspacing=0 border=0 
width="99%" align=center>
<tr><td>
<font face="Helvetica,Arial,Sans-serif" size="1">

<?php
/* Get the index for this page */
$len = strcspn($page, "__");
$fname = substr($page, 0, $len);
require "$fname"."__index.tmpl";
?>

</font>
</td></tr>
</table>
</td>

</tr>
</table>
</div>
