<?php
/*

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

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
if (Is_Readable($page.".html"))
  require $page.".html";
?>

</font>
</td>

<td>
<table bgcolor="#dddddd" cellpadding=2 cellspacing=0 border=0 
width="99%" align=center>
<tr><td>
<font face="Helvetica,Arial,Sans-serif" size="1">

<?php
/* Get the index for this page */
$len = strcspn($page, "_");
$fname = substr($page, 0, $len);
if (Is_Readable($fname."_index.html"))
  require $fname."_index.html";
eit
?>

</font>
</td></tr>
</table>
</td>

</tr>
</table>
</div>
