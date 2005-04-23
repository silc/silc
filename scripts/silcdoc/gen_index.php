<?php
/*

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  type values:

	0 = add left index, details and right index
	1 = add left index, details, no right index
	2 = no left index, add details, no right index
*/
?>

<html>
<head>
 <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-a" />
 <meta http-equiv="Content-Language" content="en" />
 <meta name="description" content="SILC Secure Internet Live Conferencing" />
 <meta name="keywords" content="SILC, secure, chat, protocol, cipher, encrypt, SKE" />
 <meta content="INDEX, FOLLOW" name="ROBOTS" />
 <style type="text/css">
  <!--
  body { color: #000000; background: #f0f0f0; font-family: Helvetica, Arial, Sans-serif; }
  a:link { text-decoration: none; color: #2f488f; }
  a:visited { text-decoration: none;color: #2f488f; }
  a:active { text-decoration: none; color: #2f488f; }
  -->
 </style>
</head>

<body topmargin="0" leftmargin="0" marginheight="0" marginwidth="0">

<table border="0" cellspacing="0" cellpadding="6" width="100%">
 <tr valign="top" bgcolor="#dddddd">
  <td><small>Copyright &copy; 2001 - 2005 SILC Project<br />
    <a href="http://silcnet.org">SILC Project Website</a></small></td>
  <td align="right"><small>
   <a href="index.html">SILC Toolkit Reference Manual</a><br />
   <a href="toolkit_index.html">Index</a></small></td>
   </small></td>
 </tr>
</table>
<table border="0" cellspacing="0" cellpadding="0" width="100%">
<tr bgcolor="#444444"><td><img src="space.gif" width="1" height="1"border="0" alt="" ></td></tr>
</table>

<table cellpadding="0" cellspacing="0" border="0">
 <tr valign="top">

  <td width="200" bgcolor="#f0f0f0">
   <img src="space.gif" width="1" height="1" border="0" alt="">
   <table width="100%" cellpadding="2" cellspacing="2" border="0">
    <tr valign="top"><td>
<br />
<small>
<?php
if ($type != 2)
  require "$dest/index.tmpl";
?>
</small>
<br /><br /><br /><br />
    </td></tr>
   </table>
  </td>

  <td bgcolor="#cccccc" background="dot.gif">
   <img src="space.gif" width="1" height="1" border="0" alt=""></td>

  <td width="720" bgcolor="#ffffff">
   <img src="space.gif" width="1" height="1" border="0" alt="">
   <table cellpadding="2" cellspacing="6" width="100%">
    <tr><td valign="top">
<br />
<?php
require "$page";
?>
<br /><br /><br /><br />
    </td></tr>
   </table>
  </td>

  <td bgcolor="#cccccc" background="dot.gif">
   <img src="space.gif" width="1" height="1" border="0" alt=""></td>

  <td width="180" bgcolor="#f0f0f0">
    <img src="space.gif" width="1" height="1" border="0" alt="">
    <table width="100%" cellpadding="4" cellspacing="0">
    <tr valign="top"><td>
<br />
<font face="Helvetica,Arial,Sans-serif" size="1">
<?php
if ($type == 0) {
  /* Get the index for this page */
  $len = strcspn($page, "-");
  $fname = substr($page, 0, $len);
  require "$fname"."-index.tmpl";
}
?>
</font>

<br /><br /><br /><br />
    </td></tr>
    </table>
  </td>
</tr>
</table>

<table border="0" cellspacing="0" cellpadding="0" width="100%">
<tr bgcolor="#444444"><td><img src="space.gif" width="1" height="1"border="0" alt="" ></td></tr>
</table>
<table border="0" cellspacing="0" cellpadding="6" width="100%">
 <tr valign="top" bgcolor="#dddddd">
  <td><small>Copyright &copy; 2001 - 2005 SILC Project<br />
    <a href="http://silcnet.org">SILC Project Website</a></small></td>
  <td align="right"><small>
   <a href="index.html">SILC Toolkit Reference Manual</a><br />
   <a href="toolkit_index.html">Index</a></small></td>
   </small></td>
 </tr>
</table>

</body>
</html>
