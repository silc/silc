<?php

// directories where SILC documents are located
$DocRoot = "/home/www/silcnet.org/d/";
$HTMLRoot = $DocRoot;

// remove dangerous characters, only alphanumerical characters are passed
$SecurityFilter = $HTMLRoot.EReg_Replace('([^a-zA-Z0-9_.])*','',$page);

?>

<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
 <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-a" />
 <meta http-equiv="Content-Language" content="en" />
 <meta name="description" content="SILC Secure Internet Live Conferencing" />
 <meta name="keywords" content="SILC, secure, chat, protocol, cipher, encrypt, SKE" />
 <meta content="INDEX, FOLLOW" name="ROBOTS" />
 <style type="text/css">
  <!--
  body { color: #000000; background: #bbbbbb; font-family: Helvetica, Arial, Sans-serif; }
  a:link { text-decoration: none; color: #2f486f; }
  a:visited { text-decoration: none;color: #2f486f; }
  a:active { text-decoration: none; color: #2f486f; }
  -->
 </style>

 <title> SILC Secure Internet Live Conferencing - 
<?php

if (Is_Readable($SecurityFilter.".php"))
  echo $page;
else
  echo "news";

?>
 </title>

</head>

<body bgcolor="#aaaaaa" text="#000000" link="#2f486f" alink="#2f486f" vlink="#2f486f">

<br />
<div align="center">
<table width="800" bgcolor="#000000" cellpadding="1" cellspacing="0" border="0">
 <tr>
  <td>
    <table width="100%" bgcolor="#ffffff" cellpadding="0" cellspacing="0" border="0">
     <tr>
      <td bgcolor="#e2e2e2">
        <br /><a href="index.php?page=news"><img src="img/silc.gif" width="700" height="100" alt=" SILC Secure Internet Live Conferencing " border="0" /></a>
      </td>
     </tr>
     <tr><td bgcolor="#000000" height="1"></td></tr>
     <tr>
      <td>
        <table width="100%" bgcolor="#e2e2e2" cellpadding="10" cellspacing="0" border="0">
        <tr><td><font face="Helvetica,Arial,Sans-serif">
<?php
// read document, if it is not valid then read opening page
if (Is_Readable($SecurityFilter))
  require $SecurityFilter;
else
  require $HTMLRoot."news.php";
?>
           </font>
          </td>
         </tr>
        </table>
      </td>
     </tr>
    </table>
  </td>
 </tr>
</table>
</font>
</div>

</body>
</html>
