<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
 <title> SILC Secure Internet Live Conferencing </title>
 <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
 <style TYPE="text/css">
 <!--
  body { color: #000000; background: #aaaaaa; font-family: Helvetica, Arial, Sans-serif; }
  a:link { text-decoration: none; color: #2f486f; }
  a:visited { text-decoration: none;color: #2f486f; }
  a:active { text-decoration: none; color: #2f486f; }
 -->
 </style>
</head>

<body bgcolor="#aaaaaa" text="#000000" link="#2f486f" alink="#2f486f" vlink="#2f486f">

<br>
<div align="center">
<table width="700" bgcolor="#000000" cellpadding="1" cellspacing="0" border="0">
 <tr>
  <td>
    <table width="100%" bgcolor="#ffffff" cellpadding="0" cellspacing="0" border="0">
     <tr>
      <td bgcolor="#e2e2e2">
        <br><a href="index.php?page=news"><img src="img/silc.gif" width="700" height="100" alt=" SILC Secure Internet Live Conferencing " border="0"></a>
      </td>
     </tr>
     <tr><td bgcolor="#000000" height="1"><img src="img/pixel.gif" alt="" height="1"></td></tr>
     <tr>
      <td>
        <div align="center">
        <table cellspacing="3" cellpadding="10" border="0"><tr><td>
        <font size="2" face="Helvetica,Arial,Sans-serif">
        o <a href="index.php?page=about">About the SILC</a><br>
        o <a href="index.php?page=history">History</a><br>
        o <a href="index.php?page=lists">SILC Mailing Lists</a><br>
        o <a href="index.php?page=docs">SILC Documentation</a><br>
        </font>
        </td><td>
        <font size="2" face="Helvetica,Arial,Sans-serif">
        o <a href="index.php?page=download">Download SILC</a><br>
        o <a href="index.php?page=faq">The SILC FAQ</a><br>
        o <a href="index.php?page=features">SILC Features</a><br>
        o <a href="changes.txt">ChangeLog</a><br>
        </font>
        </td><td>
        <font size="2" face="Helvetica,Arial,Sans-serif">
        o <a href="index.php?page=todo">TODO list</a><br>
        o <a href="index.php?page=contribute">Contributing</a><br>
        o <a href="index.php?page=cvs">Anonymous CVS Access</a><br>
        o <a href="index.php?page=copying">The General Public License (GPL)</a><br>
        </font>
        </td></tr></table>
        </div>
      </td>
     <tr><td bgcolor="#000000" height="1"><img src="img/pixel.gif" alt="" height="1"></td></tr>
     <tr>
      <td>
        <table width="100%" bgcolor="#e2e2e2" cellpadding="10" cellspacing="0" border="0">
        <tr><td><font face="Helvetica,Arial,Sans-serif">
<?php

// directory where SILC FTP files are located
$FTPRoot = "/home/ftp/pub/silc/";

// directory where SILC HTML documents are located
$DocRoot = "/home/priikone/public_html/silc/";

// remove dangerous characters, only alphanumerical characters are passed
$SecurityFilter = $DocRoot.EReg_Replace('([^a-zA-Z0-9])*','',$page).".php";

// read latest release version
if (File_Exists($DocRoot."LATEST")) {
  $fp = FOpen($DocRoot."LATEST","r");
  $latest = EReg_Replace('([^a-zA-Z0-9.])*','',FGetS($fp,255));
  FClose($fp);
}

function div($a,$b) {
return (int) ($a/$b);
}

$latest_d = filemtime($DocRoot."LATEST"); 
$latest_date = date("l dS of F Y H:i:s", $latest_d);

// read document, if it is not valid then read first page
if (Is_File($SecurityFilter))
  require $SecurityFilter;
else
  require $DocRoot."news.php";

?>
        </font>
        </td></tr>
        </table>
      </td>
     </tr>
    </table>
  </td>
 </tr>
</table>
<font size="1" face="Helvetica,Arial,Sans-serif">webpage by
<a href="mailto:salo at Xtrmntr.org">salo at Xtrmntr.org</a> | 
<b><font color="#2f486f"><? require $DocRoot."counter.php"; ?></font></b> |
<a href="http://validator.w3.org/check/referer">W3C HTML 4.01 compliant</a>
</font>
</div>

</body>
</html>
