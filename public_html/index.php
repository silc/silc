<?php
// 
// Copyright (c) 2001, Lubomir Sedlacik <salo@silcnet.org>
// and other members of the SILC Project (http://silcnet.org)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 
// 1) Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2) Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3) Neither the name of the SILC Project nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
// 

// Read neccessary stuff if accessible
  if (@Is_Readable("config.php")) include("config.php");
  if (@Is_Readable("mirror.php")) include("mirror.php");

?>
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
 <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
 <meta http-equiv="Content-Language" content="en" />
 <meta name="description" content="SILC Secure Internet Live Conferencing" />
 <meta name="keywords" content="SILC silcnet secure chat protocol cipher encrypt encryption SKE private channel conferencing" />
 <meta content="INDEX, FOLLOW" name="ROBOTS" />
 <title> SILC Secure Internet Live Conferencing - 
<?php

  // sites
  if ($Country_Code != "")
    $WWW_Site = $Country_Code.".silcnet.org";
  else
    $WWW_Site = "silcnet.org";

  if ($Country_Code != "" && StrToLower($FTP_Archive) == "yes")
    $FTP_Site = "ftp.".$Country_Code.".silcnet.org";
  else
    $FTP_Site = "ftp.silcnet.org";

  if ($Country_Code != "" && StrToLower($CVS_Archive) == "yes"
                          && $CVS_User && $CVS_Root)
    $CVS_Site = "cvs.".$Country_Code.".silcnet.org";
  else {
    $CVS_Site = "cvs.silcnet.org";
    $CVS_User = "cvs";
    $CVS_Root = "/cvs/silc";
  }

  // find out release dates from release archive files
  $Date_Toolkit = date("l dS of F Y H:i:s",
                  filemtime("download/toolkit/sources/silc-toolkit-".$Latest_Toolkit.".tar.gz"));
  $Date_Client  = date("l dS of F Y H:i:s",
                  filemtime("download/client/sources/silc-client-".$Latest_Client.".tar.gz"));
  $Date_Server  = date("l dS of F Y H:i:s",
                  filemtime("download/server/sources/silc-server-".$Latest_Server.".tar.gz"));

  // remove possibly dangerous characters, only alphanumerical characters are passed
  function Filter($input) {
    return EReg_Replace("([^a-zA-Z0-9])*", "", $input);
  }

  // div();
  function div($a,$b) {
    return (int) ($a/$b);
  }

  $pass = 0;
  if (@Is_Readable("html/".Filter($page).".php")) {
    echo $page;
    $pass = 1;
  }
  else
    echo "news";
?>
 </title>
 <link href="silc.css" rel="stylesheet" type="text/css" />
</head>
<body>

<table width="100%" cellpadding="0" cellspacing ="0" border="0">
<tr><td align="center">

<table width="700" cellpadding="1" cellspacing="0" border="0">
 <tr>
  <td class="outline">
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
     <tr>
      <td class="links">
        <img src="img/silc.gif" width="700" height="100" alt=" " />
      </td>
     </tr>
     <tr>
      <td class="links" align="center">
        <table cellspacing="3" cellpadding="10" border="0">
        <tr><td valign="top" class="links">
        <b>General</b><br />
        <small class="normal">o</small> <a href="?page=news" class="normal">SILC News</a><br />
        <small class="normal">o</small> <a href="?page=about" class="normal">About the SILC</a><br />
        <small class="normal">o</small> <a href="?page=history" class="normal">History of SILC</a><br />
        <small class="normal">o</small> <a href="?page=contact" class="normal">Contact Us</a><br />
        <small class="normal">o</small> <a href="?page=lists" class="normal">SILC Mailing Lists</a><br />
        </td><td valign="top" class="links">
        <b>Documentation</b><br />
        <small class="normal">o</small> <a href="?page=docs" class="normal">SILC Documentation</a><br />
        <small class="normal">o</small> <a href="?page=whitepaper" class="normal">SILC White Paper</a><br />
        <small class="normal">o</small> <a href="?page=faq" class="normal">SILC FAQ</a><br />
        <small class="normal">o</small> <a href="?page=features" class="normal">SILC Features</a><br />
        <small class="normal">o</small> <a href="?page=todo" class="normal">TODO List</a><br />
        </td><td valign="top" class="links">
        <b>Software</b><br />
        <small class="normal">o</small> <a href="?page=download" class="normal">Download SILC</a><br />
        <small class="normal">o</small> <a href="?page=mirrors" class="normal">Mirrors Worldwide</a><br />
        <small class="normal">o</small> <a href="?page=cvs" class="normal">Anonymous CVS</a><br />
        <small class="normal">o</small> <a href="txt/changes.txt" class="normal">ChangeLog</a><br />
        <small class="normal">o</small> <a href="?page=copying" class="normal">Licensing</a><br />
        </td><td valign="top" class="links">
        <b>Community</b><br />
        <small class="normal">o</small> <a href="?page=servers" class="normal">Server List</a><br />
        <small class="normal">o</small> <a href="?page=contribute" class="normal">Contributing</a><br />
        <small class="normal">o</small> <a href="?page=help" class="normal">Help</a><br />
        <small class="normal">o</small> <a href="?page=links" class="normal">Links</a><br />
        <small class="normal">o</small> <a href="txt/credits.txt" class="normal">Credits</a><br />
        </td></tr></table>
      </td>
     </tr>
     <tr><td class="line"></td></tr>
     <tr>
      <td class="<?php if($pass == 1 && $page == "whitepaper") $color="whitepaper"; else $color="text"; echo $color; ?>">
        <table width="100%" cellpadding="10" cellspacing="0" border="0">
        <tr><td class="<?php echo $color; ?>">
<?php
  // read document, if it is not valid then read opening page
  if ($pass == 1)
    include("html/".Filter($page).".php");
  else
    include("html/news.php");
?>
          </td>
         </tr>
<?php

  if ($OS_Type) {
    switch(StrToLower($OS_Type)) {
      case "bsd":   $img = "daemon.gif";
                    $alt = "( daemon powered - IMAGE )";
                    break;
      case "linux": $img = "penguin.gif";
                    $alt = "( penguin powered - IMAGE )";
                    break;
      case "sun":   $img = "sun.png";
                    $alt = "( powered by Sun - IMAGE )";
                    break;
    }
    echo "<tr>";
    echo "<td align=\"right\" valign=\"bottom\">";
    echo "&nbsp;<br />";
    echo "<img src=\"img/".$img."\" alt=\"".$alt."\" />";
    echo "</td>";
    echo "</tr>";
  }
?>
        </table>
      </td>
     </tr>
    </table>
  </td>
 </tr>
</table>
<small class="highlight">
webpage by
<a href="mailto:salo at silcnet.org" class="small">salo at silcnet.org</a> | 
<?php
  // insert counter
  include("html/counter.php");
?> | W3C 
<a href="http://validator.w3.org/check/referer" class="small">XHTML</a> and 
<a href="http://jigsaw.w3.org/css-validator/check/referer" class="small">CSS</a>
</small>
<br /><br />

</td></tr></table>

</body>
</html>
