&nbsp;<br />
<b><big>Download SILC</big></b>
<br />&nbsp;<br />
The SILC is distributed in three different packages; the SILC Client, the 
SILC Server and the SILC Toolkit. The SILC Client is intended for end 
users, the SILC Server for system administrators and the SILC Toolkit for 
developers.
<br />&nbsp;<br />
Use a <a href="?page=mirrors" class="normal">mirror</a> near you for downloads.
<br />&nbsp;<br />

<b>SILC Client <?php echo $Latest_Client; ?></b>
<br />&nbsp;<br />
The SILC Client package is inteded for end users who need only the SILC 
client. The package includes the new Irssi-SILC client.
<br />&nbsp;<br />
Sources HTTP:
<a href="download/silc-client-<?php echo $Latest_Client; ?>.tar.gz" class="normal">
tar.gz</a> (<?php echo
div(FileSize("download/silc-client-".$Latest_Client.".tar.gz"),1024); ?> kB),
<a href="download/silc-client-<?php echo $Latest_Client; ?>.tar.bz2" class="normal">
tar.bz2</a> (<?php echo
div(FileSize("download/silc-client-".$Latest_Client.".tar.bz2"),1024); ?> kB)
<br />

Sources FTP: <a href="ftp://<?php echo $FTP_Site.$FTP_Root ?>/" 
class="normal">tar.gz and tar.bz2</a>
<br />

Binaries HTTP: 
<a href="download/silc-client-<?php echo $Latest_RPM_Client; ?>.i386.rpm" 
class="normal">RPM</a> (<?php echo 
div(FileSize("download/silc-client-".$Latest_RPM_Client.".i386.rpm"),1024); 
?> kB)
, <a href="download/silc-<?php echo $Latest_Windows_Client; ?>.exe.zip" 
class="normal">Cygwin</a> (<?php 
echo div(FileSize("download/silc-".$Latest_Windows_Client.".exe.zip"),1024); ?> kB)
, <a href="download/SILCclie-<?php echo $Latest_Solaris_Client; ?>-sol8-sparc-local.gz" 
class="normal">Solaris 8/SPARC</a> (<?php
echo div(FileSize("download/SILCclie-".$Latest_Solaris_Client."-sol8-sparc-local.gz"),1024); ?> kB)

<br />

Binaries FTP: <a href="ftp://<?php echo $FTP_Site.$FTP_Root ?>/rpm/" 
class="normal">RPM</a>, <a href="ftp://<?php echo $FTP_Site.$FTP_Root ?>/solaris/" 
class="normal">Solaris 8/SPARC</a>
<br />&nbsp;<br />


<b>SILC Server <?php echo $Latest_Server; ?></b>
<br />&nbsp;<br />
The SILC Server package is intended for system administrators who wants to 
setup their own SILC server or router. The package includes only the 
server and not the client. People who is running SILC servers and are 
interested to get the server linked to the new router on silc.silcnet.org 
contact <a href="mailto:priikone at silcnet.org" class="normal">me</a> now.
<br />&nbsp;<br />
Sources HTTP:
<a href="download/silc-server-<?php echo $Latest_Server; ?>.tar.gz" class="normal">
tar.gz</a> (<?php echo
div(FileSize("download/silc-server-".$Latest_Server.".tar.gz"),1024); ?> kB),
<a href="download/silc-server-<?php echo $Latest_Server; ?>.tar.bz2" class="normal">
tar.bz2</a> (<?php echo
div(FileSize("download/silc-server-".$Latest_Server.".tar.bz2"),1024); ?> kB)
<br />
Sources FTP: <a href="ftp://<?php echo $FTP_Site.$FTP_Root ?>/" class="normal">tar.gz and tar.bz2</a>
<br />&nbsp;<br />

<b>SILC Toolkit <?php echo $Latest_Toolkit; ?></b>
<br />&nbsp;<br />
The SILC Toolkit package is intended for developers and programmers who 
would like to create their own SILC applications or help in the 
development of the SILC protocol. The Win32 binary package available 
includes the entire Toolkit with sources and compiled DLLs.
<br />&nbsp;<br />
Sources HTTP:
<a href="download/silc-toolkit-<?php echo $Latest_Toolkit; ?>.tar.gz" class="normal">
tar.gz</a> (<?php echo
div(FileSize("download/silc-toolkit-".$Latest_Toolkit.".tar.gz"),1024); ?> kB),
<a href="download/silc-toolkit-<?php echo $Latest_Toolkit; ?>.tar.bz2" class="normal">
tar.bz2</a> (<?php echo
div(FileSize("download/silc-toolkit-".$Latest_Toolkit.".tar.bz2"),1024); ?> kB)
<br />
Sources FTP: <a href="ftp://<?php echo $FTP_Site.$FTP_Root ?>/" class="normal">tar.gz and tar.bz2</a>
<br />
Binaries HTTP:<a href="download/silc-toolkit-<?php echo $Latest_Toolkit_Win32 ?>.zip" class="normal">
Win32</a> (<?php echo
div(FileSize("download/silc-toolkit-".$Latest_Toolkit_Win32.".zip"),1024); ?> kB)
<br />&nbsp;<br />

<b>CVS Snapshots</b>
<br />&nbsp;<br />
Daily CVS snapshots are available. These are generated 22:00 GMT every
night.  Read the <a href="?page=cvs" class="normal">CVS page</a> for more
information.
<br />&nbsp;<br />
HTTP: <a href="download/silc.tar.gz" class="normal">CVS Snapshot</a>
<br />&nbsp;<br />
<b>Portability</b>
<br />&nbsp;<br />
The SILC has been reported to work on, at least:
<br />&nbsp;<br />
&nbsp;- <a href="http://www.linux.org/" class="normal">GNU/Linux</a><br />
&nbsp;- <a href="http://www.freebsd.org/" class="normal">FreeBSD</a><br />
&nbsp;- <a href="http://www.netbsd.org/" class="normal">NetBSD</a><br />
&nbsp;- <a href="http://www.openbsd.org/" class="normal">OpenBSD</a><br />
&nbsp;- <a href="http://www.hp.com/products1/unix/operating/" class="normal">HP-UX</a><br />
&nbsp;- <a href="http://www.sun.com/software/solaris/" class="normal">Solaris</a><br />
&nbsp;- <a href="http://www.sgi.com/developers/technology/irix.html" class="normal">IRIX</a><br />
&nbsp;- <a href="http://www.microsoft.com/windows/" class="normal">Windows</a><br />
&nbsp;- <a href="http://sources.redhat.com/cygwin/" class="normal">Cygwin</a> &amp; <a href="http://www.mingw.org/" class="normal">MinGW</a>
