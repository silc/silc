<b>Anonymous CVS access</b>
<font size="2">
<p>
Anonymous CVS access is now available to SILC CVS repository. The
repository includes everything related to SILC project; source codes,
documentation and even these web pages. The CVS access is of course public
but it is intended for developers.  After you have checked out the SILC
source tree you should read README.CVS file from the source tree or rest
of this web page.
<p>
Also note that this is the closest to real time development you can get
thus you cannot expect that the source tree would work or even compile.
While it is our intention that the trunk would always at least compile
there might be situations when it will not.

<p><br>

<b>Browsing the Source Tree</b>
<p>
If you want to browse the source tree using web browser before checking
out the tree with CVS use following link:
<p>
<a href="cvs/source/">Web Access to CVS repository
</a>
<p>
Note that this is not real-time access to the CVS repository. It is
updated once a day. If you want real-time access then checkout the CVS
repository.

<p><br>

<b>Howto Checkout The Source Tree</b>
<p>
The repository can be checked out by using anonymous pserver with CVS.
<p>
For those who are using sh/ksh/bash the check out is done as follows:
<p>
<font size="3">
<tt>
export CVSROOT=:pserver:silc@silc.pspt.fi:/storage/silc/CVS
<p>
cvs login<br>
cvs co silc<br>
</tt>
</font>

<p>
For those who are using csh/tcsh the check out is done as follows:
<p>
<font size="3">
<tt>
setenv CVSROOT :pserver:silc@silc.pspt.fi:/storage/silc/CVS
<p>
cvs login<br>
cvs co silc<br>
</tt>
</font>
<p>
If you don't want to set $CVSROOT environment variable you can set the
path to the cvs as command line options:
<p>
<font size="3">
<tt>
cvs -d:pserver:silc@silc.pspt.fi:/storage/silc/CVS login<br>
cvs -d:pserver:silc@silc.pspt.fi:/storage/silc/CVS co silc
</tt>
</font>
<p>
What ever method you decide to use, after you have done cvs login you will
be prompted for password:
<p>
<b>CVS password: </b>silc
<p>
Type the password "silc" and press Enter.
<p>
The actual SILC source tree is checked out using the cvs co silc command,
described above. This command will fetch the source tree and save it into
directory named silc. SILC CVS repository currently does not have any
branches thus this will check out the trunk. The size of the trunk is
currently about 11 MB but will grow in the future.

<p><br>

<b>What SILC Source Tree Includes</b>
<p>
SILC Source tree includes a lot more stuff that appears in public
distribution.  The source tree includes, for example, internal scripts,
configuration files, SILC webpages etc.  These never appear on a public
distribution.
<p>
Following directories currently exist in SILC source tree.
<p>
<font size="3">
<tt>
doc/
<ul>
Includes all the SILC documentation.  Some of the documentation
are generated when distribution is generated.  The automatically
generated files must never be commited to CVS.
</ul>
includes/
<ul>
Includes SILC include files.
</ul>
lib/
<ul>
Includes SILC libraries.  There maybe libraries on the CVS that
does not appear on public distribution.
</ul>
public_html/
<ul>
Includes the official SILC web pages and everything that relates
to them.  This directory never appears on public distribution.
</ul>
silc/
<ul>
Includes SILC client.  There can be some extra files that will
never appear in public distribution, such as, configuration files.
</ul>
silcd/
<ul>
Includes SILC server.  There can be some extra files that will
never appear in public distribution, such as, configuration files.
</ul>
</tt>
</font>

<p><br>

<b>Howto Compile SILC Source Tree</b>
<p>
After checkout from CVS the SILC source tree must be prepared for 
configuration and compilation.  To compile the source tree, give,
<p>
<font size="3">
<tt>
./prepare<br>
./configure --enable-debug<br>
make
</tt>
</font>
<p>

The ./prepare script is included in to the source tree and it never
appears in public distribution.  The script prepares the source tree
by creating configuration scripts and Makefiles.  The prepare must be
run every time you make some changes to configuration scripts (however,
making changes to Makefile.am's does not require running ./prepare).
<p>
As a developer you should read the ./configure script's help by
giving ./configure --help and study all of its different options.  Also,
you should configure the script with --enable-debug option as it
compiles SILC with -g (debugging) option and it enables the 
SILC_LOG_DEBUG* scripts.  Warning is due here:  The debugging produced
by both cilent and server is very heavy, thus it is common to test
the programs as follows:
<p>
<font size="3">
<tt>
./silc -d -f configfile 2&gt;log<br>
./silcd -d -f configfile 2&gt;log
</tt>
</font>

<p><br>

<b>Howto Clean SILC Source Tree</b>
<p>
To entirely clear the source tree to the state after it was checked out
from CVS, give,
<p>
<font size="3">
<tt>
./prepare-clean
</tt>
</font><p>

This calls `make distclean' plus removes automatically generated files
by hand.  It also removes *.log files. However, it will not remove
any other files you might have created.

<p><br>

<b>Makefiles and configuration files</b>
<p>
Developers should never directly write a Makefile.  All Makefiles are
always automatically generated by ./prepare and later by ./configure
scripts.  Instead, developers must write Makefile.am files.  There
are plenty of examples what they should look like.  If you change
Makefile.am during development you don't have to run ./prepare, just
run normal make.
<p>
Configuration files are the files that ./prepare automatically generates
and what will be included into public distribution.  ./prepare creates
for example the ./configure script that is not commited to the CVS.
`configure.in' is the file that developers must edit to change ./configure
script.  After changing one must run  ./prepare.
</font><p>
