<b>Anonymous CVS access</b>
<font size="2">
<br /><br />
Anonymous CVS access is now available to SILC CVS repository. The
repository includes everything related to SILC project; source codes,
documentation and even these web pages. The CVS access is of course public
but it is intended for developers. After you have checked out the SILC
source tree you should read README.CVS file from the source tree or rest
of this web page.
<br /><br />
Also note that this is the closest to real time development you can get
thus you cannot expect that the source tree would work or even compile.
While it is our intention that the trunk would always at least compile
there might be situations when it will not.

<br /><br />

<b>Browsing the Source Tree</b>
<br /><br />
If you want to browse the source tree using web browser before checking
out the tree with CVS use following link:
<br /><br />
<a href="http://cvs.silcnet.org/">Web Access to CVS repository
</a>
<br /><br />
Note that this is not real-time access to the CVS repository. It is
updated once a day. If you want real-time access then checkout the CVS
repository.

<br /><br />

<b>Howto Checkout The Source Tree</b>
<br /><br />
The repository can be checked out by using anonymous pserver with CVS.
<br /><br />
For those who are using sh/ksh/bashi/zsh the check out is done as follows:
<br /><br />
<font size="3">
<tt>
export CVSROOT=:pserver:cvs@cvs.silcnet.org:/cvs/silc
<br /><br />
cvs login<br />
cvs co silc<br />
cvs logout<br />
</tt>
</font>

<br /><br />
For those who are using csh/tcsh the check out is done as follows:
<br /><br />
<font size="3">
<tt>
setenv CVSROOT :pserver:cvs@cvs.silcnet.org:/cvs/silc
<br /><br />
cvs login<br />
cvs co silc<br />
cvs logout<br />
</tt>
</font>
<br /><br />
If you don't want to set $CVSROOT environment variable you can set the
path to the cvs as command line option:
<br /><br />
<font size="3">
<tt>
cvs -d:pserver:cvs@cvs.silcnet.org:/cvs/silc login<br />
cvs -d:pserver:cvs@cvs.silcnet.org:/cvs/silc co silc<br />
cvs -d:pserver:cvs@cvs.silcnet.org:/cvs/silc logout
</tt>
</font>
<br /><br />
Whatever method you will decide to use, after you have done cvs login you will
be prompted for password:
<br /><br />
<b>CVS password: </b>silc
<br /><br />
Type the password "silc" and press &lt;ENTER&gt;
<br /><br />
The actual SILC source tree is checked out using the cvs co silc command,
described above. This command will fetch the source tree and save it into
directory named silc. SILC CVS repository currently does not have any
branches thus this will check out the trunk. The size of the trunk is
currently about 13 MB but will grow in the future.

<br /><br />

<b>What SILC Source Tree Includes</b>
<br /><br />
SILC Source tree includes a lot more stuff that appears in public
distribution. The source tree includes, for example, internal scripts,
configuration files, SILC webpages etc. These never appear on a public
distribution.
<br /><br />
Following directories currently exist in SILC source tree.
<br /><br />
<font size="3">
<tt>
doc/
<br /><br />
Includes all the SILC documentation. Few parts of the documentation
are generated when distribution is generated. The automatically
generated files should never be commited to CVS.
<br /><br />
includes/
<br /><br />
Includes SILC include files.
<br /><br />
lib/
<br /><br />
Includes SILC libraries. There are maybe libraries in the CVS which
are not inclduded in public distribution.
<br /><br />
public_html/
<br /><br />
Includes the official SILC web pages and everything related to them.
This directory will never appear in public distribution.
<br /><br />
silc/
<br /><br />
Includes SILC client. There can be some extra files that will
never appear in public distribution, such as configuration files.
<br /><br />
silcd/
<br /><br />
Includes SILC server. There can be some extra files that will
never appear in public distribution, such as configuration files.
</tt>
</font>

<br /><br />

<b>Howto Compile SILC Source Tree</b>
<br /><br />
After checkout from CVS the SILC source tree needs to be prepared for
configuration and compilation. To compile the source tree, type:
<br /><br />
<font size="3">
<tt>
./prepare<br />
./configure --enable-debug<br />
make<br /><br />
note: on non-Linux operating systems GNU make (gmake) is prefered
</tt>
</font>
<br /><br />

The ./prepare script is included in the source tree and it will never
appears in public distribution. The script prepares the source tree
by creating configuration scripts and Makefiles. The prepare must be
run every time you made any changes to configuration scripts (however,
making changes to Makefile.am's does not require running ./prepare).
<br /><br />
As a developer you should read the ./configure script's help by typing
./configure --help and study all of its different options. Also you
should configure the script with --enable-debug option as it compiles
SILC with -g (debugging) option and it enables the SILC_LOG_DEBUG*
scripts. Warning is due here:  The debugging produced by both cilent
and server is very huge, thus it is common to test the programs as
follows:
<br /><br />
<font size="3">
<tt>
./silc -d -f configfile 2&gt;log<br />
./silcd -d -f configfile 2&gt;log
</tt>
</font>

<br /><br />

<b>How to clean SILC Source Tree</b>
<br /><br />
To entirely clear the source tree to the state after it was checked out
from CVS, type:
<br /><br />
<font size="3">
<tt>
./prepare-clean
</tt>
</font><br /><br />

This calls `make distclean' plus removes automatically generated files
by hand. It also removes *.log files. However, it will not remove any
other files you might have created.

<br /><br />

<b>Makefiles and configuration files</b>
<br /><br />
Developers should never directly write a Makefile. All Makefiles are
always automatically generated by ./prepare and later by ./configure
scripts. Instead, developers have to write Makefile.am files. There
are plenty of examples what they should look like. If you changed
Makefile.am during development you do not need to run ./prepare, just
run normal make.
<br />
Configuration files are the files that ./prepare automatically generates
and which will be included into public distribution. ./prepare creates
for example the ./configure script that is not commited to the CVS.
`configure.in' is the file that developers have to edit to change ./configure
script. After doing changes you need to run ./prepare.
</font>
