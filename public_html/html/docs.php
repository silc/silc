&nbsp;<br />
<b><big>SILC Documentation</big></b>
<br />&nbsp;<br />

README file from packages: <a href="docs/README" class="normal">README</a>
<br />&nbsp;<br />
Software manual: <i>Coming later</i>

<br />&nbsp;<br />&nbsp;<br />

<b>Installation Instructions</b>
<br />&nbsp;<br />
General installation instructions are available in all SILC distributions 
in the INSTALL file.
<br />&nbsp;<br />
<a href="?page=install" class="normal">Installation instructions</a>

<br />&nbsp;<br />&nbsp;<br />

<b><big>Technical Documentation</big></b>
<br />&nbsp;<br />

<b>SILC Toolkit Reference Manual</b>
<br />&nbsp;<br />
SILC Toolkit Reference Manual includes documentation for the SILC Toolkit 
package.  It includes interface references to all interfaces found in 
various SILC libraries.  The reference manual is automatically generated 
from the source code.  Note that this version is preliminary and does not 
include references to all interfaces.
<br />&nbsp;<br />
<a href="docs/toolkit/" class="normal">HTML version</a>, 
<a href="docs/toolkit.html.tar.gz" class="normal">html.tar.gz</a>

<br />&nbsp;<br />&nbsp;<br />

<b>Coding Conventions</b>
<br />&nbsp;<br />
If you would like to submit code to the SILC Project we would like you to 
first check out these coding conventions.  They are here for the benefit 
of all who read the code and is involved in the development of the SILC.
<br />&nbsp;<br />
<a href="docs/CodingStyle" class="normal">CodingStyle</a>

<br />&nbsp;<br />&nbsp;<br />

<b><big>SILC Protocol Documentation</big></b>
<br />&nbsp;<br />

<b>SILC Protocol White Paper</b>
<br />&nbsp;<br />
SILC Protocol White Paper gives short but deep enough introduction to the 
SILC Protocol. Note that this is for those who would like to know how the 
protocol works. For more detailed description of the protocol we suggest 
reading the protocol specifications.
<br />&nbsp;<br />

<a href="?page=whitepaper" class="normal">HTML version</a>,
<a href="docs/silc_protocol.pdf.gz" class="normal">gzipped PDF</a>,
<a href="docs/silc_protocol.ps.gz" class="normal">gzipped PostScript</a>

<br />&nbsp;<br />&nbsp;<br />

<b>SILC Protocol Internet Drafts</b>
<br />&nbsp;<br />
SILC Protocol is documented and four Internet Drafts exist. These 
Internet Drafts are also available from the
<a href="http://www.ietf.org/" class="normal">IETF</a>.
<br />&nbsp;<br />

<b>Secure Internet Live Conferencing (SILC), Protocol Specification</b>
<br />&nbsp;<br />
Abstract
<br />&nbsp;<br />
   This memo describes a Secure Internet Live Conferencing (SILC)
   protocol which provides secure conferencing services over insecure
   network channel. SILC is IRC [IRC] like protocol, however, it is
   not equivalent to IRC and does not support IRC. Strong cryptographic
   methods are used to protect SILC packets inside the SILC network.
   Three other Internet Drafts relates very closely to this memo;
   SILC Packet Protocol [SILC2], SILC Key Exchange and Authentication
   Protocols [SILC3] and SILC Commands [SILC4].
<br />&nbsp;<br />
<a href="docs/draft-riikonen-silc-spec-04.txt" class="normal">
draft-riikonen-silc-spec-04.txt</a>
<br />&nbsp;<br />&nbsp;<br />

<b>SILC Packet Protocol</b>
<br />&nbsp;<br />
Abstract
<br />&nbsp;<br />
   This memo describes a Packet Protocol used in the Secure Internet Live
   Conferencing (SILC) protocol, specified in the Secure Internet Live
   Conferencing, Protocol Specification Internet Draft [SILC1].  This
   protocol describes the packet types and packet payloads which defines
   the contents of the packets. It provides secure binary packet protocol
   that assures that the content of the packets is secured and authenticated.
<br />&nbsp;<br />
<a href="docs/draft-riikonen-silc-pp-04.txt" class="normal">
draft-riikonen-silc-pp-04.txt</a>
<br />&nbsp;<br />&nbsp;<br />

<b>SILC Key Exchange and Authentication Protocols</b>
<br />&nbsp;<br />
Abstract
<br />&nbsp;<br />
   This memo describes two protocols used in the Secure Internet Live  
   Conferencing (SILC) protocol, specified in the Secure Internet Live 
   Conferencing, Protocol Specification internet-draft [SILC1].  The   
   SILC Key Exchange (SKE) protocol provides secure key exchange between
   two parties resulting into shared secret key material. The protocol
   is based on Diffie-Hellman key exchange algorithm and its functionality
   is derived from several key exchange protocols. SKE uses best parts
   of the SSH2 Key Exchange protocol, Station-To-Station (STS) protocol 
   and the OAKLEY Key Determination protocol [OAKLEY].
<br />&nbsp;<br />
   The SILC Connection Authentication protocol provides user level
   authentication used when creating connections in SILC network. The 
   protocol is transparent to the authentication data which means that it
   can be used to authenticate the user with, for example, passphrase  
   (pre-shared-secret) or public key (and certificate).
<br />&nbsp;<br />
<a href="docs/draft-riikonen-silc-ke-auth-04.txt" class="normal">
draft-riikonen-silc-ke-auth-04.txt</a>
<br />&nbsp;<br />&nbsp;<br />

<b>SILC Commands</b>
<br />&nbsp;<br />
Abstract
<br />&nbsp;<br />
   This memo describes the commands used in the Secure Internet Live
   Conferencing (SILC) protocol, specified in the Secure Internet Live
   Conferencing, Protocol Specification Internet Draft [SILC1].  The
   SILC Commands are very important part of the SILC protocol.  Usually
   the commands are used by SILC clients to manage the SILC session, but
   also SILC servers may use the commands.  This memo specifies detailed
   command messages and command reply messages.
<br />&nbsp;<br />
<a href="docs/draft-riikonen-silc-commands-02.txt" class="normal">
draft-riikonen-silc-commands-02.txt</a>
