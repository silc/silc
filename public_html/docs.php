<b>SILC Documentation</b>
<font size="2">
<br /><br />
Currently working on the SILC documentation is in progress and the software
does not have extensive documentation at all.
<br /><br />
README file from packages: <a href="docs/README">README</a>
<br />
Coding Style in SILC source tree: <a href="docs/CodingStyle">CodingStyle</a>
<br /><br />
<i>Coming later: Software manual, SILC Library Reference manual</i>

<br /><br /><br />

</font>
<b>SILC Protocol Internet Drafts</b>
<br /><br />
<font size="2">
SILC Protocol is documented and four Internet Drafts exist. These 
Internet Drafts are also available from
<a href="http://www.ietf.org">IETF</a>.
<br><b>Updated on Sun Jul 22 22:01:38 EEST 2001</b>: These new 
updated drafts will be submitted to the IETF after the August 14th 2001.
<br /><br />

<b>Secure Internet Live Conferencing (SILC), Protocol Specification</b>
<br /><br />
Abstract
<br /><br />
   This memo describes a Secure Internet Live Conferencing (SILC)
   protocol which provides secure conferencing services over insecure
   network channel. SILC is IRC [IRC] like protocol, however, it is
   not equivalent to IRC and does not support IRC. Strong cryptographic
   methods are used to protect SILC packets inside the SILC network.
   Three other Internet Drafts relates very closely to this memo;
   SILC Packet Protocol [SILC2], SILC Key Exchange and Authentication
   Protocols [SILC3] and SILC Commands [SILC4].
<br /><br />
<a href="docs/draft-riikonen-silc-spec-03.txt">
draft-riikonen-silc-spec-03.txt</a>
<br /><br /><br />

<b>SILC Packet Protocol</b>
<br /><br />
Abstract
<br /><br />
   This memo describes a Packet Protocol used in the Secure Internet Live
   Conferencing (SILC) protocol, specified in the Secure Internet Live
   Conferencing, Protocol Specification Internet Draft [SILC1].  This
   protocol describes the packet types and packet payloads which defines
   the contents of the packets. It provides secure binary packet protocol
   that assures that the content of the packets is secured and authenticated.
<br /><br />
<a href="docs/draft-riikonen-silc-pp-03.txt">
draft-riikonen-silc-pp-03.txt</a>
<br /><br /><br />

<b>SILC Key Exchange and Authentication Protocols</b>
<br /><br />
Abstract
<br /><br />
   This memo describes two protocols used in the Secure Internet Live  
   Conferencing (SILC) protocol, specified in the Secure Internet Live 
   Conferencing, Protocol Specification internet-draft [SILC1].  The   
   SILC Key Exchange (SKE) protocol provides secure key exchange between
   two parties resulting into shared secret key material. The protocol
   is based on Diffie-Hellman key exchange algorithm and its functionality
   is derived from several key exchange protocols. SKE uses best parts
   of the SSH2 Key Exchange protocol, Station-To-Station (STS) protocol 
   and the OAKLEY Key Determination protocol [OAKLEY].
<br /><br />
   The SILC Connection Authentication protocol provides user level
   authentication used when creating connections in SILC network. The 
   protocol is transparent to the authentication data which means that it
   can be used to authenticate the user with, for example, passphrase  
   (pre-shared-secret) or public key (and certificate).
<br /><br />
<a href="docs/draft-riikonen-silc-ke-auth-03.txt">
draft-riikonen-silc-ke-auth-03.txt</a>
<br /><br /><br />

<b>SILC Commands</b>
<br /><br />
Abstract
<br /><br />
   This memo describes the commands used in the Secure Internet Live
   Conferencing (SILC) protocol, specified in the Secure Internet Live
   Conferencing, Protocol Specification Internet Draft [SILC1].  The
   SILC Commands are very important part of the SILC protocol.  Usually
   the commands are used by SILC clients to manage the SILC session, but
   also SILC servers may use the commands.  This memo specifies detailed
   command messages and command reply messages.
<br /><br />
<a href="docs/draft-riikonen-silc-commands-01.txt">
draft-riikonen-silc-commands-01.txt</a>
<br />
</font>
