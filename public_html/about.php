<b>About SILC</b>
<font size="2">
<br><br>
SILC (Secure Internet Live Conferencing) is a protocol which provides
secure conferencing services in the Internet over insecure channel. SILC 
superficially resembles IRC, although they are very different internally.
They both provide conferencing services and have almost same set of of 
commands. Other than that, they are nothing alike. The SILC is secure and 
the network model is entirely different compared to IRC.
<br><br>
SILC provides security services that any other conferencing protocol does
not offer today. The most popular conferencing service, IRC, is entirely
insecure. If you need secure place to talk to some people or to group of
people over the Internet, IRC or any other conferencing service, for that 
matter, cannot be used. Anyone can see the messages and their contents in 
the IRC network. And the most worse case, some people is able to change 
the contents of the messages. Also, all the authentication data, such as, 
passwords are sent plaintext.
<br><br>
SILC is a lot more than just about `encrypting the traffic'. That is easy
enough to do with IRC and SSL hybrids, but even then the entire network 
cannot be secured, only part of it. SILC provides security services, such 
as, sending private messages entirely secure; no one can see the message 
except you and the real receiver of the message. SILC also provides same 
functionality for channels; no one except those clients joined to the 
channel may see the messages destined to the channel. Communication 
between client and server is also secured with session keys, and all 
commands, authentication data (such as passwords etc.) and other traffic 
is entirely secured. The entire network, and all parts of it, is secured. 
We are not aware of any other conferencing protocol providing same 
features at the present time.
<br><br>
SILC has secure key exchange protocol that is used to create the session
keys for each connection. SILC also provides strong authentication based
on either passwords or public key authentication. All authentication data
is always encrypted in the SILC network. All connections has their own
session keys, all channels has channel specific keys, and all private
messages can be secured with private message specific keys.
<br><br>
</font>

<b>Availability</b>
<font size="2">
<br><br>
The SILC is distributed currently as three different packages. The SILC 
Client package, the SILC Server package and the SILC Toolkit package. Each 
of the package has its intended audience.
<br><br>
- SILC Client package is intended for end users who seek a good and full 
featured SILC client. The SILC Client package currently includes 
Irssi-SILC client that supports all SILC features, themes and much more. 
It is curses based but has a possibility of adding various other frontends 
to it. The Irssi-SILC client's user interface is based on the Irssi client 
(see <a href="http://irssi.org/">Irssi project</a>).
<br><br>
- SILC Server package is intended for system administrators who would like 
to run their own SILC server or SILC router. The package includes the 
actual server but not the client. If you are running a server and would 
like to connect it to the silc.silcnet.org router you can contact us.
<br><br>
- SILC Toolkit package is intended for developers and programmers who 
would like to create their own SILC based applications or help in the 
development of the SILC protocol. The actual development of the SILC is 
done in the Toolkit and all the other packages are based on the Toolkit 
releases. The Toolkit includes SILC Protocol Core library, SILC Crypto 
library, SILC Key Exchange (SKE) library, SILC Math library, SILC Modules 
(SIM) library, SILC Utility library, SILC Client library and some other 
libraries. It also includes the Irssi-SILC Client, another client as an 
example how to program with the Toolkit and the SILC Server.
<br><br>
</font>

<b>Licensing</b>
<font size="2">
<br><br>
SILC is an open source (or freeware) project and it has been released
under the GNU General Public Licence. The SILC is free to use and
everyone is free to distribute and change the SILC under the terms of the
GNU GPL. While there is no guarantee for the product, SILC is made as 
secure as possible. The fact that the software and the protocol
is open for public analysis is a good thing for end user.
<br><br>
Protocol specification of SILC protocol is available for anyone to look
at. There exists four Internet Drafts that has been submitted to the <a
href="http://www.ietf.org">IETF</a>. See <a
href="index.php?page=docs">documentation page</a> for more information.
<br><br></font>
<b>Contact</b>
<font size="2">
<br><br>
Feedback and comments are welcome. You can reach me in the following Address.
<br><br>
Pekka Riikonen<br>
priikone at silcnet.org
</font>
<br><br>
