&nbsp;<br />
<b><big>SILC Crypto FAQ</big></b>
<br />&nbsp;<br />

&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_10" class="normal">
1.1 What is this FAQ?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_20" class="normal">
1.2 I found incorrect information in the FAQ, who do I notify?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_30" class="normal">
1.3 Your FAQ does not answer my questions, where can I send my question?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_40" class="normal">
1.4 I have found a security problem in SILC protocol/implementation.  Who
   should I notify?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_50" class="normal">
1.5 Does SILC support AES?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_60" class="normal">
1.6 Does SILC support DES or 3DES?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_70" class="normal">
1.7 What other algorithms SILC support?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_80" class="normal">
1.8 What encryption modes SILC support?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_90" class="normal">
1.9 What hash functions SILC support?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_100" class="normal">
1.10 What public key algorithms SILC support?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_110" class="normal">
1.11 Does SILC support PGP keys?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_120" class="normal">
1.12 Does SILC support SSH keys?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_130" class="normal">
1.13 Does SILC support X.509 certificates?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_140" class="normal">
1.14 So SILC can be used with other keys too instead of just SILC public 
   keys?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_140" class="normal">
1.15 How the MAC is computed in SILC?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_160" class="normal">
1.16 Why SILC does not use PGP to encrypt messages?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_170" class="normal">
1.17 Why SILC does not use TLS/SSL to encrypt messages?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_180" class="normal">
1.18 Why SILC does not use SSH tunneling or IPSEC to encrypt messages?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_190" class="normal">
1.19 How is the transport in SILC protected then?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_200" class="normal">
1.20 Do I understand you correctly that TLS/SSL + PGP would be same as
   SILCs own protection now?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_210" class="normal">
1.21 Are you also saying that a chat protocol using TLS/SSL alone is not 
   actually sufficient (like IRC+SSL)?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_220" class="normal">
1.22 Are you also saying that a chat protocol using PGP alone is not
   actually sufficient (like ICQ+PGP)?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_230" class="normal">
1.23 So chat protocol always needs both secured transport and secured 
   messages, right?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_240" class="normal">
1.24 What is the purpose of the SILC key exchange (SKE) protocol?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_250" class="normal">
1.25 How does SKE protocol protect against man-in-the-middle attacks which can be used to attack Diffie-Hellman?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_260" class="normal">
1.26 Would have it been possible to use some other key exchange protocol
   in SILC instead of developing SKE?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_270" class="normal">
1.27 Should I verify the public key of the server when I connect to it?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_280" class="normal">
1.28 Should I verify all other public keys in SILC?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_290" class="normal">
1.29 Why SILC does not used OpenSSL crypto library instead of its own?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_300" class="normal">
1.30 Is it possible to digitally sign messages in SILC?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_310" class="normal">
1.31 I am a Harry Hacker, and I want to crack your protocol.  What would be
   the best way to attack SILC protocol?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_320" class="normal">
1.32 What could happen if a server in SILC network would become compromised?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_330" class="normal">
1.33 What could happen if a router would become compromised?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_340" class="normal">
1.34 Is my channel messages protected on compromised server or not?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_350" class="normal">
1.35 Is my private messages protected on compromised server or not?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_360" class="normal">
1.36 Should I then always use private keys for all messages?</a><br />
&nbsp;&nbsp;&nbsp;&nbsp;<a href="#f1_370" class="normal">
1.37 How likely is it that some server would become compromised?</a><br />

<br />&nbsp;<br />

<a name="f1_10"></a>
<samp class="highlight">Q: What is this FAQ?</samp><br />
A: This FAQ answers questions regarding cryptography and security in SILC
   protocol and implementation.  It attempts to answer the most 
   frequently asked questions that normal users ask.  It also try 
   to be detailed enough to give precise answers for those who already 
   understand a bit more about cryptography and security.  When we make 
   claims or assumptions about security issues we always try to include 
   the reference to the answer which then can be used to learn more about 
   the specific security issue.
<br />&nbsp;<br />

<a name="f1_20"></a>
<samp class="highlight">Q: I found incorrect information in the FAQ, who do I notify?</samp><br />
A: If you think that some information is incorrect in this FAQ you may
   send your comments to the 
<a href="mailto:info@silcnet.org" class="normal">info@silcnet.org</a> email address.
<br />&nbsp;<br />

<a name="f1_30"></a>
<samp class="highlight">Q: Your FAQ does not answer my questions, where can I send my question?</samp><br />
A: If you have questions that you think should be part of this FAQ you
   may send them to
<a href="mailto:info@silcnet.org" class="normal">info@silcnet.org</a> email address.
<br />&nbsp;<br />

<a name="f1_40"></a>
<samp class="highlight">Q: I have found a security problem in SILC protocol/implementation.  Who should I notify?</samp><br />
A: If you find a security problem either in the protocol or in the
   implementation we would appreciate it if you let us know about it first
   before doing anything else.  You can send us email to 
<a href="mailto:security@silcnet.org" class="normal">security@silcnet.org</a>
   if you think you have found a security problem.
<br />&nbsp;<br />

<a name="f1_50"></a>
<samp class="highlight">Q: Does SILC support AES?</samp><br />
A: Yes, the AES with 256 bit encryption key is required in SILC protocol.  
   The required encryption mode with AES is CBC.  SILC also supports other
   algorithms but they are optional.
<br />&nbsp;<br />

<a name="f1_60"></a>
<samp class="highlight">Q: Does SILC support DES or 3DES?</samp><br />
A: Only the AES is required algorithm in SILC protocol.  DES or 3DES has 
   not been added to the SILC specification.  However, the SILC key 
   exchange protocol is very flexible and you can negotiate to use DES
   or 3DES if you want, but officially SILC does not support DES or 3DES.
<br />&nbsp;<br />

<a name="f1_70"></a>
<samp class="highlight">Q: What other algorithms SILC support?</samp><br />
A: Like said, only the AES is required.  The protocol specification also
   lists optional algorithms like Twofish, CAST, RC6, etc., and you can
   negotiate other algorithms as well during the SILC key exchange 
   protocol, if needed.
<br />&nbsp;<br />

<a name="f1_80"></a>
<samp class="highlight">Q: What encryption modes SILC support?</samp><br />
A: The required mode is currently CBC.  Other modes are optional.  
   However, there has been discussion on adding additional required mode,
   for example CTR mode.  In the future, SILC is also going to have
   support for so called "authenticated encryption" modes as soon as
   NIST finalizes its selection process for these modes.
<br />&nbsp;<br />

<a name="f1_90"></a>
<samp class="highlight">Q: What hash functions SILC support?</samp><br />
A: The required hash function is SHA-1, but also the MD5 is added to the
   specification as optional hash function.  The SHA-1 is also the 
   required hash function when used as part of HMAC to provide integrity
   protection for encrypted packets.
<br />&nbsp;<br />

<a name="f1_100"></a>
<samp class="highlight">Q: What public key algorithms SILC support?</samp><br />
A: The required public key algorithm is RSA, but optional support is
   for DSS.  The RSA algorithm in SILC supports PKCS#1 standard.  During
   the key exchange protocol also Diffie-Hellman public key algorithm
   is used to exchange keys.  The Diffie-Hellman in SILC supports PKCS#3
   standard.  Adding support for other algorithms like El Gamal is 
   possible by negotiating them in SILC key exchange.
<br />&nbsp;<br />

<a name="f1_110"></a>
<samp class="highlight">Q: Does SILC support PGP keys?</samp><br />
A: PGP keys, or as they are officially called OpenPGP certificates are
   supported in SILC protocol.  Current implementation however does not
   yet have support for them.
<br />&nbsp;<br />

<a name="f1_120"></a>
<samp class="highlight">Q: Does SILC support SSH keys?</samp><br />
A: SSH2 public keys are supported in SILC protocol.  Current 
   implementation however does not yet have support for them.
<br />&nbsp;<br />

<a name="f1_130"></a>
<samp class="highlight">Q: Does SILC support X.509 certificates?</samp><br />
A: Yes, X.509 certificates are supported in SILC protocol.  Current 
   implementation however does not yet have support for them.  After the
   support is added then adding support also for CRLs and also perhaps 
   OCSP will be added to the implementation.
<br />&nbsp;<br />

<a name="f1_140"></a>
<samp class="highlight">Q: So SILC can be used with other keys too instead of just SILC public keys?</samp><br />
A: Yes, that's the purpose of having support for other public keys and
   certificates.  The implementation most likely still wants to create
   you a SILC key pair, but if you have for example PGP key pair that 
   would be the one you are using in SILC.
<br />&nbsp;<br />

<a name="f1_150"></a>
<samp class="highlight">Q: How the MAC is computed in SILC?</samp><br />
A: The MAC for SILC packet in the secure binary packet protocol is 
   computed always before encryption from the plaintext, and the MAC
   is appended at the end of the SILC packet, and is never encrypted.
   Also the channel message MAC is computed from plaintext when channel
   message is sent.
<br />&nbsp;<br />

<a name="f1_160"></a>
<samp class="highlight">Q: Why SILC does not use PGP to encrypt messages?</samp><br />
A: We know it is hard to understand why PGP is not used to encrypt 
   messages in SILC, but things in cryptography is never as simple as
   they seem to be.  PGP alone is not suitable to be used and does not 
   meet the security requirements in SILC, and therefore is not secure
   enough to be used alone in SILC-like network 
   <a href="http://www.counterpane.com/chotext.html" class="normal">[1]</a>,
   <a href="http://www.counterpane.com/pgp-attack.html" class="normal">[2]</a>.
<br />&nbsp;<br />

   However, PGP can be used with SILC.  It is entirely possible to
   use PGP to encrypt and/or sign messages in SILC, but as primary
   protection PGP is not sufficient.
<br />&nbsp;<br />

<a name="f1_170"></a>
<samp class="highlight">Q: Why SILC does not use TLS/SSL to encrypt messages?</samp><br />
A: The transport layer alone cannot provide security for individual
   messages which are not point to point in nature.  The TLS/SSL protects
   only point to point traffic arbitrarily and using that to protect
   for example private message which has no correlation to the actual
   transport makes no sense.  The messages need to be protected
   with message specific keys, for example channel messages are protected
   with channel keys.  The transport in SILC is protected as well with
   session keys (point to point), which would be analogous to using 
   TLS/SSL, but there is no specific reason to use TLS/SSL for that in 
   SILC.
<br />&nbsp;<br />

<a name="f1_180"></a>
<samp class="highlight">Q: Why SILC does not use SSH tunneling or IPSEC to encrypt messages?</samp><br />
A: For the same reasons as why it is not using TLS/SSL.
<br />&nbsp;<br />

<a name="f1_190"></a>
<samp class="highlight">Q: How is the transport in SILC protected then?</samp><br />
A: The transport is protected with session keys negotiated during the
   SILC key exchange protocol.  SILC protocol defines secure binary packet
   protocol, which provides encrypted and authenticated binary packets.
   All data in SILC are sent using this secure binary packet protocol
   and all packets are automatically encrypted.  This is analogous of
   using TLS/SSL to protect the socket layer, except that SILC defines
   the binary packet protocol itself.  Another example of protocol having 
   its own secure binary packet protocol is SSH, and it is analogous to 
   TLS/SSL too.
<br />&nbsp;<br />

   But note that protecting the transport is not sufficient enough to
   protect individual messages.  Transport is just arbitrary data point
   to point, where as channel message for example is a message from one
   sender to many recipients and requires different kind of protection.
   Protecting transport is one thing, and protecting messages end to end
   is another.
<br />&nbsp;<br />

<a name="f1_200"></a>
<samp class="highlight">Q: Do I understand you correctly that TLS/SSL + PGP would be same as SILCs own protection now?</samp><br />
A: TLS/SSL + PGP + something else too, would be about same, but the end
   result would be really ad hoc solution since these are separate,
   external security protocols and not something designed to work 
   together.  Also, at the time SILC was designed OpenPGP standard did
   not exist so using it would have been out of question anyway.  Your 
   favorite chat protocol does not suddenly become secure when you start 
   slapping different security protocols on top of it.  It requires 
   thorough planning and designing to work in secure manner.
<br />&nbsp;<br />

   SILC has been designed the security in mind from the day one and
   for this reason securing the transport and providing end to end
   security for private messages, channel messages and other messages
   is integrated.  The end result would have not been as secure if
   external protocols would have been just applied over insecure
   chat protocol hoping for the best.  Now they are integrated and
   designed to work together, and there is no need to apply external
   security protocols.
<br />&nbsp;<br />

<a name="f1_210"></a>
<samp class="highlight">Q: Are you also saying that a chat protocol using TLS/SSL alone is not actually sufficient (like IRC+SSL)?</samp><br />
A: If it is used alone (no other protection), then basicly that's what I'm 
   saying, but of course things are not that simple.  If the TLS/SSL is 
   used correctly, that is, all points in the chat network are protected 
   then it can provide security.  But if even one point in the chat 
   network is not secured then the entire network can be considered 
   compromised.  Also, if one server in the network is compromised then 
   entire network and all messages are compromised since messages are not 
   actually secure, only the transport.  Ask yourself this: If you remove 
   the TLS/SSL, is your message secured or not?  If you answer no, then 
   it doesn't provide sufficient security for chat networks.  Also, note 
   that it does not provide message authentication, only packet data 
   authentication, and that is not the same thing (a packet is point to 
   point, a message is not).
<br />&nbsp;<br />

<a name="f1_220"></a>
<samp class="highlight">Q: Are you also saying that a chat protocol using PGP alone is not actually sufficient (like ICQ+PGP)?</samp><br />
A: Here I assume protocols that just protect the message with PGP, then
   yes, that's what I am saying.  This is even more serious than
   those using just TLS/SSL.  Why?  Because there is no packet protection 
   at all, only message protection.  The message may be encrypted and 
   authenticated but the packet is not.  This allows attacks like forgery 
   attacks, plaintext and ciphertext tampering, reply and out of order 
   delivery attacks, chosen ciphertext attacks, even adaptive chosen 
   ciphertext attacks
   <a href="http://www.counterpane.com/chotext.html" class="normal">[1]</a>,
   <a href="http://www.counterpane.com/pgp-attack.html" class="normal">[2]</a>,
   and many more.  Some of these attacks may be rendered ineffective by
   doing the implementation carefully but the protocol remains broken
   regardless.
<br />&nbsp;<br />

<a name="f1_230"></a>
<samp class="highlight">Q: So chat protocol always needs both secured transport and secured messages, right?</samp><br />
A: Yes, you got it now!  And SILC provides exactly that.  Its transport
   is secured with the secure binary packet protocol and it provides
   message encryption and authentication.
<br />&nbsp;<br />

<a name="f1_240"></a>
<samp class="highlight">Q: What is the purpose of the SILC key exchange (SKE) protocol?</samp><br />
A: The primary purpose of the SILC key exchange protocol is to create
   session key for protecting the traffic between the client and the
   server.  It is executed always when client connects to the server.
   It can also be used to create other key material for other sessions,
   like file transfer session.  The SKE use Diffie-Hellman for key
   exchange algorithm, and supports digital signatures and mutual
   authentication.  The SKE is based on SSH2, STS and OAKLEY key exchange
   protocols.  The SKE is also used to negotiate the security properties
   that are going to be used in the session.  These properties are
   the encryption algorithm, HMAC, public key algorithm, hash
   algorithm, key lengths, encryption modes, etc.
<br />&nbsp;<br />

<a name="f1_250"></a>
<samp class="highlight">Q: The SILC key exchange protocol is using Diffie-Hellman.  How does it protect against man-in-the-middle attacks which can be used to attack Diffie-Hellman?</samp><br />
A: Diffie-Hellman is known to be vulnerable to man-in-the-middle attack
   when it is used alone.  For that reason it must not be used alone
   ever.  In SILC key exchange (SKE) protocol digital signatures are
   used to prevent the man-in-the-middle attacks.  Using digital 
   signatures with Diffie-Hellman is the common way to avoid these
   problems, and in addition it provides peer authentication at the
   same time.  Other key exchange protocols which use Diffie-Hellman
   with digital signatures too are IKE, SSH2, TLS/SSL, and many more.
<br />&nbsp;<br />

   Naturally, in the end the user and the application is responsible of
   avoiding the man-in-the-middle attack; the public key of the remote
   must be verified before trusting it.  If this is not done, then
   the digital signatures makes no difference.  This is the case with
   any key exchange protocol using digital signatures.
<br />&nbsp;<br />

<a name="f1_260"></a>
<samp class="highlight">Q: Would have it been possible to use some other key exchange protocol in SILC instead of developing SKE?</samp><br />
A: At the time SILC was developed the answer was simply no, it would have
   not been possible.  The problem often is that security protocols tend
   to develop their own key exchange protocols even though at least
   theoretically it would be possible and wise to use protocol which
   is proved secure.  In practice this is never done.  TLS/SSL has its
   own key exchange, SSH has its own key exchange, and SILC has its
   own key exchange.  When the Internet Key Exchange (IKE) protocol was
   being developed it was our hope that it would have become general
   purpose key exchange protocol but the reality was that it was tightly
   developed for IPSEC instead.  The end result is that it would be
   huge overkill to use IKE with any other protocol than IPSEC.
<br />&nbsp;<br />

<a name="f1_270"></a>
<samp class="highlight">Q: Should I verify the public key of the server when I connect to it?</samp><br />
A: Definitely yes.  Commonly in security protocols which does not use
   certificates by default the public key is verified in the first time
   it is received and then it is cached on local disk.  In SILC the same
   thing is done.  When you connect the very first time to the server
   you will be prompted to verify and accept the public key.  This is the
   time when you should (must) verify the public key.  After accepting
   the key it is saved locally and used later to do the verification 
   automatically.  This is same as with SSH; you accept the SSH server
   key the very first time and then cache it locally for later use.
<br />&nbsp;<br />

   The moral is this: you always must verify all public keys to be 
   certain that man-in-the-middle attack is not in progress.  It is your 
   risk to take if you do not verify the key.
<br />&nbsp;<br />

<a name="f1_280"></a>
<samp class="highlight">Q: Should I verify all other public keys in SILC?</samp><br />
A: Definitely yes.  You can receive public keys when you negotiate for
   example private message key with some other client, and you must
   verify the key before accepting it.  Reason are same as in previous
   answer.
<br />&nbsp;<br />

<a name="f1_290"></a>
<samp class="highlight">Q: Why SILC does not used OpenSSL crypto library instead of its own?</samp><br />
A: The OpenSSL crypto library as you know it now did not even exist
   when the SILC crypto library was developed in 1997.  The SSLeay
   crypto library which was the predecessor of OpenSSL package did
   exist but was not suitable for our use at the time.
<br />&nbsp;<br />

   Now that OpenSSL crypto library is popular, it still is not
   sufficient enough for us.  SILC specification requires AES algorithm
   but OpenSSL crypto library as of this writing (Oct 2002) still does not 
   support it.  This alone makes the OpenSSL crypto library impossible
   for us to use.
<br />&nbsp;<br />

   Also, we feel that using different crypto libraries and using the one
   we have developed over the years is good in the end for everybody.  A
   bug that would affect SILC may not then affect OpenSSL, and on the
   other hand bug that would affect OpenSSL crypto library may not then
   affect SILC.  Diversity also in crypto libraries is a good thing.
<br />&nbsp;<br />

   Finally, in our opinion SILC crypto library is equally good or even
   better than OpenSSL crypto library.
<br />&nbsp;<br />

<a name="f1_300"></a>
<samp class="highlight">Q: Is it possible to digitally sign messages in SILC?</samp><br />
A: Yes, this is possible, however the detailed definition of how this is
   done with different public keys/certificates has not yet been defined
   as of this writing (Oct 2002).  The next protocol version 1.2 will 
   define this and it will be added to the implementation immediately.
<br />&nbsp;<br />

<a name="f1_310"></a>
<samp class="highlight">Q: I am a Harry Hacker, and I want to crack your protocol.  What would be the best way to attack SILC protocol?</samp><br />
A: Hehe.  There is no simple answer to this question.  Designing a 
   security protocol is extremely difficult.  It is actually more 
   difficult than, say, designing an encryption algorithm.  Why?  Because 
   security protocols tend to be so complex.  And even when they are
   not complex they are always more complex than just one cryptographic
   primitive like encryption algorithm.  Now, attacking cryptographic
   algorithm to break the protocol is usually never the best way to
   go about since the attacks against algorithms are usually just
   theoretical and hard to mount.  Attacking the protocol as a whole may 
   also be pretty difficult since the operations in the protocol are 
   usually protected by those cryptographic primitives.  The best way of 
   attacking any security protocol is usually to attack the 
   implementation, since that's the number one source of problems in
   security protocols.
<br />&nbsp;<br />

   However, I don't know whether you want to analyze the protocol 
   itself, in an attempt to try to find security holes or weaknesses in
   the protocol, or whether you want to just break the protocol.  If you
   want to do the first, then the best way to go about is to learn all
   the details about SILC protocol, how it works, how the implementation
   is supposed to work, and what security measures are used in the 
   protocol.  Then you start analyzing the protocol and trying to look
   for obvious mistakes.  Then you can try to apply some attacks you know
   about to the protocol and see what would happen.  If you want to
   do the second then you probably need to get your hands dirty and
   try to figure out ways to do it in practice by finding implementation
   problems, design problems and applying attacks in practice to the
   implementation you are using.  Also, always think big.  Protocols are
   not used in a class jar, they are used by human beings in a real world
   and you can break a protocol by not attacking the protocol at all, but 
   by attacking something from the side.
<br />&nbsp;<br />

<a name="f1_320"></a>
<samp class="highlight">Q: What could happen if a server in SILC network would become compromised?</samp><br />
A: This is of course hypothetical but let's assume the entire server would
   be in the hands of malicious attacker and he can control everything 
   that happens in the server.  This would of course mean that the 
   attacker has compromised the entire machine, not just SILC server.
   He also would have replaced the original SILC server with tampered
   version which the attacker can control.  It would not be nice 
   situation.  First, all local connections to the server would be 
   compromised since the server knows the session keys for local 
   connections.  Second, all channels that the server has locally joined 
   users would be compromised since the server knows those channel keys.  
   However, other invite-only, private or secret channels would not be 
   compromised since the attacker has no access to those channels.  Also 
   channels that are using channel private keys would not be compromised.  
   Third, all data and messages protected with session keys would be 
   compromised.  However, all messages protected with private keys, like 
   private message keys, and channel private keys would not be 
   compromised since the server does not know these keys.
<br />&nbsp;<br />

   So it would not be pretty sight, but it's same with any security
   protocol like SSH.  If SSH server is compromised then there's not
   much you can do.  In SILC however you can still do something; you
   can decide to use private keys to protect all messages.  Servers
   do not know these keys so even if the server is compromised it would
   be safe.  It cannot decrypt those messages.  So, in SILC there is 
   always the fallback to something else.  This is important in security
   protocols; how can you make the protocol secure even if it partially
   fails?  Answer is by having fallbacks that are available if something
   fails.  Fallback after the other.  As long it fallbacks to something
   that provides security it is better than nothing.  Another problem
   is of course that of how fast the protocol is able to recover from
   these security failures.  This is more complicated matter however,
   but naturally the compromised server need to be removed from the
   network as soon as possible.  The protocol recovers then immediately.
<br />&nbsp;<br />

<a name="f1_330"></a>
<samp class="highlight">Q: What could happen if a router would become compromised?</samp><br />
A: The situation would be similar to having compromised server except
   that router knows all locally (in the router, ie. in the cell) created
   channels, so all local channels that are not using channel private 
   keys would be compromised.  However, channels that are created on other
   routers, and if there are no local users on those channels in the 
   router, would not be compromised, since channel keys are cell specific.
<br />&nbsp;<br />

<a name="f1_340"></a>
<samp class="highlight">Q: Is my channel messages protected on compromised server or not?</samp><br />
A: If you are using channel private key then always yes.  If the 
   compromised server does not know about the channel then always yes.
   If you are not using channel private key, and the server knows the
   current channel key then no, if the server is compromised.  But note
   that if some server in the network is compromised it does not 
   automatically mean that your channel messages are compromised.
<br />&nbsp;<br />

<a name="f1_350"></a>
<samp class="highlight">Q: Is my private messages protected on compromised server or not?</samp><br />
A: If you are using private message keys then always yes.  If you are not
   using then no, if the server is compromised and the private message
   passes through the compromised server.  Again, a compromised server
   in network does not automatically mean that private message is 
   compromised.  Also the structure of the network in SILC is designed
   so that messages do not go to servers unless they really need to
   do so (since there is no tree-like network structure, where messages
   could pass through several servers).
<br />&nbsp;<br />

<a name="f1_360"></a>
<samp class="highlight">Q: Should I then always use private keys for all messages?</samp><br />
A: If you think that the network or server you are using is not something
   you can trust in any degree then yes.  If the server is your company's
   internal SILC server then I guess you may even trust it.  It is your
   decision and you decide what is the acceptable level of risk you are
   willing to take, and what is your required level of security.  For
   private messages using private keys is trivial since you can 
   automatically negotiate the keys with SKE.  Using channel private key
   is however more complicated since all users in the channel need to 
   know the key in order to be able to talk on the channel.  It may be
   for example pre-shared key that all users on the channel know.
<br />&nbsp;<br />

<a name="f1_370"></a>
<samp class="highlight">Q: How likely is it that some server would become compromised?</samp><br />
A: Like said in last questions all these scenarios were hypothetical, and
   if the server is not compromised then there are no problems of the
   kind just discussed.  It is very hard to say how likely it is.  It is
   unlikely, but a possibility.  Server administrators must keep the 
   machine protected in general too, since if the machine is compromised 
   a whole lot of other stuff is compromised too, not just SILC server.
<br />&nbsp;<br />

