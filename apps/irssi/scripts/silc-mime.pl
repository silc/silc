#!/usr/bin/perl

use vars qw($VERSION %IRSSI);

use Irssi 20020704;
$VERSION = "1.0";
%IRSSI = (
    authors	=> "Jochen 'c0ffee' Eisinger",
    contact	=> "c0ffee\@penguin-breeder.org",
    name	=> "SILC2 MIME handler",
    description => "This script implements MIME handlers for SILC2, according to draft-riikonen-silc-flags-payloads-00, RFC 822, 1525, 2046, 2733, 2822, 3009",
    license	=> "GPL2 or any later",
    url		=> "http://www.penguin-breeder.org/silc/",
    changed	=> "Sun Aug 24 17:52 CEST 2003",
);

use MIME::Parser;
use Mail::Field;
use Mail::Cap;
use IO::Scalar;
use IO::File;
use File::Temp qw/ :POSIX /;
use Sys::Hostname;

my @mcaps;

## 
# read_mime_database
# 
# Loads all mailcap databases specified in the setting
# mime_database.  Default is ~/.mailcap and /etc/mailcap in
# that order.  Function is invoked on startup.
sub read_mime_database {
    # read mailcap databases rfc1525
    foreach (split /\s+/, Irssi::settings_get_str("mime_database")) {
        if (( -f $_ ) and ( -R $_ )) {
	    Irssi::printformat(MSGLEVEL_CRAP, 'load_mailcap', $_);
	    $mcap = new Mail::Cap $_;
	    push @mcaps, $mcap;
	} else {
	    Irssi::printformat(MSGLEVEL_CRAP, 'load_mailcap_fail', $_);
	}
    }
}

##
# unescape
#
# Removes the null-byte escaping from a data block.  Returns the
# unescaped data.  All data send via mime signals must be escaped.
sub unescape {
    my ($escaped) = @_;
    $escaped =~ s/\001\001/\000/g;
    $escaped =~ s/\001\002/\001/g;

    return $escaped;
}

##
# escape
#
# Escapes null-bytes for signal transfer.  Used to transfer binary data
# in null-terminated strings.  Returns the escaped data.  All data send
# via mime signals must be escaped.
sub escape {
    my ($unescaped) = @_;
    $unescaped =~ s/\001/\001\002/g;
    $unescaped =~ s/\000/\001\001/g;

    return $unescaped;
}

my %partial;

##
# process_mime_entity(MIME::Entity $msg)
#
# -1 failure, 0 success
sub process_mime_entity {
  my ($entity) = @_;

  $mimetype = Mail::Field->new('Content-type', $entity->head->get('Content-Type'));

  # check whether this is message/partial
  if ($mimetype->type eq  "message/partial") {

    # without an ID i don't know what stream this is related to
    if ($mimetype->id eq "") {
      Irssi::printformat(MSGLEVEL_CRAP, 'message_partial_failure', "no ID");
      return -1;
    }

    # the first packet is treated seperatly
    if ($mimetype->number == 1) {

      # the IDs should be unique
      if (defined $partial{$mimetype->id}) {
        Irssi::printformat(MSGLEVEL_CRAP, 'message_partial_failure', "duplicate ID");
        $fh = $partial{$mimetype->id}{file};
        $fh->close;
	unlink $partial{$mimetype->id}{name};
	undef $partial{$mimetype->id};
        return -1;
      }

      # create a new record
      $partial{$mimetype->id}{received} = 1;
      $partial{$mimetype->id}{name} = tmpnam();
      $fh = new IO::File "> $partial{$mimetype->id}{name}";
      $partial{$mimetype->id}{file} = $fh;
      $partial{$mimetype->id}{count} = 1;
      $partial{$mimetype->id}{total} = $mimetype->total;
      
    } else { # 2nd and later packets

      # detect unknown IDs
      if (not defined $partial{$mimetype->id}) {
        Irssi::printformat(MSGLEVEL_CRAP, 'message_partial_failure', "unknown ID");
        return -1;
      }
      
      # the 'total' information can be set in any packet,
      # however it has to be the same all the time
      if ($mimetype->total > 0) {
      
        if (($partial{$mimetype->id}{total} > 0) &&
            ($partial{$mimetype->id}{total} != $mimetype->total)) {
          Irssi::printformat(MSGLEVEL_CRAP, 'message_partial_failure', "invalid count");
      	  $fh = $partial{$mimetype->id}{file};
      	  $fh->close;
	  unlink $partial{$mimetype->id}{name};
      	  undef $partial{$mimetype->id};
      	  return -1;
        }
      
        $partial{$mimetype->id}{total} = $mimetype->total;
      
      }
      
      # we expect to receive packets in order
      if ($mimetype->number != ($partial{$mimetype->id}{count} + 1)) {
        Irssi::printformat(MSGLEVEL_CRAP, 'message_partial_failure', "invalid sequence number");
        $fh = $partial{$mimetype->id}{file};
        $fh->close;
	unlink $partial{$mimetype->id}{name};
        undef $partial{$mimetype->id};
        return -1;
      }
      
      # update our sequence record and save the packet
      $partial{$mimetype->id}{count} = $mimetype->number;

    }

    # and save the packet
    $fh = $partial{$mimetype->id}{file};
    if ($io = $entity->bodyhandle->open("r")) {
      while (defined($_ = $io->getline)) { print $fh $_ }
      $io->close;
    }

    # return if this wasn't the last packet
    if (($partial{$mimetype->id}{total} == 0) || 
        ($partial{$mimetype->id}{count} < $partial{$mimetype->id}{total})) {
      return 1;
    }

    # last packet...
    $tempfile = $partial{$mimetype->id}{name};
    $fh = $partial{$mimetype->id}{file};
    $fh->close;
    undef $partial{$mimetype->id};

    $parser = new MIME::Parser;
    $parser->output_dir("/tmp");
    $mime = $parser->parse_open($tempfile);

    $ret = process_mime_entity($mime);

    $parser->filer->purge;
    unlink $tempfile;
    return $ret;

  }

  # we could check for */parityfec (RTP packets) rfc2733, 3009

  # save to temporary file
  $tempfile = tmpnam();
  open TFILE, '>', $tempfile;
  if ($io = $entity->open("r")) {
    while (defined($_ = $io->getline)) { print TFILE $_; }
    $io->close;
  }
  close TFILE;  

  # try to handle it
  foreach $mcap (@mcaps) {
    $mcap->view($mimetype->type, $tempfile);

    next if not $?;
    unlink $tempfile if Irssi::settings_get_bool("mime_unlink_tempfiles");
    return 1;
  }

  unlink $tempfile if Irssi::settings_get_bool("mime_unlink_tempfiles");
  return $mimetype->type;
}

##
# sig_mime
#
# signal handler for incoming MIME type messages.  If the encoding or
# the content type are missing or not parsable, they default to binary
# and application/octet-stream respectivly.  If a decoder for the given
# transfer encoding is available, the message is decoded.  If a handler
# for the given content type is available in one of the mailcap databases,
# the handler is invoked and the signal is stopped.  The mailcap databases
# are scanned in order of loading.  Temporary files are unlinked if the
# setting mime_unlink_tempfiles is true.
sub sig_mime {

    my ($server, $witem, $blob, $sender, $verified) = @_;

    $parser = new MIME::Parser;
    $parser->output_dir("/tmp");
    $mime = $parser->parse_data(unescape($blob));

    $ret = process_mime_entity($mime);

    $parser->filer->purge;

    if ($ret == 1) {
      Irssi::signal_stop();
    } elsif  ($ret == -1) {
      return;
    } else {
      Irssi::print "Unknown MIME type $ret received...";
    }
}

##
# cmd_mmsg
#
# Sends a file with a given MIME type and transfer encoding.
#
# MMSG [<-channel>] <target> <file> [<content-type>  [<transfer-encoding>]]
#
# Sends a private data message to other user in the network.  The message
# will be send as a MIME encoded data message.
#
# If -channel option is provided then this command actually send channel
# message to the specified channel.  The message IS NOT private message, it
# is normal channel message.
#
# Messages that exceed roughly 64k have to be split up into smaller packets.
# This is done automatically.
#
# If no transfer-encoding is given it defaults to binary or 7bit for messages
# that have to be split up.
#
# If no content-type is given it defaults to application/octet-stream.
#
# Examples
#
# /MMSG Foobar smiley.gif image/gif binary
# /MMSG -channel silc silc.patch text/x-patch 7bit
# /MMSG * boing.mp3 audio/mpeg
sub cmd_mmsg {
    my ($data, $server, $witem) = @_;

    if ($server->{chat_type} ne "SILC") {
	Irssi::printformat(MSGLEVEL_CRAP, 'mmsg_chattype');
	return;
    }

    ($is_channel, $target, $file, $type, $encoding) =
        $data =~ /^\s*(?:(-channel)?\s+)? # match the -channel
	          (\*|\S+)\s+             # target
		  (\S+)                   # filename
		  (?:\s+(\S+)             # mime type
		     (?:\s+(\S+))?)?\s*   # encoding
		 $/ix;

    Irssi::printformat(MSGLEVEL_CRAP, 'mmsg_parameters'), return
        if ($target eq "") or ($file eq "");

    Irssi::printformat(MSGLEVEL_CRAP, 'mmsg_file', $file), return
        if not ( -f $file );

    $type = Irssi::settings_get_str("mime_default_type")
        if not defined $type;
    $encoding = Irssi::settings_get_str("mime_default_encoding")
        if not defined $encoding;

    # does the target exist? we don't test that... especially the
    # -channel parameter is ignored :/

    # XXX
    $to = $witem;

    $entity = new MIME::Entity->build(
        'MIME-Version' => "1.0",
    	Encoding       => $encoding,
	Type	       => $type,
	Path	       => $file
    );

    $tempfile = tmpnam();
    open TFILE, '>', $tempfile;
    $entity->print(\*TFILE);
    close TFILE;

    
    # 21:27 <@pekka> c0ffee: the core routines will crop the message if it
    #                doesn't fit.. I would use a bit shorter than the MAX_LEN
    # 21:28 <@pekka> c0ffee: -1024 bytes is sufficient
    # 21:28 <@pekka> c0ffee: should be sufficient in all possible cases
    if ((stat($tempfile))[7] < 0xfbff) {
    
      unlink $tempfile;
      Irssi::signal_emit("mime-send", $server, $to, escape($entity->stringify), 0);
    } else {

      open TFILE, $tempfile;
      $id = sprintf "id-%06d-%08d\@%s", int(rand(65535)), time(), hostname();;
      $chunks = 0;
      do {
        read TFILE, $data, 0xfb00;
	$chunks++;

        $entity = new MIME::Entity->build(
            'MIME-Version' => "1.0",
    	    Encoding       => "binary",
	    Type           => "message/partial; id=\"$id\"; number=$chunks" . 
	    			(eof(TFILE) ? "; total=$chunks" : ""),
	    Data           => $data
        );
        Irssi::signal_emit("mime-send", $server, $to, escape($entity->stringify), 0);

    } while (!eof(TFILE));
    close TFILE;
    
    unlink $tempfile;
  }
}

# Signal handlers
Irssi::signal_add("mime", "sig_mime");

# Commands
Irssi::command_bind("mmsg", "cmd_mmsg");

# Settings
Irssi::settings_add_str("misc", "mime_database", 
    "$ENV{HOME}/.mailcap /etc/mailcap");
Irssi::settings_add_bool("misc", "mime_unlink_tempfiles", 0);
Irssi::settings_add_str("misc", "mime_default_type", "application/octet-stream");
Irssi::settings_add_str("misc", "mime_default_encoding", "binary");

# Init
Irssi::theme_register(['load_mailcap', 'Loading mailcaps from {hilight $0}',
	'load_mailcap_fail', 'Couldn\'t find {hilight $0}',
	'message_partial_failure', 'message/partial: {hilight $0-}',
	'mmsg_chattype', 'command was not designed for this chat type',
	'mmsg_parameters', 'not enough parameters given',
	'mmsg_file', 'File {hilight $0} not found']);

read_mime_database();
