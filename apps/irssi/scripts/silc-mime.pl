#!/usr/bin/perl

use vars qw($VERSION %IRSSI);

use Irssi 20020704;
$VERSION = "1.1";
%IRSSI = (
    authors	=> "Jochen 'c0ffee' Eisinger",
    contact	=> "c0ffee\@penguin-breeder.org",
    name	=> "SILC2 MIME handler",
    description => "This script implements MIME handlers for SILC2, according to draft-riikonen-silc-flags-payloads-00",
    license	=> "GPL2 or any later",
    url		=> "http://www.penguin-breeder.org/silc/",
    changed	=> "Wed Aug 29 10:45 CET 2003",
);

use MIME::Parser;
use Mail::Field;
use Mail::Cap;
use File::MMagic;
use IO::Scalar;
use IO::File;
use File::Temp qw/ tempfile /;
use Sys::Hostname;
use POSIX qw/ ceil /;

my @mcaps;
my $magic = new File::MMagic;

## 
# read_mime_database
# 
# Loads all mailcap databases specified in the setting
# mime_database.  Default is ~/.mailcap and /etc/mailcap in
# that order.  Function is invoked on startup.
#
# MIME Magic Info is also read...
sub read_mime_database {
    # read mailcap databases rfc1525
    foreach (split /\s+/, Irssi::settings_get_str("mime_database")) {
        if (( -f $_ ) and ( -R $_ )) {
	    Irssi::printformat(MSGLEVEL_CRAP, 'load_mailcap', $_)
	      if Irssi::settings_get_bool("mime_verbose");
	    $mcap = new Mail::Cap $_;
	    push @mcaps, $mcap;
	} else {
	    Irssi::printformat(MSGLEVEL_CRAP, 'load_mailcap_fail', $_)
	      if Irssi::settings_get_bool("mime_verbose");
	}
    }

    $mfile = Irssi::settings_get_str("mime_magic");

    if ($mfile ne "") {
        Irssi::printformat(MSGLEVEL_CRAP, 'load_mime_magic', $mfile);
        $magic = File::MMagic::new($mfile);
    }

    if ( not -d Irssi::settings_get_str("mime_temp_dir")) {

        Irssi::printformat(MSGLEVEL_CRAP, 'no_temp_dir',
            Irssi::settings_get_str("mime_temp_dir"));

        Irssi:settings_set_str("mime_temp_dir", "/tmp");

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

##
# background_exec
#
# fork and execute
#
sub background_exec {
  my ($witem, $signed, $sender, $type, $cmd) = @_;

  if ($signed == -1) {
    $format = "mime_data_received";
  } elsif ($signed == 0) {
    $format = "mime_data_received_signed";
  } elsif ($signed == 1) {
    $format = "mime_data_received_unknown";
  } elsif ($signed == 2) {
    $format = "mime_data_received_failed";
  }

  if ($witem->{type}) {
    $witem->printformat(MSGLEVEL_CRAP, $format, $sender, $type);
  } else {
    Irssi::printformat(MSGLEVEL_CRAP, $format, $sender, $type);
  }

  Irssi::command("EXEC " . Irssi::settings_get_str("mime_exec_param") .
		 $cmd);
}

my %partial;

##
# process_mime_entity(WI_ITEM_REC, $signed, $sender, MIME::Entity $msg)
#
# -1 failure, 0 success
sub process_mime_entity {
  my ($witem, $signed, $sender, $entity) = @_;

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
      ($fh, $partial{$mimetype->id}{name})= tempfile("msg-XXXXXXXX", SUFFIX => ".dat", DIR => Irssi::settings_get_str("mime_temp_dir"));
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
    $parser->output_dir(Irssi::settings_get_str("mime_temp_dir"));
    $mime = $parser->parse_open($tempfile);

    $ret = process_mime_entity($witem, $signed, $sender, $mime);

    $parser->filer->purge;
    unlink $tempfile;
    return $ret;

  }

  # we could check for */parityfec (RTP packets) rfc2733, 3009

  # save to temporary file
  ($fh, $tempfile) = tempfile("msg-XXXXXXXX", SUFFIX => ".dat", DIR => Irssi::settings_get_str("mime_temp_dir"));
  if ($io = $entity->open("r")) {
    while (defined($_ = $io->getline)) { print $fh $_; }
    $io->close;
  }
  close $fh;  

  # try to handle it
  foreach $mcap (@mcaps) {

    $cmd = $mcap->viewCmd($mimetype->type, $tempfile);
    next if not defined $cmd;

    background_exec($witem, $signed, $sender, $mimetype->type, $cmd);
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
    $parser->output_dir(Irssi::settings_get_str("mime_temp_dir"));
    $mime = $parser->parse_data(unescape($blob));

    $ret = process_mime_entity($witem, $verified, $sender, $mime);

    $parser->filer->purge;

    if ($ret == 1) {
        Irssi::signal_stop();
    } elsif  ($ret == -1) {
        return;
    } else {
        $theme = $witem->{theme} || Irssi::current_theme;
	$format = $theme->get_format("fe-common/silc", "message_data");
	$format =~ s/\$0/$sender/;
	$format =~ s/\$1/$ret/;
	if ($witem->{type}) {
            $witem->print($theme->format_expand($format));
        } else {
            Irssi::print($theme->format_expand($format));
        }
        Irssi::signal_stop();
    }
}

##
# cmd_mmsg
#
# Sends a file with a given MIME type and transfer encoding.
#
# MMSG [<-sign>] [<-channel>] <target> <file> [<type>  [<encoding>]]
#
# Sends a private data message to other user in the network.  The message
# will be send as a MIME encoded data message.
#
# If -channel option is provided then this command actually send channel
# message to the specified channel.  The message IS NOT private message, it
# is normal channel message.
#
# If the -sign optin is provided, the message will be additionally
# signed.
#
# Messages that exceed roughly 64k have to be split up into smaller packets.
# This is done automatically.
#
# If no transfer-encoding is given it defaults to binary or 7bit for messages
# that have to be split up.
#
# If no content-type is given it is guessed using a MIME magic file.
#
# Settings
#
#   mime_magic            - path to MIME magic file, or internal 
#                           defaults if empty
#   mime_default_encoding - encoding to use if none specified
#   mime_temp_dir         - where to store temporary files
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

    ($sign, $is_channel, $target, $file, $type, $encoding) =
        $data =~ /^\s*(?:(-sign)?\s+)?    # match the -sign
		  \s*(?:(-channel)?\s+)?  # match the -channel
	          (\*|\S+)\s+             # target
		  (\S+)                   # filename
		  (?:\s+(\S+)             # mime type
		     (?:\s+(\S+))?)?\s*   # encoding
		 $/ix;

    Irssi::printformat(MSGLEVEL_CRAP, 'mmsg_parameters'), return
        if ($target eq "") or ($file eq "");

    Irssi::printformat(MSGLEVEL_CRAP, 'mmsg_file', $file), return
        if not ( -f $file );

    $type = $magic->checktype_filename($file)
        if not defined $type;
    $encoding = Irssi::settings_get_str("mime_default_encoding")
        if not defined $encoding;

    # does the target exist? we don't test that... especially the
    # -channel parameter is ignored :/

    if ($target eq "*") {

      $is_channel = ($witem->{type} eq "CHANNEL" ? "-channel" : "");
      $target = $witem->{name};

    }

    $entity = new MIME::Entity->build(
        'MIME-Version' => "1.0",
    	Encoding       => $encoding,
	Type	       => $type,
	Path	       => $file
    );

    ($fh, $tempfile) = tempfile( DIR => Irssi::settings_get_str("mime_temp_dir"));
    $entity->print($fh);
    close $fh;

    $is_channel = (lc($is_channel) eq "-channel" ? 1 : 0);
    $sign = (lc($sign) eq "-sign" ? 1 : 0);

    if ($is_channel) {
      $dest = $server->channel_find($target);
    } else {
      $dest = $server->query_find($target);
    }

    
    # 21:27 <@pekka> c0ffee: the core routines will crop the message if it
    #                doesn't fit.. I would use a bit shorter than the MAX_LEN
    # 21:28 <@pekka> c0ffee: -1024 bytes is sufficient
    # 21:28 <@pekka> c0ffee: should be sufficient in all possible cases
    if ((stat($tempfile))[7] < 0xfbff) {
      $format = ($sign ? "mime_data_send_signed" : "mime_data_send");
      if ($dest->{type}) {
        $dest->printformat(MSGLEVEL_CRAP, $format, $type);
      } else {
        Irssi::printformat(MSGLEVEL_CRAP, $format, $type);
      }

      unlink $tempfile;
      Irssi::signal_emit("mime-send", $server, \$is_channel,
			 $target, escape($entity->stringify), \$sign);
    } else {

      $format = ($sign ? "mime_data_multi_signed" : "mime_data_multi");
      $chunks = ceil((stat $tempfile)[7] / 0xfb00);
      if ($dest->{type}) {
        $dest->printformat(MSGLEVEL_CRAP, $format, $type, $chunks);
      } else {
        Irssi::printformat(MSGLEVEL_CRAP, $format, $type, $chunks);
      }

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
        Irssi::signal_emit("mime-send", $server, \$is_channel,
				$target, escape($entity->stringify), \$sign);

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
Irssi::settings_add_bool("misc", "mime_unlink_tempfiles", 1);
Irssi::settings_add_str("misc", "mime_default_encoding", "binary");
Irssi::settings_add_bool("misc", "mime_verbose", 0);
Irssi::settings_add_str("misc", "mime_temp_dir", "/tmp");
Irssi::settings_add_str("misc", "mime_magic", "");
Irssi::settings_add_str("misc", "mime_exec_param", "");

# Init
Irssi::theme_register(['load_mailcap', 'Loading mailcaps from {hilight $0}',
	'load_mailcap_fail', 'Couldn\'t find {hilight $0}',
	'message_partial_failure', 'message/partial: {hilight $0-}',
	'mmsg_chattype', 'command was not designed for this chat type',
	'mmsg_parameters', 'not enough parameters given',
	'mmsg_file', 'File {hilight $0} not found',
	'load_mime_magic', 'Loading MIME magic types from {hilight $0}',
	'no_temp_dir', 'Directory {hilight $0} does not exist, defaulting to /tmp',
	'mime_data_received', '{nick $0} sent "{hilight $1}" data message',
	'mime_data_received_signed', '{nick $0} sent "{hilight $1}" data message (signature {flag_signed})',
	'mime_data_received_unknown', '{nick $0} sent "{hilight $1}" data message (signature {flag_unknown})',
	'mime_data_received_failed', '{nick $0} sent "{hilight $1}" data message (signature {flag_failed})',
	'mime_data_send', 'sending "{hilight $0}" data message',
	'mime_data_send_signed', 'sending "{hilight $0}" data message (signature {flag_signed})',
	'mime_data_multi', 'sending "{hilight $0}" data message ($1 chunks)',
	'mime_data_multi_signed', 'sending "{hilight $0}" data message ($1 chunks, signaute {flag_signed})']);



read_mime_database();
