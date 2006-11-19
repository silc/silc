#!/usr/bin/perl -w

#<scriptinfo>
use vars qw($VERSION %IRSSI);

use Irssi 20020519;
$VERSION = "0.3";
%IRSSI = (
    authors	=> "c0ffee",
    contact	=> "c0ffee\@penguin-breeder.org",
    name	=> "sign_messages from silc-plugin",
    description	=> "introduces a setting sign_messages which automatically signs messages",
    license	=> "Public Domain",
    url		=> "http://www.penguin-breeder.org/?page=silc",
    changed	=> "Wed Jan 29 20:55 CET 2003",
);
#</scriptinfo>

sub sig_ownpub {
  my ($server, $msg, $target) = @_;

  if (($server->{chat_type} =~ /^silc$/i) && 
      (Irssi::settings_get_bool("sign_messages"))) {

    Irssi::signal_stop();
    $server->command("SMSG -channel $target $msg");

  }

}

sub sig_sendtext {
  my ($line, $server, $witem) = @_;
  return unless ref $witem;

  if (($server->{chat_type} =~ /^silc$/i) && 
      (Irssi::settings_get_bool("sign_messages"))) {

    return if $line eq "";

    if ($witem->{type} eq "CHANNEL") {
      $target = "-channel $witem->{name}";
    } elsif ($witem->{type} eq "QUERY") {
      $target = "$witem->{name}";
    } else {
      return;
    }

    Irssi::signal_stop();
    $server->command("SMSG $target $line");

  }

}

Irssi::signal_add_first("send text", "sig_sendtext");
Irssi::settings_add_bool("silc", "sign_messages", 0);
