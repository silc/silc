# $Id$

use Irssi 20020121.2020 ();
$VERSION = "0.10";
%IRSSI = (
	  authors     => 'Jean-Yves "decadix" Lefort',
	  contact     => 'jylefort\@brutele.be, decadix on IRCNet',
	  name        => 'beep',
	  description => 'Replaces your terminal bell by a command specified via /set; adds a beep_when_not_away setting',
	  license     => 'BSD',
	  changed     => '$Date$ ',
);

# /set's:
#
#	beep_when_not_away	opposite of builtin beep_when_away
#
#	beep_command		if not empty, the specified command will be
#				executed instead of the normal terminal bell

use strict;

sub beep {
  my $server = Irssi::active_server;
  if ($server && ! $server->{usermode_away}
      && ! Irssi::settings_get_bool("beep_when_not_away")) {
    Irssi::signal_stop();
  } else {
    if (my $command = Irssi::settings_get_str("beep_command")) {
      system($command);
      Irssi::signal_stop();
    }
  }
}

Irssi::settings_add_bool("lookandfeel", "beep_when_not_away", 0);
Irssi::settings_add_str("misc", "beep_command",
			"esdplay ~/sound/events/beep.wav &");

Irssi::signal_add("beep", "beep");
