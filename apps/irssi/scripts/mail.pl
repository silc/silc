# Mail counter statusbar item
# for irssi 0.7.99 by Timo Sirainen
#  /SET mail_ext_program - specify external mail checker program
#  /SET mail_file - specifies mbox file location
#  /SET mail_refresh_time - in seconds, how often to check for new mail

use strict;
use Irssi::TextUI;

my $extprog;
my ($last_refresh_time, $refresh_tag);

# for mbox caching
my ($last_size, $last_mtime, $last_mailcount);

sub mbox_count {
  my $mailfile = shift;

  my @stat = stat($mailfile);
  my $size = $stat[7];
  my $mtime = $stat[9];

  # if the file hasn't changed, get the count from cache
  return $last_mailcount if ($last_size == $size && $last_mtime == $mtime);
  $last_size = $size;
  $last_mtime = $mtime;

  my $count;
  if ($extprog ne "") {
    $count = `$extprog`;
    chomp $count;
  } else {
    return 0 if (!open(F, $mailfile));

    $count = 0;
    while (<F>) {
      $count++ if (/^From /);
      $count-- if (/^Subject: .*FOLDER INTERNAL DATA/);
    }
    close(F);
  }

  $last_mailcount = $count;
  return $count;
}

sub mail {
  my ($item, $get_size_only) = @_;

  my $count = mbox_count(Irssi::settings_get_str('mail_file'));
  if ($count == 0) {
    # no mail - don't print the [Mail: ] at all
    if ($get_size_only) {
      $item->{min_size} = $item->{max_size} = 0;
    }
  } else {
    $item->default_handler($get_size_only, undef, $count, 1);
  }
}

sub refresh_mail {
  Irssi::statusbar_items_redraw('mail');
}

sub read_settings {
  $extprog = Irssi::settings_get_str('mail_ext_program');
  my $time = Irssi::settings_get_int('mail_refresh_time');
  return if ($time == $last_refresh_time);

  $last_refresh_time = $time;
  Irssi::timeout_remove($refresh_tag) if ($refresh_tag);
  $refresh_tag = Irssi::timeout_add($time*1000, 'refresh_mail', undef);
}

Irssi::settings_add_str('misc', 'mail_ext_program', '');
Irssi::settings_add_str('misc', 'mail_file', $ENV{'MAIL'});
Irssi::settings_add_int('misc', 'mail_refresh_time', 60);

Irssi::statusbar_item_register('mail', '{sb Mail: $0-}', 'mail');

read_settings();
Irssi::signal_add('setup changed', 'read_settings');
mbox_count(Irssi::settings_get_str('mail_file'));
