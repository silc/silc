#!/usr/bin/env perl

# Generates the silc manpages from yodl sources.

use strict;

my ($yodl2man, $i, $command);
my (@yodl, @men);

$yodl2man = qx/which yodl2man/;
chomp($yodl2man);

@yodl = ('silc.yo', 'silcd.yo', 'silcd.conf.yo', 'silc.conf.yo');
@men  = ('silc.1', 'silcd.8', 'silcd.conf.5', 'silc.conf.5');

for ($i=0; $i<scalar(@yodl); $i++) {
  if (-e $yodl[$i]) {
    $command = "$yodl2man -o $men[$i] $yodl[$i]"; 
    system("$command");
  }
}
