#! /usr/bin/tcl
#
#  stripspaces.tcl - strip trailing spaces from source files
#
#  Author: Johnny Mnemonic <johnny@themnemonic.org>
#
#  Copyright (C) 2002 Johnny Mnemonic
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#

# Procedures
# ---
proc do_strip_main {in_file out_file} {
  set lines 0
  if {[catch {set fd [open "$in_file" r]} errtmp]} {return -1}
  if {[catch {set fw [open "$out_file" w]} errtmp]} {return -1}

  while {![eof $fd]} {
    set str [string trimright [gets $fd]]
    if {![eof $fd]} {
      incr lines
      puts $fw $str;
    }
  }

  close $fd
  close $fw
  return $lines
}

# Main
# ---
if {$argc < 1} {
  puts stderr "Usage: `./stripspaces.tcl <file> \[output\]'"
  puts stderr ""
  exit 1
}

set in_file [lindex $argv 0]

if {![file readable $in_file]} {
  puts stderr "Error: Cannot open file \"$in_file\"."
  puts stderr ""
  exit 1
}

if {$argc > 1} {
  set out_file [lindex $argv 1]
} else {
  set out_file "$in_file.strip"
}

puts stderr "Stripping trailing spaces from \"$in_file\" (output: \"$out_file\")"

set ret [do_strip_main $in_file $out_file]

if {$ret < 0} {
  puts stderr "Failed. Couldn't open the input/output filename."
  puts stderr ""
} else {
  puts stderr "Done. Parsed $ret lines."
}
