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

# Global variables
set Targets ""
set Output ""

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
proc parse_args {} {
  global argc argv Targets Output

  # unset this if we find a "--" argument
  set argv_safe $argv
  set parse_args 1
  while {[llength $argv_safe] > 0} {
    set this_arg [lvarpop argv_safe]
    switch -exact -- $this_arg {
      "-o" {
        if {!$parse_args} {lappend Targets $this_arg; continue}
        set next_arg [lvarpop argv_safe]
        if {$next_arg == ""} {
          puts stderr "Error: option requires an argument -- o"
          puts stderr ""
          exit 1
        }
        set Output $next_arg
      }
      "--" {
        if {!$parse_args} {lappend Targets $this_arg; continue}
        set parse_args 0
      }
      default {
        lappend Targets $this_arg
      }
    }
  }

  return
}

# Main
# ---

# check what they gave us
parse_args

if {[llength $Targets] < 1} {
  puts stderr "Usage: ./stripspaces.tcl \[-o output\] <file1> \[file2\] ..."
  puts stderr ""
  exit 1
}

if {([llength $Targets] > 1) && ($Output != "")} {
  if {[file exists $Output]} {
    if {![file isdirectory $Output]} {
      puts stderr "Error: Specified multiple files but output target exists and is not a directory!"
      puts stderr ""
      exit 1
    }
  } else {
    if {[catch {mkdir $Output} errtmp]} {
      puts stderr "Error: Couldn't create directory \"$Output\""
      puts stderr ""
      exit 1
    }
  }
}

set done 0

foreach xfile $Targets {
  if {![file readable $xfile]} {
    puts stderr "Error: Cannot open file \"$xfile\" (skipped)."
    continue
  }

  if {$Output == ""} {
    set xoutput "$xfile.strip"
  } elseif {[file isdirectory $Output]} {
    set xoutput "$Output/$xfile.strip"
  } else {
    set xoutput $Output
  }

  puts stderr "Stripping trailing spaces from \"$xfile\" (output: \"$xoutput\")"
  set ret [do_strip_main $xfile $xoutput]
  if {$ret < 0} {
    puts stderr "$xfile: Failed. Couldn't open the input/output filename."
    puts stderr ""
  } else {
    puts stderr "File $xfile done. Parsed $ret lines."
  }

  incr done
}
