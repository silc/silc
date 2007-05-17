#!/usr/bin/perl

$p = `pwd`;

if($p =~ /.*(\/win32)/)
{
	@dirents = split('/', $p);
	if(@dirents > 2)
	{
		# check dependencies
		print "Checking dependencies\n";
		@statLibSilcDllDebug = stat("libsilc/Debug/libsilc.dll");
		@statLibSilcExpDebug = stat("libsilc/Debug/libsilc.exp");
		@statLibSilcLibDebug = stat("libsilc/Debug/libsilc.lib");
		if(! @statLibSilcDllDebug || ! @statLibSilcExpDebug || ! @statLibSilcLibDebug)
		{
			die "Please rebuild libsilc Debug before creating the distribution\n";
		}
		
		@statLibSilcDllRelease = stat("libsilc/Release/libsilc.dll");
		@statLibSilcExpRelease = stat("libsilc/Release/libsilc.exp");
		@statLibSilcLibRelease = stat("libsilc/Release/libsilc.lib");
		if(! @statLibSilcDllRelease || ! @statLibSilcExpRelease || ! @statLibSilcLibRelease)
		{
			die "Please rebuild libsilc Release before creating the distribution\n";
		}
		
		@statLibSilcClientDllDebug = stat("libsilcclient/Debug/libsilcclient.dll");
		@statLibSilcClientExpDebug = stat("libsilcclient/Debug/libsilcclient.exp");
		@statLibSilcClientLibDebug = stat("libsilcclient/Debug/libsilcclient.lib");
		if(! @statLibSilcClientDllDebug || 
			! @statLibSilcClientExpDebug || 
			! @statLibSilcClientLibDebug || 
			(@statLibSilcClientDllDebug[9] < @statLibSilcDllDebug[9]) ||
			(@statLibSilcClientExpDebug[9] < @statLibSilcExpDebug[9]) ||
			(@statLibSilcClientLibDebug[9] < @statLibSilcLibDebug[9])
			)
		{			
			die "Please rebuild libsilcclient Debug before creating the distribution\n";
		}

		@statLibSilcClientDllRelease = stat("libsilcclient/Release/libsilcclient.dll");
		@statLibSilcClientExpRelease = stat("libsilcclient/Release/libsilcclient.exp");
		@statLibSilcClientLibRelease = stat("libsilcclient/Release/libsilcclient.lib");
		if(! @statLibSilcClientDllRelease || 
			! @statLibSilcClientExpRelease || 
			! @statLibSilcClientLibRelease ||
			(@statLibSilcClientDllRelease[9] < @statLibSilcDllRelease[9]) ||
			(@statLibSilcClientExpRelease[9] < @statLibSilcExpRelease[9]) ||
			(@statLibSilcClientLibRelease[9] < @statLibSilcLibRelease[9])
			)
		{
			die "Please rebuild libsilcclient Release before creating the distribution\n";
		}

		@statLibSilcStaticLibDebug = stat("libsilc_static/Debug/libsilc_static.lib");
		if(! @statLibSilcStaticLibDebug)
		{
			die "Please rebuild libsilc_static Debug before creating the distribution\n";
		}
		
		@statLibSilcStaticLibRelease = stat("libsilc_static/Release/libsilc_static.lib");
		if(! @statLibSilcStaticLibRelease)
		{
			die "Please rebuild libsilc_static Release before creating the distribution\n";
		}
		
		@statLibSilcClientStaticLibDebug = stat("libsilcclient_static/Debug/libsilcclient_static.lib");
		if(! @statLibSilcClientStaticLibDebug || (@statLibSilcClientStaticLibDebug[9] < @statLibSilcStaticLibDebug[9]))
		{			
			die "Please rebuild libsilcclient_static Debug before creating the distribution\n";
		}

		@statLibSilcClientStaticLibRelease = stat("libsilcclient_static/Release/libsilcclient_static.lib");
		if(! @statLibSilcClientStaticLibRelease || (@statLibSilcClientStaticLibRelease[9] < @statLibSilcStaticLibRelease[9]))
		{			
			die "Please rebuild libsilcclient_static Release before creating the distribution\n";
		}

		$index = @dirents - 2;
		$top = @dirents[$index];
		`find . -name \"*.obj\" -exec rm -f \\{} \\;`;
		`find . -name \"*.idb\" -exec rm -f \\{} \\;`;
		`find . -name \"*.pdb\" -exec rm -f \\{} \\;`;
		`find . -name \"*.pch\" -exec rm -f \\{} \\;`;
		`find ../ -name \"*.o\" -exec rm -f \\{} \\;`;
		`find ../ -name \"*.lo\" -exec rm -f \\{} \\;`;
		`find ../ -name \"*.a\" -exec rm -f \\{} \\;`;
		`find ../ -name \"*.la\" -exec rm -f \\{} \\;`;
		`find ../ -name \"*.lai\" -exec rm -f \\{} \\;`;

		push(@excludeList, "--exclude $top/win32/Debug");
		push(@excludeList, "--exclude $top/win32/libsilc/CVS");
		push(@excludeList, "--exclude $top/win32/libsilc/libsilc.plg");
		push(@excludeList, "--exclude $top/win32/libsilcclient/CVS");
		push(@excludeList, "--exclude $top/win32/libsilcclient/libsilcclient.plg");
		push(@excludeList, "--exclude $top/win32/libsilc_static/CVS");
		push(@excludeList, "--exclude $top/win32/libsilc_static/libsilc_static.plg");
		push(@excludeList, "--exclude $top/win32/libsilcclient_static/CVS");
		push(@excludeList, "--exclude $top/win32/libsilcclient_static/libsilcclient_static.plg");
		push(@excludeList, "--exclude $top/win32/silc.ncb");
		push(@excludeList, "--exclude $top/win32/all.plg");
		push(@excludeList, "--exclude $top/win32/buildDistAfterAllReleaseAndDebug.plg");
		push(@excludeList, "--exclude $top/win32/CVS");
		push(@excludeList, "--exclude $top/win32/tests/CVS");
		push(@excludeList, "--exclude $top/win32/libsilc/Debug/libsilc.ilk");
		push(@excludeList, "--exclude $top/win32/libsilc/Debug/libsilc.pdb");
		push(@excludeList, "--exclude $top/win32/libsilcclient/Debug/libsilcclient.ilk");
		push(@excludeList, "--exclude $top/win32/libsilcclient/Debug/libsilcclient.pdb");
		push(@excludeList, "--exclude $top/win32/libsilc/Release/libsilc.ilk");
		push(@excludeList, "--exclude $top/win32/libsilc/Release/libsilc.pdb");
		push(@excludeList, "--exclude $top/win32/libsilcclient/Release/libsilcclient.ilk");
		push(@excludeList, "--exclude $top/win32/silc.opt");
		push(@excludeList, "--exclude $top/win32/tests");
		push(@excludeList, "--exclude $top/apps");
		push(@excludeList, "--exclude $top/doc/CVS");
		push(@excludeList, "--exclude $top/doc/examples/CVS");
		push(@excludeList, "--exclude $top/includes/CVS");
		push(@excludeList, "--exclude $top/lib");
		push(@excludeList, "--exclude $top/tutorial/CVS");
		push(@excludeList, "--exclude $top/tutorial/mybot/CVS");

		$excludes = "";
		foreach $entry(@excludeList)
		{
			$excludes = sprintf("%s%s ", $excludes, $entry);
		}
		
		print "Copying headers\n";
		`rm -rf include`;
		`mkdir -p include`;
		`find ../includes -name \"*.h\" -exec cp \\{} include \\;`;
		`find ../lib -name \"*.h\" -exec cp \\{} include \\;`;
		print "Creating distribution archive.\n";
		`cd ../.. ; tar $excludes -zcvf $top-win32.tgz $top/*` || die "Failed to create distribution\n";	
	}
}
else
{
	die "Please run $0 from the win32 directory of the silc distribution\n";
}

