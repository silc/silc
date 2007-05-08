# Microsoft Developer Studio Project File - Name="libsilcclient_static" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libsilcclient_static - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libsilcclient_static.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libsilcclient_static.mak" CFG="libsilcclient_static - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libsilcclient_static - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libsilcclient_static - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "Perforce Project"
# PROP Scc_LocalPath "..\.."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libsilcclient_static - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /W2 /GX /O2 /I ".\\" /I "..\\" /I "..\..\\" /I "..\..\includes" /I "..\..\lib\silccore" /I "..\..\lib\silcske" /I "..\..\lib\silcmath" /I "..\..\lib\silcmath\mpi" /I "..\..\lib\silcutil" /I "..\..\lib\silccrypt" /I "..\..\lib\silcsim" /I "..\..\lib\trq" /I "..\..\lib\silcsftp" /I "..\..\lib\contrib" /I "..\..\lib\silcapputil" /I "..\..\lib\silcvcard" /I "..\..\lib\silchttp" /I "..\..\lib\silcskr" /I "..\..\lib\silcasn1" /D "NDEBUG" /D "WIN32" /D "_MBCS" /D "_LIB" /D "MP_API_COMPATIBLE" /D "HAVE_SILCDEFS_H" /YX /FD /Zm400 /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "libsilcclient_static - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libsilcclient_static___Win32_Debug"
# PROP BASE Intermediate_Dir "libsilcclient_static___Win32_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /W2 /Gm /GX /ZI /Od /I ".\\" /I "..\\" /I "..\..\\" /I "..\..\includes" /I "..\..\lib\silccore" /I "..\..\lib\silcske" /I "..\..\lib\silcmath" /I "..\..\lib\silcmath\mpi" /I "..\..\lib\silcutil" /I "..\..\lib\silccrypt" /I "..\..\lib\silcsim" /I "..\..\lib\trq" /I "..\..\lib\silcsftp" /I "..\..\lib\contrib" /I "..\..\lib\silcapputil" /I "..\..\lib\silcvcard" /I "..\..\lib\silchttp" /I "..\..\lib\silcskr" /I "..\..\lib\silcasn1" /D "_DEBUG" /D "WIN32" /D "_MBCS" /D "_LIB" /D "MP_API_COMPATIBLE" /D "HAVE_SILCDEFS_H" /YX /FD /Zm400 /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "libsilcclient_static - Win32 Release"
# Name "libsilcclient_static - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "silcclient"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\lib\silcclient\client.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_attrs.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_channel.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_connect.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_entry.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_ftp.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_keyagr.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_listener.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_notify.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_prvmsg.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_register.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\command.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\command_reply.c
# End Source File
# End Group
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Group "silcclient No. 1"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\lib\silcclient\client.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_channel.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_connect.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_entry.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_ftp.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_internal.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_keyagr.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_listener.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_notify.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_prvmsg.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\client_register.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\command.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\command_reply.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\silcclient.h
# End Source File
# Begin Source File

SOURCE=..\..\lib\silcclient\silcclient_entry.h
# End Source File
# End Group
# End Group
# End Target
# End Project
