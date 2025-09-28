  
  @cls
  @echo off
  
  >nul chcp 437
  setLocal EnableExtensions EnableDelayedExpansion
  
  2>nul mode con cols=88 lines=23
  set "Currentversion=16.4.0"
  set "title=OfficeRTool - 2025/SEP/12 -"
  set "pswindowtitle=$Host.UI.RawUI.WindowTitle = 'Administrator: %title%'"
  title %title%
  
  echo:
  echo ### [!time!] Reset variables
  
  set "buildINI=Build_Info.ini"
  set "SettingsINI=Settings.ini"
  set "OfficeRToolpath=%~dp0"
  set "OfficeRToolpath=%OfficeRToolpath:~0,-1%"
  set "OfficeRToolname=%~n0.cmd"
  
  set "Res______=%windir%\temp\output"
  set "ScriptDir=!OfficeRToolpath!\Data\ps1"
  set "vbs___Dir=!OfficeRToolpath!\Data\vbs"
  
  set F_ConHost=
  if "%~1" == "-ForceConHost" (
    set F_ConHost=V
  )

  :: anything between this {} will be print as is
  set "{=echo:&(echo|set /p =""
  set "}=")"

  set WMI_VB=
  set WMI_CO=
  set WMI_PS=
  set CSV_TA="!OfficeRToolpath!\Data\Core\csv.xsl"

  set hMode=
  set UseHexPS=
  set UseStatusPS=
  set UseCertUtil=
  
  set c_Val=1xxxxxxxxx
  set e_Val=1xxxxxxxxx
  
  set debugMode=
  set inidownpath=
  set inidownarch=
  set inidownlang=
  set AutoPilotMode=
  set DontSaveToIni=true
  set AutoSaveToIni=true
  
  Set Proxy=
  Set ProxyWGet=
  Set ProxyCurl=
  Set ProxyAria=
  Set ProxyBITS=
  Set ProxyInvoke=
  set "http=http://"
  set "Region=PR"
  
  set "SingleNul=>nul"
  set "SingleNulV1=1>nul"
  set "SingleNulV2=2>nul"
  set "SingleNulV3=3>nul"
  set "MultiNul=1>nul 2>&1"
  set "TripleNul=1>nul 2>&1 3>&1"
  
  set Invalid="Invalid"
  set ProductError="ERROR:"
  set ProductNotFound="Not found"
  set ProductNotExist="No Instance(s) Available."
  
  set "hMenu_D=Press Enter To Skip / Press D to Disable"
  set "hMenu_I=Press Enter To Skip / Press I to Install"
  set "hMenu_S=Press Enter To Skip / Press S to Select"
  
  set "CODE=0X0000000000"
  set "ERROR_M=ERROR ###"
  set "ERROR_1=%ERROR_M% MODIFIED -OR MISSING CRITICAL FILES"
  
  set "HeexVBS=%vbs___Dir%\Hex.vbs"
  set "AritVBS=%vbs___Dir%\Arit.vbs"
  set "VB_Help=%OfficeRToolpath%\Data\core\KMS Helper.vbs"
  set "PS_Help=%OfficeRToolpath%\Data\core\KMS Helper.ps1"
  
  set "setup=Bin\setup.exe"
  set "wget=%~dp0Data\Bin\wget.exe"
  set "curl=%~dp0Data\Bin\curl.exe"
  set "aria=%~dp0Data\Bin\aria2c.exe"
  set "handle=%~dp0Data\Bin\handle.exe"
  set "cmdow=%~dp0Data\Bin\cmdow.exe"
  set "upx32=%~dp0Data\Bin\upx32.exe"
  set "valueTool=%~dp0Data\Bin\md5sum.exe"
  set "Hex2Dec=%~dp0Data\Bin\Hex2Dec.exe"
  set "speedtest=%~dp0Data\Bin\speedtest.exe"
  set "latest_S=%~dp0Data\Bin\setup_latest.exe"
  
  set "wt=%USERPROFILE%\AppData\Local\Microsoft\WindowsApps\wt.exe"
  set "ver_reg=[16].[0-9].[0-9][0-9][0-9][0-9][0-9].[0-9][0-9][0-9][0-9][0-9]"
  
  echo ### [!time!] Set debug mode
  if /i "%*" 	EQU "-debug" (
  	echo on
  	set "SingleNul="
  	set "SingleNulV1="
  	set "SingleNulV2="
  	set "SingleNulV3="
  	set "MultiNul="
  	set "TripleNul="
  	set "debugMode=on"
  )
  
  rem x32 Script running under x64 System
  rem thanks mxman2k for code.
  
  :check for x86 under x64 version
  set "hC2r=HKLM\Software\Microsoft\Office\ClickToRun"
  %MultiNul% reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration" /v "ProductReleaseIds" && (
  	set "hC2r=HKLM\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun"
  )
  
  set OSPP_HKLM=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform
  set OSPP_USER=HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform
  set XSPP_HKLM_X32=HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform
  set XSPP_HKLM_X64=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform
  set XSPP_USER=HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform
  
  set "ARGS_LIST="
  set /a ARGS_COUNT=0
  
  :: Get Possible Settings values from template file
  :: Also Count Values And Reset them
  set "FILTER=%SingleNulV2% findstr "=" "!OfficeRToolpath!\Data\template.ini""
  for /f "tokens=1 delims==" %%$ in ('"!FILTER!"') do (
    set "%%$="
    set /a ARGS_COUNT+=1
    set "ARGS_LIST=!ARGS_LIST!,%%$"
  )
  
  :: Reset Settings values from defaults settings file
  set "FILTER=%SingleNulV2% findstr "=" "!OfficeRToolpath!\Data\defaults.ini""
  for /f "tokens=1,2 delims==" %%a in ('"!FILTER!"') do (set "%%a=%%b")
  
  echo ### [!time!] set Variable for x86/x64 path
  SET "SysPath=%Windir%\System32"
  SET "CMDEXE=%Windir%\System32\cmd.exe"
  SET "REGEXE=%Windir%\System32\reg.exe"
  SET "SlmgrEXE=%Windir%\System32\slmgr.vbs"
  SET "CscriptEXE=%Windir%\System32\CScript.exe"
  SET "PowerShellEXE=%Windir%\System32\WindowsPowerShell\v1.0\powershell.exe"
  
  if exist "%systemroot%\Sysnative\reg.exe" if defined PROCESSOR_ARCHITEW6432 (
	SET "SysPath=%Windir%\Sysnative"
  	SET "CMDEXE=%Windir%\Sysnative\cmd.exe"
  	SET "REGEXE=%Windir%\Sysnative\reg.exe"
  	SET "SlmgrEXE=%Windir%\Sysnative\slmgr.vbs"
  	SET "CscriptEXE=%Windir%\Sysnative\CScript.exe"
  	SET "PowerShellEXE=%Windir%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
  	
  	cls
  	timeout 2 /nobreak %SingleNul%
  	echo:
  	echo WARNING ### Script running under x32 Environment
  	echo:
  	echo:
  	if not defined debugMode if not defined AutoTask pause
  )
  
  SET "Path=!SysPath!;%Windir%;!SysPath!\Wbem;!SysPath!\WindowsPowerShell\v1.0\"
  SET "PSModulePath=%ProgramFiles%\WindowsPowerShell\Modules;!SysPath!\WindowsPowerShell\v1.0\Modules"
  
  echo ### [!time!] Check for Invalid path
  echo "%~dp0"| %SingleNul% findstr /L "%% # & ^ ^^ @ $ ~ ! ( )" && (
  	cls
  	echo:
  	echo ERROR ### Invalid path: "%~dp0"
  	echo:
  	Echo Remove special symbols: "%% # & ^ @ $ ~ ! ( )"
  	echo:
  	if not defined debugMode if not defined AutoTask pause
  	%SingleNul% timeout 2 /nobreak
  	goto:TheEndIsNear
  ) || cd /d "!OfficeRToolpath!"
  
  set RunFromRoot=
  for %%# in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do if /i '!OfficeRToolpath!' EQU '%%#:' set RunFromRoot=True
  if defined RunFromRoot (
  	cls
  	echo:
  	echo ERROR ### Invalid path: "%~dp0"
  	echo:
  	Echo Script can't run From Root Drive
  	echo:
  	if not defined debugMode if not defined AutoTask pause
  	%SingleNul% timeout 2 /nobreak
  	goto:TheEndIsNear
  )
  
  echo ### [!time!] Check for admin privileges
  rem Run as administrator, AveYo: ps\VBS version
  %SingleNul% "!SysPath!\fltmc" || ( set "_=call "%~dpfx0" %*"
  	"!PowerShellEXE!" -nop -c start '!CMDEXE!' -args '/d/x/r',$env:_ -verb runas || (
  	"!SysPath!\mshta" vbscript:execute^("createobject(""shell.application"").shellexecute(""!CMDEXE!"",""/d/x/r "" &createobject(""WScript.Shell"").Environment(""PROCESS"")(""_""),,""runas"",1)(window.close)"^))|| (
  	cls & echo:& echo Script elavation failed& pause)
  	exit )
  	
  echo ### [!time!] Verify dll exe ps1 vbs files
  set n_line=
  set missingFiles=
  
  set "binDLL=LibTSforge.dll,A64.dll,SvcTrigger.xml,x64.dll,x86.dll,"KMS Helper.ps1","KMS Helper.vbs""
  for %%# in (!binDLL!) do (
    if not exist "Data\core\%%#" (
      if not defined n_line set n_line=* & echo:
      echo Data\core\%%# IS Missing
  	  set "missingFiles=true"
  ))
  
  set "binDLL=Arit,Hex,OffScrub_O15msi,OffScrub_O16msi,OffScrub03,OffScrub07,OffScrub10,OffScrubc2r,OLicenseCleanup,OSPP"
  for %%# in (!binDLL!) do (
    if not exist "Data\vbs\%%#.vbs" (
      if not defined n_line set n_line=* & echo:
      echo Data\vbs\%%#.vbs IS Missing
  	  set "missingFiles=true"
  ))
  
  set "binDLL=aria2c.exe cleanospp.exe cmdow.exe curl.exe handle.exe hex2dec.exe oscdimg.exe UnRAR.exe upx32.exe speedtest.exe wget.exe setup_latest.exe setup.exe md5sum.exe"
  for %%# in (!binDLL!) do (
    if not exist "Data\bin\%%#" (
      if not defined n_line set n_line=* & echo:
  	  echo Data\bin\%%# IS Missing
  	  set "missingFiles=true"
  ))
  
  set "binDLL=CheckWindowsStatus,Convert_RT_VL,Disable_Size,get_latest_setup_link,get_latest_setup_version,GetInstances,Set_Window,Setup_Complete,termproc_ps,termwnd_ps,XML_PARSER,ZeroCID,KMS4K,Ohook"
  set "binDLL=!binDLL!,Office_Online_Install,Office_Offline_Install,Speed_Test,OffScrubc2r,Get_Latest_Version"
  for %%# in (!binDLL!) do (
    if not exist "Data\ps1\%%#.ps1" (
      if not defined n_line set n_line=* & echo:
      echo Data\ps1\%%#.ps1 IS Missing
  	  set "missingFiles=true"
  ))
  
  if defined missingFiles (
    %SingleNul% timeout 3 /nobreak
  	cls
	echo:
  	echo %ERROR_1%
  	echo:
  	if not defined debugMode if not defined AutoTask pause
  	%SingleNul% timeout 2 /nobreak
  	goto:TheEndIsNear
  )
  
    
  if exist %SettingsINI% (
  	goto :verify_Settings
  )
  
  echo ### [!time!] Build Settings file
  %multinul% copy "!OfficeRToolpath!\Data\template.ini" "!OfficeRToolpath!\%SettingsINI%"
  attrib -r -a -s -h "!OfficeRToolpath!\%SettingsINI%"
  goto :skip_verify
  
  :verify_Settings
  echo ### [!time!] Verify Settings file
  set "BadIni="
  set /a Count=0
  if exist %SettingsINI% (
  	for %%$ in (!Args_list!) do ((type %SettingsINI% | %SingleNul% find /i "%%$=") || set "BadIni=true")
  	((for /f "tokens=*" %%# in ('type %SettingsINI% ^| findstr /r "="') do set /a Count+=1) && (if !Count! GTR !ARGS_COUNT! set "BadIni=true"))
  	if defined BadIni (
  	  %multinul% copy "!OfficeRToolpath!\Data\template.ini" "!OfficeRToolpath!\%SettingsINI%"
  	  attrib -r -a -s -h "!OfficeRToolpath!\%SettingsINI%"
  ))

  :skip_verify
  echo ### [!time!] Read Settings file
  for /f "tokens=1,2 delims==" %%a in ('"%SingleNulV2% type "%~dp0%SettingsINI%""') do (
  	if /i "%%b$" NEQ "$" (
  		for %%$ in (!Args_list!) do (
  			if /i "%%a" EQU "%%$" set "%%a=%%b"
  )))
  	
  echo ### [!time!] Check if WSH is disabled
  for %%$ in (HKCU, HKLM) do (
  	set "WSH_%%$="
  	%MultiNul% %REGEXE% query "%%$\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" && (
  		for /f "tokens=*" %%# in ('"reg query "%%$\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" | more +2"') do (
  			set "wsh_val=%%#"
  			if    "!wsh_val:~21!" EQU "0" 		set "WSH_%%$=SET"
  			if /i "!wsh_val:~24!" EQU "0x0" 	set "WSH_%%$=SET"
  )))
  for %%$ in (HKCU, HKLM) do (
  	if defined WSH_%%$ (
  		%MultiNul% %REGEXE% DELETE "%%$\SOFTWARE\Microsoft\Windows Script Host\Settings" /f /v Enabled || (
  			cls
  			echo ERROR ### WMI FAILURE [E1]
  			echo:
  			echo - Windows script host is disabled
  			echo:
  			if not defined debugMode if not defined AutoTask pause
  			%SingleNul% timeout 2 /nobreak
  			goto:TheEndIsNear
  )))
  
  echo ### [!time!] Check if Winmgmt is disabled
  %SingleNulV2% %REGEXE% query "HKLM\SYSTEM\CurrentControlSet\Services\Winmgmt" /v "Start" | More +2 | %SingleNul% find /i "0x4" && (
  	%MultiNul% sc config Winmgmt start=auto || (
  		cls
  		echo:
  		echo ERROR ### WMI FAILURE [B3]
  		echo:
  		echo - winmgmt service is not working
  		echo:
  		if not defined debugMode if not defined AutoTask pause
  		%SingleNul% timeout 2 /nobreak
  		goto:TheEndIsNear
  ))
  
  if defined WMI_ENGINE (
    if /i !WMI_ENGINE! NEQ VBS if /i !WMI_ENGINE! NEQ WMIC (
	  set WMI_ENGINE=VBS
  ))
  
  if defined Act_Engine (
    if /i !Act_Engine! NEQ VL if /i !Act_Engine! NEQ ZeroCID if /i !Act_Engine! NEQ KMS4K if /i !Act_Engine! NEQ Ohook (
	  set Act_Engine=VL
  )) else (
    set Act_Engine=VL
  )
  
  echo ### [!time!] Check for WMIC Tool
  
  :: First -- WMIC tool check
  %MultiNul% where wmic && (
    %SingleNulV2% wmic path Win32_Processor get AddressWidth /format:%CSV_TA%|%MultiNul% findstr /i /r "^,32$ ^,64$" && (
	  set "WMI_CO=True"
  ))
  
  ver|%MultiNul% find /i "10.0.26100" && Goto:IGNORE_24H2
  :: check if exist such Capability and install it [if necessary]
  (DISM /Online /Get-CapabilityInfo /CapabilityName:WMIC~~~~ | %MultiNul% find /i "State : Not Present") && (
    if defined Force_RESTORE if !Force_RESTORE! EQU 1 (
      echo *** Restore WMIC~~~~ Capability
      %MultiNul% DISM /Online /Add-Capability /CapabilityName:WMIC~~~~
  ))
:IGNORE_24H2
  
  echo ### [!time!] Check for VBSCRIPT Engine
  
  :: Second -- VBS engine check
  (set "WMI_VB_FAILURE=")
  if not exist "%windir%\system32\vbscript.dll" (
    set "WMI_VB_FAILURE=True" )
  cscript .vbs | %MultiNul% find /i "There is no script engine" && (
    set "WMI_VB_FAILURE=True" )

  ver|%MultiNul% find /i "10.0.26100" && Goto:IGNORE_24H2B
  :: check if exist such Capability and install it [if necessary]
  (DISM /Online /Get-CapabilityInfo /CapabilityName:VBSCRIPT~~~~ | %MultiNul% find /i "State : Not Present") && (
	set "WMI_VB_FAILURE=True"
	if defined Force_RESTORE if !Force_RESTORE! EQU 1 (
      echo *** Restore VBSCRIPT~~~~ Capability
      %MultiNul% DISM /Online /Add-Capability /CapabilityName:VBSCRIPT~~~~
  ))
:IGNORE_24H2B
  
  if not defined WMI_VB_FAILURE (
    set "WMI_VB=True" )
  
  :: Switch case, VBS-WMIC found
  :: If not found, USE PS instead
  
  if defined WMI_VB (
    if defined WMI_CO (
	  
	  :: if both tools exist
	  if /i !WMI_ENGINE! EQU VBS (
	    set "WMI_CO=" )
	  if /i !WMI_ENGINE! EQU WMIC (
	    set "WMI_VBS=" )
  ))
  
  if not defined WMI_VB (
    if not defined WMI_CO (
	  set "WMI_PS=True"
  ))
  
  if defined Force_PS (
    if /i '%Force_PS%' EQU '1' (
	set "WMI_VB="
	set "WMI_CO="
    set "WMI_PS=True"
  ))
  
  echo ### [!time!] Download LATEST version information 
  :: Remove current file
  if exist Version_Info.txt (
    del /q Version_Info.txt
  )
  :: Create new file
  >Version_Info.txt (
    %SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Get_Latest_Version.ps1"
  )
  :: validate file
  if exist Version_Info.txt (
    type Version_Info.txt|%MultiNul% find /i "current,"|| (
	  del /q Version_Info.txt
  ))
  
  echo ### [!time!] Check if WMI working properly
  set "wmi_CHECK="
  rem set "WMI_FAILURE_C=true"
  call :query "AddressWidth" "Win32_Processor"
  
  if not exist "%Res______%" (
    set "wmi_CHECK=*"
	goto :WMI_C_BYPASS
  )
  
  (type "%Res______%"|find /i ",">nul)               || set "wmi_CHECK=*"
  (type "%Res______%"|find /i %Invalid%>nul)         && set "wmi_CHECK=*"
  (type "%Res______%"|find /i %ProductError%>nul)    && set "wmi_CHECK=*"
  (type "%Res______%"|find /i %ProductNotExist%>nul) && set "wmi_CHECK=*"
  (type "%Res______%"|find /i %ProductNotFound%>nul) && set "wmi_CHECK=*"
  
  for /f "tokens=1 delims=," %%# in ('"%SingleNulV2% type "%Res______%""') do (
    (echo %%#|%MultiNul% findstr /i /r "^32$ ^64$") || set "wmi_CHECK=*"
  )

:WMI_C_BYPASS
  if defined wmi_CHECK (
  	cls & echo:
  	echo ERROR ### WMI FAILURE [C7]
  	echo:
  	echo - The WMI repository is broken
  	echo - winmgmt service is not working
  	echo - Too many wmi req. running in background
  	echo - Script run in a sandbox / limited environment
  	echo:
  	if not defined debugMode if not defined AutoTask pause
  	%SingleNul% timeout 2 /nobreak
  	goto:TheEndIsNear
  )
  
  %MultiNul% where certutil && (
    set UseCertUtil=*
  )
  
  :: https://reddit.com/r/PowerShell/comments/7qb9fc/shortest_script_challenge_convert_hex_to_ascii/?rdt=35983
  set "Command=-join(('74657374'-split'(..)'|where{$_}|foreach{[convert]::ToByte($_,16)})-as[char[]])"
  for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c "!COMMAND!""`) do if /i '%%#' EQU 'test' set UseHexPS=*
  
  set Status_PS1="@(Get-AuthenticodeSignature '%CMDEXE%' -ErrorAction SilentlyContinue).Status"
  for /f "usebackq tokens=*" %%A in (`"%SingleNulV2% powershell -nop -c !Status_PS1!"`) do (if /i '%%A' EQU 'VALID' (set "UseStatusPS=*"))
  
  rem echo ### [!time!] Check for Latest Certification 
  rem call :Certification_Validation
  
  rem echo ### [!time!] Set Defender Exclusive
  rem %SingleNulV2% %PowerShellEXE% -nop -c "Add-MpPreference -ExclusionPath '%~dp0','%~dp0Data\','%~dp0Data\core\','%~dp0Data\Bin\'"
  
  echo ### [!time!] Get Process ID Info
  call :GetPID
  
  :: Get NT.X version
  for /F "tokens=4,6 delims=[]. " %%a in ('ver') do (
  	set /a NT_X=%%a
  	set /a W_Build=%%b
  )
  
  rem XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX rem
  
  rem Identify WindowsTerminal process ID · Issue #5694
  rem https://github.com/microsoft/terminal/issues/5694
  
  rem DISCUSSION- Is my app running in Terminal- · Issue #7434
  rem https://github.com/microsoft/terminal/issues/7434
  
  rem Terminal- add support for Window Manipulation (CSI t, resize)· Issue #5
  rem https://github.com/microsoft/terminal/issues/5094
  
  rem Terminal Problem's ... Get ID ... Mode con ?? more ?
  rem fix the script to support the new buggy terminal
  rem all couple ways to deal with this s*** .........
  rem hope i did good, anyway also add in settings, 
  rem new option called ForceConhost, set to 0 ->
  rem to force use ForceConhost !
  rem thanks zadjii-msft for the idea, #13911
  
  rem XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX rem
  
  
  :: this check available only in w11
  :: where you can set terminal as default app
  :: terminal is not shown as parent process,
  :: it is attach by api's etc etc etc
  
  :: if case DelegationConsole special keys not found
  :: cmd / conhost will always be Parent, sub proces, sub sub process
  :: handle check will work, even in such case,
  
  :: but i prefere to do seperatation,
  :: if delegate keys     found, do handle check
  :: if delegate keys not found, do parent process check
  
  :: so to make things more clear
  :: we can do just handles check, since it rely on API
  :: but parent process check, can fail when delegate keys not set **
  :: even in the case wt is shown as parent process, it's not the parent
  
  :: ** Terminal is not the default host
  
  call :Terminal_Handle_Check
   
  :: case both selected, choice TERMINAL
  if /i "!Force_Conhost!" EQU "1" if "!Force_Terminal!" EQU "1" (
    set "Force_Conhost=0"
  )
  
  :: Inside console, force disable, avoid boot loop
  if not defined terminalFound set Force_Conhost=0
  
  :: Inside terminal, force disable, avoid boot loop
  if     defined terminalFound set Force_Terminal=0
  
  :: Search For NT10.X version / WT.exe full path
  if !NT_X! LSS 10     set Force_Terminal=0
  if not exist "%wt%"  set Force_Terminal=0

  if defined F_ConHost (
    
    :: it will only run after terminal lunch fail
    :: only in console host ,,, 
    
    set "Force_Conhost=0"
    set "Force_Terminal=0"
  )
  
  if not defined AutoTask (
    if "!Force_Terminal!" EQU "1" (
      start "" /I "%wt%" "!OfficeRToolpath!\!OfficeRToolname!" %*
      exit
    )
  	
    if "!Force_Conhost!" EQU "1" (
      start "" /I "conhost" cmd /c "!OfficeRToolpath!\!OfficeRToolname!" %*
      exit
    )
  )

  echo ### [!time!] Disable Size Button
  %MultiNul% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Disable_Size.ps1"
  
  echo ### [!time!] Check for multiple instances
  call :GetCount
  
  color 0F
  call :Change_Size 88 23
  
  if defined WMI_FAILURE_C (
  	cls
	echo:
  	echo %ERROR_2%
  	echo:
  	if not defined debugMode if not defined AutoTask pause
  	%SingleNul% timeout 2 /nobreak
  	goto:TheEndIsNear
  )
  
::===============================================================================================================
:: Set Settings
::===============================================================================================================
  
  if !NT_X! NEQ 10    goto :Skip_Check
  if defined AutoTask goto :Skip_Check
  
  echo ### [!time!] Check for Latest Setup file
  
  (set web_ver=)
  (set web_ver_str=)
  (set web_ver_val=)
  set "ver_dat=%windir%\temp\ver-his.dat"
  set "ver_filter=findstr /i /r "[setup.exe]*[version]*%ver_reg%" %ver_dat%"
  
  set "ODT_SETUP=%windir%\temp\setup.exe"
  set "ODT_LATEST=%windir%\temp\officedeploymenttool_latest.exe"
  set "setup_url=https://officecdn.microsoft.com/%region%/wsus/setup.exe"
  set "ver_url=https://learn.microsoft.com/en-us/officeupdates/odt-release-history"
  
  if not exist "%latest_S%" (
  
    echo ### [!time!] Download Latest Setup file
    
    set web_lnk=
    for /f "usebackq tokens=*" %%A in (`"%SingleNulV2% powershell -nop -ep bypass -file "%ScriptDir%\get_latest_setup_link.ps1""`) do set "web_lnk=%%A"
    
    if not defined web_lnk (goto :version_skip)
    REM "%wget%" --quiet --no-check-certificate %ProxyWGet% --limit-rate %Speed_Limit% "%setup_url%" --output-document="%ODT_SETUP%"
    
    %multinul% del /q "%ODT_LATEST%"
    %multinul% del /q "%ODT_SETUP%"
    %multinul% powershell -nop -ep bypass "(New-Object System.Net.WebClient).DownloadFile('!web_lnk!', '%ODT_LATEST%')"
    
    if exist %ODT_LATEST% (%ODT_LATEST% /passive /quiet /extract:"c:\Windows\Temp")
    if not exist %ODT_SETUP% (goto :version_skip)
    
    if !errorlevel! EQU 0 (
      if defined Compress_With_Upx if "!Compress_With_Upx!" EQU "1" (
  	  %multinul% copy "%ODT_SETUP%" "%windir%\temp\setup_.exe"
  	  %multinul% "%upx32%" -8 --force "%windir%\temp\setup_.exe" && (%multinul% move /y "%windir%\temp\setup_.exe" "%ODT_SETUP%") || (%multinul% del /q "%windir%\temp\setup_.exe")
  	)
  	%multinul% move /y "%ODT_SETUP%" "%latest_S%"
      %multinul% del /q "%ODT_SETUP%"
  	%multinul% del /q "%ODT_LATEST%"
    )
    
    if exist "%latest_S%" (goto :version_skip)
    goto :Skip_Check
  )
  
  %multinul% del /q %ver_dat%
  if defined AutoTask (
    goto :version_skip
  )
  
  rem apply new fix to hide the damn blue title using iwr
  rem https://stackoverflow.com/questions/18770723/hide-progress-of-invoke-webrequest
  
  for /f "usebackq tokens=*" %%A in (`"%SingleNulV2% powershell -nop -ep bypass -file "%ScriptDir%\get_latest_setup_version.ps1""`) do set "web_ver=%%A"
  
  if defined web_ver (
    goto :version_found_PS
  )
  goto :version_skip
  
  REM if not defined terminalFound (
    REM :: first try with special PS script
    REM for /f "usebackq tokens=*" %%A in (`"%SingleNulV2% powershell -nop -ep bypass -file "%ScriptDir%\get_latest_setup_version.ps1""`) do set "web_ver=%%A"
    REM if defined web_ver (goto :version_found_PS)
  REM )
  
  REM :: if not try with wget / findstr
  REM "%wget%" --quiet --no-check-certificate %ProxyWGet% --limit-rate %Speed_Limit% "%ver_url%" --output-document=%ver_dat%
  REM if !errorlevel! EQU 0 if exist %ver_dat% (
    REM for /f "tokens=*" %%k in ('"%ver_filter%"') do ((set "web_ver_val=%%k!") & goto :version_found)
  REM )
  
  REM (goto :version_skip)
  
REM :version_found

  REM for %%$ in (!web_ver_val!) do (
    REM (set web_ver_str=)
    REM (set web_ver_str=%%$)
    REM if "!web_ver_str:~0,3!" EQU "16." (
  	REM (>%ver_dat% echo !web_ver_str:~0,16!)
      REM (%multinul% findstr /r "%ver_reg%" %ver_dat%) && (
  	  REM <%ver_dat% set /p "web_ver="
    REM ))
  REM )
  
:version_found_PS
  
  (set loc_ver=)
  set VER_PS_CMD="@(Get-ItemProperty -lit '%latest_S%').VersionInfo.FileVersion"
  for /f "usebackq tokens=*" %%A in (`"%SingleNulV2% powershell -nop -c !VER_PS_CMD!"`) do set "loc_ver=%%A"
  if defined Auto_Update if defined web_ver if defined loc_ver if !web_ver! NEQ !loc_ver! if "!Auto_Update!" EQU "1" (
  
    echo *** Update Latest Setup file
    set web_lnk=
    for /f "usebackq tokens=*" %%A in (`"%SingleNulV2% powershell -nop -ep bypass -file "%ScriptDir%\get_latest_setup_link.ps1""`) do set "web_lnk=%%A"
    if not defined web_lnk (goto :version_skip)
    REM "%wget%" --quiet --no-check-certificate %ProxyWGet% --limit-rate %Speed_Limit% "%setup_url%" --output-document="%ODT_SETUP%"
    
    %multinul% del /q "%ODT_SETUP%"
    %multinul% del /q "%ODT_LATEST%"
    %multinul% powershell -nop -ep bypass "(New-Object System.Net.WebClient).DownloadFile('!web_lnk!', '%ODT_LATEST%')"
    if exist %ODT_LATEST% (%ODT_LATEST% /passive /quiet /extract:"c:\Windows\Temp")
    if not exist %ODT_SETUP% (goto :version_skip)
    
    if !errorlevel! EQU 0 (
      if defined Compress_With_Upx if "!Compress_With_Upx!" EQU "1" (
  	  %multinul% copy "%windir%\temp\setup.exe" "%windir%\temp\setup_.exe"
        %multinul% "%upx32%" -8 --force "%windir%\temp\setup_.exe" && (%multinul% move /y "%windir%\temp\setup_.exe" "%windir%\temp\setup.exe") || (%multinul% del /q "%windir%\temp\setup_.exe")
  	)
      %multinul% move /y "%windir%\temp\setup.exe" "%latest_S%"
  	%multinul% del /q "%ODT_LATEST%"
      %multinul% del /q "%ODT_SETUP%"
    )
  )
  
:version_skip

  if defined Compatible_Mode if !Compatible_Mode! NEQ 1 (
    set "setup=Bin\setup_latest.exe"
  )

:Skip_Check

  if /i '!Auto_Skip!' NEQ '1' (set "Auto_Skip=")
  if /i "!region!" NEQ "PR" if /i "!region!" NEQ "DB" if /i "!region!" NEQ "SG" (set "region=PR")

  echo ### [!time!] Setup Application List
    
  :: Table of conditions and products (Condition | Product Name)
  set "table[0]=_MondoRetail|Office Mondo Grande Suite"
  set "table[1]=_MondoVolume|Office Mondo Grande Suite"
  set "table[2]=_PersonalRetail|Office Personal 2016 Retail"
  set "table[3]=_Personal2019Retail|Office Personal 2019 Retail"
  set "table[4]=_Personal2021Retail|Office Personal 2021 Retail"
  set "table[5]=_Personal2024Retail|Office Personal 2024 Retail"
  set "table[6]=_HomeBusinessRetail|Microsoft Home And Business"
  set "table[7]=_HomeBusiness2019Retail|Microsoft Home And Business 2019"
  set "table[8]=_HomeBusiness2021Retail|Microsoft Home And Business 2021"
  set "table[9]=_HomeBusiness2024Retail|Microsoft Home And Business 2024"
  set "table[10]=_HomeStudentRetail|Microsoft Home And Student"
  set "table[11]=_HomeStudent2019Retail|Microsoft Home And Student 2019"
  set "table[12]=_HomeStudent2021Retail|Microsoft Home And Student 2021"
  set "table[13]=_HomeStudent2024Retail|Microsoft Home And Student 2024"
  set "table[14]=_O365BusinessEEANoTeamsRetail|Microsoft 365 Apps for Business"
  set "table[15]=_O365BusinessRetail|Microsoft 365 Apps for Business"
  set "table[16]=_O365HomePremRetail|Microsoft 365 Home Premium retail"
  set "table[17]=_O365ProPlusEEANoTeamsRetail|Microsoft 365 Apps for Enterprise"
  set "table[18]=_O365ProPlusRetail|Microsoft 365 Apps for Enterprise"
  set "table[19]=_O365SmallBusPremRetail|Microsoft 365 Small Business retail"
  set "table[20]=_O365AppsBasicRetail|microsoft 365 Basic"
  set "table[21]=_ProfessionalRetail|Professional Retail"
  set "table[22]=_Professional2019Retail|Professional 2019 Retail"
  set "table[23]=_Professional2021Retail|Professional 2021 Retail"
  set "table[24]=_Professional2024Retail|Professional 2024 Retail"
  
  :: Define app table: AppFlag|DefaultID|ZeroCID_ID|DisplayName
  set "AppList[0]=_AppxVisio|6bf301c1-b94a-43e9-ba31-d494598c47fb|295B2C03-4B1C-4221-B292-1411F468BD02|Visio Professional UWP Appx"
  set "AppList[1]=_AppxProject|4f414197-0fc2-4c01-b68a-86cbb9ac254c|82F502B5-B0B0-4349-BD2C-C560DF85B248|Project Professional UWP Appx"
  set "AppList[2]=_UWPappINSTALLED|4f414197-0fc2-4c01-b68a-86cbb9ac254c|82F502B5-B0B0-4349-BD2C-C560DF85B248|Office UUP Apps"
  set "AppList[3]=_OneNoteRetail|d8cace59-33d2-4ac7-9b1b-9b72339c51c8|23B672DA-A456-4860-A8F3-E062A501D7E8|OneNote 2016 SingleApp"
  set "AppList[4]=_OneNoteVolume|d8cace59-33d2-4ac7-9b1b-9b72339c51c8|23B672DA-A456-4860-A8F3-E062A501D7E8|OneNote 2016 SingleApp"
  set "AppList[5]=_OneNote2021Retail|d8cace59-33d2-4ac7-9b1b-9b72339c51c8|23B672DA-A456-4860-A8F3-E062A501D7E8|OneNote 2021 SingleApp"
  set "AppList[6]=_OneNote2024Retail|d8cace59-33d2-4ac7-9b1b-9b72339c51c8|23B672DA-A456-4860-A8F3-E062A501D7E8|OneNote 2024 SingleApp"
  set "AppList[7]=_WordRetail|bb11badf-d8aa-470e-9311-20eaf80fe5cc|C3000759-551F-4F4A-BCAC-A4B42CBF1DE2|Word 2016 SingleApp"
  set "AppList[8]=_WordVolume|bb11badf-d8aa-470e-9311-20eaf80fe5cc|C3000759-551F-4F4A-BCAC-A4B42CBF1DE2|Word 2016 SingleApp"
  set "AppList[9]=_Word2019Retail|059834fe-a8ea-4bff-b67b-4d006b5447d3|FE5FE9D5-3B06-4015-AA35-B146F85C4709|Word 2019 SingleApp"
  set "AppList[10]=_Word2019Volume|059834fe-a8ea-4bff-b67b-4d006b5447d3|FE5FE9D5-3B06-4015-AA35-B146F85C4709|Word 2019 SingleApp"
  set "AppList[11]=_Word2021Retail|ABE28AEA-625A-43B1-8E30-225EB8FBD9E5|0C728382-95FB-4A55-8F12-62E605F91727|Word 2021 SingleApp"
  set "AppList[12]=_Word2021Volume|ABE28AEA-625A-43B1-8E30-225EB8FBD9E5|0C728382-95FB-4A55-8F12-62E605F91727|Word 2021 SingleApp"
  set "AppList[13]=_Word2024Retail|D0EDED01-0881-4B37-9738-190400095098|06142AA2-E935-49CA-AF5D-08069A3D84F3|Word 2024 SingleApp"
  set "AppList[14]=_Word2024Volume|D0EDED01-0881-4B37-9738-190400095098|06142AA2-E935-49CA-AF5D-08069A3D84F3|Word 2024 SingleApp"
  set "AppList[15]=_AccessRetail|67C0FC0C-DEBA-401B-BF8B-9C8AD8395804|3B2FA33F-CD5A-43A5-BD95-F49F3F546B0B|Access 2016 SingleApp"
  set "AppList[16]=_AccessVolume|67C0FC0C-DEBA-401B-BF8B-9C8AD8395804|3B2FA33F-CD5A-43A5-BD95-F49F3F546B0B|Access 2016 SingleApp"
  set "AppList[17]=_Access2019Retail|9E9BCEEB-E736-4F26-88DE-763F87DCC485|385B91D6-9C2C-4A2E-86B5-F44D44A48C5F|Access 2019 SingleApp"
  set "AppList[18]=_Access2019Volume|9E9BCEEB-E736-4F26-88DE-763F87DCC485|385B91D6-9C2C-4A2E-86B5-F44D44A48C5F|Access 2019 SingleApp"
  set "AppList[19]=_Access2021Retail|1FE429D8-3FA7-4A39-B6F0-03DDED42FE14|AE17DB74-16B0-430B-912F-4FE456E271DB|Access 2021 SingleApp"
  set "AppList[20]=_Access2021Volume|1FE429D8-3FA7-4A39-B6F0-03DDED42FE14|AE17DB74-16B0-430B-912F-4FE456E271DB|Access 2021 SingleApp"
  set "AppList[21]=_Access2024Retail|72E9FAA7-EAD1-4F3D-9F6E-3ABC090A81D7|F748E2F7-5951-4BC2-8A06-5A1FBE42F5F4|Access 2024 SingleApp"
  set "AppList[22]=_Access2024Volume|72E9FAA7-EAD1-4F3D-9F6E-3ABC090A81D7|F748E2F7-5951-4BC2-8A06-5A1FBE42F5F4|Access 2024 SingleApp"
  set "AppList[23]=_ExcelRetail|C3E65D36-141F-4D2F-A303-A842EE756A29|685062A7-6024-42E7-8C5F-6BB9E63E697F|Excel 2016 SingleApp"
  set "AppList[24]=_ExcelVolume|C3E65D36-141F-4D2F-A303-A842EE756A29|685062A7-6024-42E7-8C5F-6BB9E63E697F|Excel 2016 SingleApp"
  set "AppList[25]=_Excel2019Retail|237854E9-79FC-4497-A0C1-A70969691C6B|05CB4E1D-CC81-45D5-A769-F34B09B9B391|Excel 2019 SingleApp"
  set "AppList[26]=_Excel2019Volume|237854E9-79FC-4497-A0C1-A70969691C6B|05CB4E1D-CC81-45D5-A769-F34B09B9B391|Excel 2019 SingleApp"
  set "AppList[27]=_Excel2021Retail|EA71EFFC-69F1-4925-9991-2F5E319BBC24|9DA1ECDB-3A62-4273-A234-BF6D43DC0778|Excel 2021 SingleApp"
  set "AppList[28]=_Excel2021Volume|EA71EFFC-69F1-4925-9991-2F5E319BBC24|9DA1ECDB-3A62-4273-A234-BF6D43DC0778|Excel 2021 SingleApp"
  set "AppList[29]=_Excel2024Retail|CBBBA2C3-0FF5-4558-846A-043EF9D78559|523FBBAB-C290-460D-A6C9-48E49709CB8E|Excel 2024 SingleApp"
  set "AppList[30]=_Excel2024Volume|CBBBA2C3-0FF5-4558-846A-043EF9D78559|523FBBAB-C290-460D-A6C9-48E49709CB8E|Excel 2024 SingleApp"
  set "AppList[31]=_OutlookRetail|EC9D9265-9D1E-4ED0-838A-CDC20F2551A1|50059979-AC6F-4458-9E79-710BCB41721A|Outlook 2016 SingleApp"
  set "AppList[32]=_OutlookVolume|EC9D9265-9D1E-4ED0-838A-CDC20F2551A1|50059979-AC6F-4458-9E79-710BCB41721A|Outlook 2016 SingleApp"
  set "AppList[33]=_Outlook2019Retail|C8F8A301-19F5-4132-96CE-2DE9D4ADBD33|92A99ED8-2923-4CB7-A4C5-31DA6B0B8CF3|Outlook 2019 SingleApp"
  set "AppList[34]=_Outlook2019Volume|C8F8A301-19F5-4132-96CE-2DE9D4ADBD33|92A99ED8-2923-4CB7-A4C5-31DA6B0B8CF3|Outlook 2019 SingleApp"
  set "AppList[35]=_Outlook2021Retail|A5799E4C-F83C-4C6E-9516-DFE9B696150B|45BF67F9-0FC8-4335-8B09-9226CEF8A576|Outlook 2021 SingleApp"
  set "AppList[36]=_Outlook2021Volume|A5799E4C-F83C-4C6E-9516-DFE9B696150B|45BF67F9-0FC8-4335-8B09-9226CEF8A576|Outlook 2021 SingleApp"
  set "AppList[37]=_Outlook2024Retail|BEF3152A-8A04-40F2-A065-340C3F23516D|9A1E1BAC-2D8B-4890-832F-0A68B27C16E0|Outlook 2024 SingleApp"
  set "AppList[38]=_Outlook2024Volume|BEF3152A-8A04-40F2-A065-340C3F23516D|9A1E1BAC-2D8B-4890-832F-0A68B27C16E0|Outlook 2024 SingleApp"
  set "AppList[39]=_PowerPointRetail|D70B1BBA-B893-4544-96E2-B7A318091C33|9B4060C9-A7F5-4A66-B732-FAF248B7240F|PowerPoint 2016 SingleApp"
  set "AppList[40]=_PowerPointVolume|D70B1BBA-B893-4544-96E2-B7A318091C33|9B4060C9-A7F5-4A66-B732-FAF248B7240F|PowerPoint 2016 SingleApp"
  set "AppList[41]=_PowerPoint2019Retail|3131FD61-5E4F-4308-8D6D-62BE1987C92C|13C2D7BF-F10D-42EB-9E93-ABF846785434|PowerPoint 2019 SingleApp"
  set "AppList[42]=_PowerPoint2019Volume|3131FD61-5E4F-4308-8D6D-62BE1987C92C|13C2D7BF-F10D-42EB-9E93-ABF846785434|PowerPoint 2019 SingleApp"
  set "AppList[43]=_PowerPoint2021Retail|6E166CC3-495D-438A-89E7-D7C9E6FD4DEA|716F2434-41B6-4969-AB73-E61E593A3875|PowerPoint 2021 SingleApp"
  set "AppList[44]=_PowerPoint2021Volume|6E166CC3-495D-438A-89E7-D7C9E6FD4DEA|716F2434-41B6-4969-AB73-E61E593A3875|PowerPoint 2021 SingleApp"
  set "AppList[45]=_PowerPoint2024Retail|B63626A4-5F05-4CED-9639-31BA730A127E|ECA0D8A6-E21B-4622-9A87-A7103FF14012|PowerPoint 2024 SingleApp"
  set "AppList[46]=_PowerPoint2024Volume|B63626A4-5F05-4CED-9639-31BA730A127E|ECA0D8A6-E21B-4622-9A87-A7103FF14012|PowerPoint 2024 SingleApp"
  set "AppList[47]=_ProPlusRetail|D450596F-894D-49E0-966A-FD39ED4C4C64|C47456E3-265D-47B6-8CA0-C30ABBD0CA36|Office Professional Plus 2016"
  set "AppList[48]=_ProPlusVolume|D450596F-894D-49E0-966A-FD39ED4C4C64|C47456E3-265D-47B6-8CA0-C30ABBD0CA36|Office Professional Plus 2016"
  set "AppList[49]=_ProPlus2019Retail|85DD8B5F-EAA4-4AF3-A628-CCE9E77C9A03|6755C7A7-4DFE-46F5-BCE8-427BE8E9DC62|Office Professional Plus 2019"
  set "AppList[50]=_ProPlus2019Volume|85DD8B5F-EAA4-4AF3-A628-CCE9E77C9A03|6755C7A7-4DFE-46F5-BCE8-427BE8E9DC62|Office Professional Plus 2019"
  set "AppList[51]=_ProPlus2021Retail|fbdb3e18-a8ef-4fb3-9183-dffd60bd0984|3F180B30-9B05-4FE2-AA8D-0C1C4790F811|Office Professional Plus 2021"
  set "AppList[52]=_ProPlus2021Volume|fbdb3e18-a8ef-4fb3-9183-dffd60bd0984|3F180B30-9B05-4FE2-AA8D-0C1C4790F811|Office Professional Plus 2021"
  set "AppList[53]=_ProPlusSPLA2021Volume|fbdb3e18-a8ef-4fb3-9183-dffd60bd0984|3F180B30-9B05-4FE2-AA8D-0C1C4790F811|Office Professional Plus 2021"
  set "AppList[54]=_ProPlus2024Retail|8D368FC1-9470-4BE2-8D66-90E836CBB051|D77244DC-2B82-4F0A-B8AE-1FCA00B7F3E2|Office Professional Plus 2024"
  set "AppList[55]=_ProPlus2024Volume|8D368FC1-9470-4BE2-8D66-90E836CBB051|D77244DC-2B82-4F0A-B8AE-1FCA00B7F3E2|Office Professional Plus 2024"
  set "AppList[56]=_ProPlusSPLA2024Volume|8D368FC1-9470-4BE2-8D66-90E836CBB051|D77244DC-2B82-4F0A-B8AE-1FCA00B7F3E2|Office Professional Plus 2024"
  set "AppList[57]=_ProjectProRetail|4F414197-0FC2-4C01-B68A-86CBB9AC254C|82F502B5-B0B0-4349-BD2C-C560DF85B248|Project Professional 2016"
  set "AppList[58]=_ProjectProVolume|4F414197-0FC2-4C01-B68A-86CBB9AC254C|82F502B5-B0B0-4349-BD2C-C560DF85B248|Project Professional 2016"
  set "AppList[59]=_ProjectProXVolume|829B8110-0E6F-4349-BCA4-42803577788D|16728639-A9AB-4994-B6D8-F81051E69833|Project Professional 2016 C2R"
  set "AppList[60]=_ProjectPro2019Retail|2CA2BF3F-949E-446A-82C7-E25A15EC78C4|D4EBADD6-401B-40D5-ADF4-A5D4ACCD72D1|Project Professional 2019"
  set "AppList[61]=_ProjectPro2019Volume|2CA2BF3F-949E-446A-82C7-E25A15EC78C4|D4EBADD6-401B-40D5-ADF4-A5D4ACCD72D1|Project Professional 2019"
  set "AppList[62]=_ProjectPro2021Retail|76881159-155c-43e0-9db7-2d70a9a3a4ca|17739068-86C4-4924-8633-1E529ABC7EFC|Project Professional 2021"
  set "AppList[63]=_ProjectPro2021Volume|76881159-155c-43e0-9db7-2d70a9a3a4ca|17739068-86C4-4924-8633-1E529ABC7EFC|Project Professional 2021"
  set "AppList[64]=_ProjectPro2024Retail|F510AF75-8AB7-4426-A236-1BFB95C34FF8|2141D341-41AA-4E45-9CA1-201E117D6495|Project Professional 2024"
  set "AppList[65]=_ProjectPro2024Volume|F510AF75-8AB7-4426-A236-1BFB95C34FF8|2141D341-41AA-4E45-9CA1-201E117D6495|Project Professional 2024"
  set "AppList[66]=_ProjectStdRetail|DA7DDABC-3FBE-4447-9E01-6AB7440B4CD4|82E6B314-2A62-4E51-9220-61358DD230E6|Project Standard 2016"
  set "AppList[67]=_ProjectStdVolume|DA7DDABC-3FBE-4447-9E01-6AB7440B4CD4|82E6B314-2A62-4E51-9220-61358DD230E6|Project Standard 2016"
  set "AppList[68]=_ProjectStdXVolume|CBBACA45-556A-4416-AD03-BDA598EAA7C8|431058F0-C059-44C5-B9E7-ED2DD46B6789|Project Standard 2016 C2R"
  set "AppList[69]=_ProjectStd2019Retail|1777F0E3-7392-4198-97EA-8AE4DE6F6381|FDAA3C03-DC27-4A8D-8CBF-C3D843A28DDC|Project Standard 2019"
  set "AppList[70]=_ProjectStd2019Volume|1777F0E3-7392-4198-97EA-8AE4DE6F6381|FDAA3C03-DC27-4A8D-8CBF-C3D843A28DDC|Project Standard 2019"
  set "AppList[71]=_ProjectStd2021Retail|6DD72704-F752-4B71-94C7-11CEC6BFC355|84313D1E-47C8-4E27-8CED-0476B7EE46C4|Project Standard 2021"
  set "AppList[72]=_ProjectStd2021Volume|6DD72704-F752-4B71-94C7-11CEC6BFC355|84313D1E-47C8-4E27-8CED-0476B7EE46C4|Project Standard 2021"
  set "AppList[73]=_ProjectStd2024Retail|9F144F27-2AC5-40B9-899D-898C2B8B4F81|4B6D9B9B-C16E-429D-BABE-8BB84C3C27D6|Project Standard 2024"
  set "AppList[74]=_ProjectStd2024Volume|9F144F27-2AC5-40B9-899D-898C2B8B4F81|4B6D9B9B-C16E-429D-BABE-8BB84C3C27D6|Project Standard 2024"
  set "AppList[75]=_PublisherRetail|041A06CB-C5B8-4772-809F-416D03D16654|FCC1757B-5D5F-486A-87CF-C4D6DEDB6032|Publisher 2016 Single App"
  set "AppList[76]=_PublisherVolume|041A06CB-C5B8-4772-809F-416D03D16654|FCC1757B-5D5F-486A-87CF-C4D6DEDB6032|Publisher 2016 Single App"
  set "AppList[77]=_Publisher2019Retail|9D3E4CCA-E172-46F1-A2F4-1D2107051444|40055495-BE00-444E-99CC-07446729B53E|Publisher 2019 Single App"
  set "AppList[78]=_Publisher2019Volume|9D3E4CCA-E172-46F1-A2F4-1D2107051444|40055495-BE00-444E-99CC-07446729B53E|Publisher 2019 Single App"
  set "AppList[79]=_Publisher2021Retail|AA66521F-2370-4AD8-A2BB-C095E3E4338F|A0234CFE-99BD-4586-A812-4F296323C760|Publisher 2021 Single App"
  set "AppList[80]=_Publisher2021Volume|AA66521F-2370-4AD8-A2BB-C095E3E4338F|A0234CFE-99BD-4586-A812-4F296323C760|Publisher 2021 Single App"
  set "AppList[81]=_SkypeForBusinessRetail|83E04EE1-FA8D-436D-8994-D31A862CAB77|03CA3B9A-0869-4749-8988-3CBC9D9F51BB|Skype For Business 2016 SingleApp"
  set "AppList[82]=_SkypeforBusinessVolume|83E04EE1-FA8D-436D-8994-D31A862CAB77|03CA3B9A-0869-4749-8988-3CBC9D9F51BB|Skype For Business 2016 SingleApp"
  set "AppList[83]=_SkypeForBusiness2019Retail|734C6C6E-B0BA-4298-A891-671772B2BD1B|15A430D4-5E3F-4E6D-8A0A-14BF3CAEE4C7|Skype For Business 2019 SingleApp"
  set "AppList[84]=_SkypeForBusiness2019Volume|734C6C6E-B0BA-4298-A891-671772B2BD1B|15A430D4-5E3F-4E6D-8A0A-14BF3CAEE4C7|Skype For Business 2019 SingleApp"
  set "AppList[85]=_SkypeForBusiness2021Retail|1F32A9AF-1274-48BD-BA1E-1AB7508A23E8|6029109C-CEB8-4EE5-B324-F8EB2981E99A|Skype For Business 2021 SingleApp"
  set "AppList[86]=_SkypeForBusiness2021Volume|1F32A9AF-1274-48BD-BA1E-1AB7508A23E8|6029109C-CEB8-4EE5-B324-F8EB2981E99A|Skype For Business 2021 SingleApp"
  set "AppList[87]=_SkypeForBusiness2024Retail|0002290A-2091-4324-9E53-3CFE28884CDE|3046A03E-2277-4A51-8CCD-A6609EAE8C19|Skype For Business 2024 SingleApp"
  set "AppList[88]=_SkypeForBusiness2024Volume|0002290A-2091-4324-9E53-3CFE28884CDE|3046A03E-2277-4A51-8CCD-A6609EAE8C19|Skype For Business 2024 SingleApp"
  set "AppList[89]=_StandardRetail|DEDFA23D-6ED1-45A6-85DC-63CAE0546DE6|0ED94AAC-2234-4309-BA29-74BDBB887083|Office Standard 2016"
  set "AppList[90]=_StandardVolume|DEDFA23D-6ED1-45A6-85DC-63CAE0546DE6|0ED94AAC-2234-4309-BA29-74BDBB887083|Office Standard 2016"
  set "AppList[91]=_Standard2019Retail|6912A74B-A5FB-401A-BFDB-2E3AB46F4B02|BEB5065C-1872-409E-94E2-403BCFB6A878|Office Standard 2019"
  set "AppList[92]=_Standard2019Volume|6912A74B-A5FB-401A-BFDB-2E3AB46F4B02|BEB5065C-1872-409E-94E2-403BCFB6A878|Office Standard 2019"
  set "AppList[93]=_Standard2021Retail|080A45C5-9F9F-49EB-B4B0-C3C610A5EBD3|223A60D8-9002-4A55-ABAC-593F5B66CA45|Office Standard 2021"
  set "AppList[94]=_Standard2021Volume|080A45C5-9F9F-49EB-B4B0-C3C610A5EBD3|223A60D8-9002-4A55-ABAC-593F5B66CA45|Office Standard 2021"
  set "AppList[95]=_StandardSPLA2021Volume|080A45C5-9F9F-49EB-B4B0-C3C610A5EBD3|223A60D8-9002-4A55-ABAC-593F5B66CA45|Office Standard 2021"
  set "AppList[96]=_Standard2024Retail|bbac904f-6a7e-418a-bb4b-24c85da06187|44A07F51-8263-4B2F-B2A5-70340055C646|Office Standard 2024"
  set "AppList[97]=_Standard2024Volume|bbac904f-6a7e-418a-bb4b-24c85da06187|44A07F51-8263-4B2F-B2A5-70340055C646|Office Standard 2024"
  set "AppList[98]=_StandardSPLA2024Volume|bbac904f-6a7e-418a-bb4b-24c85da06187|44A07F51-8263-4B2F-B2A5-70340055C646|Office Standard 2024"
  set "AppList[99]=_VisioProRetail|6BF301C1-B94A-43E9-BA31-D494598C47FB|295B2C03-4B1C-4221-B292-1411F468BD02|Visio Professional 2016"
  set "AppList[100]=_VisioProVolume|6BF301C1-B94A-43E9-BA31-D494598C47FB|295B2C03-4B1C-4221-B292-1411F468BD02|Visio Professional 2016"
  set "AppList[101]=_VisioProXVolume|B234ABE3-0857-4F9C-B05A-4DC314F85557|0594DC12-8444-4912-936A-747CA742DBDB|Visio Professional 2016 C2R"
  set "AppList[102]=_VisioPro2019Retail|5B5CF08F-B81A-431D-B080-3450D8620565|F41ABF81-F409-4B0D-889D-92B3E3D7D005|Visio Professional 2019"
  set "AppList[103]=_VisioPro2019Volume|5B5CF08F-B81A-431D-B080-3450D8620565|F41ABF81-F409-4B0D-889D-92B3E3D7D005|Visio Professional 2019"
  set "AppList[104]=_VisioPro2021Retail|FB61AC9A-1688-45D2-8F6B-0674DBFFA33C|C590605A-A08A-4CC7-8DC2-F1FFB3D06949|Visio Professional 2021"
  set "AppList[105]=_VisioPro2021Volume|FB61AC9A-1688-45D2-8F6B-0674DBFFA33C|C590605A-A08A-4CC7-8DC2-F1FFB3D06949|Visio Professional 2021"
  set "AppList[106]=_VisioPro2024Retail|FA187091-8246-47B1-964F-80A0B1E5D69A|4C2F32BF-9D0B-4D8C-8AB1-B4C6A0B9992D|Visio Professional 2024"
  set "AppList[107]=_VisioPro2024Volume|FA187091-8246-47B1-964F-80A0B1E5D69A|4C2F32BF-9D0B-4D8C-8AB1-B4C6A0B9992D|Visio Professional 2024"
  set "AppList[108]=_VisioStdRetail|AA2A7821-1827-4C2C-8F1D-4513A34DDA97|44151C2D-C398-471F-946F-7660542E3369|Visio Standard 2016"
  set "AppList[109]=_VisioStdVolume|AA2A7821-1827-4C2C-8F1D-4513A34DDA97|44151C2D-C398-471F-946F-7660542E3369|Visio Standard 2016"
  set "AppList[110]=_VisioStdXVolume|361FE620-64F4-41B5-BA77-84F8E079B1F7|1D1C6879-39A3-47A5-9A6D-ACEEFA6A289D|Visio Standard 2016 C2R"
  set "AppList[111]=_VisioStd2019Retail|E06D7DF3-AAD0-419D-8DFB-0AC37E2BDF39|933ED0E3-747D-48B0-9C2C-7CEB4C7E473D|Visio Standard 2019"
  set "AppList[112]=_VisioStd2019Volume|E06D7DF3-AAD0-419D-8DFB-0AC37E2BDF39|933ED0E3-747D-48B0-9C2C-7CEB4C7E473D|Visio Standard 2019"
  set "AppList[113]=_VisioStd2021Retail|72FCE797-1884-48DD-A860-B2F6A5EFD3CA|D55F90EE-4BA2-4D02-B216-1300EE50E2AF|Visio Standard 2021"
  set "AppList[114]=_VisioStd2021Volume|72FCE797-1884-48DD-A860-B2F6A5EFD3CA|D55F90EE-4BA2-4D02-B216-1300EE50E2AF|Visio Standard 2021"
  set "AppList[115]=_VisioStd2024Retail|923FA470-AA71-4B8B-B35C-36B79BF9F44B|0978336B-5611-497C-9414-96EFFAFF4938|Visio Standard 2024"
  set "AppList[116]=_VisioStd2024Volume|923FA470-AA71-4B8B-B35C-36B79BF9F44B|0978336B-5611-497C-9414-96EFFAFF4938|Visio Standard 2024"
  
  echo ### [!time!] Verify Disabled apps
  set "DISABLE_App_List=Word, Excel, Powerpoint, Access, Outlook, Publisher, OneNote, Skype, Teams, OneDrive, Bing, Visio, Project"
  for %%$ in (%DISABLE_App_List%) do set "%%$DISABLEApp="
  if defined Package_Apps_Disable for %%$ in (%Package_Apps_Disable%) do (
  	for %%# in (%DISABLE_App_List%) do (
  		if /i '%%$' EQU '%%#' set "%%#DISABLEApp=true"
  	)
  )
  
  echo ### [!time!] Verify Single apps install
  set "Single_App_List=Word, Excel, Powerpoint, Access, Outlook, Publisher, OneNote, Skype, Visio, Project"
  for %%$ in (%Single_App_List%) do set "%%$SingleApp="
  if defined Single_Apps_Selection for %%$ in (%Single_Apps_Selection%) do (
  	for %%# in (%Single_App_List%) do (
  		if /i '%%$' EQU '%%#' set "%%#SingleApp=true"
  	)
  )
  
  >nul chcp 65001
  SET "PAD_CHNK="
  IF "%PAD_STYLE%"=="1" (SET "PAD_CHNK=■")
  IF "%PAD_STYLE%"=="2" (SET "PAD_CHNK=▒")
  IF "%PAD_STYLE%"=="3" (SET "PAD_CHNK=□")
  IF "%PAD_STYLE%"=="4" (SET "PAD_CHNK=:")
  IF "%PAD_STYLE%"=="5" (SET "PAD_CHNK==")
  IF "%PAD_STYLE%"=="6" (SET "PAD_CHNK=#")
  IF "%PAD_STYLE%"=="7" (SET "PAD_CHNK=~")
  if not defined PAD_CHNK (
    SET PAD_STYLE=
    SET "PAD_CHNK=="
  )
  >nul chcp 437

::===============================================================================================================
:: Security check
::===============================================================================================================
  
  echo ### [!time!] Set Proxy Settings
  if defined Proxy (
  	set Proxy_SVR=
  	set Proxy_IIP=
  	set "http=https://"
  	Set "ProxyInvoke=-Proxy '!Proxy!'"
  	Set "ProxyBITS=-ProxyUsage Override -ProxyList !Proxy!"
  	
  	Set ProxyCurl=--proxy "!Proxy!"
  	Set ProxyAria=--http-proxy "!Proxy!"
  	Set ProxyWGet=-e use_proxy=yes -e https_proxy="!Proxy!"
  	
  	if defined USER if defined PWD (
  	  Set ProxyCurl=--proxy "http://!user!:!pwd!@!Proxy!"
  	  Set ProxyAria=--http-proxy "http://!user!:!pwd!@!Proxy!"
  	  Set ProxyWGet=-e use_proxy=yes -e "http://!user!:!pwd!@!Proxy!"
  ))
  
  if defined Use_Https if /i "!Use_Https!" EQU "1" set "http=https://"
  
  echo ### [!time!] protected folder check
  (echo. >"Data\dummyfile" && %SingleNul% del /q "Data\dummyfile") || (
  	cls
  	echo.
  	echo ERROR ### Read Only Folder
  	echo:
  	if not defined debugMode if not defined AutoTask pause
  	goto:TheEndIsNear
  )
  
::===============================================================================================================
:: Verify version
::===============================================================================================================
  
  REM echo ### [!time!] Check for latest version

  REM set Tag=
  REM set Pass=
  REM set OfficeRToolLink=
  REM set "FileName=OfficeRTool.7z"
  REM set Latest="%windir%\Temp\latest"
  REM set URL="https://officertool.org/Download/LatestR.txt"
  
  REM if "!Dont_Check!" EQU "1" (
    REM goto :Colour_script
  REM )
  
  REM if exist %Latest% del /q %Latest%
  REM %SingleNulV2% "%wget%" --quiet --no-check-certificate %ProxyWGet% --limit-rate %Speed_Limit% %url% --output-document="%Latest%"
  REM if not exist %Latest% (
    REM goto :Colour_script
  REM )
  
  REM for /f "tokens=1,2 delims==" %%f in ('type %Latest%') do (     
  REM rem CERTUTIL Code
  REM if defined UseCertUtil (
    REM for %%$ in (input.txt, output.txt) do %MultiNul% del /q %windir%\temp\%%$
    REM echo %%g>%windir%\temp\input.txt
    REM %MultiNul% certutil -f -decodehex %windir%\temp\input.txt %Res______%.txt && (
        REM <%Res______%.txt set /p output=
        REM if /i "%%f" EQU "ver"  set "Tag=!output!"
      REM if /i "%%f" EQU "pass" set "Pass=!output!"
      REM if /i "%%f" EQU "link" set "OfficeRToolLink=!output!"
  REM ))
  REM rem PS Code
  REM if not defined UseCertUtil if defined UseHexPS (
    REM set "Command=-join(('%%g'-split'(..)'|where{$_}|foreach{[convert]::ToByte($_,16)})-as[char[]])"
      REM for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c "!COMMAND!""`) do (
      REM if /i "%%f" EQU "ver"  set "Tag=%%#"
      REM if /i "%%f" EQU "pass" set "Pass=%%#"
      REM if /i "%%f" EQU "link" set "OfficeRToolLink=%%#"
    REM ))
  REM )
  REM del /q %Latest%

::===============================================================================================================
:: Colour script
::===============================================================================================================

:Colour_script
  
  echo ### [!time!] Prepere Colors script
  rem Check if ANSI Colors is supported
  rem https://ss64.com/nt/syntax-ansi.html
  
  for /F "tokens=4,6 delims=[]. " %%a in ('ver') do (
    if %%a GEQ 10 (
      if %%b GEQ 10586 (
        rem [ANSI colors are available by default in Windows version 1909 or newer]
        if %%b GEQ 18363 goto :UseANSIColors      
        rem [from 10.0.10586 to 10.0.18362.239 we need VirtualTerminalLevel Enabled -> 0x1]
        %SingleNulV2% %REGEXE% query HKCU\Console /v VirtualTerminalLevel | %SingleNul% find /i "0x1" && goto :UseANSIColors
        rem [we add it now, later in next run we will using ANSI code]
        %MultiNul% %REGEXE% add HKCU\Console /f /v VirtualTerminalLevel /t REG_DWORD /d 0x1
  )))
  
  rem lean xp+ color macros by AveYo:  %<%:af " hello "%>>%  &  %<%:cf " w\"or\"ld "%>%   for single \ / " use .%ESC%\  .%ESC%/  \"%ESC%\"
  for /f "delims=:" %%$ in ('"echo;prompt $h$s$h:|!CMDEXE! /d"') do set "ESC=%%$"
  set "<=pushd "%appdata%"&%SingleNulV2% findstr /c:\ /a"
  set ">=\..\c nul&set /p s=%ESC%%ESC%%ESC%%ESC%%ESC%%ESC%%ESC%<nul&popd&echo;"
  set ">>=%>:~0,-6%"
  set /p s=\<nul>"%appdata%\c"
  set "ANSI_COLORS="
  
  :: BACKGROUND COLORS
  set "B_Black=0" & set "B_Red=4" & set "B_Green=2"
  set "B_Yellow=6" & set "B_Blue=1" & set "B_Magenta=5"
  set "B_White=7" & set "B_Gray=8" & set "B_Aqua=3"
  set "BB_Black=0" & set "BB_Red=C" & set "BB_Green=A"
  set "BB_Yellow=E" & set "BB_Blue=9" & set "BB_Magenta=D"
  set "BB_White=F" & set "BB_Gray=8" & set "BB_Aqua=B"

  :: FORGROUND COLORS
  set "F_Black=0" & set "F_Red=4" & set "F_Green=2"
  set "F_Yellow=6" & set "F_Blue=1" & set "F_Magenta=5"
  set "F_White=7" & set "F_Gray=8" & set "F_Aqua=3"
  set "FF_Black=0" & set "FF_Red=C" & set "FF_Green=A"
  set "FF_Yellow=E" & set "FF_Blue=9" & set "FF_Magenta=D"
  set "FF_White=F" & set "FF_Gray=8" & set "FF_Aqua=B"
  
  goto :zNext
  
:UseANSIColors
  
  rem ANSI Colors in standard Windows 10 shell
  rem https://gist.github.com/mlocati/fdabcaeb8071d5c75a2d51712db24011
  
  set "ANSI_COLORS=*"
  
  :: BASIC CHARS
  :: ALT 0,2,7 --> 
  :: WORK WITH NOTPAD++
  set "<=["
  set ">=[0m"

  :: STYLES
  set "Reset=0m" & set "Bold=1m"
  set "Underline=4m" & set "Inverse=7m"

  :: BACKGROUND COLORS
  set "B_Black=30m" & set "B_Red=31m" & set "B_Green=32m"
  set "B_Yellow=33m" & set "B_Blue=34m" & set "B_Magenta=35m"
  set "B_Cyan=36m" & set "B_White=37m"
  set "BB_Black=90m" & set "BB_Red=91m" & set "BB_Green=92m"
  set "BB_Yellow=93m" & set "BB_Blue=94m" & set "BB_Magenta=95m"
  set "BB_Cyan=96m" & set "BB_White=97m"

  :: FOREGROUND COLORS
  set "F_Black=40m" & set "F_Red=41m" & set "F_Green=42m"
  set "F_Yellow=43m" & set "F_Blue=44m" & set "F_Magenta=45m"
  set "F_Cyan=46m" & set "F_White=47m"
  set "FF_Black=100m" & set "FF_Red=101m" & set "FF_Green=102m"
  set "FF_Yellow=103m" & set "FF_Blue=104m" & set "FF_Magenta=105m"
  set "FF_Cyan=106m" & set "FF_White=107m"
  
  goto :zNext

::===============================================================================================================
:: Debug mode
::===============================================================================================================

:zNext

  if /i "%*" EQU "-debug" (
    set "Use_Custom_Profile=0"
    call :debugMode
    exit /b
  )
  
:debugMode

::===============================================================================================================
:: DEFINE SYSTEM ENVIRONMENT
::===============================================================================================================
  
  echo ### [!time!] Check for unsupported system
  set WinBuild=
  for /F "tokens=6 delims=[]. " %%A in ('"%SingleNulV2% ver"') do set /a WinBuild=%%A
  if not defined WinBuild (
    cls & echo ERROR ### WMI FAILURE [FF]
    echo: & echo - WinBuild value is missing
    echo:
    if not defined debugMode if not defined AutoTask pause
    %SingleNul% timeout 2 /nobreak
    goto:TheEndIsNear
  )
  
  set "sls=SoftwareLicensingService"
  set "slp=SoftwareLicensingProduct"
  set "osps=OfficeSoftwareProtectionService"
  set "ospp=OfficeSoftwareProtectionProduct"
  
  if !WinBuild! LSS 7601 (
    (echo:)&&(echo:)&&(echo Unsupported Windows detected)
	(echo:)&&(echo Minimum OS must be Windows 7 SP1 or better)
	(echo:)&&(goto:TheEndIsNear)
  )
  if !WinBuild! LSS 9200 (
    set "S_CLASS=OfficeSoftwareProtectionService"
	set "A_CLASS=OfficeSoftwareProtectionProduct"
  )
  if !WinBuild! GEQ 9200 (
    set "S_CLASS=SoftwareLicensingService"
	set "A_CLASS=SoftwareLicensingProduct"
  )
  
  set tmpX=
  call :query "AddressWidth" "Win32_Processor"
  for /f "tokens=1 delims=," %%g in ('"%SingleNulV2% type "%Res______%""') do set "tmpX=%%g"
  ((set winx=win_x%tmpX: =%)&&(set "repairplatform=x%tmpX: =%"))
  
  echo ### [!time!] Detect Language
  call :Get-WinUserLanguageList_Warper
  call :CheckSystemLanguage
  set "repairlang=!o16lang!"
  
  echo ### [!time!] Detect office version
  call :query "version" "%sls%"
  for /f "tokens=1 delims=," %%g in ('type "%Res______%"') do set slsVer=%%g
  set "slsversion=%slsVer: =%"
  
  if %WinBuild% LSS 9200 (
  	call :query "version" "%osps%"
  	for /f "tokens=1 delims=," %%g in ('type "%Res______%"') do set ospsVer=%%g
  	set "ospsversion=%ospsVer: =%"
  )
  
  echo ### [!time!] Verify / Build INI file
  cd /D "%OfficeRToolpath%"
  if not exist %buildINI% (
  	set "CreateIniFile="
  	if not defined DontSaveToIni	set CreateIniFile=***
  	if defined AutoSaveToIni 		set CreateIniFile=***
  	if defined CreateIniFile (
  		if /i '%PROCESSOR_ARCHITECTURE%' EQU 'x86' 		(IF NOT DEFINED PROCESSOR_ARCHITEW6432 set sBit=86)
  		if /i '%PROCESSOR_ARCHITECTURE%' EQU 'x86' 		(IF DEFINED PROCESSOR_ARCHITEW6432 set sBit=64)
  		if /i '%PROCESSOR_ARCHITECTURE%' EQU 'AMD64' 	set sBit=64
  		if /i '%PROCESSOR_ARCHITECTURE%' EQU 'IA64' 	set sBit=64
  		>%buildINI% 2>&1 echo. && (
  			%SingleNul% del /q %buildINI%
  			>>%buildINI% echo --------------------------------
  			>>%buildINI% echo :: default download-path
  			>>%buildINI% echo %SystemDrive%\Downloads
  			>>%buildINI% echo --------------------------------
  			>>%buildINI% echo :: default download-language
  			>>%buildINI% echo !o16lang!
  			>>%buildINI% echo --------------------------------
  			>>%buildINI% echo :: default download-architecture
  			>>%buildINI% echo x!sBit!
  			>>%buildINI% echo --------------------------------
  		)
  	)
  )
  
::===============================================================================================================
:: Create Auto Activate every 7 days
::===============================================================================================================
echo ### [!time!] Create auto activation task
:AutoTask_Begin
  Set AutoTask=
  if "%~1" EQU "-AutoTask" (Set "AutoTask=*" & goto :AutoTask_Done)
  set "RT_TASK=%WINDIR%\Temp\GS_BACKUP_TASK.xml"
  set "RT__PS1=%WINDIR%\Temp\GS_BACKUP_TASK.PS1"
  call :export RT_UPDATE_TASK >%RT_TASK%
  
   >%RT__PS1% echo sv SID -val @^(Get-LocalUser -name $env:USERNAME^).Sid.Value -scope global -force
  >>%RT__PS1% echo if ^(-not^($SID^)^) {Remove-Item -Path '%RT_TASK%' -Force; exit;}
  >>%RT__PS1% echo $RT_TASK ^= Get-Content '%RT_TASK%'
  >>%RT__PS1% echo $RT_TASK ^= $RT_TASK -Replace 'SID_SID_SID',  $SID
  >>%RT__PS1% echo $RT_TASK ^= $RT_TASK -Replace 'GUDSYNC_EXE',  '%~dpnx0'
  >>%RT__PS1% echo $RT_TASK ^= $RT_TASK -Replace 'DayDayDay',    '%Day%'
  >>%RT__PS1% echo $RT_TASK ^= $RT_TASK -Replace 'HourHourHour', '%Hour%'
  >>%RT__PS1% echo $RT_TASK ^| Set-Content '%RT_TASK%'
  if exist !RT_TASK! %SingleNulV2% %PowerShellEXE% -ExecutionPolicy bypass -nop -file %RT__PS1%
  
  %MultiNul% schtasks /delete /f /TN RT_BACKUP_TASK
  %MultiNul% schtasks /Create /XML %RT_TASK% /tn RT_BACKUP_TASK /f
:AutoTask_Done
  
::===============================================================================================================
:: Office(R)Tool Main Menu
::===============================================================================================================

  if defined debugMode goto:xcX44
  if exist "My Digital Life Forums.lnk" (
  									set "SLUI=%windir%\system32\slui.exe"
  	if exist  "%windir%\Sysnative"  set "SLUI=%windir%\Sysnative\slui.exe"
  	call :SR_Create "My Digital Life Forums" "https://forums.mydigitallife.net/threads/84450" "%SLUI%" "%OfficeRToolpath%"
  	goto:xcx44
  )
  
  echo ### [!time!] Adjust Internet Speed Setting [First Run]
  set /a "Speed_Test=0"
  for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Speed_Test.ps1" "Get""`) do set /a "Speed_Test=%%#"
  if !Speed_Test! GTR 0 (
    set Speed_Limit=!Speed_Test!M
	%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Speed_Test.ps1" "Set"
  )
  
  echo ### [!time!] Create MDL shortcut
  
  timeout 2 /nobreak %SingleNul%
  cls
  
  :: Borrowed from MSMG project :)
  :: nice welcome screen.
  
  set "_spc_=  "
  if defined TerminalFound (
  	set "_spc_="
  )
  
  echo:
  echo.!_spc_!  ===============================================================================
  echo.!_spc_!  !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! Office(R)Tool - EULA !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!
  echo.!_spc_!  ===============================================================================
  echo:
  echo.!_spc_!  Another Great project From My Digital Life Forums.
  echo.!_spc_!  Official web site :: https://forums.mydigitallife.net/threads/84450
  echo:
  echo:
  echo.!_spc_!  The Office(R)Tool is basically a tool to service, customize, add or remove
  echo.!_spc_!  features and components, enable or disable features to Office 2016, 2019, 2021
  echo:
  echo:
  echo.!_spc_!  This Office(R)Tool is provided 'as-is', without any express or implied warranty
  echo.!_spc_!  In no event will the author be held liable for any damages arising from the use
  echo.!_spc_!  of this script.
  echo:
  
  :: Not work well will new console
  :: work fine under ConHost
  
  :: ALT 0 2 7
  set "ESC="
  
  :: work well will new console
  :: maybe under ConHost, didn't check
  
  :: ALT 0 0 8
  set "BS="
  
  :: ALT 0 0 0 7
  set "BEL="
  
  rem ALT 0 1 3 + ALT 0 3 2
  rem (0D) Carriage Return + (20) Space
  
  rem seen first time in BlackBird script
  rem https://www.eso.org/~ndelmott/ascii.html
  
  rem How can I echo a newline in a batch file?
  rem https://stackoverflow.com/questions/132799
  
  :: Option A
  REM for /f %%a in ('copy %SystemRoot%\explorer.exe nul /z') do set "RET=%%a"
  
  :: Option B
  (set RET=^
%=Do not remove this line=%
)

if     defined TerminalFound (
  <nul set /p"=!BEL!!_spc_!  |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||!RET!"
)
if not defined TerminalFound (
  echo.!_spc_!  ^</\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/^>
  echo.!_spc_!  ^<\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\^>
)
  choice /C:AR /N /M "!RET!!_spc_!  !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! [ 'A'ccept / 'R'eject ] !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  if errorlevel 2 exit
  goto :xjkkk
  

:xjkkk
  
  											set "SLUI=%windir%\system32\slui.exe"
  if exist  "%windir%\Sysnative\slui.exe"  	set "SLUI=%windir%\Sysnative\slui.exe"
  call :SR_Create "My Digital Life Forums" "https://forums.mydigitallife.net/threads/84450" "!SLUI!" "%OfficeRToolpath%"
:xcX44

  
  if defined AutoTask (
    set "Use_Custom_Profile=0"
    goto Office16VnextInstall_SKIP
  )
  
:Office16VnextInstall
  if defined AutoTask (timeout 4 /nobreak & exit)
:Office16VnextInstall_SKIP

  cls
  set "do_not_change_size=0"
  if defined Use_Custom_Profile if !Use_Custom_Profile! EQU 1 if exist Profiles\*.xml set "do_not_change_size=1"
  if !do_not_change_size! equ 0 call :Change_Size 140 46
  
  set "DloadLP="
  set "DloadImg="
  set "createIso="
  set "OnlineInstaller="
  set "downpath=not set"
  set "checknewVersion="
  set "o16updlocid=not set"
  set "o16arch=not set"
  set "o16lang=en-US"
  set "langtext=Default Language"
  set "o16lcid=1033"
  set "Auto_Pilot_RET="
  set "AutoPilotMode="
  
  cd /D "%OfficeRToolpath%"
  SET /a countx=0
  if exist %buildINI% (
  	for /F "tokens=*" %%a in (%buildINI%) do (
  		SET /a countx=!countx! + 1
  		set "var!countx!=%%a"
  	)
  	
  	if defined var3 set "var3=!var3:""="!"
  	if defined var3 set "var3=!var3:""="!"
  	if defined var3	if '"!var3:~1,-1!"' EQU '!var3!' set "var3=!var3:~1,-1!"
  	if defined var3 if /i "!var3:~1,2!" NEQ ":\" set var3=
  	
  	if not defined var3 (
  		set "var3=%SystemDrive%\Downloads"
  		if not exist "!var3!" md "!var3!"
  	)
  	
  	if defined var3 (
  		if not exist "!var3!" %SingleNulV2% md "!var3!"
  		if not exist "!var3!" (
  			set "var3=%SystemDrive%\Downloads"
  			if not exist "!var3!" md "!var3!"
  		)
  	)
  	
  	if !countx! GEQ 10 call :UpdateLangFromIni
  )
  
  rem get rid of the not genuine banner solution by Windows_Addict
  
  rem first NAG ~ check for IP address On start up
  rem https://forums.mydigitallife.net/threads/kms_vl_all-smart-activation-script.79535/page-180#post-1659178
  
  rem second NAG ~ check if ip address is from range of 0.0.0.0 to ?
  rem HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Common\Licensing\LVUXRecords
  rem https://forums.mydigitallife.net/threads/kms_vl_all-smart-activation-script.79535/page-237#post-1734148
  
  rem How-to: Generate Random Numbers
  rem https://ss64.com/nt/syntax-random.html
  
  Set /a rand_A=192
  REM Set /a rand_A=(%RANDOM%*(255-192)/32768)+193
  
  Set /a rand_B=168
  REM Set /a rand_B=(%RANDOM%*(255-168)/32768)+169
  
  Set /a rand_C=(%RANDOM%*255/32768)+1
  Set /a rand_D=(%RANDOM%*255/32768)+1
  
  set "IP_ADDRESS=!rand_A!.!rand_B!.!rand_C!.!rand_D!"
  
  call :CleanRegistryKeys
  %MultiNul% del /q latest*.txt
  %MultiNul% %REGEXE% add "%XSPP_USER%"     /f /v KeyManagementServiceName /t REG_SZ /d "!IP_ADDRESS!"
  %MultiNul% %REGEXE% add "%XSPP_HKLM_X32%" /f /v KeyManagementServiceName /t REG_SZ /d "!IP_ADDRESS!"
  %MultiNul% %REGEXE% add "%XSPP_HKLM_X64%" /f /v KeyManagementServiceName /t REG_SZ /d "!IP_ADDRESS!"
  
  if defined AutoTask goto:KMSActivation_ACT_WARPER

  :: Auto Pilot Script
  if defined Use_Custom_Profile if !Use_Custom_Profile! EQU 1 if exist Profiles\*.xml goto :Auto_Pilot
  
  cls
  
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! OFFICE DOWNLOAD AND INSTALL !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  
  if defined WMI_PS set "WMI_E=PS"
  if defined WMI_VB set "WMI_E=VBS"
  if defined WMI_CO set "WMI_E=WMIC"
  
  echo:
  echo [Current] Release :: v!CurrentVersion! * [Server] Release :: v!TAG! * [ENGINE] :: %WMI_E% * [Activation] :: %Act_Engine%
  echo:
  call :Print "[H] SCRUB OFFICE" "%BB_Blue%"
  echo:
  call :Print "[R] RESET OR REPAIR OFFICE" "%BB_Blue%"
  echo:
  call :Print "[A] SHOW ACTIVATION INFORMATION" "%BB_Yellow%"
  echo:
  call :Print "[C] CONVERT INTO VOLUME/MAK LICENSES (VOL, KMS4k, ZeroCID)" "%BB_Yellow%"
  echo:
  call :Print "[K] INITIATE ACTIVATION OR RENEWAL: KMS, OHOOK, ZEROCID, KMS4K" "%BB_Yellow%"
  echo:
  call :Print "[N] INSTALL OFFICE FROM ONLINE INSTALL PACKAGE" "%BB_Green%"
  echo:
  call :Print "[O] DOWNLOAD OFFICE ONLINE WEB-INSTALLER PACKAGE SETUP FILE" "%BB_Green%"
  echo:
  call :Print "[L] DOWNLOAD OFFICE ONLINE WEB-INSTALLER LANGUAGE PACK SETUP FILE" "%BB_Green%"
  echo:
  call :Print "[M] DOWNLOAD OFFICE OFFLINE INSTALL IMAGE" "%BB_Red%"
  echo:
  call :Print "[D] DOWNLOAD OFFICE OFFLINE INSTALL PACKAGE" "%BB_Red%"
  echo:
  call :Print "[I] INSTALL OFFICE FROM OFFLINE INSTALL PACKAGE-IMAGE" "%BB_Red%"
  echo:
  call :Print "[S] CREATE ISO IMAGE FROM OFFLINE INSTALL PACKAGE-IMAGE" "%BB_Red%"
  echo:
  call :Print "[V] ENABLE VISUAL UI" "%BB_Blue%"
  echo:
  call :Print "[P] LOAD CONFIGURATION FILE[S]" "%BB_Blue%"
  echo:
  call :Print "[F] CHECK PUBLIC OFFICE DISTRIBUTION CHANNELS" "%BB_Blue%"
  echo:
  call :Print "[T] DISABLE ACQUISITION AND SENDING OF TELEMETRY DATA" "%BB_Blue%"
  echo:
  call :Print "[U] CHANGE OFFICE UPDATE-PATH (SWITCH DISTRIBUTION CHANNEL)" "%BB_Blue%"
  echo:
  call :Print "[G] DOWNLOAD LATEST RELEASE" "%BB_Magenta%"	
  echo:
  call :Print "[E] EXIT AND CLOSE THIS WINDOW" "%BB_Magenta%"
  echo:
  
  if defined debugMode (echo 00Y | choice)
  CHOICE /C DSICKAUTOREHVPNFMLG /N /M "YOUR CHOICE ?"
  if %errorlevel%==1  goto:DownloadO16Offline
  if %errorlevel%==2  set "createIso=defined"&goto:InstallO16
  if %errorlevel%==3  goto:InstallO16
  if %errorlevel%==4  goto:Convert16Activate
  if %errorlevel%==5  goto:KMSActivation_ACT_WARPER
  if %errorlevel%==6  goto:CheckActivationStatus
  if %errorlevel%==7  goto:ChangeUpdPath
  if %errorlevel%==8  goto:DisableTelemetry
  if %errorlevel%==9  goto:DownloadO16Online
  if %errorlevel%==10 goto:ResetRepair
  if %errorlevel%==11 goto:TheEndIsNear
  if %errorlevel%==12 goto:Scrub
  if %errorlevel%==13 (set logo=LTSC&goto:EnableVisualUI)
  if %errorlevel%==14 (set "Auto_Pilot_RET=X"&goto:Auto_Pilot)
  if %errorlevel%==15 (set "OnlineInstaller=defined"&goto:InstallO16)
  if %errorlevel%==16 goto:CheckPlease
  if %errorlevel%==17 (set "DloadImg=defined"&goto:DownloadO16Online)
  if %errorlevel%==18 (set "DloadLP=defined"&goto:DownloadO16Online)
  if %errorlevel%==19 goto :GetLatestVersion
  goto:Office16VnextInstall
  
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
 ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ 
 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&

:export
rem AveYo's :export text attachments snippet
setlocal enabledelayedexpansion || Prints all text between lines starting with :NAME:[ and :NAME:] - A pure batch snippet by AveYo
set [=&for /f "delims=:" %%s in ('findstr/nbrc:":%~1:\[" /c:":%~1:\]" "%~f0"') do if defined [ (set/a ]=%%s-3) else set/a [=%%s-1
<"%~fs0" ((for /l %%i in (0 1 %[%) do set /p =)&for /l %%i in (%[% 1 %]%) do (set txt=&set /p txt=&echo(!txt!)) &endlocal &exit/b

:RT_UPDATE_TASK:[
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2022-07-23T17:02:05</Date>
    <Author>Mr X.Y.Z</Author>
    <URI>\RT_UPDATE_SERVER</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2022-07-23THourHourHour:00+03:00</StartBoundary>
      <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
      <Enabled>true</Enabled>
      <ScheduleByWeek>
        <DaysOfWeek>
          <DayDayDay />
        </DaysOfWeek>
        <WeeksInterval>1</WeeksInterval>
      </ScheduleByWeek>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>SID_SID_SID</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell</Command>
      <Arguments>-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -nop -c "start 'GUDSYNC_EXE' -Args '-AutoTask' -Verb RunAs -WindowStyle Hidden"</Arguments>
    </Exec>
  </Actions>
</Task>
:RT_UPDATE_TASK:]

:Self_Update:[
  @cls
  @echo off
  >nul chcp 437
  setLocal EnableExtensions EnableDelayedExpansion
  
  set "SingleNul=>nul"
  set "SingleNulV1=1>nul"
  set "SingleNulV2=2>nul"
  set "SingleNulV3=3>nul"
  set "MultiNul=1>nul 2>&1"
  set "TripleNul=1>nul 2>&1 3>&1"
  
  rem x32 Script running under x64 System
  rem thanks mxman2k for code.
  
  SET "SysPath=%Windir%\System32"
  SET "CMDEXE=%Windir%\System32\cmd.exe"
  SET "REGEXE=%Windir%\System32\reg.exe"
  SET "SlmgrEXE=%Windir%\System32\slmgr.vbs"
  SET "CscriptEXE=%Windir%\System32\CScript.exe"
  SET "PowerShellEXE=%Windir%\System32\WindowsPowerShell\v1.0\powershell.exe"
  
  if exist "%systemroot%\Sysnative\reg.exe" if defined PROCESSOR_ARCHITEW6432 (
  
  	SET "SysPath=%Windir%\Sysnative"
  	SET "CMDEXE=%Windir%\Sysnative\cmd.exe"
  	SET "REGEXE=%Windir%\Sysnative\reg.exe"
  	SET "SlmgrEXE=%Windir%\Sysnative\slmgr.vbs"
  	SET "CscriptEXE=%Windir%\Sysnative\CScript.exe"
  	SET "PowerShellEXE=%Windir%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
  )
  
  SET "Path=!SysPath!;%Windir%;!SysPath!\Wbem;!SysPath!\WindowsPowerShell\v1.0\"
  SET "PSModulePath=%ProgramFiles%\WindowsPowerShell\Modules;!SysPath!\WindowsPowerShell\v1.0\Modules"
  
  rem Run as Admin with native shell, any path, params, loop guard, minimal i/o, by AveYo
  %SingleNul% "!REGEXE!" add hkcu\software\classes\.Admin\shell\runas\command /f /ve /d "!CMDEXE! /x /d /r set \"f0=%%2\" &call \"%%2\" %%3" & set "_= %*"
  %SingleNul% "!SysPath!\fltmc" || if "%f0%" neq "%~f0" ( cd.>"%tmp%\runas.Admin" & start "%~n0" /high /min "%tmp%\runas.Admin" "%~f0" "%_:"=""%" &exit /b )
  
  timeout 2
  taskkill /f /PID %~2 /t
  
  attrib "%~4Settings.ini" -r -a -s -h
  attrib "%windir%\Temp\Settings.ini" -r -a -s -h
  del /q "%windir%\Temp\Settings.ini"
  
  attrib "%~4Build_Info.ini" -r -a -s -h
  attrib "%windir%\Temp\Build_Info.ini" -r -a -s -h
  del /q "%windir%\Temp\Build_Info.ini"
  
  rd /s /q "%windir%\Temp\xml"
  md "%windir%\Temp\xml"
  
  copy /y "%~4Data\Bin\*7z*.*" "%windir%\Temp"
  copy /y "%~4Settings.ini" "%windir%\Temp"
  copy /y "%~4Build_Info.ini" "%windir%\Temp"
  copy /y "%~4Profiles\*.xml" "%windir%\Temp\xml"
  
  rd/s/q "%~4"
  md "%~4"
  pushd "%windir%\Temp"
  7z x -p%~1 -y "%~3" * -o"%~4"
  attrib "%~4Settings.ini" -r -a -s -h
  attrib "%~4Build_Info.ini" -r -a -s -h
  
  if exist Settings.ini   copy /y Settings.ini   "%~4"
  if exist Build_Info.ini copy /y Build_Info.ini "%~4"
  if exist "XML\*.xml" (
    rd /s /q "%~4Profiles"
    md "%~4Profiles"
    copy /y "XML\*.xml" "%~4Profiles"
  )
  del /q "%~3"
  del /q *7z*.*
  del /q Settings.ini
  del /q Build_Info.ini
  rd /s /q XML
  
  set c_Val=1xxxxxxxxx
  set e_Val=1xxxxxxxxx
  
  pushd "%~4"
  rem start "" /I "OfficeRTool.cmd"
  %PowerShellEXE% -noprofile -executionpolicy bypass "start 'OfficeRTool.cmd' -verb RunAS"
  del /q "%~f0"
  exit /b
:Self_Update:]

rem How to make a shortcut from CMD?
rem https://superuser.com/questions/392061/how-to-make-a-shortcut-from-cmd
rem https://admhelp.microfocus.com/uft/en/all/VBScript/Content/html/d91b9d23-a7e5-4ec2-8b55-ef6ffe9c777d.htm
rem https://docs.microsoft.com/en-us/troubleshoot/windows-client/admin-development/create-desktop-shortcut-with-wsh

:SR_Create
  if defined WMI_PS (
    goto :SR_Create_PS )
	
  set "CreateShortcut=%windir%\Temp\CreateShortcut.vbs"
   > "%CreateShortcut%" echo.
  >> "%CreateShortcut%" echo Set oWS = WScript.CreateObject("WScript.Shell")
  >> "%CreateShortcut%" echo sLinkFile = "%~4\%~1.lnk"
  >> "%CreateShortcut%" echo Set oLink = oWS.CreateShortcut(sLinkFile)
  >> "%CreateShortcut%" echo oLink.TargetPath = "%~2"
  >> "%CreateShortcut%" echo oLink.IconLocation  = "%~3"
  REM >> "%CreateShortcut%" echo oLink.WorkingDirectory  = "%~4"
  >> "%CreateShortcut%" echo oLink.Save
  %MultiNul% %CscriptEXE% "%CreateShortcut%"
  del "%CreateShortcut%"
  goto :eof

:SR_Create_PS  
  set "CreateShortcut=%windir%\Temp\CreateShortcut.ps1"
   > "%CreateShortcut%" echo.
  >> "%CreateShortcut%" echo # Create Shortcut on User Desktop using PowerShell - ShellGeek
  >> "%CreateShortcut%" echo # https://shellgeek.com/create-shortcuts-on-user-desktop-using-powershell/
  >> "%CreateShortcut%" echo.
  >> "%CreateShortcut%" echo $SourceFilePath = "%~2"
  >> "%CreateShortcut%" echo $ShortcutPath = "%~4\%~1.lnk"
  >> "%CreateShortcut%" echo $WScriptObj = New-Object -ComObject ^("WScript.Shell"^)
  >> "%CreateShortcut%" echo $shortcut = $WscriptObj.CreateShortcut^($ShortcutPath^)
  >> "%CreateShortcut%" echo $shortcut.TargetPath = $SourceFilePath
  >> "%CreateShortcut%" echo $shortcut.IconLocation = "%~3"
  >> "%CreateShortcut%" echo $shortcut.Save^(^)
  %MultiNul% %PowerShellEXE% -nop -c "%CreateShortcut%"
  del "%CreateShortcut%"
  goto :eof

:GetPID

rem based on homay idea, converted to PS
rem https://social.msdn.microsoft.com/Forums/en-US/270f0842-963d-4ed9-b27d-27957628004c/

:: reset values
set "PID="

:: plan A

rem wmic output result are very bad
rem this solution prove to work ...

:: wmic not exist
%MultiNul% where wmic || goto :GetPID_PS

%MultiNul% del /q %Res______%
%SingleNulV2% wmic path Win32_Process where (CommandLine like '%%%%wmic path Win32_Process%%%%') get Name,ParentProcessId /format:list > %Res______%
if exist %Res______% for /f "tokens=1,2 delims==" %%a in ('"%SingleNulV2% type %Res______%"') do (
  if /i '%%a' EQU 'DUMMY'           set "XXX=%%b"
  if /i '%%a' EQU 'ParentProcessId' set "PID=%%b"
) 

if defined PID (
  exit /b )

:GetPID_PS
%MultiNul% where Powershell || goto :GetPID_

:: plan B
set COMMAND="@(Get-WMIObject -Classname Win32_Process | Where CommandLine -MATCH 'Get-WMIObject -Classname Win32_Process').ParentProcessId"
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c !COMMAND!"`) do set "PID=%%#"

:: Go home
:GetPID_
goto :eof



:Terminal_Handle_Check

:: if terminal set to default,
:: every cmd windows will attach to main windowsterminal.exe window
:: the parent process will be expolorer.exe, not windowsterminal.exe

:: reset value
set "TerminalFound="

:: regular check
if not defined PID exit /b
if defined NT_X if !NT_X! LSS 10 exit /b

set "count="
set COMMAND="@(gcim win32_process | where Name -Match 'WindowsTerminal.exe').Count"
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c !COMMAND!"`) do set /a "count=%%#"
if defined count if !count! LSS 1 exit /b

echo ### [!time!] Check for Terminal app

:: PS1 method

:: Windows Terminal v17 - v18 [Preview] with new tab shit etc etc
for %%# in (Proc_ID,Proc_Name,Proc_Handle,ParentProcessId, Preview) do set "%%#="
for /f "usebackq tokens=1,2 delims=:" %%a in (`"%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\termwnd_ps.ps1""`) do (
  
  REM 'Id' - '972'
  REM 'ProcessName' - 'WindowsTerminal'
  REM 'MainWindowHandle' - '0x0e0270'
  
  if /i '%%a' EQU 'Id'               set "Proc_ID=%%b"
  if /i '%%a' EQU 'ProcessName'      set "Proc_Name=%%b"
  if /i '%%a' EQU 'MainWindowHandle' set "Proc_Handle=%%b"
)

if defined Proc_ID if defined Proc_Name if defined Proc_Handle (
  set terminalFound=*
  set Preview=*
  exit /b
)

:: Windows Terminal v12 - v13 - v14 - v15 - v16 - v17 - v18 [Preview]
for %%# in (Proc_ID,Proc_Name,Proc_Handle,ParentProcessId) do set "%%#="
for /f "usebackq tokens=1,2 delims=:" %%a in (`"%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\termproc_ps.ps1""`) do (
  
  REM 'Id' - '972'
  REM 'ProcessName' - 'WindowsTerminal'
  REM 'MainWindowHandle' - '0x0e0270'
  
  if /i '%%a' EQU 'Id'               set "Proc_ID=%%b"
  if /i '%%a' EQU 'ProcessName'      set "Proc_Name=%%b"
  if /i '%%a' EQU 'MainWindowHandle' set "Proc_Handle=%%b"
)

if defined Proc_ID if defined Proc_Name if defined Proc_Handle (
  set terminalFound=*
  exit /b
)

:: Manual method

for %%# in (Proc_ID,Proc_Name,Proc_Handle,ParentProcessId) do set "%%#="

if not defined PID (
  exit /b )

%multinul% del /q %Res______%
%multinul% reg add HKCU\Software\Sysinternals\Handle /v EulaAccepted /f /d 1 /t reg_dword

(%SingleNulV2% "%handle%" -nobanner -a -v "cmd.exe(!PID!)" -p "WindowsTerminal" | more +1 >%Res______%) || exit /b

REM get process -> ID
<%Res______% set /p result=
for /f "tokens=1,2,3,4,5 delims=," %%a in ('"echo !result!"') do set "Proc_ID=%%b"

if defined Proc_ID (
  set "terminalFound=*"
  REM get Process -> MainWindowHandle (using Get-process->MainWindowHandle)
  set COMMAND="@(Get-process | Where Id -EQ !Proc_ID!).MainWindowHandle"
  for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c !COMMAND!"`) do set "Proc_Handle=%%#"
)

if defined Proc_ID if defined Proc_Handle (
  set terminalFound=*
  exit /b
)

for %%# in (Proc_ID,Proc_Name,Proc_Handle,ParentProcessId) do set "%%#="
goto :eof

:GetCount

:: first 2 checks will fail on W7,
:: rem maybe on W8, W8.1 ,,,,,,,,,,,,,
if defined NT_X if %NT_X% LSS 10 (
  goto :wmic_check
)

:: Main Plan ~ Custom PS Script
:: the only method that work on Terminal with tabs,
:: even if Terminal is not the owener Process (w11 -> Case terminal is default)
:: Support this checks --- Name,CommandLine,Current_Working_Directory,SubProcess,
:: title check is not nececery anymore, replaced with Current_Working_Directory check

set /a "Count=0"
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\GetInstances.ps1""`) do set /a "count=%%#"

if !count! GTR 0 goto :GetCount_

:: Backup plan ~ PS
:: Check instance using Get-Process And win32_process classes
:: The Cons, not detect current path, detect Title for the main Terminal Tab
:: more cons, case of terminal windows, Console, cmd /c .. -And Powershell Console .\RTool\Rtool.cmd
:: will detect as 2 process, one because console title, second because cmd command line

set "ID_LIST="
set /a "Count=0"

:: add Parent Process
if defined Proc_ID (echo "!ID_LIST!" | %SingleNul% find /i "!Proc_ID!") || set "ID_LIST=!ID_LIST!,!Proc_ID!"
:: add any Process with matched title
set COMMAND="@(Get-Process | where {($_.ProcessName -Match 'WindowsTerminal' -OR $_.ProcessName -Match 'cmd') -and $_.MainWindowTitle -Match 'OfficeRTool'}).ID"
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c !COMMAND!"`) do ((echo "!ID_LIST!" | %SingleNul% find /i "%%#") || set "ID_LIST=!ID_LIST!,%%#")
:: add any Process with matched command line
set COMMAND="@(gcim win32_process | where {($_.Name -Match 'WindowsTerminal.exe' -OR $_.Name -Match 'cmd.exe') -and $_.commandline -Match 'OfficeRTool' -And $_.commandline -notmatch 'powershell'}).ProcessId"
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c !COMMAND!"`) do ((echo "!ID_LIST!" | %SingleNul% find /i "%%#") || set "ID_LIST=!ID_LIST!,%%#")

if defined ID_LIST for %%$ IN (!ID_LIST!) do (
  
  rem if process doesn't have any 3 lvl parent -> Continue
  if not defined Proc_ID ( set /a Count+=1 )
  
  rem fix for case :: [PID] -> [???] -> [Proc_ID]
  rem so ignore PID value -> Check Proc_ID value instead 
  if     defined Proc_ID ( if /i '%PID%' NEQ '%%$' set /a Count+=1 )
)
if !count! GTR 0 goto :GetCount_

:wmic_check

:: Backup plan ~ WMIC
:: Check instance using win32_process class
:: The Cons, will not detect current path, title

set /a "Count=0"
%MultiNul% del /q %Res______%
%SingleNulV2% wmic path Win32_Process where (Commandline like '%%%%OfficeRTool%%%%' And Name like '%%%%cmd.exe%%%%' And NOT Commandline Like '%%%%wmic.exe%%%%') get name /format:list >>%Res______%
%SingleNulV2% wmic path Win32_Process where (Commandline like '%%%%OfficeRTool%%%%' And Name like '%%%%WindowsTerminal.exe%%%%' And NOT Commandline Like '%%%%wmic.exe%%%%') get name /format:list >>%Res______%
if exist %Res______% for /f "tokens=*" %%k in ('"type %Res______%"') do set /a count+=1
if !count! GTR 0 goto :GetCount_

:done
exit /b

:GetCount_
if !count! GEQ 2 (
  
  cls
  
  if not defined terminalFound (
  
  	rem not change size when using terminal
  	rem because other tabs
  	call :Change_Size 80 12
  )
  
  echo:
  echo:
  echo:
  echo:
  echo                           ERROR ### MULTIPLE INSTANCE FOUND
  echo:
  echo                           Closing in 3 sec.
  echo:
  timeout 3 /nobreak %SingleNul%
  exit
)

goto :eof

:Change_Size
if defined AutoTask exit /b
if defined terminalFound (
  goto :Change_Size_T
)
goto :Change_Size_C
exit /b

:getDPI

rem Found a bug, set scalilng to 125,
rem than set custom scaling
rem now both option active via registry ??????

if not defined DpiValue (
  if defined Win8DpiScaling if !Win8DpiScaling! EQU 0x0 (exit /b)
)
if not defined Win8DpiScaling (
  if defined DpiValue if /i !DpiValue! EQU 0x0 (exit /b)
)

if defined DpiValue if defined Win8DpiScaling (
  if /i !Win8DpiScaling! EQU 0x0 if /i !DpiValue! EQU 0x0 (exit /b)
)

rem both can co-exist in same time
rem first set settings to 25% or 50%,
rem and set custom settings later,
rem so both settings co-exist in same time

if defined DpiValue if /i !DpiValue! NEQ 0x0 (
  
  rem it can only happen if set basic 25 50 or else
  rem and set custom settings later 
  
  if defined Win8DpiScaling if !Win8DpiScaling! EQU 0x1 goto :getDPI_
  
  rem we don't have Win8DpiScaling settings on
  rem so continue in 3. 2. 1. ................
  
  if /i !DpiValue! EQU 0x1 set "X_PERCEN=1.05"
  if /i !DpiValue! EQU 0x2 set "X_PERCEN=1.05"
  if /i !DpiValue! EQU 0x3 set "X_PERCEN=1.05"
  if /i !DpiValue! EQU 0x4 set "X_PERCEN=1.05"
  if /i !DpiValue! EQU 0x5 set "X_PERCEN=1.05"
  if /i !DpiValue! EQU 0x6 set "X_PERCEN=1.05"
  
  exit /b
)

:getDPI_

set output=
if defined LogPixels (
  %multinul% reg add HKCU\Software\Sysinternals\Hex2Dec /v EulaAccepted /f /d 1 /t reg_dword
  for /f "tokens=1,2 delims== " %%a in ('""%Hex2Dec%" /nobanner !LogPixels!"') do set /a "output=%%b+14"
)

if defined output (

  if !output! LSS 111 exit /b
  set /a LogPixels="!output!-100"
  
  :: A scaling table up to 125 Percent
  if /i !LogPixels! EQU 11 (set "X_PERCEN=1.02")
  if /i !LogPixels! EQU 12 (set "X_PERCEN=1.02")
  if /i !LogPixels! EQU 13 (set "X_PERCEN=1.1")
  if /i !LogPixels! EQU 14 (set "X_PERCEN=1.1")
  if /i !LogPixels! EQU 15 (set "X_PERCEN=1.11")
  if /i !LogPixels! EQU 16 (set "X_PERCEN=1.15")
  if /i !LogPixels! EQU 17 (set "X_PERCEN=1.15")
  if /i !LogPixels! EQU 18 (set "X_PERCEN=1.1")
  if /i !LogPixels! EQU 19 (set "X_PERCEN=1.1")
  if /i !LogPixels! EQU 20 (set "X_PERCEN=1.1")
  if /i !LogPixels! EQU 21 (set "X_PERCEN=1.13")
  if /i !LogPixels! EQU 22 (set "X_PERCEN=1.2")
  if /i !LogPixels! EQU 23 (set "X_PERCEN=1.2")
  if /i !LogPixels! EQU 24 (set "X_PERCEN=1.2")
  if /i !LogPixels! EQU 25 (set "X_PERCEN=1.24")
  if /i !LogPixels! EQU 26 (set "X_PERCEN=1.24")
  if /i !LogPixels! EQU 27 (set "X_PERCEN=1.21")
  if /i !LogPixels! EQU 28 (set "X_PERCEN=1.21")
  if /i !LogPixels! EQU 29 (set "X_PERCEN=1.21")
  if /i !LogPixels! EQU 30 (set "X_PERCEN=1.22")
  if /i !LogPixels! EQU 31 (set "X_PERCEN=1.24")
  if /i !LogPixels! EQU 32 (set "X_PERCEN=1.3")
  if /i !LogPixels! EQU 33 (set "X_PERCEN=1.3")
  if /i !LogPixels! EQU 34 (set "X_PERCEN=1.33")
  
  :: Above 126 Scaling
  if /i !LogPixels! GEQ 35 (set "X_PERCEN=1.07")
  
  exit /b
)

goto :eof

:Change_Size_C
rem Check current con size with mode con
(set Lines=)&(set Columns=)
for /f "tokens=1,2 delims=: " %%a in ('"%SingleNulV2% mode con"') do set "%%a=%%b"
if defined Lines if defined Columns (
  if !Lines! EQU %2 if !Columns! EQU %1 exit /b
  goto :Change_Size_C_
)

rem Check current con size with PowerShell
(set Width=)&(set Height=)
set COMMAND="@(get-host).ui.rawui.BufferSize.Width"
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c !COMMAND!"`) do set /a "Width=%%#"
set COMMAND="@(get-host).ui.rawui.BufferSize.Height"
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c !COMMAND!"`) do set /a "Height=%%#"
if defined Width if defined Height (
  if !Width! EQU %1 if !Height! EQU %2 exit /b
  goto :Change_Size_C_
)

:Change_Size_C_

rem try with mode con ......
rem [ this command clean the screen ]
mode con cols=%1 lines=%2
if !errorlevel! EQU 0 exit /b

rem try change screen size with PS,
rem [ this command not clean the screen, but borders look like shit ]
%SingleNulV2% %PowerShellEXE% -nop -c "[console]::WindowWidth=%1; [console]::WindowHeight=%2 ;"
exit /b

:Change_Size_T

rem Change screen under terminal window
rem using special PS script

set output=
set DpiValue=
set LogPixels=
set Win8DpiScaling=
set Monitor_Count=0
set Monitor_REG_PATH=

for /f "tokens=3 delims= " %%$ in ('"%SingleNulV2% reg query "HKCU\Control Panel\Desktop" /v LogPixels"') do set "LogPixels=%%$"
for /f "tokens=3 delims= " %%$ in ('"%SingleNulV2% reg query "HKCU\Control Panel\Desktop" /v Win8DpiScaling"') do set "Win8DpiScaling=%%$"


%multinul% reg query "HKCU\Control Panel\Desktop\PerMonitorSettings" && (
  for /f "tokens=*" %%$ in ('"%SingleNulV2% reg query "HKCU\Control Panel\Desktop\PerMonitorSettings""') do set /a Monitor_Count+=1
)

if !Monitor_Count! EQU 1 (
  for /f "tokens=*" %%$ in ('"%SingleNulV2% reg query "HKCU\Control Panel\Desktop\PerMonitorSettings""') do set "Monitor_REG_PATH=%%$"
)

if defined Monitor_REG_PATH (
  for /f "tokens=3 delims= " %%$ in ('"%SingleNulV2% reg query "!Monitor_REG_PATH!" /v "DpiValue""') do set "DpiValue=%%$"
)

if !Auto_Scaling! EQU 1 (
  if defined DpiValue       (call :getDPI & goto :Change_Size_T_NEXT)
  if defined Win8DpiScaling (call :getDPI & goto :Change_Size_T_NEXT)
)

:Change_Size_T_NEXT

REM about Arithmetic Operators
REM https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_arithmetic_operators?view=powershell-7.3

(set colss=) & (set lines=)
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c [math]::Round(%1*(%C_FACTOR%*%C_PERCEN%*%X_PERCEN%))"`) do set "colss=%%#"
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c [math]::Round(%2*(%L_FACTOR%*%L_PERCEN%*%X_PERCEN%))"`) do set "lines=%%#"
if defined colss if defined lines goto :Change_Size_T__

if defined WMI_PS (
  goto :Change_Size_T_ERR)
  
REM VBScript - Numbers
REM https://www.tutorialspoint.com/vbscript/vbscript_numbers.htm

(set colss=) & (set lines=)
for /f "tokens=*" %%$ in ('"%SingleNulV2% %CscriptEXE% /nologo "%AritVBS%" %1 %C_FACTOR% %C_PERCEN% %X_PERCEN%"') do set "colss=%%$"
for /f "tokens=*" %%$ in ('"%SingleNulV2% %CscriptEXE% /nologo "%AritVBS%" %2 %L_FACTOR% %L_PERCEN% %X_PERCEN%"') do set "lines=%%$"
if defined colss if defined lines goto :Change_Size_T__

:Change_Size_T_ERR
cls
echo:
echo ERROR ### Can't set value for Lines / Columns
echo:
if not defined debugMode if not defined AutoTask pause
%SingleNul% timeout 2 /nobreak
goto:TheEndIsNear

:Change_Size_T__

:: reset hex value
set hex_val=

:: if we dont have handle, try change using ps custom code
if not defined Proc_Handle goto :Change_Size_T_

:: quick solution for v18 preview
:: new options to move out tabs .. wtf ...
:: MainWindowHandle can CHANGE every time ...
:: if tabs are moving etc etc etc

if defined Preview for /f "usebackq tokens=1,2 delims=:" %%a in (`"%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\termwnd_ps.ps1""`) do (^
if /i '%%a' EQU 'MainWindowHandle' if /i '%%b' NEQ '!Proc_Handle!' (set "Proc_Handle=%%b" && %MultiNul% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Disable_Size.ps1"))

rem Undocumented Dynamic variables (read only)
rem https://ss64.com/nt/syntax-variables.html

set output=
call cmd /c exit /b !Proc_Handle!
set "output=!=exitcode!"
if defined output (
(echo "!output!" | %SingleNul% find /i "0000000") || (
  set "hex_val=0x!output:~1!"
  if "!output:~1,2!" EQU "00" set "hex_val=0x!output:~2!"
  goto :Change_Size_T_F
))

rem Base 16 (hexadecimal) to base 10 (decimal)
rem https://ninoburini.wordpress.com/2022/05/29/convert-numbers-between-base-10-decimal-and-base-16-hexadecimal-in-powershell/

set "output="
set "Command='{0:X}' -f [Int]($env:Proc_Handle)"
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c !COMMAND!"`) do set "output=%%#"
if defined output ((set "hex_val=0x0!output!") & goto :Change_Size_T_F)

rem convert hex to decimal and vice versa with simple command-line utility
rem https://learn.microsoft.com/en-us/sysinternals/downloads/hex2dec

set "output="
%multinul% reg add HKCU\Software\Sysinternals\Hex2Dec /v EulaAccepted /f /d 1 /t reg_dword
for /f "tokens=1,2 delims== " %%a in ('"%SingleNulV2% "%Hex2Dec%" /nobanner !Proc_Handle!"') do set "output=%%b"
if defined output ((set "hex_val=!output:~0,2!0!output:~2!") & goto :Change_Size_T_F)

if defined WMI_PS (
  goto :Change_Size_T_)

rem VBScript Hex Function
rem https://www.w3schools.com/asp/func_hex.asp

for /f "tokens=*" %%$ in ('"%SingleNulV2% %CscriptEXE% /nologo "%HeexVBS%" !Proc_Handle!"') do set "hex_val=%%$"
if defined hex_val goto :Change_Size_T_F

:: problem .......
goto :Change_Size_T_

:Change_Size_T_F
(%SingleNulV2% "%cmdow%" !hex_val! /SIZ !colss! !lines!) || goto :Change_Size_T_

set isVisible=
%multinul% del /q %Res______%
%PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\CheckWindowsStatus.ps1" >%Res______% %SingleNulV2%
if exist %Res______% (<%Res______% set /p isVisible=)
if defined isVisible if /i !isVisible! == False (
  :: re-start script under conhost ... 
  start "" /I "conhost" cmd /c "!OfficeRToolpath!\!OfficeRToolname!" -ForceConHost
  exit
)
exit /b

:Change_Size_T_

:: this function will look for PROC_ID value
%multinul% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Set_Window.ps1"

set isVisible=
%multinul% del /q %Res______%
%PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\CheckWindowsStatus.ps1" >%Res______% %SingleNulV2%
if exist %Res______% (<%Res______% set /p isVisible=)
if defined isVisible if /i !isVisible! == False (
  :: re-start script under conhost ... 
  start "" /I "conhost" cmd /c "!OfficeRToolpath!\!OfficeRToolname!" -ForceConHost
  exit
)

exit /b

:GetLatestVersion
  if not defined TAG (
  	cls&echo.
  	echo Could get latest version.
  	echo.
  	timeout /t 4 
  	goto:Office16VnextInstall
  )
  cls
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! Download Latest Release !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  
  %MultiNul% del /q "%windir%\Temp\%FileName%"
  echo:&echo Download Latest Release --- v!tag!
  %SingleNulV2% "%wget%" --quiet --no-check-certificate --user-agent="%User_Agent%" --content-disposition %ProxyWGet% --limit-rate %Speed_Limit% --output-document="%windir%\Temp\%FileName%" "%OfficeRToolLink%"
  if %errorlevel% NEQ 0 (
  	echo:
  	echo Fail to Download Latest Release
  	echo:
  	timeout /t 4
  	goto:Office16VnextInstall
  )
  
  if exist "%windir%\Temp\%FileName%" if defined PID if defined Pass (
  	call :export Self_Update > "%windir%\Temp\Self_Update.cmd"
  	
  	if defined terminalFound if defined PROC_ID (
  	
  	    set /a open_tabs=0			
  		%multinul% reg add HKCU\Software\Sysinternals\Handle /v EulaAccepted /f /d 1 /t reg_dword
  		for /f "tokens=* skip=1" %%$ in ('"%SingleNulV2% "%handle%" -nobanner -a -v "OpenConsole" -p %PROC_ID%"') do set /a open_tabs+=1
  		
  		rem fail safe ....
  		if !open_tabs! EQU 0 (
  		  set /a "PID=%PROC_ID%"
  		)
  		
  		rem 1 instance ... we good
  		if !open_tabs! EQU 1 (
  		  set /a "PID=%PROC_ID%"
  		)
  		
  		rem found windows terminal with multiple open tabs ....
  		if !open_tabs! GTR 1 (
  		  if defined Kill_main_Window if "%Kill_main_Window%" EQU "1" set /a "PID=%PROC_ID%"
  		)
  	)
  	
  	%PowerShellEXE% -noprofile -executionpolicy bypass -command Start '!CMDEXE!' -Verb RunAs -WindowStyle Hidden -Args '/c call \"%windir%\Temp\Self_Update.cmd\" \"!Pass!\" \"!PID!\" \"%windir%\Temp\%FileName%\" \"%~dp0\"'
  	if defined terminalFound if not defined PROC_ID ((timeout 1 %SingleNul%) & (%MultiNul% TASKKILL /F /IM windowsterminal.exe /T))
  	echo Update In progress.
  	timeout /t 12 /nobreak %SingleNul%
  	echo:
  	echo Update Process failed.
  	echo:
  	goto:Office16VnextInstall
  )
  
  echo:
  echo echo Update Process failed.
  echo Possible reasons:
  echo [1] Fail to Found PID
  echo [2] Fail to Download Latest Release
  echo:
  timeout /t 4
  goto:Office16VnextInstall

:GenerateIMGLink
  if "%of16install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/ProPlusRetail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2016_PROPLUS_Retail.ISO"
  )
  
  if "%of19install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/ProPlus2019Retail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2019_PROPLUS_Retail.ISO"
  )
  
  if "%of21install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/ProPlus2021Retail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2021_PROPLUS_Retail.ISO"
  )
  
  if "%of24install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/ProPlus2024Retail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2024_PROPLUS_Retail.ISO"
  )
  
  if "%pr16install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/ProjectProRetail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2016_PROJECT_PRO_Retail.ISO"
  )
  
  if "%pr19install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/ProjectPro2019Retail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2019_PROJECT_PRO_Retail.ISO"
  )
  
  if "%pr21install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/ProjectPro2021Retail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2021_PROJECT_PRO_Retail.ISO"
  )
  
  if "%pr24install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/ProjectPro2024Retail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2024_PROJECT_PRO_Retail.ISO"
  )
  
  if "%vi16install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/VISIOProRetail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2016_VISIO_PRO_Retail.ISO"
  )
  
  if "%vi19install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/VISIOPro2019Retail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2019_VISIO_PRO_Retail.ISO"
  )
  
  if "%vi21install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/VISIOPro2021Retail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2021_VISIO_PRO_Retail.ISO"
  )
  
  if "%vi24install%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/VISIOPro2024Retail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_2024_VISIO_PRO_Retail.ISO"
  )
  
  if "%O365HomePremRetail%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/O365HomePremRetail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_Microsoft_365_Home_Premium_Retail.ISO"
  )
  
  if "%O365BusinessRetail%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/O365BusinessRetail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_Microsoft_365_Business_Premium_Retail.ISO"
  )
  
  if "%O365ProPlusRetail%" NEQ "0" (
  	echo $OfficeDownloadURL='https://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/!o16lang!/O365ProPlusRetail.img'
  	echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath "!o16lang!_Microsoft_365_Professional_Plus_Retail.ISO"
  )
  
  echo if (Test-Path($OfficeDownloadFile)){
  echo 	Remove-Item $OfficeDownloadFile
  echo }
  echo Write-Host
  echo Write-Host 'Download !o16lang! !WebProduct! Offline image file'
  echo Write-Host
rem	echo $AskUser = Read-Host "Copy Link to Clipboard [Y/N]?"
rem	echo if ($AskUser){if ($AskUser -Match 'y') {
  echo Set-Clipboard -value $OfficeDownloadURL
REM echo 	start 'CMD' -Args '/c echo',$OfficeDownloadURL,'^|clip' -WindowStyle Hidden
  echo write-host Generated Link copied to clipboard
rem	echo 	Start-Sleep 2
rem	echo 	exit
rem	echo }}
  echo try {
  echo 	@^(cmd /c sc query bits^)^|Out-Null
  echo 	if ($LASTEXITCODE -eq 0){
rem	echo 	if ^(@^(Get-Service ^| where Name -Eq 'Bits'^).Count -Eq 1^) {
  echo 		Start-BitsTransfer -Source $OfficeDownloadURL -Destination $OfficeDownloadFile !ProxyBITS! -ea 1
  echo }}
  echo catch {}
  echo if (-not(Test-Path($OfficeDownloadFile))){
  echo 	try {
if defined proxy (
  echo 		$proxy = new-object System.Net.WebProxy^("!Proxy!"^)
)
  echo 		$Client=(new-object Net.WebClient)
if defined proxy (
  echo 		$Client.Proxy=$proxy
)
  echo 		$Client.DownloadFile($OfficeDownloadURL, $OfficeDownloadFile)
  echo 		$Client.Dispose()
  echo 	}
  echo 	catch {
REM echo 		Start $OfficeDownloadURL
  echo 		write-host
  echo 		write-host Error occurred .......
  echo 		Start-Sleep 6
  echo 	}
  echo }
  echo if (Test-Path($OfficeDownloadFile)){
  echo 	If ((Get-Item $OfficeDownloadFile).length -gt 1024kb) {
  echo 		Write-Host
  echo 		Write-Host 'image File generated Inside: ',$env:inidownpath,'.'
  echo 	}
  echo 	Else {
  echo 		Write-Host
  echo 		Write-Host 'ERROR ### Check your office configuration'
  echo 		Remove-Item $OfficeDownloadFile
  echo 	}
  echo }
goto :eof

:GenerateSetupLink
  echo $OfficeDownloadURL='https://c2rsetup.officeapps.live.com/c2r/download.aspx^?ProductreleaseID=!WebProduct!^&language=!o16lang!^&platform=!o16arch!'
  echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath '!o16lang!_!WebProduct!_!o16arch!_online_installer.exe'
  echo if (Test-Path($OfficeDownloadFile)){
  echo 	Remove-Item $OfficeDownloadFile
  echo }
  echo Write-Host
  echo Write-Host 'Download !o16lang! !WebProduct! !o16arch! online installer Setup file'
  echo Write-Host
rem	echo $AskUser = Read-Host "Copy Link to Clipboard [Y/N]?"
rem	echo if ($AskUser){if ($AskUser -Match 'y') {
  echo Set-Clipboard -value $OfficeDownloadURL
REM echo 	start 'CMD' -Args '/c echo',$OfficeDownloadURL,'^|clip' -WindowStyle Hidden
  echo write-host Generated Link copied to clipboard
rem	echo 	Start-Sleep 2
rem	echo 	exit
rem	echo }}
  echo try {
  echo 	@^(cmd /c sc query bits^)^|Out-Null
  echo 	if ($LASTEXITCODE -eq 0){
rem echo 	if ^(@^(Get-Service ^| where Name -Eq 'Bits'^).Count -Eq 1^) {
  echo 		Start-BitsTransfer -Source $OfficeDownloadURL -Destination $OfficeDownloadFile !ProxyBITS! -ea 1	
  echo }}
  echo catch {}
  echo if (-not(Test-Path($OfficeDownloadFile))){
  echo 	try {
if defined proxy (
  echo 		$proxy = new-object System.Net.WebProxy^("!Proxy!"^)
)
  echo 		$Client=(new-object Net.WebClient)
if defined proxy (
  echo 		$Client.Proxy=$proxy
)
  echo 		$Client.DownloadFile($OfficeDownloadURL, $OfficeDownloadFile)
  echo 		$Client.Dispose()
  echo 	}
  echo 	catch {
REM echo 		Start $OfficeDownloadURL
  echo 		write-host
  echo 		write-host Error occurred .......
  echo 		Start-Sleep 6
  echo 	}
  echo }
  echo if (Test-Path($OfficeDownloadFile)){
  echo 	If ((Get-Item $OfficeDownloadFile).length -gt 1024kb) {
  echo 		Write-Host
  echo 		Write-Host 'Setup file can be found inside: ',$env:inidownpath,'.'
  echo 	}
  echo 	Else {
  echo 		Write-Host
  echo 		Write-Host 'ERROR ### Check your office configuration'
  echo 		Remove-Item $OfficeDownloadFile
  echo 	}
  echo }
goto :eof

:GenerateLPLink
  echo $OfficeDownloadURL='https://c2rsetup.officeapps.live.com/c2r/download.aspx^?ProductreleaseID=languagepack^&language=!o16lang!^&platform=!o16arch!^&source=O16LAP^&version=O16GA'
  echo $OfficeDownloadFile=Join-Path -Path $env:inidownpath -ChildPath '!o16lang!_languagepack_!o16arch!_online_installer.exe'
  echo if (Test-Path($OfficeDownloadFile)){
  echo 	Remove-Item $OfficeDownloadFile
  echo }
  echo Write-Host
  echo Write-Host 'Download !o16lang! !o16arch! online LP Setup file'
  echo Write-Host
rem	echo $AskUser = Read-Host "Copy Link to Clipboard [Y/N]?"
rem	echo if ($AskUser){if ($AskUser -Match 'y') {
  echo Set-Clipboard -value $OfficeDownloadURL
REM echo 	start 'CMD' -Args '/c echo',$OfficeDownloadURL,'^|clip' -WindowStyle Hidden
  echo write-host Generated Link copied to clipboard
rem	echo 	Start-Sleep 2
rem	echo 	exit
rem	echo }}
  echo try {
  echo 	@^(cmd /c sc query bits^)^|Out-Null
  echo 	if ($LASTEXITCODE -eq 0){
rem echo 	if ^(@^(Get-Service ^| where Name -Eq 'Bits'^).Count -Eq 1^) {
  echo 		Start-BitsTransfer -Source $OfficeDownloadURL -Destination $OfficeDownloadFile !ProxyBITS! -ea 1
  echo }}
  echo catch {}
  echo if (-not(Test-Path($OfficeDownloadFile))){
  echo 	try {
if defined proxy (
  echo 		$proxy = new-object System.Net.WebProxy^("!Proxy!"^)
)
  echo 		$Client=(new-object Net.WebClient)
if defined proxy (
  echo 		$Client.Proxy=$proxy
)
  echo 		$Client.DownloadFile($OfficeDownloadURL, $OfficeDownloadFile)
  echo 		$Client.Dispose()
  echo 	}
  echo 	catch {
REM echo 		Start $OfficeDownloadURL
  echo 		write-host
  echo 		write-host Error occurred .......
  echo 		Start-Sleep 6
  echo 	}
  echo }
  echo if (Test-Path($OfficeDownloadFile)){
  echo 	If ((Get-Item $OfficeDownloadFile).length -gt 1024kb) {
  echo 		Write-Host
  echo 		Write-Host 'Setup file can be found inside: ',$env:inidownpath,'.'
  echo 	}
  echo 	Else {
  echo 		Write-Host
  echo 		Write-Host 'ERROR ### Check your office configuration'
  echo 		Remove-Item $OfficeDownloadFile
  echo 	}
  echo }
goto :eof

:MainLangSelection
  echo:
  echo ### Language selection ###
  echo:
  echo -^> Afrikaans, Albanian, Amharic, Arabic, Armenian, Assamese, Azerbaijani Latin
  echo -^> Bangla Bangladesh, Bangla Bengali India, Basque Basque, Belarusian, Bosnian, Bulgarian
  echo -^> Catalan, Catalan Valencia, Chinese Simplified, Chinese Traditional, Croatian, Czech
  echo -^> Danish, Dari, Dutch # English, English UK, Estonian
  echo -^> Filipino, Finnish, French, French Canada
  echo -^> Galician, Georgian, German, Greek, Gujarati
  echo -^> Hebrew, Hindi, Hungarian
  echo -^> Icelandic, Indonesian, Irish, Italian # Japanese
  echo -^> Kannada, Kazakh, Khmer, KiSwahili, Konkani, Korean, Kyrgyz
  echo -^> Latvian, Lithuanian, Luxembourgish
  echo -^> Macedonian, Malay Latin, Malayalam, Maltese, Maori, Marathi, Mongolian
  echo -^> Nepali, Norwedian Nynorsk, Norwegian Bokmal # Odia
  echo -^> Persian, Polish, Portuguese Portugal, Portuguese Brazilian, Punjabi Gurmukhi
  echo -^> Quechua # Romanian, Russian
  echo -^> Scottish Gaelic, Serbian, Serbian Bosnia, Serbian Serbia, Sindhi Arabic, Sinhala, Slovak, Slovenian,
  echo    Spanish, Spanish Mexico, Swedish
  echo -^> Tamil, Tatar Cyrillic, Telugu, Thai, Turkish, Turkmen
  echo -^> Ukrainian, Urdu, Uyghur, Uzbek # Vietnamese # Welsh
  goto :eof
  
:ProofLangSelection
  echo:
  echo ### Language selection ###
  echo:
  echo -^> Afrikaans, Albanian, Arabic, Armenian, Assamese, Azerbaijani Latin
  echo -^> Bangla Bangladesh, Bangla Bengali India, Basque Basque, Bosnian, Bulgarian
  echo -^> Catalan, Catalan Valencia, Chinese Simplified, Chinese Traditional, Croatian, Czech
  echo -^> Danish, Dutch # English, Estonian
  echo -^> Finnish, French
  echo -^> Galician, Georgian, German, Greek, Gujarati
  echo -^> Hausa Nigeria, Hebrew, Hindi, Hungarian
  echo -^> Icelandic, Igbo, Indonesian, Irish, Italian, IsiXhosa, IsiZulu # Japanese
  echo -^> Kannada, Kazakh, Kinyarwanda, KiSwahili, Konkani, Korean, Kyrgyz
  echo -^> Latvian, Lithuanian, Luxembourgish
  echo -^> Macedonian, Malay Latin, Malayalam, Maltese, Maori, Marathi
  echo -^> Nepali, Norwedian Nynorsk, Norwegian Bokmal # Odia
  echo -^> Pashto, Persian, Polish, Portuguese Portugal, Portuguese Brazilian, Punjabi Gurmukhi
  echo -^> Romanian, Romansh, Russian
  echo -^> Scottish Gaelic, Serbian, Serbian Bosnia, Serbian Serbia, Sinhala, Slovak, Slovenian,
  echo    Spanish, Swedish, Sesotho sa Leboa, Setswana
  echo -^> Tamil, Tatar Cyrillic, Telugu, Thai, Turkish
  echo -^> Ukrainian, Urdu, Uzbek # Vietnamese # Welsh, Wolof # Yoruba
  goto :eof
  
:AllLangSelection
  echo:
  echo ### Language selection ###
  echo:
  echo -^> Afrikaans, Albanian, Amharic, Arabic, Armenian, Assamese, Azerbaijani Latin
  echo -^> Bangla Bangladesh, Bangla Bengali India, Basque Basque, Belarusian, Bosnian, Bulgarian
  echo -^> Catalan, Catalan Valencia, Chinese Simplified, Chinese Traditional, Croatian, Czech
  echo -^> Danish, Dari, Dutch # English, English UK, Estonian
  echo -^> Filipino, Finnish, French, French Canada
  echo -^> Galician, Georgian, German, Greek, Gujarati
  echo -^> Hausa Nigeria, Hebrew, Hindi, Hungarian
  echo -^> Icelandic, Igbo, Indonesian, Irish, Italian, IsiXhosa, IsiZulu # Japanese
  echo -^> Kannada, Kazakh, Khmer, Kinyarwanda, KiSwahili, Konkani, Korean, Kyrgyz
  echo -^> Latvian, Lithuanian, Luxembourgish
  echo -^> Macedonian, Malay Latin, Malayalam, Maltese, Maori, Marathi, Mongolian
  echo -^> Nepali, Norwedian Nynorsk, Norwegian Bokmal # Odia
  echo -^> Pashto, Persian, Polish, Portuguese Portugal, Portuguese Brazilian, Punjabi Gurmukhi
  echo -^> Quechua # Romanian, Romansh, Russian
  echo -^> Scottish Gaelic, Serbian, Serbian Bosnia, Serbian Serbia, Sindhi Arabic, Sinhala, Slovak, Slovenian,
  echo    Spanish, Spanish Mexico, Swedish, Sesotho sa Leboa, Setswana
  echo -^> Tamil, Tatar Cyrillic, Telugu, Thai, Turkish, Turkmen
  echo -^> Ukrainian, Urdu, Uyghur, Uzbek # Vietnamese # Welsh, Wolof # Yoruba
  goto :eof

:Print
  if defined ANSI_COLORS (
  	call :PrintANSI %1 %2
  ) else (
  	call :PrintAncient %1 "0%~2"
  )
  goto :eof
  
:PrintANSI
  echo %<%%~2%~1%>%
  goto :eof
  
:PrintAncient
  %<%:%~2 %1%>%
  goto :eof
  
:PrintVersionInfo
  set "VALUE=%<%%FF_Black:m=;%%BB_White%"
  set "PROPERTY=%<%%FF_Blue:m=;%%BB_WHITE:m=;%%Bold%"
  
  if defined ANSI_COLORS (
  	echo %PROPERTY% %~1 %>%%VALUE% %~2 %>%%PROPERTY% %~3 %>%%VALUE% %~4 %>%%PROPERTY% %~5 %>%%VALUE% %~6 %>%
  ) else (
  	%<%:9f " %~1 "%>>% & %<%:8f " %~2 "%>>% & %<%:9f " %~3 "%>>% & %<%:8f " %~4 "%>>% & %<%:9f " %~5 "%>>% & %<%:8f " %~6 "%>%
  )
  goto :eof

:PrintTitle
  if     defined ANSI_COLORS 	call :PrintANSI 	%* "%FF_Magenta:m=;%%B_Yellow:m=;%%Bold%"
  if not defined ANSI_COLORS 	call :PrintAncient	%* "5E"
  goto :eof
  
:CheckPlease
  
  cls
  
  :: Remove current file
  if exist Version_Info.txt (
    del /q Version_Info.txt
  )
  
  :: Ignore .. if w7 found
  if %WinBuild% LSS 9200 (
    goto :CheckPlease_w7
  )
  
  :: Create new file
  >Version_Info.txt (
    %SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Get_Latest_Version.ps1"
  )
  :: validate file
  if exist Version_Info.txt (
    type Version_Info.txt|%MultiNul% find /i "current,"|| (
	  del /q Version_Info.txt
  ))

:CheckPlease_w7
  
  echo:
  echo *** Checking public Office distribution channels for new updates
  echo:
  echo:
  
  set "checknewVersion=defined"
  call :CheckNewVersion Current 492350f6-3a01-4f97-b9c0-c7c6ddf67d60
  call :CheckNewVersion CurrentPreview 64256afe-f5d9-4f86-8936-8840a6a4f5be
  call :CheckNewVersion BetaChannel 5440fd1f-7ecb-4221-8110-145efaa6372f
  call :CheckNewVersion MonthlyEnterprise 55336b82-a18d-4dd6-b5f6-9e5095c314a6	
  call :CheckNewVersion SemiAnnual 7ffbc6bf-bc32-4f92-8982-f9dd17fd3114
  call :CheckNewVersion SemiAnnualPreview b8f9b850-328d-4355-9145-c59439a0c4cf
  call :CheckNewVersion PerpetualVL2019 f2e724c1-748f-4b47-8fb8-8e0d210e9208
  call :CheckNewVersion PerpetualVL2021 5030841d-c919-4594-8d2d-84ae4f96e58e
  call :CheckNewVersion PerpetualVL2024 7983BAC0-E531-40CF-BE00-FD24FE66619C
  call :CheckNewVersion DogfoodDevMain ea4a4090-de26-49d7-93c1-91bff9e53fc3
  
  ((echo:)&&(echo:)&&(echo:)&&(pause))
  goto:Office16VnextInstall
  
:CheckAndActivateProduct
:: Dynamically access the flag value using delayed expansion
set isActivated=No
set "IsEnabled=!%AppFlag%!"
rem echo Checking !AppFlag!: "!IsEnabled!"

:: If the flag is YES, activate the product
if /i "!IsEnabled!"=="YES" (
    echo Activating !ProductName! [!ID_!]
    call :Office16Activate !ID_!
	set isActivated=YES
)
goto :eof  :: Exit the subroutine

:: Function to set ID based on Act_Engine, check flag, and activate product
:ProcessAndActivate
:: Get the values from the calling context
:: Dynamically access the flag value using delayed expansion
set "IsEnabled=!%AppFlag%!"
rem echo Checking !AppFlag!: "!IsEnabled!"

set "DefaultID=%DefaultID%"
set "ZeroCID_ID=%ZeroCID_ID%"
set "ProductName=%ProductName%"

:: Set the ID based on Act_Engine
set "ID_=%DefaultID%"
if /i "!Act_Engine!" == "ZeroCID" (
    set "ID_=%ZeroCID_ID%"
)

:: Dynamically check the flag
set "IsEnabled=!%AppFlag%!"

:: If the flag is YES, activate the product
if /i "!IsEnabled!"=="YES" (
    echo Activating !ProductName! [!ID_!]
    call :Office16Activate !ID_!
)
goto :eof
  
:KMSActivation_ACT_WARPER
  cls
   
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! ACTIVATE OFFICE PRODUCTS !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  goto:KMSActivation_ACT_WARPER_Y
:KMSActivation_ACT_WARPER_X
  echo:
  echo #### ACTIVATE OFFICE VOLUME PRODUCTS
:KMSActivation_ACT_WARPER_Y	
  echo.
  
  set ohook_found=
  for %%# in (15 16) do (
    for %%A in ("%ProgramFiles%" "%ProgramW6432%" "%ProgramFiles(x86)%") do (
      %MultiNul% dir "%%~A\Microsoft Office\Office%%#\sppc*dll" /AL /b && set ohook_found=* ))

  for %%# in (System SystemX86) do (
    for %%G in ("Office 15" "Office") do (
      for %%A in ("%ProgramFiles%" "%ProgramW6432%" "%ProgramFiles(x86)%") do (
	    %MultiNul% dir "%%~A\Microsoft %%~G\root\vfs\%%#\sppc*dll" /AL /b && set ohook_found=*)))
  
  if defined ohook_found (
    if defined AutoTask (exit)
	echo MAS - Ohook found ...
	echo No activation is needed
	choice /c:YN /m:"Do you want to continue with activation?"
	if errorlevel 2 (
	  goto:Office16VnextInstall)
	rem if errorlevel 1 goto YES
  )
  
  if not defined External_IP (
    if /i "!Act_Engine!" EQU "VL" (
      call :Load_DLL ))
	  
  call :CleanRegistryKeys
  if     defined External_IP (
    call :UpdateRegistryKeys %External_IP% %External_PORT%
  )
  if not defined External_IP (
    call :UpdateRegistryKeys %KMSHostIP% %KMSPort%
  )
  call :CheckOfficeApplications

  :: Mondo Application Only
  :: Mondo Application Only
  :: Mondo Application Only
  
  if /i "!Act_Engine!" == "Ohook" (
	  %SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Ohook.ps1"
	  if defined AutoTask (exit)
	  goto:Office16VnextInstall
     )

  :: Set the default ID
  set "ID_=9caabccb-61b1-4b4b-8bec-d10a3c3ac2ce"

  :: Check if Act_Engine is not ZeroCID and switch ID
  if /i "!Act_Engine!" == "ZeroCID" (
    set "ID_=2CD0EA7E-749F-4288-A05E-567C573B2A6C" )
  
  :: Loop through table entries using for /l (0 to 24)
  for /l %%i in (0,1,24) do (
    :: If the product is activated, skip the rest of the loop and go to the next iteration
    if /i "!isActivated!"=="YES" (
      set "isActivated="
      goto :endLoop
    )
    
    :: Process the table entry if it is defined
    if defined table[%%i] (
      for /F "tokens=1,2 delims=|" %%A in ("!table[%%i]!") do (
        set "AppFlag=%%A"
        set "ProductName=%%B"
      )
      
      :: Call CheckAndActivateProduct to handle product activation
      call :CheckAndActivateProduct
    )
  )

:: Next iteration handling
:endLoop
:: You can add conditions to exit the loop if needed (although `for /l` will end after the last iteration automatically).

  :: Loop through table entries
  for /L %%i in (0,1,116) do (
    if defined AppList[%%i] (
      for /F "tokens=1-4 delims=|" %%A in ("!AppList[%%i]!") do (
        set "AppFlag=%%A"
        set "DefaultID=%%B"
        set "ZeroCID_ID=%%C"
        set "ProductName=%%D"
        call :ProcessAndActivate )))
  
  if not defined External_IP (
    if /i "!Act_Engine!" EQU "VL" (
    call :UnLoad_DLL ))
  REM call :CleanRegistryKeys
  timeout /t 8

  if defined AutoTask (exit)
  goto:Office16VnextInstall
  
::===============================================================================================================
::===============================================================================================================
:EnableVisualUI
  cls
   
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! ENABLE VISUAL UI !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  set "root="
  if exist "%ProgramFiles%\Microsoft Office\root" set "root=%ProgramFiles%\Microsoft Office\root"
  if exist "%ProgramFiles(x86)%\Microsoft Office\root" set "root=%ProgramFiles(x86)%\Microsoft Office\root"
  
  if not defined root (
  	echo.
  	echo Error ### Fail to find integrator.exe Tool
  	echo.
  	if not defined debugMode if not defined AutoTask pause
  	goto:Office16VnextInstall
  ) else (
  	if not exist "!root!\Integration\integrator.exe" (
  		echo.
  		echo Error ### Fail to find integrator.exe Tool
  		echo.
  		if not defined debugMode if not defined AutoTask pause
  		goto:Office16VnextInstall
  	)
  )

  echo !logo! |%SingleNul% find /i "LTSC" && (
  	echo.
  	echo -- Integrate Professional 2021 Retail License
  	%MultiNul% "!root!\Integration\integrator" /I /License PRIDName=Professional2021Retail.16 PidKey=G7R2D-6NQ7C-CX62B-9YR9J-DGRYH
  )
  
  echo !logo! |%SingleNul% find /i "365" && (
  	echo.
  	echo -- Integrate Mondo 2016 Retail License
  	%MultiNul% "!root!\Integration\integrator" /I /License PRIDName=MondoRetail.16 PidKey=2N6B3-BXW6B-W2XBT-VVQ64-7H7DH
  )
  
  echo !logo! |%SingleNul% find /i "MONDO" && (
  	echo.
  	echo -- Integrate Mondo 2016 Volume License
  	%MultiNul% "!root!\Integration\integrator" /I /License PRIDName=MondoVolume.16 PidKey=HFTND-W9MK4-8B7MJ-B6C4G-XQBR2
  )

  echo -- Clean Registry Keys
  for /f "tokens=3,4,5,6,7,8,9,10 delims=-" %%A in ('whoami /user ^| find /i "S-1-5"') do (
  	%MultiNul% %REGEXE% delete "HKEY_USERS\S-%%A-%%B-%%C-%%D-%%E-%%F-%%G\SOFTWARE\Microsoft\Office" /f
  	%MultiNul% %REGEXE% delete "HKEY_USERS\S-%%A-%%B-%%C-%%D-%%E-%%F-%%G\SOFTWARE\Wow6432Node\Microsoft\Office" /f
  	%MultiNul% %REGEXE% delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\ExperimentConfigs\ExternalFeatureOverrides" /f
  )

  echo -- Install Visual UI Registry Keys
  call :reg_own "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Licensing\CurrentSkuIdAggregationForApp" "" S-1-5-32-544 "" Allow SetValue
  for %%# in (Word, Excel, Powerpoint, Access, Outlook, Publisher, OneNote, project, visio) do (
    %MultiNul% %REGEXE% add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ExperimentConfigs\ExternalFeatureOverrides\%%#" /f /v "Microsoft.Office.UXPlatform.FluentSVRefresh" /t REG_SZ /d "true"
    %MultiNul% %REGEXE% add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ExperimentConfigs\ExternalFeatureOverrides\%%#" /f /v "Microsoft.Office.UXPlatform.RibbonTouchOptimization" /t REG_SZ /d "true"
    %MultiNul% %REGEXE% add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ExperimentConfigs\ExternalFeatureOverrides\%%#" /f /v "Microsoft.Office.UXPlatform.FluentSVRibbonOptionsMenu" /t REG_SZ /d "true"
    %MultiNul% %REGEXE% add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Licensing\CurrentSkuIdAggregationForApp" /f /v "%%#" /t REG_SZ /d "{FBDB3E18-A8EF-4FB3-9183-DFFD60BD0984},{CE5FFCAF-75DA-4362-A9CB-00D2689918AA},"
  )
  call :reg_own "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Licensing\CurrentSkuIdAggregationForApp" "" S-1-5-32-544 "" Deny SetValue

  echo -- Done.
  echo.

  echo Note:
  echo To initiate the Visual Refresh,
  echo it may be required to start some Office apps
  echo a couple of times.
  echo.
  echo Many Thanks to Xtreme21, Krakatoa, rioachim
  echo for helping make and debug this script
  echo.
  if not defined debugMode if not defined AutoTask pause
  
  goto:Office16VnextInstall

:reg_own #key [optional] all user owner access permission  :        call :reg_own "HKCU\My" "" S-1-5-32-544 "" Allow FullControl
  %PowerShellEXE% -nop -c $A='%~1','%~2','%~3','%~4','%~5','%~6';iex(([io.file]::ReadAllText('%~f0')-split':Own1\:.*')[1])&exit/b:Own1:
  $D1=[uri].module.gettype('System.Diagnostics.Process')."GetM`ethods"(42) |where {$_.Name -eq 'SetPrivilege'} #`:no-ev-warn
  'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege'|foreach {$D1.Invoke($null, @("$_",2))}
  $path=$A[0]; $rk=$path-split'\\',2; $HK=gi -lit Registry::$($rk[0]) -fo; $s=$A[1]; $sps=[Security.Principal.SecurityIdentifier]
  $u=($A[2],'S-1-5-32-544')[!$A[2]];$o=($A[3],$u)[!$A[3]];$w=$u,$o |% {new-object $sps($_)}; $old=!$A[3];$own=!$old; $y=$s-eq'all'
  $rar=new-object Security.AccessControl.RegistryAccessRule( $w[0], ($A[5],'FullControl')[!$A[5]], 1, 0, ($A[4],'Allow')[!$A[4]] )
  $x=$s-eq'none';function Own1($k){$t=$HK.OpenSubKey($k,2,'TakeOwnership');if($t){0,4|%{try{$o=$t.GetAccessControl($_)}catch{$old=0}
  };if($old){$own=1;$w[1]=$o.GetOwner($sps)};$o.SetOwner($w[0]);$t.SetAccessControl($o); $c=$HK.OpenSubKey($k,2,'ChangePermissions')
  $p=$c.GetAccessControl(2);if($y){$p.SetAccessRuleProtection(1,1)};$p.ResetAccessRule($rar);if($x){$p.RemoveAccessRuleAll($rar)}
  $c.SetAccessControl($p);if($own){$o.SetOwner($w[1]);$t.SetAccessControl($o)};if($s){$subkeys=$HK.OpenSubKey($k).GetSubKeyNames()
  foreach($n in $subkeys){Own1 "$k\$n"}}}};Own1 $rk[1];if($env:VO){get-acl Registry::$path|fl} #:Own1: lean & mean snippet by AveYo

:SCRUB
  cls
  echo.
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! Remove Office 11 - 12 - 14 - 15 - 16 - C2R !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo ____________________________________________________________________________
  echo.
  echo.
  set "xzzyz5="
  set /p xzzyz5=Press Enter to continue, Any key to back to MAIN MENU ^>
  if defined xzzyz5 goto:Office16VnextInstall
  
  set result="%Res______%" 
  
  cls
  echo.
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! Remove Office 11 - 12 - 14 - 15 - 16 - C2R !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo ____________________________________________________________________________
  
  if defined WMI_VB_FAILURE (
    goto :_Skip_VBS___ )
	
  if defined WMI_PS (
    goto :_Skip_VBS___ )

  echo. & echo.
	
  echo Process :: Clean Keys ^& Licences
  %MultiNul% "%OfficeRToolpath%\Data\Bin\cleanospp.exe"
  %CscriptEXE% "%OfficeRToolpath%\Data\vbs\OLicenseCleanup.vbs" //nologo //b /QUIET
  echo ....................................................................................................

  echo Process :: Clean Registry ^& Folders
  >!result! 2>&1 dir "%ProgramFiles%\Microsoft Office*" /ad /b && (
  	for /f "tokens=*" %%# in ('type !result!') do %MultiNul% call :DestryFolder "%ProgramFiles%\%%#"
  )
  
  >!result! 2>&1 dir "%ProgramFiles(x86)%\Microsoft Office*" /ad /b && (
  	for /f "tokens=*" %%# in ('type !result!') do %MultiNul% call :DestryFolder "%ProgramFiles(x86)%\%%#"
  )
  
  %MultiNul% del /q !result!
  for /f "tokens=3,4,5,6,7,8,9,10 delims=-" %%A in ('whoami /user ^| find /i "S-1-5"') do (set "GUID=S-%%A-%%B-%%C-%%D-%%E-%%F-%%G")
  for %%$ in (HKEY_LOCAL_MACHINE,HKEY_CURRENT_USER,HKEY_USERS) do (
  	echo "%%$" |%SingleNul% find /i "HKEY_USERS" && (
  		%SingleNulV2% %REGEXE% query "%%$\!GUID!\SOFTWARE\Microsoft" /f office 			  | >>!result! find /i "%%$"
  		%SingleNulV2% %REGEXE% query "%%$\!GUID!\SOFTWARE\Wow6432Node\Microsoft" /f office | >>!result! find /i "%%$"
  	) || (
  		%SingleNulV2% %REGEXE% query "%%$\SOFTWARE\microsoft" /f office 					  | >>!result! find /i "%%$"
  		%SingleNulV2% %REGEXE% query "%%$\SOFTWARE\WOW6432Node\microsoft" /f office 		  | >>!result! find /i "%%$"
  	)
  )
  if exist !result! (
  	for /f "tokens=*" %%$ in ('type !result!') do (
  		%MultiNul% %REGEXE% delete "%%$" /f
  	)
  	%MultiNul% del /q !result!
  )
  
  :_Skip_VBS___
  if defined WMI_VB_FAILURE (
    %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\OffScrubc2r.ps1"
	goto :skip_VBS__
  )
  if defined WMI_PS (
    %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\OffScrubc2r.ps1"
	goto :skip_VBS__
  )
  echo ....................................................................................................

  echo Process :: OffScrubC2R.vbs
  %CscriptEXE% "%OfficeRToolpath%\Data\vbs\OffScrubC2R.vbs" //nologo //b ALL /NoCancel /Force /OSE /Quiet /NoReboot /Passive
  echo ....................................................................................................

  for %%G in (OffScrub_O16msi.vbs,OffScrub_O15msi.vbs,OffScrub10.vbs,OffScrub07.vbs,OffScrub03.vbs) do (
  	echo Process :: %%G
  	%CscriptEXE% "%OfficeRToolpath%\Data\vbs\%%G" //nologo //b ALL /NoCancel /Force /OSE /Quiet /NoReboot /Passive
  	echo.
  )

  echo Process :: Clean Leftover
:skip_VBS__
  >!result! 2>&1 dir "%ProgramFiles%\Microsoft Office*" /ad /b && (
  	for /f "tokens=*" %%# in ('type !result!') do %MultiNul% call :DestryFolder "%ProgramFiles%\%%#"
  )
  
  >!result! 2>&1 dir "%ProgramFiles(x86)%\Microsoft Office*" /ad /b && (
  	for /f "tokens=*" %%# in ('type !result!') do %MultiNul% call :DestryFolder "%ProgramFiles(x86)%\%%#"
  )
  
  call :DestryFolder "%USERPROFILE%\AppData\Local\Microsoft\Office"
  
  %MultiNul% del /q !result!
  for /f "tokens=3,4,5,6,7,8,9,10 delims=-" %%A in ('whoami /user ^| find /i "S-1-5"') do (set "GUID=S-%%A-%%B-%%C-%%D-%%E-%%F-%%G")
  for %%$ in (HKEY_LOCAL_MACHINE,HKEY_CURRENT_USER,HKEY_USERS) do (
  	echo "%%$" |%SingleNul% find /i "HKEY_USERS" && (
  		%SingleNulV2% %REGEXE% query "%%$\!GUID!\SOFTWARE\Microsoft" /f office 			  | >>!result! find /i "%%$"
  		%SingleNulV2% %REGEXE% query "%%$\!GUID!\SOFTWARE\Wow6432Node\Microsoft" /f office | >>!result! find /i "%%$"
  	) || (
  		%SingleNulV2% %REGEXE% query "%%$\SOFTWARE\microsoft" /f office 					  | >>!result! find /i "%%$"
  		%SingleNulV2% %REGEXE% query "%%$\SOFTWARE\WOW6432Node\microsoft" /f office 		  | >>!result! find /i "%%$"
  	)
  )
  if exist !result! (
  	for /f "tokens=*" %%$ in ('type !result!') do (
  		%MultiNul% %REGEXE% delete "%%$" /f
  	)
  	%MultiNul% del /q !result!
  )

  echo.
  if not defined debugMode if not defined AutoTask pause
  goto :Office16VnextInstall
  
:Compare

  set _Lwr=
  set _lHg=
  set _same=

  set "Var_1=%~1"
  set "Var_2=%~2"

  set "var_1=%var_1:.= %"
  set "var_2=%var_2:.= %"

  set /a x1=0 & set /a x2=0
  set /a x3=0 & set /a x4=0

  set /a y1=0 & set /a y2=0
  set /a y3=0 & set /a y4=0

  for /f "tokens=1,2,3,4" %%a in ("!var_1!") do (
  	if "%%a" NEQ "" set /a X1=%%a
  	if "%%b" NEQ "" set /a X2=%%b
  	if "%%c" NEQ "" set /a X3=%%c
  	if "%%d" NEQ "" set /a X4=%%d
  )

  for /f "tokens=1,2,3,4" %%a in ("!Var_2!") do (
  	if "%%a" NEQ "" set /a Y1=%%a
  	if "%%b" NEQ "" set /a Y2=%%b
  	if "%%c" NEQ "" set /a Y3=%%c
  	if "%%d" NEQ "" set /a Y4=%%d
  )

  if !x1! NEQ !y1! (
  	if !x1! GTR !y1! (set _lHg=* & goto:eof)
  	if !x1! LSS !y1! (set _Lwr=* & goto:eof)
  )

  if !x2! NEQ !y2! (
  	if !x2! GTR !y2! (set _lHg=* & goto:eof)
  	if !x2! LSS !y2! (set _Lwr=* & goto:eof)
  )

  if !x3! NEQ !y3! (
  	if !x3! GTR !y3! (set _lHg=* & goto:eof)
  	if !x3! LSS !y3! (set _Lwr=* & goto:eof)
  )

  if !x4! NEQ !y4! (
  	if !x4! GTR !y4! (set _lHg=* & goto:eof)
  	if !x4! LSS !y4! (set _Lwr=* & goto:eof)
  )

  set _Same=*

  goto :eof

:DestryFolder
  %MultiNul% rd/s/q "%windir%\Temp"
  %MultiNul% md "%windir%\Temp"
  set targetFolder=%*
  if exist %targetFolder% (
  	rd /s /q %targetFolder%
  	if exist %targetFolder% (
  		for /f "tokens=*" %%g in ('dir /b/s /a-d %targetFolder%') do move /y "%%g" "%windir%\Temp"
  		rd /s /q %targetFolder%
  	)
  )
  goto :eof

:CheckNewVersion
  
  set "o16build=not set "
  set "o16latestbuild=not set"
  
  if /i '%1' EQU 'CURRENT' 			set "ADDIN=          "
  if /i '%1' EQU 'CurrentPreview' 	set "ADDIN=   "
  if /i '%1' EQU 'BetaChannel' 		set "ADDIN=      "
  if /i '%1' EQU 'MonthlyEnterprise' 	set "ADDIN="
  if /i '%1' EQU 'SemiAnnual' 		set "ADDIN=       "
  if /i '%1' EQU 'SemiAnnualPreview' 	set "ADDIN="
  if /i '%1' EQU 'PerpetualVL2019' 	set "ADDIN=  "
  if /i '%1' EQU 'PerpetualVL2021' 	set "ADDIN=  "
  if /i '%1' EQU 'PerpetualVL2024' 	set "ADDIN=  "
  if /i '%1' EQU 'DogfoodDevMain' 	set "ADDIN=   "
    
  if %WinBuild% LSS 9200 (
    if /i "%~1" EQU "PerpetualVL2019" (
	  Call :PrintVersionInfo "CHANNEL ::" "%1%ADDIN%" "ID ::" "%2" "VERSION ::" "%o16latestbuild%"
	  goto :eof )
	if /i "%~1" EQU "PerpetualVL2021" (
	  Call :PrintVersionInfo "CHANNEL ::" "%1%ADDIN%" "ID ::" "%2" "VERSION ::" "%o16latestbuild%"	
	  goto :eof )
	if /i "%~1" EQU "PerpetualVL2024" (
	  Call :PrintVersionInfo "CHANNEL ::" "%1%ADDIN%" "ID ::" "%2" "VERSION ::" "%o16latestbuild%"
	  goto :eof )
  )
  
  if /i "%1" EQU "Manual_Override" goto:CheckNewVersion_v1
  if exist "%OfficeRToolpath%\latest_%1_build.txt" (
    (<"%OfficeRToolpath%\latest_%1_build.txt" set /p o16build=)
	set "o16build=%o16build:~0,-1%"
  )

:CheckNewVersion_v1
  if not exist Version_Info.txt (
    goto :CheckNewVersion_v2
  )
  for /f "tokens=1,2,3,4 delims=," %%A in ('"type Version_Info.txt"') do (
    if /i "%%A" EQU "%~1" (
	  if %WinBuild% GEQ 9200 if "%%D" EQU "10.0" (
        set "o16latestbuild=%%C"
        goto :CheckVersionDone
      )
	  if %WinBuild% LSS 9200 if "%%D" EQU "7.0" (
        set "o16latestbuild=%%C"
        goto :CheckVersionDone
      )
  ))
  
  ::fail
  goto :CheckVersionDone

:CheckNewVersion_v2

  %MultiNul% del /q "%temp%\v32.cab"
  %MultiNul% del /q "%temp%\VersionDescriptor.xml"
  
  set "o16latestbuild=not set"
  set "o16downloadloc=officecdn.microsoft.com.edgesuite.net/%region%/%2/Office/Data"
  
  "%wget%" %ProxyWGet% --limit-rate %Speed_Limit% --quiet --no-check-certificate --no-check-certificate --retry-connrefused --continue --tries=20 -O "%temp%/v32.cab" "!http!!o16downloadloc!/v32.cab"
  if exist "%temp%/v32.cab" (
    %MultiNul% expand "%temp%/v32.cab" "%temp%" -f:VersionDescriptor.xml
  )
  
  rem WIn 8-9-10-11 Skip to NExt label
  if %WinBuild% GEQ 9200 (
    goto :CheckNewVersion_v2_v10
  )
  
  rem WIn 7 Continue here
  set VER_IXX=
  if exist "%temp%/VersionDescriptor.xml" for /f "tokens=2" %%$ in ('"type "%temp%\VersionDescriptor.xml" | find /i "Available Build""') do set "VER_IXX=%%$"
  if defined VER_IXX set "VER_IXX=!VER_IXX:~7,-1!"
  if defined VER_IXX if /i "!VER_IXX:~0,3!" NEQ "16." (
    set VER_IXX=
  )
  
  REM - Not sure why, sometimes both same
  REM - sometimes its actually {default} version -0- {non win 7 version} -0-
  
  if defined VER_IXX (
    set "o16latestbuild=!VER_IXX!"
	goto :CheckVersionDone
  )
  
  ::fail
  goto :CheckNewVersion_v3
  
  REM WIN -7- CHECK DONE

:CheckNewVersion_v2_v10
  
  REM CASE OF NON 2019 LTSC CHANNEL
  REM CASE OF NON 2021 LTSC CHANNEL
  
  set VER_DEF=
  if exist "%temp%/VersionDescriptor.xml" for /f "tokens=11 delims== " %%$ in ('"type "%temp%\VersionDescriptor.xml" | find /i "I640Version""') do (
    if not defined VER_DEF (
	  set "VER_DEF=%%$"
	  set "VER_DEF=!VER_DEF:~1,-1!"
  ))
  
  if defined VER_DEF if /i "!VER_DEF:~0,3!" EQU "16." (
  	set "o16latestbuild=!VER_DEF!"
  	goto :CheckVersionDone
  )
  
  set VER_DEF=
  if exist "%temp%/VersionDescriptor.xml" if not defined VER_DEF (
    for /f "tokens=3" %%$ in ('"type "%temp%\VersionDescriptor.xml" | find /i "AvailableBuild RestrictionType""') do (
	  if not defined VER_DEF (
	    set "VER_DEF=%%$"
		set "VER_DEF=!VER_DEF:~9,-1!"
  )))
  
  if defined VER_DEF if /i "!VER_DEF:~0,3!" EQU "16." (
  	set "o16latestbuild=!VER_DEF!"
  	goto :CheckVersionDone
  )
  
  REM CASE OF --- 2019 LTSC CHANNEL
  REM CASE OF --- 2021 LTSC CHANNEL
  
  set VER_DEF=
  if exist "%temp%/VersionDescriptor.xml" for /f "tokens=2" %%$ in ('"type "%temp%\VersionDescriptor.xml" | find /i "Available Build""') do set "VER_DEF=%%$"
  if defined VER_DEF set "VER_DEF=!VER_DEF:~7,-1!"
  if defined VER_DEF if /i "!VER_DEF:~0,3!" EQU "16." (
  	set "o16latestbuild=!VER_DEF!"
  	goto :CheckVersionDone
  )
  
  ::fail
  goto :CheckNewVersion_v3
  
  REM WIN -X- CHECK DONE

:CheckNewVersion_v3  
  if %WinBuild% GEQ 9200 (%MultiNul% "%wget%" --no-verbose --no-check-certificate %ProxyWGet% --limit-rate %Speed_Limit% --output-document="%windir%\Temp\VersionDescriptor.txt" --tries=20 "https://mrodevicemgr.officeapps.live.com/mrodevicemgrsvc/api/v2/C2RReleaseData/?audienceFFN=%2")
  if %WinBuild% LSS 9200 (%MultiNul% "%wget%" --no-verbose --no-check-certificate %ProxyWGet% --limit-rate %Speed_Limit% --output-document="%windir%\Temp\VersionDescriptor.txt" --tries=20 "https://mrodevicemgr.officeapps.live.com/mrodevicemgrsvc/api/v2/C2RReleaseData/?audienceFFN=%2&osver=Client|6.1.0")
  if %errorlevel% GEQ 1 goto:ErrCheckNewVersion1
  type "%windir%\Temp\VersionDescriptor.txt" | find "AvailableBuild" >"%windir%\Temp\found_office_build.txt"
  if %errorlevel% GEQ 1 goto:ErrCheckNewVersion2
  <"%windir%\Temp\found_office_build.txt" set /p o16latestbuild=
  set "o16latestbuild=%o16latestbuild:~21,16%"
  
:CheckVersionDone
  (set "spaces=     ")
  %MultiNul% del /q "%temp%\v32.cab"
  %MultiNul% del /q "%temp%\VersionDescriptor.xml"
  if "%o16latestbuild:~15,1%" EQU " " (
    (set "o16latestbuild=%o16latestbuild:~0,14%")&&(set "spaces=       ")
  )
  if "%o16latestbuild:~0,3%" NEQ "16." goto:ErrCheckNewVersion3
  if "%1" EQU "Manual_Override" goto:CheckNewVersionSkip2a
  if "!o16build!" NEQ "!o16latestbuild!" (
  	if defined checknewVersion Call :PrintVersionInfo "CHANNEL ::" "%1%ADDIN%" "ID ::" "%2" "VERSION ::" "%o16latestbuild%"
  	echo !o16latestbuild! >"%OfficeRToolpath%\latest_%1_build.txt"
  	echo !o16build! >>"%OfficeRToolpath%\latest_%1_build.txt"
  	goto:CheckNewVersionSkip2b
  )
:CheckNewVersionSkip2a
if defined checknewVersion %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "'   'Last known good Build:' '" -foreground "White" -nonewline; Write-Host "%o16latestbuild%'%spaces%'" -foreground "Green" -nonewline; Write-Host "No newer Build available" -foreground "White"

:CheckNewVersionSkip2b
  %SingleNulV2% del /f /q "%windir%\Temp\VersionDescriptor.txt"
  %SingleNulV2% del /f /q "%windir%\Temp\found_office_build.txt"
  set "buildcheck=ok"
  goto:eof

:ErrCheckNewVersion1
  echo:
  %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** ERROR checking: * %1 * channel" -foreground "Red"
  %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** No response from Office content delivery server" -foreground "Red"
  %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** Check Internet connection and/or Channel-ID" -foreground "White"
  echo:
  set "buildcheck=not ok"
  goto:eof

:ErrCheckNewVersion2
  echo:
  %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** ERROR checking: * %1 * " -foreground "Red"
  %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** No Build / Version number found in file: * VersionDescriptor.txt" -foreground "Red"
  copy "%windir%\Temp\VersionDescriptor.txt" "%windir%\Temp\%1_VersionDescriptor.txt" %MultiNul%
  rem %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** Check file "%windir%\Temp\%1_VersionDescriptor.txt" -foreground "White"
  set "buildcheck=not ok"
  goto:eof
  
:ErrCheckNewVersion3
  echo:
  %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** ERROR checking: * %1 * " -foreground "Red"
  %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** Unsupported Build / Version number detected: * !o16latestbuild! *" -foreground "Red"
  copy "%windir%\Temp\VersionDescriptor.txt" "%windir%\Temp\%1_VersionDescriptor.txt" %MultiNul%
  copy "%windir%\Temp\found_office_build.txt" "%windir%\Temp\%1_found_office_build.txt" %MultiNul%
  REM %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** Check file "%windir%\Temp\%1_VersionDescriptor.txt" -foreground "White"
  REM %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** Check file "%windir%\Temp\%1_found_office_build.txt" -foreground "White"
  echo:
  set "buildcheck=not ok"
  goto:eof
  
::===============================================================================================================
::===============================================================================================================

:DownloadO16Offline
  if defined AutoPilotMode if !_Action! EQU 1 (
    goto :DownOfflineContinue_X
  )
  cd /D "%OfficeRToolpath%"
  set "installtrigger=0"
  set "channeltrigger=0"
  set "o16updlocid=not set"
  set "o16build=not set"
   
  cls & echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! Selected Configuration !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  echo DownloadPath: "!inidownpath!"
  echo:
  if "!o16updlocid!" EQU "492350f6-3a01-4f97-b9c0-c7c6ddf67d60" echo Channel-ID:    !o16updlocid! (Current) && goto:DownOfflineContinue
  if "!o16updlocid!" EQU "64256afe-f5d9-4f86-8936-8840a6a4f5be" echo Channel-ID:    !o16updlocid! (CurrentPreview) && goto:DownOfflineContinue
  if "!o16updlocid!" EQU "5440fd1f-7ecb-4221-8110-145efaa6372f" echo Channel-ID:    !o16updlocid! (BetaChannel) && goto:DownOfflineContinue
  if "!o16updlocid!" EQU "55336b82-a18d-4dd6-b5f6-9e5095c314a6" echo Channel-ID:    !o16updlocid! (MonthlyEnterprise) && goto:DownOfflineContinue
  if "!o16updlocid!" EQU "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" echo Channel-ID:    !o16updlocid! (SemiAnnual) && goto:DownOfflineContinue
  if "!o16updlocid!" EQU "b8f9b850-328d-4355-9145-c59439a0c4cf" echo Channel-ID:    !o16updlocid! (SemiAnnualPreview) && goto:DownOfflineContinue
  if "!o16updlocid!" EQU "f2e724c1-748f-4b47-8fb8-8e0d210e9208" echo Channel-ID:    !o16updlocid! (PerpetualVL2019) && goto:DownOfflineContinue
  if "!o16updlocid!" EQU "5030841d-c919-4594-8d2d-84ae4f96e58e" echo Channel-ID:    !o16updlocid! (PerpetualVL2021) && goto:DownOfflineContinue
  if "!o16updlocid!" EQU "7983BAC0-E531-40CF-BE00-FD24FE66619C" echo Channel-ID:    !o16updlocid! (PerpetualVL2024) && goto:DownOfflineContinue
  if "!o16updlocid!" EQU "ea4a4090-de26-49d7-93c1-91bff9e53fc3" echo Channel-ID:    !o16updlocid! (DogfoodDevMain) && goto:DownOfflineContinue
  
  if "!o16updlocid!" EQU "not set" echo Channel-ID:    not set && goto:DownOfflineContinue
  echo Channel-ID:    !o16updlocid! (Manual_Override)
::===============================================================================================================
:DownOfflineContinue
  echo:
  echo Office build:  !o16build!
  echo:
  echo Language:      !o16lang! (!langtext!)
  echo:
  echo Architecture:  !o16arch!
  echo ____________________________________________________________________________
  echo:
  echo Set new Office Package download path or press return for
  
  echo "!downpath!" | %SingleNul% find /i "not set" && (
  	set "downpath=%SystemDrive%\Downloads"
  )
  set /p downpath=Set Office Package Download Path ^= "!downpath!" ^>
  
:DownOfflineContinue_X
  set "downpath=!downpath:"=!"
  if defined AutoPilotMode if !_Action! EQU 1 (
    set "downpath=!_Location:"=!"
  )
  if /i "!downpath!" EQU "X" (set "downpath=not set")&&(
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode if !_Action! EQU 1 goto :eof
    goto:Office16VnextInstall
  )
  set "downdrive=!downpath:~0,2!"
  if "!downdrive:~-1!" NEQ ":" (echo:)&&(echo Unknown Drive "!downdrive!" - Drive not found)&&(echo Enter correct driveletter:\directory or enter "X" to exit)&&(echo:)&&(pause)&&(set "downpath=not set")&&(
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode if !_Action! EQU 1 goto :eof
    goto:DownloadO16Offline
  )
  cd /d !downdrive!\ %MultiNul%
  if errorlevel 1 (echo:)&&(echo Unknown Drive "!downdrive!" - Drive not found)&&(echo Enter correct driveletter:\directory or enter "X" to exit)&&(echo:)&&(pause)&&(set "downpath=not set")&&(
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode if !_Action! EQU 1 goto :eof
    goto:DownloadO16Offline
  )
  set "downdrive=!downpath:~0,3!"
  if "!downdrive:~-1!" EQU "\" (set "downpath=!downdrive!!downpath:~3!") else (set "downpath=!downdrive:~0,2!\!downpath:~2!")
  if "!downpath:~-1!" EQU "\" set "downpath=!downpath:~0,-1!"
::===============================================================================================================
  cd /D "%OfficeRToolpath%"
  set "installtrigger=0"
  echo:
  if "%inidownpath%" NEQ "!downpath!" ((echo Office install package download path changed)&&(echo old path "%inidownpath%" -- new path "!downpath!")&&(echo:))
  if defined AutoSaveToIni goto :_xv5
  if defined DontSaveToIni goto :SkipDownPathSave
  if "%inidownpath%" NEQ "!downpath!" set /p installtrigger=Save new path to %buildINI%? (1/0) ^>
  if "!installtrigger!" EQU "0" goto:SkipDownPathSave
  if /I "!installtrigger!" EQU "X" goto:SkipDownPathSave
  :_xv5
  set "inidownpath=!downpath!"
  echo -------------------------------->%buildINI%
  echo ^:^: default download-path>>%buildINI%
  echo %inidownpath%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-language>>%buildINI%
  echo %inidownlang%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-architecture>>%buildINI%
  echo %inidownarch%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo Download path saved.
::===============================================================================================================
:SkipDownPathSave
  if defined AutoPilotMode if !_Action! EQU 1 (
    goto :SkipDownPathSave_XX_Y
  )
  
  echo:
  echo "Public known" standard distribution channels
  echo Channel Name                                    - Internal Naming   Index-#
  echo ___________________________________________________________________________
  echo:
  echo Current (Retail/RTM)                        - (Production::CC)        (1)
  echo CurrentPreview (Office Insider SLOW)        - (Insiders::CC)          (2)
  echo BetaChannel (Office Insider FAST)           - (Insiders::DEVMAIN)     (3)
  echo MonthlyEnterprise                           - (Production::MEC)       (4)
  echo SemiAnnual (Business)                       - (Production::DC)        (5)
  echo SemiAnnualPreview (Business Insider)        - (Insiders::FRDC)        (6)
  echo PerpetualVL2019                             - (Production::LTSC)      (7)
  echo PerpetualVL2021                             - (Production::LTSC2021)  (8)
  echo PerpetualVL2024                             - (Production::LTSC2024)  (9)
  echo DogfoodDevMain                              - (Dogfood::DevMain)      (D)
  echo Manual_Override (set identifier for Channel-ID's not public known)    (M)
  echo Exit to Main Menu                                                     (X)
  
:SkipDownPathSave_X
  if defined AutoPilotMode if !_Action! EQU 1 (
    goto :SkipDownPathSave_XX_Y
  )
  echo:
  set /a channeltrigger=1
  set /p channeltrigger=Set Channel-Index-# (1,2,3,4,5,6,7,8,9,M) or X or press return for Current ^>
  (echo !channeltrigger!| %MultiNul% findstr /i /r "^[1-9]$ ^[d]$ ^[x]$ ^[m]$") && (
    if "!channeltrigger!" EQU "1" goto:ChanSel1
    if "!channeltrigger!" EQU "2" goto:ChanSel2
    if "!channeltrigger!" EQU "3" goto:ChanSel3
    if "!channeltrigger!" EQU "4" goto:ChanSel4
    if "!channeltrigger!" EQU "5" goto:ChanSel5
    if "!channeltrigger!" EQU "6" goto:ChanSel6
    if "!channeltrigger!" EQU "7" goto:ChanSel7
    if "!channeltrigger!" EQU "8" goto:ChanSel8
	if "!channeltrigger!" EQU "9" goto:ChanSel9
	if /i "!channeltrigger!" EQU "D" goto:ChanSel10
    if /I "!channeltrigger!" EQU "M" ((set "o16updlocid=not set")&&(set "o16build=not set")&&(goto:ChanSelMan))
    if /I "!channeltrigger!" EQU "X" ((set "o16updlocid=not set")&&(set "o16build=not set")&&(goto:Office16VnextInstall))
  ) || (goto :SkipDownPathSave_X)
  goto :SkipDownPathSave_X
  
::===============================================================================================================
:ChanSel1
  set "o16updlocid=492350f6-3a01-4f97-b9c0-c7c6ddf67d60"
  call :CheckNewVersion Current !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=Current"
  goto:ChannelSelected
::===============================================================================================================
:ChanSel2
  set "o16updlocid=64256afe-f5d9-4f86-8936-8840a6a4f5be"
  call :CheckNewVersion CurrentPreview !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=CurrentPreview"
  goto:ChannelSelected
::===============================================================================================================
:ChanSel3
  set "o16updlocid=5440fd1f-7ecb-4221-8110-145efaa6372f"
  call :CheckNewVersion BetaChannel !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=BetaChannel"
  goto:ChannelSelected
::===============================================================================================================
:ChanSel4
  set "o16updlocid=55336b82-a18d-4dd6-b5f6-9e5095c314a6"
  call :CheckNewVersion MonthlyEnterprise !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=MonthlyEnterprise"
  goto:ChannelSelected
::===============================================================================================================
:ChanSel5
  set "o16updlocid=7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"
  call :CheckNewVersion SemiAnnual !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=SemiAnnual"
  goto:ChannelSelected
::===============================================================================================================
:ChanSel6
  set "o16updlocid=b8f9b850-328d-4355-9145-c59439a0c4cf"
  call :CheckNewVersion SemiAnnualPreview !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=SemiAnnualPreview"
  goto:ChannelSelected
::===============================================================================================================
:ChanSel7
  set "o16updlocid=f2e724c1-748f-4b47-8fb8-8e0d210e9208"
  call :CheckNewVersion PerpetualVL2019 !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=PerpetualVL2019"
  goto:ChannelSelected
::===============================================================================================================
:ChanSel8
  set "o16updlocid=5030841d-c919-4594-8d2d-84ae4f96e58e"
  call :CheckNewVersion PerpetualVL2021 !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=PerpetualVL2021"
  goto:ChannelSelected
::===============================================================================================================
:ChanSel9
  set "o16updlocid=7983BAC0-E531-40CF-BE00-FD24FE66619C"
  call :CheckNewVersion PerpetualVL2024 !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=PerpetualVL2024"
  goto:ChannelSelected
::===============================================================================================================
:ChanSel10
set "o16updlocid=ea4a4090-de26-49d7-93c1-91bff9e53fc3"
  call :CheckNewVersion DogfoodDevMain !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=DogfoodDevMain"
  goto:ChannelSelected
::===============================================================================================================
:ChanSelMan
  echo:
  echo "Microsoft Internal Use Only" Beta/Testing distribution channels
  echo Internal Naming           Channel-ID:                               Index-#
  echo ___________________________________________________________________________
  echo:
  echo Dogfood::DevMain     ---^> ea4a4090-de26-49d7-93c1-91bff9e53fc3         (1)
  echo Dogfood::CC          ---^> f3260cf1-a92c-4c75-b02e-d64c0a86a968         (2)
  echo Dogfood::DCEXT       ---^> c4a7726f-06ea-48e2-a13a-9d78849eb706         (3)
  echo Dogfood::FRDC        ---^> 834504cc-dc55-4c6d-9e71-e024d0253f6d         (4)
  echo Microsoft::CC        ---^> 5462eee5-1e97-495b-9370-853cd873bb07         (5)
  echo Microsoft::DC        ---^> f4f024c8-d611-4748-a7e0-02b6e754c0fe         (6)
  echo Microsoft::DevMain   ---^> b61285dd-d9f7-41f2-9757-8f61cba4e9c8         (7)
  echo Microsoft::FRDC      ---^> 9a3b7ff2-58ed-40fd-add5-1e5158059d1c         (8)
  echo Microsoft::LTSC2021  ---^> 86752282-5841-4120-ac80-db03ae6b5fdb         (9)
  echo Microsoft::LTSC2024  ---^> C02D8FE6-5242-4DA8-972F-82EE55E00671         (10)
  echo Insiders::LTSC       ---^> 2e148de9-61c8-4051-b103-4af54baffbb4         (A)
  echo Insiders::LTSC2021   ---^> 12f4f6ad-fdea-4d2a-a90f-17496cc19a48         (B)
  echo Insiders::LTSC2024   ---^> 20481F5C-C268-4624-936C-52EB39DDBD97         (C)
  echo Insiders::MEC        ---^> 0002c1ba-b76b-4af9-b1ee-ae2ad587371f         (D)
  echo Exit to Main Menu                                                       (X)
  echo:

:ChanSelMan_1	
  echo:
  set /p o16updlocid=Set Channel (enter Channel-ID or Index-#) ^>
  if not defined o16updlocid goto :ChanSelMan_1
  ((echo !o16updlocid!| %MultiNul% findstr /i /r "^[0-9]$ ^[1][0]$ ^[a-c]$ ^[x]$") && ( goto :ChanSelMan_2) || (
    set is_Channel=
    set REG_PS_CMD="[REGEX]::IsMatch($env:o16updlocid,'^([0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][-][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z])-([0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z])-([0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z])-([0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z])$',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)"
    for /f "usebackq tokens=*" %%A in (`"%SingleNulV2% powershell -nop -c !REG_PS_CMD!"`) do set "is_Channel=%%A"
    if defined is_Channel if /i !is_Channel! EQU TRUE (goto :ChanSelMan_2)
    goto :ChanSelMan_1
  ))
  goto :ChanSelMan_1

:ChanSelMan_2
  rem if "!o16updlocid!" EQU "not set" goto:DownloadO16Offline
  if /I "!o16updlocid!" EQU "X" (set "o16updlocid=not set")&&(set "o16build=not set")&&(goto:Office16VnextInstall)
  if "!o16updlocid!" EQU "0" (set "o16updlocid=not set")&&(set "o16build=not set")&&(goto:Office16VnextInstall)
  if "!o16updlocid!" EQU "1" set "o16updlocid=ea4a4090-de26-49d7-93c1-91bff9e53fc3"
  if "!o16updlocid!" EQU "2" set "o16updlocid=f3260cf1-a92c-4c75-b02e-d64c0a86a968"
  if "!o16updlocid!" EQU "3" set "o16updlocid=c4a7726f-06ea-48e2-a13a-9d78849eb706"
  if "!o16updlocid!" EQU "4" set "o16updlocid=834504cc-dc55-4c6d-9e71-e024d0253f6d
  if "!o16updlocid!" EQU "5" set "o16updlocid=5462eee5-1e97-495b-9370-853cd873bb07"
  if "!o16updlocid!" EQU "6" set "o16updlocid=f4f024c8-d611-4748-a7e0-02b6e754c0fe"
  if "!o16updlocid!" EQU "7" set "o16updlocid=b61285dd-d9f7-41f2-9757-8f61cba4e9c8"
  if "!o16updlocid!" EQU "8" set "o16updlocid=2e148de9-61c8-4051-b103-4af54baffbb4"
  if "!o16updlocid!" EQU "9" set "o16updlocid=86752282-5841-4120-ac80-db03ae6b5fdb"
  if "!o16updlocid!" EQU "10" set "o16updlocid=C02D8FE6-5242-4DA8-972F-82EE55E00671"
  if /I "!o16updlocid!" EQU "A" set "o16updlocid=2e148de9-61c8-4051-b103-4af54baffbb4"
  if /I "!o16updlocid!" EQU "B" set "o16updlocid=12f4f6ad-fdea-4d2a-a90f-17496cc19a48"
  if /I "!o16updlocid!" EQU "C" set "o16updlocid=20481F5C-C268-4624-936C-52EB39DDBD97"
  if /I "!o16updlocid!" EQU "D" set "o16updlocid=0002c1ba-b76b-4af9-b1ee-ae2ad587371f"
  echo Channel-ID:   !o16updlocid! (Manual_Override)
  call :CheckNewVersion Manual_Override !o16updlocid!
  set "o16build=!o16latestbuild!"
  goto :ChannelSelected
  
:SkipDownPathSave_XX_Y

  set "o16build=!_Version!"
  set "distribchannel=!_channel!"
  
  if /i !distribchannel! EQU Current (
    set "o16updlocid=492350f6-3a01-4f97-b9c0-c7c6ddf67d60"
  )
  if /i !distribchannel! EQU CurrentPreview (
    set "o16updlocid=64256afe-f5d9-4f86-8936-8840a6a4f5be"
  )
  if /i !distribchannel! EQU BetaChannel (
    set "o16updlocid=5440fd1f-7ecb-4221-8110-145efaa6372f"
  )
  if /i !distribchannel! EQU MonthlyEnterprise (
    set "o16updlocid=55336b82-a18d-4dd6-b5f6-9e5095c314a6"
  )
  if /i !distribchannel! EQU SemiAnnual (
    set "o16updlocid=7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"
  )
  if /i !distribchannel! EQU SemiAnnualPreview (
    set "o16updlocid=b8f9b850-328d-4355-9145-c59439a0c4cf"
  )
  if /i !distribchannel! EQU PerpetualVL2019 (
    set "o16updlocid=f2e724c1-748f-4b47-8fb8-8e0d210e9208"
  )
  if /i !distribchannel! EQU PerpetualVL2021 (
    set "o16updlocid=5030841d-c919-4594-8d2d-84ae4f96e58e"
  )
  if /i !distribchannel! EQU PerpetualVL2024 (
    set "o16updlocid=7983BAC0-E531-40CF-BE00-FD24FE66619C"
  )
  if /i !distribchannel! EQU DogfoodDevMain (
    set "o16updlocid=ea4a4090-de26-49d7-93c1-91bff9e53fc3"
  )
  if /i !_Version! EQU AUTO (
    call :CheckNewVersion !distribchannel! !o16updlocid!
    set "o16build=!o16latestbuild!"
    echo "!o16latestbuild!"|%SingleNul% find /i "not set" && (
      echo:
      echo ERROR ### Fail to fetch version information
      echo:
      if not defined debugMode if not defined AutoTask (
	    pause
	    goto :Office16VnextInstall
      )
      goto :TheEndIsNear
  	)
  )
  set "o16downloadloc=officecdn.microsoft.com.edgesuite.net/%region%/!o16updlocid!/Office/Data"
  goto :LangSelect_2
  
::===============================================================================================================
:ChannelSelected
  set "o16downloadloc=officecdn.microsoft.com.edgesuite.net/%region%/!o16updlocid!/Office/Data"
  echo:
  if "%buildcheck%" EQU "not ok" ((pause)&&(set "o16updlocid=not set")&&(set "o16build=not set")&&(goto:Office16VnextInstall))
  set "o16buildCKS=!o16build!"
    set /p o16build=Set Office Build - or press return for !o16build! ^>
  echo "!o16build!" | %SingleNul% findstr /r "%ver_reg%" || (set "o16build=!o16buildCKS!" & goto :ChannelSelected)
  if "!o16build!" EQU "not set" (set "o16updlocid=not set")&&(set "o16build=not set")&&(goto:Office16VnextInstall)
  if /I "!o16build!" EQU "X" (set "o16updlocid=not set")&&(set "o16build=not set")&&(goto:Office16VnextInstall)
::===============================================================================================================
:LangSelect
  call :MainLangSelection
:LangSelect_
  echo:
:LangSelect_2
  set MULTI_lang=
  if /i "!o16lang!" EQU "not set" call :CheckSystemLanguage
    REM set /p o16lang=Set Language Value - or press return for !o16lang! ^>
  if not defined AutoPilotMode set /p MULTI_lang=Set Language[s] Value[s] - or press return for !o16lang! ^> 
  if defined     AutoPilotMode if !_Action! EQU 1 (
    set "MULTI_lang=!_Language!"
  )
  set "o16lang=!o16lang:, =!"
  set "o16lang=!o16lang:,=!"
  if defined o16lang if /i "x!o16lang:~0,1!" EQU "x " set "o16lang=!o16lang:~1!"
  if defined o16lang if /i "!o16lang:-1!x" EQU " x" set "o16lang=!o16lang:~0,-1!"
  call :SetO16Language
  if defined langnotfound (
  	set "o16lang=not set"
  	goto:LangSelect_
  )
  
  REM if defined MULTI_lang set "MULTI_lang=!MULTI_lang:-=,!"
  if defined MULTI_lang set "MULTI_lang=!MULTI_lang:;=,!"
  if defined MULTI_lang set "MULTI_lang=!MULTI_lang:#=,!"
  
  set /a LANG_COUNT=0
  set LANG_TEST=
  if defined MULTI_lang (
  	set "XWtf=!MULTI_lang: =$!"
  	for %%a in (!XWtf!) do (
  		set "newVal=%%a"
  		set "newVal=!newVal:$= !"
  		call :verify_LANG_XXZ !newVal!
  	)
  )
  
  if !LANG_COUNT! EQU 1 (
  	set "o16lang=!MULTI_lang!"
  	set MULTI_lang=
  	set "o16lang=!o16lang:, =!"
  	set "o16lang=!o16lang:,=!"
  	if defined o16lang if /i "x!o16lang:~0,1!" EQU "x " set "o16lang=!o16lang:~1!"
  	if defined o16lang if /i "!o16lang:-1!x" EQU " x" set "o16lang=!o16lang:~0,-1!"
  	call :SetO16Language
  )
  
::===============================================================================================================
  cd /D "%OfficeRToolpath%"
  set "installtrigger=0"
  if "%inidownlang%" NEQ "!o16lang!" ((echo:)&&(echo Office install package download language changed)&&(echo old language "%inidownlang%" -- new language "!o16lang!")&&(echo:))
  if defined AutoSaveToIni goto :_x35
  if defined DontSaveToIni goto :ArchSelect
  if "%inidownlang%" NEQ "!o16lang!" set /p installtrigger=Save new language to %buildINI%? (1/0) ^>
  if "!installtrigger!" EQU "0" goto:ArchSelect
  if /I "!installtrigger!" EQU "X" goto:ArchSelect
  :_x35
  set "inidownlang=!o16lang!"
  echo -------------------------------->%buildINI%
  echo ^:^: default download-path>>%buildINI%
  echo %inidownpath%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-language>>%buildINI%
  echo %inidownlang%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-architecture>>%buildINI%
  echo %inidownarch%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo Download language saved.
  
::===============================================================================================================
:ArchSelect
  
  if defined AutoPilotMode if !_Action! EQU 1 (
    if /i '%PROCESSOR_ARCHITECTURE%' EQU 'x86' 		(IF NOT DEFINED PROCESSOR_ARCHITEW6432 set sBit=86)
    if /i '%PROCESSOR_ARCHITECTURE%' EQU 'x86' 		(IF DEFINED PROCESSOR_ARCHITEW6432 set sBit=64)
    if /i '%PROCESSOR_ARCHITECTURE%' EQU 'AMD64' 	set sBit=64
    if /i '%PROCESSOR_ARCHITECTURE%' EQU 'IA64' 	set sBit=64
    
    if /i !_system! EQU Auto (
      set "o16arch=x!sBit!"
    )
    if /i !_system! EQU x86 (
      set "o16arch=x86"
    )
    if /i !_system! EQU AMD64 (
      set "o16arch=x64"
    )
    if /i !_system! EQU IA64 (
      set "o16arch=x64"
    )
    
    goto :Office16VNextDownload
  )
  
  if /i '!o16arch!' EQU 'not set' (
  	if /i '%PROCESSOR_ARCHITECTURE%' EQU 'x86' 		(IF NOT DEFINED PROCESSOR_ARCHITEW6432 set sBit=86)
  	if /i '%PROCESSOR_ARCHITECTURE%' EQU 'x86' 		(IF DEFINED PROCESSOR_ARCHITEW6432 set sBit=64)
  	if /i '%PROCESSOR_ARCHITECTURE%' EQU 'AMD64' 	set sBit=64
  	if /i '%PROCESSOR_ARCHITECTURE%' EQU 'IA64' 	set sBit=64
  	set "o16arch=x!sBit!"
  	if defined inidownarch (
  		echo !inidownarch! | %SingleNul% find /i "not set" && set "o16arch=x!sBit!" || set "o16arch=!inidownarch!"
  	)
  )
  
  echo:
  set /p o16arch=Set architecture to download (x86 or x64 or Multi) - or press return for !o16arch! ^>
  if /i "!o16arch!" EQU "x86" goto:SkipArchSelect
  if /i "!o16arch!" EQU "x64" goto:SkipArchSelect
  if /i "!o16arch!" EQU "Multi" goto:SkipArchSelect
  set "o16arch=not set"
  goto:ArchSelect
::===============================================================================================================
:SkipArchSelect
  cd /D "%OfficeRToolpath%"
  set "installtrigger=0"
  echo:
  if "%inidownarch%" NEQ "!o16arch!" ((echo Office install package download architecture changed)&&(echo old architecture "%inidownarch%" -- new architecture "!o16arch!")&&(echo:))
  if defined AutoSaveToIni goto :_x35xf
  if defined DontSaveToIni goto :SkipDownArchSave
  if "%inidownarch%" NEQ "!o16arch!" set /p installtrigger=Save new architecture to %buildINI%? (1/0) ^>
  if "!installtrigger!" EQU "0" goto:SkipDownArchSave
  if /I "!installtrigger!" EQU "X" goto:SkipDownArchSave
  :_x35xf
  set "inidownarch=!o16arch!"
  echo -------------------------------->%buildINI%
  echo ^:^: default download-path>>%buildINI%
  echo %inidownpath%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-language>>%buildINI%
  echo %inidownlang%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-architecture>>%buildINI%
  echo %inidownarch%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo Download architecture saved.
::===============================================================================================================
:SkipDownArchSave
  set "multi_ARC="
  if /i "!o16arch!" EQU "Multi" set multi_ARC=TRUE
  cls
    echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! Pending Download (SUMMARY) !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  
  rem echo:
  echo Architecture: !o16arch!
  set "installtrigger=0"
  echo Office Build: !o16build!
  if defined MULTI_lang (
    echo Language:     !MULTI_lang!
  )
  if not defined MULTI_lang ( 
    echo Language:     !o16lang! (%langtext%)
  )
  if "!o16updlocid!" EQU "492350f6-3a01-4f97-b9c0-c7c6ddf67d60" echo Channel-ID:   !o16updlocid! (Current) && goto:PendDownContinue
  if "!o16updlocid!" EQU "64256afe-f5d9-4f86-8936-8840a6a4f5be" echo Channel-ID:   !o16updlocid! (CurrentPreview) && goto:PendDownContinue
  if "!o16updlocid!" EQU "5440fd1f-7ecb-4221-8110-145efaa6372f" echo Channel-ID:   !o16updlocid! (BetaChannel) && goto:PendDownContinue
  if "!o16updlocid!" EQU "55336b82-a18d-4dd6-b5f6-9e5095c314a6" echo Channel-ID:   !o16updlocid! (MonthlyEnterprise) && goto:PendDownContinue
  if "!o16updlocid!" EQU "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" echo Channel-ID:   !o16updlocid! (SemiAnnual) && goto:PendDownContinue
  if "!o16updlocid!" EQU "b8f9b850-328d-4355-9145-c59439a0c4cf" echo Channel-ID:   !o16updlocid! (SemiAnnualPreview) && goto:PendDownContinue
  if "!o16updlocid!" EQU "f2e724c1-748f-4b47-8fb8-8e0d210e9208" echo Channel-ID:   !o16updlocid! (PerpetualVL2019) && goto:PendDownContinue
  if "!o16updlocid!" EQU "5030841d-c919-4594-8d2d-84ae4f96e58e" echo Channel-ID:   !o16updlocid! (PerpetualVL2021) && goto:PendDownContinue
  if "!o16updlocid!" EQU "7983BAC0-E531-40CF-BE00-FD24FE66619C" echo Channel-ID:   !o16updlocid! (PerpetualVL2024) && goto:PendDownContinue
  if "!o16updlocid!" EQU "ea4a4090-de26-49d7-93c1-91bff9e53fc3" echo Channel-ID:   !o16updlocid! (DogfoodDevMain) && goto:PendDownContinue
  echo Channel-ID:   !o16updlocid! (Manual_Override)
::===============================================================================================================
:PendDownContinue
  rem echo:
  REM call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! DOWNLOADING OFFICE OFFLINE SETUP PACKAGE !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  rem echo:
  
  echo DownloadPath: !downpath!
  echo ____________________________________________________________________________
  
:Error_Check_2_VALIDATE
  echo:
  set "installtrigger="
  set /p installtrigger=(Enter) to download, (R)estart download, (E)xit to main menu ^>
  if defined installtrigger (
    ((echo !installtrigger!|%multinul% findstr /i /r "^[R]$ ^[E]$") && (goto :Error_Check_2_PASS) || (goto :Error_Check_2_VALIDATE))
    goto :Error_Check_2_VALIDATE
  )
:Error_Check_2_PASS	
  if /i "!installtrigger!" EQU "R" (goto:DownloadO16Offline)
  if /i "!installtrigger!" EQU "E" (set "o16updlocid=not set")&&(set "o16build=not set")&&(goto:Office16VnextInstall)
::===============================================================================================================
::===============================================================================================================
:Office16VNextDownload
  if "!o16updlocid!" EQU "492350f6-3a01-4f97-b9c0-c7c6ddf67d60" set "downbranch=Current" 				&& call :ContVNextDownload
  if "!o16updlocid!" EQU "64256afe-f5d9-4f86-8936-8840a6a4f5be" set "downbranch=CurrentPreview" 		&& call :ContVNextDownload
  if "!o16updlocid!" EQU "5440fd1f-7ecb-4221-8110-145efaa6372f" set "downbranch=BetaChannel" 			&& call :ContVNextDownload
  if "!o16updlocid!" EQU "55336b82-a18d-4dd6-b5f6-9e5095c314a6" set "downbranch=MonthlyEnterprise" 	    && call :ContVNextDownload
  if "!o16updlocid!" EQU "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" set "downbranch=SemiAnnual" 			&& call :ContVNextDownload
  if "!o16updlocid!" EQU "b8f9b850-328d-4355-9145-c59439a0c4cf" set "downbranch=SemiAnnualPreview" 	    && call :ContVNextDownload
  if "!o16updlocid!" EQU "f2e724c1-748f-4b47-8fb8-8e0d210e9208" set "downbranch=PerpetualVL2019" 		&& call :ContVNextDownload
  if "!o16updlocid!" EQU "5030841d-c919-4594-8d2d-84ae4f96e58e" set "downbranch=PerpetualVL2021" 		&& call :ContVNextDownload
  if "!o16updlocid!" EQU "7983BAC0-E531-40CF-BE00-FD24FE66619C" set "downbranch=PerpetualVL2024" 		&& call :ContVNextDownload
  if "!o16updlocid!" EQU "ea4a4090-de26-49d7-93c1-91bff9e53fc3" set "downbranch=DogfoodDevMain" 		&& call :ContVNextDownload
  set "downbranch=Manual_Override"
  goto :Office16VnextInstall
::===============================================================================================================
:ContVNextDownload
  						set "ARCH_XY=!o16arch!"
  						set "LANG_XY=!o16lang!"
  if defined multi_ARC 	set "ARCH_XY=x86_x64"
  if defined MULTI_lang 	set "LANG_XY=MULTI"
  
  set "directory-prefix=!LANG_XY!_Office_!downbranch!_!ARCH_XY!_v!o16build!"
  if defined AutoPilotMode if !_Action! EQU 1 (
    set "directory-prefix=!_Name: =_!"
  )
  
  :: people complain etc etc
  :: so it disabled for now.
  
  REM set "new_path="
  REM set "new_path=!downpath!\\!directory-prefix!"
  REM set "new_path=!new_path:\\=\!"
  REM if exist "!new_path!" (
    REM rd/s/q "!new_path!" %MultiNul%
  REM )
  
  if defined MULTI_lang (
  	set "XWtf=!MULTI_lang: =$!"
  	for %%a in (!XWtf!) do (
  		set "newVal=%%a"
  		set "newVal=!newVal:$= !"
  		call :DOWNLOAD_LANG_XXZ !newVal!
  	)
  	
  	timeout 4 /nobreak
  	goto :Office16VnextInstall
  )
  
  if defined multi_ARC (
  	set "o16arch=x86"
  	call :ContVNextDownload_next
  	set "o16arch=x64"
  	call :ContVNextDownload_next
  	
  	timeout 4 /nobreak
  	goto :Office16VnextInstall
  )
  
  call :ContVNextDownload_next
  timeout 4 /nobreak
  
  if defined Auto_Pilot_RET (
    goto :Office16VnextInstall
  )
  if defined AutoPilotMode (
    goto :eof
  )
  goto :Office16VnextInstall
  
:ContVNextDownload_next
  cls
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! DOWNLOADING OFFICE OFFLINE SETUP PACKAGE !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  echo #### Download Office - !o16lang! - !o16arch!
  
  set wgetERR=
  cd /d "%downdrive%\" %MultiNul%
  
  md "!downpath!" %MultiNul%
  cd /d "!downpath!" %MultiNul%
  
  call :!o16arch!DOWNLOAD
  goto :eof

:DOWNLOAD_BASE

if defined default if /i !default! NEQ Wget if /i !default! NEQ Curl if /i !default! NEQ Aria (
  set default=ARIA
)

if not defined Default (
  set default=ARIA
)
  
if exist "%directory-prefix%\Office\Data\%~1" (
  echo %~1|%MultiNul% findstr /i /r "^.*\.dat$" || (
    
	if defined UseCertUtil (
	  certutil /v "%directory-prefix%\Office\Data\%~1"|%MultiNul% find /i "FAILED" || (
        echo.
        echo File :: "*****\%~1" Exist ^& Authenticated [verified]
        goto :eof
    ))
	
	if not defined UseCertUtil if defined UseStatusPS (
	  set "Status="
	  set Status_PS1="@(Get-AuthenticodeSignature '%directory-prefix%\Office\Data\%~1' -ErrorAction SilentlyContinue).Status"
	  for /f "usebackq tokens=*" %%A in (`"%SingleNulV2% powershell -nop -c !Status_PS1!"`) do set "Status=%%A"
	  
	  if defined status if /i '!Status!' EQU 'Valid' (
        echo.
        echo File :: "*****\%~1" Exist ^& Authenticated [verified]
        goto :eof
    ))
))

echo.
echo Download File :: %~1

if /i !default! EQU Curl (
  "%curl%" -S --insecure --retry 2 --limit-rate %Speed_Limit% --create-dirs %ProxyCurl% -C - --output "%directory-prefix%\Office\Data\%~1" %http%%o16downloadloc%/%~1
)
if /i !default! EQU Aria (
  set sources=
  for %%# in (PR,DB,SG) do (
    if defined sources set "sources=!sources!	%http%officecdn.microsoft.com.edgesuite.net/%%#/!o16updlocid!/Office/Data/%~1"
    if not defined sources set "sources=%http%officecdn.microsoft.com.edgesuite.net/%%#/!o16updlocid!/Office/Data/%~1"
  )
  echo.>%windir%\temp\log
  "%Aria%" --log="%windir%\temp\log" --log-level=debug --console-log-level=error --summary-interval=0 --download-result=hide --continue --split=%s_parts% --min-split-size=%s_size%M --max-connection-per-server=10 --max-download-limit=%Speed_Limit% --max-tries=2 --retry-wait=2 --check-certificate=false %ProxyAria% --out="%directory-prefix%\Office\Data\%~1" !sources!
)
if /i !default! EQU Wget (
  "%wget%" %ProxyWGet% --limit-rate %Speed_Limit% --quiet --no-check-certificate --show-progress --retry-connrefused --continue --tries=20 --force-directories --no-host-directories --cut-dirs=2 --directory-prefix=%directory-prefix% %http%%o16downloadloc%/%~1
)

set /a last_error=!errorlevel!
if !last_error! GEQ 1 (
  echo %~1|%MultiNul% findstr /i /r "^.*\.cat$" && goto :eof
  call :WgetError "%http%%o16downloadloc%/!o16build!/%~1"
)

rem fix for aria2 new-line problem
if !last_error! EQU 0 if /i !default! EQU Aria (
  %MultiNul% findstr /i /L /C:"ServerStat.cc:107" /C:"SingleFileAllocationIterator.cc:75" %windir%\temp\log && echo: && goto :eof
)
goto :eof

:DOWNLOAD_MORE

if defined default if /i !default! NEQ Wget if /i !default! NEQ Curl if /i !default! NEQ Aria (
  set default=ARIA
)

if not defined Default (
  set default=ARIA
)

if exist "%directory-prefix%\Office\Data\!o16build!\%~1" (
  echo %~1|%MultiNul% findstr /i /r "^.*\.dat$" || (
  
    if defined UseCertUtil (
	  certutil /v "%directory-prefix%\Office\Data\!o16build!\%~1"|%MultiNul% find /i "FAILED" || (
        echo.
        echo File :: "*****\%~1" Exist ^& Authenticated [verified]
        goto :eof
    ))
	
    if not defined UseCertUtil if defined UseStatusPS (
	  set "Status="
	  set Status_PS1="@(Get-AuthenticodeSignature '%directory-prefix%\Office\Data\!o16build!\%~1' -ErrorAction SilentlyContinue).Status"
	  for /f "usebackq tokens=*" %%A in (`"%SingleNulV2% powershell -nop -c !Status_PS1!"`) do set "Status=%%A"
	  
	  if defined status if /i '!Status!' EQU 'Valid' (
        echo.
        echo File :: "*****\%~1" Exist ^& Authenticated [verified]
        goto :eof
    ))
))

echo.
echo Download File :: !o16build!/%~1

echo %~1|%MultiNul% findstr /i /r "^.*\.cat$" && (
  %MultiNul% "%wget%" %ProxyWGet% --quiet --no-check-certificate --method=HEAD %http%%o16downloadloc%/!o16build!/%~1
  if !errorlevel! NEQ 0 goto :eof
)

if /i !default! EQU Curl (
  "%curl%" -S --insecure --retry 2 --limit-rate %Speed_Limit% --create-dirs %ProxyCurl% -C - --output "%directory-prefix%\Office\Data\!o16build!\%~1" "%http%%o16downloadloc%/!o16build!/%~1"
)
if /i !default! EQU Aria (
  set sources=
  for %%# in (PR,DB,SG) do (
    if defined sources set "sources=!sources!	%http%officecdn.microsoft.com.edgesuite.net/%%#/!o16updlocid!/Office/Data/!o16build!/%~1"
    if not defined sources set "sources=%http%officecdn.microsoft.com.edgesuite.net/%%#/!o16updlocid!/Office/Data/!o16build!/%~1"
  )
  echo.>%windir%\temp\log
  "%Aria%" --log="%windir%\temp\log" --log-level=debug --console-log-level=error --summary-interval=0 --download-result=hide --continue --split=%s_parts% --min-split-size=%s_size%M --max-connection-per-server=10 --max-download-limit=%Speed_Limit% --max-tries=2 --retry-wait=2 --check-certificate=false %ProxyAria% --out="%directory-prefix%\Office\Data\!o16build!\%~1" !sources!
)
if /i !default! EQU Wget (
  "%wget%" %ProxyWGet% --limit-rate %Speed_Limit% --quiet --no-check-certificate --show-progress --retry-connrefused --continue --tries=20 --force-directories --no-host-directories --cut-dirs=2 --directory-prefix=%directory-prefix% %http%%o16downloadloc%/!o16build!/%~1
)

set /a last_error=!errorlevel!
if !last_error! GEQ 1 (
  echo %~1|%MultiNul% findstr /i /r "^.*\.cat$" && goto :eof
  call :WgetError "%http%%o16downloadloc%/!o16build!/%~1"
)

rem fix for aria2 new-line problem
if !last_error! EQU 0 if /i !default! EQU Aria (
  %MultiNul% findstr /i /L /C:"ServerStat.cc:107" /c:"ServerStat.cc:134" /C:"SingleFileAllocationIterator.cc:75" %windir%\temp\log && echo: && goto :eof
)
goto :eof

:X86DOWNLOAD

set Thelma=v32.cab^
,v32_!o16build!.cab

set Louise=i320.cab^
,i32%o16lcid%.cab^
,s320.cab^
,i640.cab^
,i64%o16lcid%.cab^
,i640.cab.cat^
,s32%o16lcid%.cab^
,sp32%o16lcid%.cab^
,stream.x86.!o16lang!.dat^
,stream.x86.x-none.dat^
,stream.x86.!o16lang!.dat.cat^
,stream.x86.x-none.dat.cat

  ::===============================================================================================================
  ::	Download x86/32bit Office setup files
  
  if not defined wgetERR (
    %MultiNul% "%wget%" %ProxyWGet% --quiet --no-check-certificate --method=HEAD %http%%o16downloadloc%/!o16build!/i64%o16lcid%.cab || (
      echo.
	  echo PACKAGE Not exist
	  echo:
      set wgetERR=*
	  %SingleNul% timeout /t 2
    )
  )
  
  	
  for %%$ in (%Thelma%) do (
    if defined wgetERR (
	  goto :CREATE_PACKAGE )
    call :DOWNLOAD_BASE %%$
  )
  
  for %%$ in (%Louise%) do (
    if defined wgetERR (
	  goto :CREATE_PACKAGE )
    call :DOWNLOAD_MORE %%$
  )
  
  goto :CREATE_PACKAGE

:X64DOWNLOAD

set Thelma=v64.cab^
,v64_!o16build!.cab

set Louise=i640.cab^
,i64%o16lcid%.cab^
,i640.cab.cat^
,s640.cab^
,s64%o16lcid%.cab^
,sp64%o16lcid%.cab^
,stream.x64.!o16lang!.dat^
,stream.x64.x-none.dat^
,stream.x64.!o16lang!.dat.cat^
,stream.x64.x-none.dat.cat

  ::===============================================================================================================
  ::	Download x64/64bit Office setup files
  
  if not defined wgetERR (
    %MultiNul% "%wget%" %ProxyWGet% --quiet --no-check-certificate --method=HEAD %http%%o16downloadloc%/!o16build!/i64%o16lcid%.cab || (
      echo.
	  echo PACKAGE Not exist
	  echo:
      set wgetERR=*
	  %SingleNul% timeout /t 2
    )
  )

  for %%$ in (%Thelma%) do (
    if defined wgetERR (
	  goto :CREATE_PACKAGE )
    call :DOWNLOAD_BASE %%$
  )
  
  for %%$ in (%Louise%) do (
    if defined wgetERR (
	  goto :CREATE_PACKAGE )
    call :DOWNLOAD_MORE %%$
  )
  
  goto :CREATE_PACKAGE
  
::===============================================================================================================	
:: Download setup file(s) used in both x86 and x64 architectures

:CREATE_PACKAGE

  if not defined MULTI_lang (
    if defined wgetERR goto :eof
  )
 
::===============================================================================================================	
  
  if /i "!downbranch!" EQU "Manual_Override" echo Manual_Override>"%directory-prefix%\package.info"
  if /i "!downbranch!" EQU "Current" echo Current>"%directory-prefix%\package.info"
  if /i "!downbranch!" EQU "CurrentPreview" echo CurrentPreview>"%directory-prefix%\package.info"
  if /i "!downbranch!" EQU "BetaChannel" echo BetaChannel>"%directory-prefix%\package.info"
  if /i "!downbranch!" EQU "MonthlyEnterprise" echo MonthlyEnterprise>"%directory-prefix%\package.info"
  if /i "!downbranch!" EQU "SemiAnnual" echo SemiAnnual>"%directory-prefix%\package.info"
  if /i "!downbranch!" EQU "SemiAnnualPreview" echo SemiAnnualPreview>"%directory-prefix%\package.info"
  if /i "!downbranch!" EQU "PerpetualVL2019" echo PerpetualVL2019>"%directory-prefix%\package.info"
  if /i "!downbranch!" EQU "PerpetualVL2021" echo PerpetualVL2021>"%directory-prefix%\package.info"
  if /i "!downbranch!" EQU "PerpetualVL2024" echo PerpetualVL2024>"%directory-prefix%\package.info"
  if /i "!downbranch!" EQU "DogfoodDevMain" echo DogfoodDevMain>"%directory-prefix%\package.info"
  
  if not exist "%directory-prefix%" (
    goto :eof
  )
  echo !o16build!>>"%directory-prefix%\package.info"
  if defined MULTI_lang (
  	echo Multi>>"%directory-prefix%\package.info"
  ) else (
  	echo !o16lang!>>"%directory-prefix%\package.info"
  )
  if defined multi_ARC (
  	echo Multi>>"%directory-prefix%\package.info"
  ) else (
  	echo !o16arch!>>"%directory-prefix%\package.info"
  )
  echo !o16updlocid!>>"%directory-prefix%\package.info"
  
  echo:
  echo:
  
  if not defined multi_ARC %SingleNul% timeout /t 2
  goto :eof
  
::===============================================================================================================
::===============================================================================================================
:WgetError
  set "errortrigger=0"
  %PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "*** ERROR downloading: %1" -foreground "Red"
  echo:
  
  if !Dont_Ask! EQU 1 (
  	set wgetERR=true
  	if not defined MULTI_lang if exist "!downpath!\%directory-prefix%" rd "!downpath!\%directory-prefix%" /S /Q
  	if     defined MULTI_lang if exist "!downpath!\%directory-prefix%" (
  		pushd "!downpath!\%directory-prefix%"
  		if /i "!o16arch!" EQU "x86" set "fixed_bit=32"
  		if /i "!o16arch!" EQU "x64" set "fixed_bit=64"
  		for /f "tokens=*" %%# in ('"%SingleNulV2% dir /a/s/b *!fixed_bit!*!o16lang!*"') do %MultiNul% del /q %%#
  		for /f "tokens=*" %%# in ('"%SingleNulV2% dir /a/s/b *!fixed_bit!*!o16lcid!*"') do %MultiNul% del /q %%#
  		popd
  	)
  	
  	timeout 5 /nobreak
  	echo:
  	goto :eof
  )
  
  set /p errortrigger=Cancel Download now? (Y/N) ^>
  if /i "%errortrigger%" EQU "Y" (
  	set wgetERR=true
  	if not defined MULTI_lang if exist "!downpath!\%directory-prefix%" rd "!downpath!\%directory-prefix%" /S /Q
  	if defined MULTI_lang if exist "!downpath!\%directory-prefix%" (
  		pushd "!downpath!\%directory-prefix%"
  		if /i "!o16arch!" EQU "x86" set "fixed_bit=32"
  		if /i "!o16arch!" EQU "x64" set "fixed_bit=64"
  		for /f "tokens=*" %%# in ('"%SingleNulV2% dir /a/s/b *!fixed_bit!*!o16lang!*"') do %MultiNul% del /q %%#
  		for /f "tokens=*" %%# in ('"%SingleNulV2% dir /a/s/b *!fixed_bit!*!o16lcid!*"') do %MultiNul% del /q %%#
  		popd
  	)
  )
  echo:
  goto :eof
::===============================================================================================================
::===============================================================================================================
:DownloadO16Online
  cd /D "%OfficeRToolpath%"
   
  cls
  echo:
                      set "tt=DOWNLOAD OFFICE ONLINE SETUP FILE"
  if defined DloadLP  set "tt=DOWNLOAD OFFICE ONLINE LP FILE"
  if defined DloadImg set "tt=DOWNLOAD OFFICE OFFLINE INSTALL IMAGE"
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! !tt! !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo ____________________________________________________________________________
    
  set "txt="
  
  set "of16install=0"
  set "of19install=0"
  set "of21install=0"
  set "of24install=0"
  
  set "pr16install=0"
  set "pr19install=0"
  set "pr21install=0"
  set "pr24install=0"
  
  set "vi16install=0"
  set "vi19install=0"
  set "vi21install=0"
  set "vi24install=0"
  
  set O365HomePremRetail=0
  set O365BusinessRetail=0
  set O365ProPlusRetail=0
  set "WebProduct=not set"
  set "installtrigger=0"
  if defined DloadLP goto :ArchSelectXYYY
  if not defined DloadImg if not defined DloadLP set "txt=setup.exe "
  
  echo:
  echo Language:      !o16lang! (!langtext!)
  echo:
  echo Architecture:  !o16arch!
  echo ____________________________________________________________________________
  echo:
  echo Set new Office Package download path or press return for
  
  echo "!downpath!" | %SingleNul% find /i "not set" && (
  	set "downpath=%SystemDrive%\Downloads"
  )
  set /p downpath=Set Office Package Download Path ^= "!downpath!" ^>
  set "downpath=!downpath:"=!"
  if defined AutoPilotMode if !_Action! EQU 1 (
    set "downpath=!_Location:"=!"
  )
  if /i "!downpath!" EQU "X" (set "downpath=not set")&&goto:Office16VnextInstall
  set "downdrive=!downpath:~0,2!"
  if "!downdrive:~-1!" NEQ ":" (echo:)&&(echo Unknown Drive "!downdrive!" - Drive not found)&&(echo Enter correct driveletter:\directory or enter "X" to exit)&&(echo:)&&(pause)&&(set "downpath=not set")&&goto:Office16VnextInstall
  cd /d !downdrive!\ %MultiNul%
  if errorlevel 1 (echo:)&&(echo Unknown Drive "!downdrive!" - Drive not found)&&(echo Enter correct driveletter:\directory or enter "X" to exit)&&(echo:)&&(pause)&&(set "downpath=not set")&&goto:Office16VnextInstall
  set "downdrive=!downpath:~0,3!"
  if "!downdrive:~-1!" EQU "\" (set "downpath=!downdrive!!downpath:~3!") else (set "downpath=!downdrive:~0,2!\!downpath:~2!")
  if "!downpath:~-1!" EQU "\" set "downpath=!downpath:~0,-1!"
    ::===============================================================================================================
  cd /D "%OfficeRToolpath%"
  set "installtrigger=0"
  echo:
  if "%inidownpath%" NEQ "!downpath!" ((echo Office install package download path changed)&&(echo old path "%inidownpath%" -- new path "!downpath!")&&(echo:))
  if defined AutoSaveToIni goto :begistenses
  if defined DontSaveToIni goto :hedumbletonic
  if "%inidownpath%" NEQ "!downpath!" set /p installtrigger=Save new path to %buildINI%? (1/0) ^>
  if "!installtrigger!" EQU "0" goto:hedumbletonic
  if /I "!installtrigger!" EQU "X" goto:hedumbletonic
:begistenses
  set "inidownpath=!downpath!"
  echo -------------------------------->%buildINI%
  echo ^:^: default download-path>>%buildINI%
  echo %inidownpath%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-language>>%buildINI%
  echo %inidownlang%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-architecture>>%buildINI%
  echo %inidownarch%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo Download path saved.
::===============================================================================================================
:hedumbletonic
  
  
  echo:
  echo %hMenu_S%
  echo #######################################
  
  echo:	
  set /p installtrigger=Generate Office 2016 products !txt!download-link ^>
  if /I "!installtrigger!" EQU "X" goto:Office16VnextInstall
  if "!installtrigger!" NEQ "0" goto:WEBOFF2016
  
  set /p installtrigger=Generate Office 2019 products !txt!download-link ^>
  if /I "!installtrigger!" EQU "X" goto:Office16VnextInstall
  if "!installtrigger!" NEQ "0" goto:WEBOFF2019
  
  set /p installtrigger=Generate Office 2021 products !txt!download-link ^>
  if /I "!installtrigger!" EQU "X" goto:Office16VnextInstall
  if "!installtrigger!" NEQ "0" goto:WEBOFF2021
  
  set /p installtrigger=Generate Office 2024 products !txt!download-link ^>
  if /I "!installtrigger!" EQU "X" goto:Office16VnextInstall
  if "!installtrigger!" NEQ "0" goto:WEBOFF2024
  
  if defined DloadLP goto :sually
  
  echo:
  
  set /p O365HomePremRetail=Generate Microsoft 365 Home Premium !txt!download-link ^>
  if /I "%O365HomePremRetail%" EQU "X" goto:Office16VnextInstall
  if "%O365HomePremRetail%" 	 NEQ "0" set "WebProduct=O365HomePremRetail" & goto:ArchSelectXYYY
  
  set /p O365BusinessRetail=Generate Microsoft 365 Business Premium !txt!download-link ^>
  if /I "%O365BusinessRetail%" EQU "X" goto:Office16VnextInstall
  if "%O365BusinessRetail%" 	 NEQ "0" set "WebProduct=O365BusinessRetail" & goto:ArchSelectXYYY
  
  set /p O365ProPlusRetail=Generate Microsoft 365 Professional Plus !txt!download-link ^>
  if /I "%O365ProPlusRetail%"  EQU "X" goto:Office16VnextInstall
  if "%O365ProPlusRetail%" 	 NEQ "0" set "WebProduct=O365ProPlusRetail" & goto:ArchSelectXYYY
  
:sually
  %SingleNul% timeout 2 /nobreak
  goto:DownloadO16Online
  
:WEBOFF2016
  echo:
  echo %hMenu_S%
  echo #######################################
  echo:
    set /p of16install=Set Office Professional Plus 2016 Install ^>
  if "%of16install%" NEQ "0" (set "WebProduct=ProPlusRetail")&&(goto:ArchSelectXYYY)
    set /p pr16install=Set Project Professional 2016 Install ^>
  if "%pr16install%" NEQ "0" (set "WebProduct=ProjectProRetail")&&(goto:ArchSelectXYYY)
    set /p vi16install=Set Visio Professional 2016 Install ^>
  if "%vi16install%" NEQ "0" (set "WebProduct=VisioProRetail")&&(goto:ArchSelectXYYY)
  goto:WEBOFFNOTHING
  
:WEBOFF2019
  echo:
  echo %hMenu_S%
  echo #######################################
  echo:
    set /p of19install=Set Office Professional Plus 2019 Install ^>
  if "%of19install%" NEQ "0" (set "WebProduct=ProPlus2019Retail")&&(goto:ArchSelectXYYY)
    set /p pr19install=Set Project Professional 2019 Install ^>
  if "%pr19install%" NEQ "0" (set "WebProduct=ProjectPro2019Retail")&&(goto:ArchSelectXYYY)
    set /p vi19install=Set Visio Professional 2019 Install ^>
  if "%vi19install%" NEQ "0" (set "WebProduct=VisioPro2019Retail")&&(goto:ArchSelectXYYY)
  goto:WEBOFFNOTHING
  
:WEBOFF2021
  echo:
  echo %hMenu_S%
  echo #######################################
  echo:
    set /p of21install=Set Office Professional Plus 2021 Install ^>
  if "%of21install%" NEQ "0" (set "WebProduct=ProPlus2021Retail")&&(goto:ArchSelectXYYY)
    set /p pr21install=Set Project Professional 2021 Install ^>
  if "%pr21install%" NEQ "0" (set "WebProduct=ProjectPro2021Retail")&&(goto:ArchSelectXYYY)
    set /p vi21install=Set Visio Professional 2021 Install ^>
  if "%vi21install%" NEQ "0" (set "WebProduct=VisioPro2021Retail")&&(goto:ArchSelectXYYY)
  goto:WEBOFFNOTHING
  
:WEBOFF2024
  echo:
  echo %hMenu_S%
  echo #######################################
  echo:
    set /p of24install=Set Office Professional Plus 2024 Install ^>
  if "%of24install%" NEQ "0" (set "WebProduct=ProPlus2024Retail")&&(goto:ArchSelectXYYY)
    set /p pr24install=Set Project Professional 2024 Install ^>
  if "%pr24install%" NEQ "0" (set "WebProduct=ProjectPro2024Retail")&&(goto:ArchSelectXYYY)
    set /p vi24install=Set Visio Professional 2024 Install ^>
  if "%vi24install%" NEQ "0" (set "WebProduct=VisioPro2024Retail")&&(goto:ArchSelectXYYY)
  goto:WEBOFFNOTHING
  
:WEBOFFNOTHING
  echo:
  echo ____________________________________________________________________________
  echo:
  echo Nothing selected - Returning to Main Menu now
  echo:
  if not defined debugMode if not defined AutoTask pause
  goto:Office16VnextInstall
::===============================================================================================================
::===============================================================================================================

:ArchSelectXYYY
  if defined DloadImg set "o16arch=Multi" & goto:WebLangSelect
  if /i '%PROCESSOR_ARCHITECTURE%' EQU 'x86' 		(IF NOT DEFINED PROCESSOR_ARCHITEW6432 set sBit=86)
  if /i '%PROCESSOR_ARCHITECTURE%' EQU 'x86' 		(IF DEFINED PROCESSOR_ARCHITEW6432 set sBit=64)
  if /i '%PROCESSOR_ARCHITECTURE%' EQU 'AMD64' 	set sBit=64
  if /i '%PROCESSOR_ARCHITECTURE%' EQU 'IA64' 	set sBit=64
  
  set "o16arch=x!sBit!"
  if defined inidownarch ((echo "!inidownarch!" | %SingleNul% find /i "not set") || set "o16arch=!inidownarch!")
  if /i '!o16arch!' EQU 'Multi' set "o16arch=x!sBit!"	
  if /i 'x!sBit!' NEQ '!o16arch!' (if /i '!sBit!' EQU '86' (set "o16arch=x!sBit!"))
  
  echo:
  set /p o16arch=Set architecture to download (x86 or x64) - or press return for !o16arch! ^>
  if /i "!o16arch!" EQU "x86" goto:WebLangSelect
  if /i "!o16arch!" EQU "x64" goto:WebLangSelect
  set "o16arch=not set"
  goto:ArchSelectXYYY

:WebLangSelect
    cd /D "%OfficeRToolpath%"
  set "installtrigger=0"
  echo:
  if "%inidownarch%" NEQ "!o16arch!" ((echo Office install package download architecture changed)&&(echo old architecture "%inidownarch%" -- new architecture "!o16arch!")&&(echo:))
  if defined AutoSaveToIni goto :arkets
  if defined DontSaveToIni goto :bowishadve
  if "%inidownarch%" NEQ "!o16arch!" set /p installtrigger=Save new architecture to %buildINI%? (1/0) ^>
  if "!installtrigger!" EQU "0" goto:bowishadve
  if /I "!installtrigger!" EQU "X" goto:bowishadve
  
  :arkets
  set "inidownarch=!o16arch!"
  echo -------------------------------->%buildINI%
  echo ^:^: default download-path>>%buildINI%
  echo %inidownpath%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-language>>%buildINI%
  echo %inidownlang%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-architecture>>%buildINI%
  echo %inidownarch%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo Download architecture saved.
::===============================================================================================================
:bowishadve
  if not defined DloadLP  call :MainLangSelection
  if     defined DloadLP  call :AllLangSelection
:osofess
  echo:
  if /i "!o16lang!" EQU "not set" call :CheckSystemLanguage
    set /p o16lang=Set Language Value - or press return for !o16lang! ^>
  set "o16lang=!o16lang:, =!"
  set "o16lang=!o16lang:,=!"
  if defined o16lang if /i "x!o16lang:~0,1!" EQU "x " set "o16lang=!o16lang:~1!"
  if defined o16lang if /i "!o16lang:-1!x" EQU " x" set "o16lang=!o16lang:~0,-1!"
  call :SetO16Language
  if defined langnotfound (
  	set "o16lang=not set"
  	goto :osofess
  )
  
  cd /D "%OfficeRToolpath%"
  set "installtrigger=0"
  if "%inidownlang%" NEQ "!o16lang!" ((echo:)&&(echo Office install package download language changed)&&(echo old language "%inidownlang%" -- new language "!o16lang!")&&(echo:))
  if defined AutoSaveToIni goto :gestantic
  if defined DontSaveToIni goto :lamiconds
  if "%inidownlang%" NEQ "!o16lang!" set /p installtrigger=Save new language to %buildINI%? (1/0) ^>
  if "!installtrigger!" EQU "0" goto:lamiconds
  if /I "!installtrigger!" EQU "X" goto:lamiconds
  
  :gestantic
  set "inidownlang=!o16lang!"
  echo -------------------------------->%buildINI%
  echo ^:^: default download-path>>%buildINI%
  echo %inidownpath%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-language>>%buildINI%
  echo %inidownlang%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-architecture>>%buildINI%
  echo %inidownarch%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo Download language saved.
  
::===============================================================================================================
:lamiconds
::===============================================================================================================
  echo:
  echo ____________________________________________________________________________
  echo:
                      set "tt=Pending Online SETUP Downlad (SUMMARY)"
  if defined DloadLP  set "tt=Pending Online LP Downlad (SUMMARY)"
  if defined DloadImg set "tt=Pending Online IMAGE Downlad (SUMMARY)"
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! !tt! !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  
  if "%of16install%" NEQ "0" echo Download Office 2016 ?      : YES
  if "%of19install%" NEQ "0" echo Download Office 2019 ?      : YES
  if "%of21install%" NEQ "0" echo Download Office 2021 ?      : YES
  if "%of24install%" NEQ "0" echo Download Office 2024 ?      : YES
  
  if "%pr16install%" NEQ "0" echo Download Project 2016 ?     : YES
  if "%pr19install%" NEQ "0" echo Download Project 2019 ?     : YES
  if "%pr21install%" NEQ "0" echo Download Project 2021 ?     : YES
  if "%pr24install%" NEQ "0" echo Download Project 2024 ?     : YES
  
  if "%vi16install%" NEQ "0" echo Download Visio 2016 ?       : YES
  if "%vi19install%" NEQ "0" echo Download Visio 2019 ?       : YES
  if "%vi21install%" NEQ "0" echo Download Visio 2021 ?       : YES
  if "%vi24install%" NEQ "0" echo Download Visio 2024 ?       : YES
  
  if "%O365HomePremRetail%" NEQ "0" echo Download Microsoft Office 365 Home Premium ?       : YES
  if "%O365BusinessRetail%" NEQ "0" echo Download Microsoft Office 365 Business ?       : YES
  if "%O365ProPlusRetail%"  NEQ "0" echo Download Microsoft Office 365 Professional Plus ?       : YES
    
  echo:
  echo Install Architecture ?     : !o16arch!
  echo Install Language ?         : !o16lang!
  echo ____________________________________________________________________________
  
:Error_Check_3_VALIDATE
  echo:
  set "installtrigger="
  set /p installtrigger=(Enter) to download, (R)estart download, (E)xit to main menu ^>
  if defined installtrigger (
    ((echo !installtrigger!|%multinul% findstr /i /r "^[R]$ ^[E]$") && (goto :Error_Check_3_PASS) || (goto :Error_Check_3_VALIDATE))
    goto :Error_Check_3_VALIDATE
  )
:Error_Check_3_PASS
    if /i "!installtrigger!" EQU "R" goto:DownloadO16Online
  if /I "!installtrigger!" EQU "E" goto:Office16VnextInstall
::===============================================================================================================
::===============================================================================================================
:OfficeWebInstall
    cls
  echo:
  					set "tt=DOWNLOAD OFFICE ONLINE SETUP INSTALLER"
  if defined DloadImg set "tt=DOWNLOAD OFFICE OFFLINE IMAGE INSTALLER"
  if defined DloadLP  set "tt=DOWNLOAD OFFICE ONLINE LANGUAGE PACK INSTALLER"
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! !tt! !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  if defined DloadImg (
  
  	call :GenerateIMGLink > "%windir%\Temp\tmp.ps1"
  	%PowerShellEXE% -noprofile -executionpolicy bypass -file "%windir%\Temp\tmp.ps1"
  	
  	set "ISO="
  	set "OfficeVer="
  	set "Zz=%~dp0Data\Bin\7z.exe"
  	
  	if "%of16install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2016_PROPLUS_Retail.ISO"
  	if "%of19install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2019_PROPLUS_Retail.ISO"
  	if "%of21install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2021_PROPLUS_Retail.ISO"
  	if "%of24install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2024_PROPLUS_Retail.ISO"
  	
  	if "%pr16install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2016_PROJECT_PRO_Retail.ISO"
  	if "%pr19install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2019_PROJECT_PRO_Retail.ISO"
  	if "%pr21install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2021_PROJECT_PRO_Retail.ISO"
  	if "%pr24install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2024_PROJECT_PRO_Retail.ISO"
  	
  	if "%vi16install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2016_VISIO_PRO_Retail.ISO"
  	if "%vi19install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2019_VISIO_PRO_Retail.ISO"
  	if "%vi21install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2021_VISIO_PRO_Retail.ISO"
  	if "%vi24install%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_2024_VISIO_PRO_Retail.ISO"
  	
  	if "%O365HomePremRetail%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_Microsoft_365_Home_Premium_Retail.ISO"
  	if "%O365BusinessRetail%" NEQ "0" set "ISO=%inidownpath%\!o16lang!_Microsoft_365_Business_Premium_Retail.ISO"
  	if "%O365ProPlusRetail%"  NEQ "0" set "ISO=%inidownpath%\!o16lang!_Microsoft_365_Professional_Plus_Retail.ISO"
  	
  	set "forCmd="!Zz!" l "!ISO!" "Office\Data""
  	goto:NEXTBLAT
  	
  )
  
  if defined DloadLP (
  	call :GenerateLPLink > "%windir%\Temp\tmp.ps1"
  	%PowerShellEXE% -noprofile -executionpolicy bypass -file "%windir%\Temp\tmp.ps1"
  	goto:TheFinalCountDown
  )

  if not defined DloadLP if not defined DloadImg (
  
  	call :GenerateSetupLink > "%windir%\Temp\tmp.ps1"
  	%PowerShellEXE% -noprofile -executionpolicy bypass -file "%windir%\Temp\tmp.ps1"
  	goto:TheFinalCountDown
  )
  
:NEXTBLAT
  if exist "%ISO%" for /f "tokens=4 skip=19 delims= " %%$ in ('"!forCmd!"') do if not defined OfficeVer set "OfficeVer=%%$"
  for %%I in ("%ISO%") do set "SourcePath=%%~dpI"
  for %%I in ("%ISO%") do set "newFile=%%~nI_v!OfficeVer:~12!.iso"
  if defined OfficeVer if not exist "!SourcePath!!newFile!" ren "%ISO%" "!newFile!"

:TheFinalCountDown
    echo ____________________________________________________________________________
  echo:
    echo:
  timeout /t 8
    goto:Office16VnextInstall
::===============================================================================================================
::===============================================================================================================
:CheckActivationStatus
::===============================================================================================================
  call :CheckOfficeApplications
   
::===============================================================================================================
  set "CDNBaseUrl=not set"
  set "UpdateUrl=not set"
  set "UpdateBranch=not set"
  cls
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! SHOW CURRENT ACTIVATION STATUS !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  echo Office installation path:
  echo %installpath16%
  echo:
  if "%ProPlusVLFound%" EQU "YES" ((set "ChannelName=Native Volume (VLSC)")&&(set "UpdateUrl=Windows Update")&&(goto:CheckActCont))
  if "%StandardVLFound%" EQU "YES" ((set "ChannelName=Native Volume (VLSC)")&&(set "UpdateUrl=Windows Update")&&(goto:CheckActCont))
  if "%ProjectProVLFound%" EQU "YES" ((set "ChannelName=Native Volume (VLSC)")&&(set "UpdateUrl=Windows Update")&&(goto:CheckActCont))
  if "%VisioProVLFound%" EQU "YES" ((set "ChannelName=Native Volume (VLSC)")&&(set "UpdateUrl=Windows Update")&&(goto:CheckActCont))
  if "%_UWPappINSTALLED%" EQU "YES" ((set "ChannelName=Microsoft (Apps) Store")&&(set "UpdateUrl=Microsoft (Apps) Store")&&(goto:CheckActCont))
  for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\Configuration" /v "CDNBaseUrl" 2^>nul') DO (Set "CDNBaseUrl=%%B")
  for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\Configuration" /v "UpdateUrl" 2^>nul') DO (Set "UpdateUrl=%%B")
  call:DecodeChannelName %UpdateUrl%
::===============================================================================================================
:CheckActCont
  echo Distribution-Channel:
  echo %ChannelName%
  echo:
  echo Updates-Url:
  echo %UpdateUrl%
  echo ____________________________________________________________________________
  
  set ohook_found=
  for %%# in (15 16) do (
    for %%A in ("%ProgramFiles%" "%ProgramW6432%" "%ProgramFiles(x86)%") do (
      %MultiNul% dir "%%~A\Microsoft Office\Office%%#\sppc*dll" /AL /b && set ohook_found=* ))

  for %%# in (System SystemX86) do (
    for %%G in ("Office 15" "Office") do (
      for %%A in ("%ProgramFiles%" "%ProgramW6432%" "%ProgramFiles(x86)%") do (
	    %MultiNul% dir "%%~A\Microsoft %%~G\root\vfs\%%#\sppc*dll" /AL /b && set ohook_found=*)))
  
  if defined ohook_found (
    echo:
    echo Permanent activation was found ^(MAS - Ohook^)
	echo You can ignore down below results
	echo:
    echo ____________________________________________________________________________
  )
  
  echo:
  
  if "%_MondoRetail%" EQU "YES" ((echo Office Mondo Grande Suite --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_MondoVolume%" EQU "YES" ((echo Office Mondo Grande Suite --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  
  if "%_ProPlusRetail%" EQU "YES" ((echo Office Professional Plus 2016 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProPlus))
  if "%_ProPlusVolume%" EQU "YES" ((echo Office Professional Plus 2016 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProPlus))
  if "%_ProPlus2019Retail%" EQU "YES" ((echo Office Professional Plus 2019 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProPlus2019))
  if "%_ProPlus2019Volume%" EQU "YES" ((echo Office Professional Plus 2019 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProPlus2019))
  if "%_ProPlus2021Retail%" EQU "YES" ((echo Office Professional Plus 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProPlus2021))
  if "%_ProPlus2021Volume%" EQU "YES" ((echo Office Professional Plus 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProPlus2021))
  if "%_ProPlusSPLA2021Volume%" EQU "YES" ((echo Office Professional Plus 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProPlus2021))
  if "%_ProPlus2024Retail%" EQU "YES" ((echo Office Professional Plus 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProPlus2024))
  if "%_ProPlus2024Volume%" EQU "YES" ((echo Office Professional Plus 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProPlus2024))
  if "%_ProPlusSPLA2024Volume%" EQU "YES" ((echo Office Professional Plus 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProPlus2024))
    
  if "%_ProfessionalRetail%" EQU "YES" ((echo Professional Retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_Professional2019Retail%" EQU "YES" ((echo Professional 2019 Retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_Professional2021Retail%" EQU "YES" ((echo Professional 2021 Retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_Professional2024Retail%" EQU "YES" ((echo Professional 2024 Retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  
  if "%_PersonalRetail%" EQU "YES" ((echo Office Personal 2016 Retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_Personal2019Retail%" EQU "YES" ((echo Office Personal 2019 Retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_Personal2021Retail%" EQU "YES" ((echo Office Personal 2021 Retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_Personal2019Retail%" EQU "YES" ((echo Office Personal 2019 Retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_Personal2024Retail%" EQU "YES" ((echo Office Personal 2024 Retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  
  if "%_StandardRetail%" EQU "YES" ((echo Office Standard 2016 --- ProductVersion: %o16version%)&&(echo:)&&(call :CheckKMSActivation Standard))
  if "%_StandardVolume%" EQU "YES" ((echo Office Standard 2016 --- ProductVersion: %o16version%)&&(echo:)&&(call :CheckKMSActivation Standard))
  if "%_Standard2019Retail%" EQU "YES" ((echo Office Standard 2019 --- ProductVersion: %o16version%)&&(echo:)&&(call :CheckKMSActivation Standard2019))
  if "%_Standard2019Volume%" EQU "YES" ((echo Office Standard 2019 --- ProductVersion: %o16version%)&&(echo:)&&(call :CheckKMSActivation Standard2019))
  if "%_Standard2021Retail%" EQU "YES" ((echo Office Standard 2021 --- ProductVersion: %o16version%)&&(echo:)&&(call :CheckKMSActivation Standard2021))
  if "%_Standard2021Volume%" EQU "YES" ((echo Office Standard 2021 --- ProductVersion: %o16version%)&&(echo:)&&(call :CheckKMSActivation Standard2021))
  if "%_StandardSPLA2021Volume%" EQU "YES" ((echo Office Standard 2021 --- ProductVersion: %o16version%)&&(echo:)&&(call :CheckKMSActivation Standard2021))
  if "%_Standard2024Retail%" EQU "YES" ((echo Office Standard 2024 --- ProductVersion: %o16version%)&&(echo:)&&(call :CheckKMSActivation Standard2024))
  if "%_Standard2024Volume%" EQU "YES" ((echo Office Standard 2024 --- ProductVersion: %o16version%)&&(echo:)&&(call :CheckKMSActivation Standard2024))
  if "%_StandardSPLA2024Volume%" EQU "YES" ((echo Office Standard 2024 --- ProductVersion: %o16version%)&&(echo:)&&(call :CheckKMSActivation Standard2024))
  
  if "%_O365BusinessEEANoTeamsRetail%" EQU "YES" ((echo Microsoft 365 Apps for Business --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_O365BusinessRetail%" EQU "YES" ((echo Microsoft 365 Apps for Business --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_O365HomePremRetail%" EQU "YES" ((echo Microsoft 365 Home Premium retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_O365ProPlusEEANoTeamsRetail%" EQU "YES" ((echo Microsoft 365 Apps for Enterprise --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_O365ProPlusRetail%" EQU "YES" ((echo Microsoft 365 Apps for Enterprise --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_O365SmallBusPremRetail%" EQU "YES" ((echo Microsoft 365 Small Business retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_O365AppsBasicRetail%" EQU "YES" ((echo Microsoft 365 Basic retail --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  
  if "%_AppxAccess%" EQU "YES" ((echo Access UWP Appx ----- ProductVersion : %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_AppxExcel%" EQU "YES" ((echo Excel UWP Appx --- ProductVersion : %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_AppxOneNote%" EQU "YES" ((echo OneNote UWP Appx ---- ProductVersion : %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_AppxOutlook%" EQU "YES" ((echo Outlook UWP Appx ---- ProductVersion : %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_AppxPowerPoint%" EQU "YES" ((echo PowerPoint UWP Appx - ProductVersion : %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_AppxProject%" EQU "YES" ((echo Project Professional UWP Appx - ProductVersion : %o16version%)&&(call :CheckKMSActivation ProjectPro))
  if "%_AppxPublisher%" EQU "YES" ((echo Publisher UWP Appx -- ProductVersion : %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_AppxSkypeForBusiness%" EQU "YES" ((echo Skype UWP Appx ------ ProductVersion : %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_AppxVisio%" EQU "YES" ((echo Visio Professional UWP Appx --- ProductVersion : %o16version%)&&(call :CheckKMSActivation VisioPro))
  if "%_AppxWinword%" EQU "YES" ((echo Word UWP Appx --- ProductVersion : %o16version%)&&(call :CheckKMSActivation Mondo))

  if "%_HomeStudentRetail%" EQU "YES" ((echo Microsoft Home And Student --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_HomeStudent2019Retail%" EQU "YES" ((echo Microsoft Home And Student 2019 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_HomeStudent2021Retail%" EQU "YES" ((echo Microsoft Home And Student 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_HomeStudent2024Retail%" EQU "YES" ((echo Microsoft Home And Student 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  
  if "%_HomeBusinessRetail%" EQU "YES" ((echo Microsoft Home And Business --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_HomeBusiness2019Retail%" EQU "YES" ((echo Microsoft Home And Business 2019 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_HomeBusiness2021Retail%" EQU "YES" ((echo Microsoft Home And Business 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))
  if "%_HomeBusiness2024Retail%" EQU "YES" ((echo Microsoft Home And Business 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Mondo))

  if "%_AccessRetail%" EQU "YES" ((echo Access 2016 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Access))
  if "%_AccessVolume%" EQU "YES" ((echo Access 2016 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Access))  
  if "%_Access2019Retail%" EQU "YES" ((echo Access 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Access2019))
  if "%_Access2019Volume%" EQU "YES" ((echo Access 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Access2019))
  if "%_Access2021Retail%" EQU "YES" ((echo Access 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Access2021))
  if "%_Access2021Volume%" EQU "YES" ((echo Access 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Access2021))
  if "%_Access2024Retail%" EQU "YES" ((echo Access 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Access2024))
  if "%_Access2024Volume%" EQU "YES" ((echo Access 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Access2024))

  if "%_ExcelRetail%" EQU "YES" ((echo Excel 2016 SingleApp ----------------- ProductVersion : %o16version%)&&(call :CheckKMSActivation Excel))
  if "%_ExcelVolume%" EQU "YES" ((echo Excel 2016 SingleApp ----------------- ProductVersion : %o16version%)&&(call :CheckKMSActivation Excel))  
  if "%_Excel2019Retail%" EQU "YES" ((echo Excel 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Excel2019))
  if "%_Excel2019Volume%" EQU "YES" ((echo Excel 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Excel2019))
  if "%_Excel2021Retail%" EQU "YES" ((echo Excel 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Excel2021))
  if "%_Excel2021Volume%" EQU "YES" ((echo Excel 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Excel2021))
  if "%_Excel2024Retail%" EQU "YES" ((echo Excel 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Excel2024))
  if "%_Excel2024Volume%" EQU "YES" ((echo Excel 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Excel2024))

  if "%_OneNoteRetail%" EQU "YES" ((echo OneNote 2016 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation OneNote))
  if "%_OneNoteVolume%" EQU "YES" ((echo OneNote 2016 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation OneNote))
  if "%_OneNote2021Retail%" EQU "YES" ((echo OneNote 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation OneNote))
  if "%_OneNote2024Retail%" EQU "YES" ((echo OneNote 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation OneNote))
  
  if "%_OutlookRetail%" EQU "YES" ((echo Outlook 2016 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Outlook))
  if "%_OutlookVolume%" EQU "YES" ((echo Outlook 2016 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Outlook))
  if "%_Outlook2019Retail%" EQU "YES" ((echo Outlook 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Outlook2019))
  if "%_Outlook2019Volume%" EQU "YES" ((echo Outlook 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Outlook2019))
  if "%_Outlook2021Retail%" EQU "YES" ((echo Outlook 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Outlook2021))
  if "%_Outlook2021Volume%" EQU "YES" ((echo Outlook 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Outlook2021))
  if "%_Outlook2024Retail%" EQU "YES" ((echo Outlook 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Outlook2024))
  if "%_Outlook2024Volume%" EQU "YES" ((echo Outlook 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Outlook2024))
  
  if "%_PowerPointRetail%" EQU "YES" ((echo PowerPoint 2016 SingleApp ------------ ProductVersion : %o16version%)&&(call :CheckKMSActivation PowerPoint))
  if "%_PowerPointVolume%" EQU "YES" ((echo PowerPoint 2016 SingleApp ------------ ProductVersion : %o16version%)&&(call :CheckKMSActivation PowerPoint))
  if "%_PowerPoint2019Retail%" EQU "YES" ((echo PowerPoint 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation PowerPoint2019))
  if "%_PowerPoint2019Volume%" EQU "YES" ((echo PowerPoint 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation PowerPoint2019))
  if "%_PowerPoint2021Retail%" EQU "YES" ((echo PowerPoint 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation PowerPoint2021))
  if "%_PowerPoint2021Volume%" EQU "YES" ((echo PowerPoint 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation PowerPoint2021))
  if "%_PowerPoint2024Retail%" EQU "YES" ((echo PowerPoint 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation PowerPoint2024))
  if "%_PowerPoint2024Volume%" EQU "YES" ((echo PowerPoint 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation PowerPoint2024))
  
  if "%_ProjectProRetail%" EQU "YES" ((echo Project Professional 2016 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectPro))
  if "%_ProjectProVolume%" EQU "YES" ((echo Project Professional 2016 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectPro))
  if "%_ProjectProXVolume%" EQU "YES" ((echo Project Professional 2016 C2R --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectProXC2R))
  if "%_ProjectPro2019Retail%" EQU "YES" ((echo Project Professional 2019 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectPro2019))
  if "%_ProjectPro2019Volume%" EQU "YES" ((echo Project Professional 2019 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectPro2019))
  if "%_ProjectPro2021Retail%" EQU "YES" ((echo Project Professional 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectPro2021))
  if "%_ProjectPro2021Volume%" EQU "YES" ((echo Project Professional 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectPro2021))
  if "%_ProjectPro2024Retail%" EQU "YES" ((echo Project Professional 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectPro2024))
  if "%_ProjectPro2024Volume%" EQU "YES" ((echo Project Professional 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectPro2024))
  
  if "%_ProjectStdRetail%" EQU "YES" ((echo Project Standard 2016 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectStd))
  if "%_ProjectStdVolume%" EQU "YES" ((echo Project Standard 2016 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectStd))
  if "%_ProjectStdXVolume%" EQU "YES" ((echo Project Standard 2016 C2R --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectStdXC2R))
  if "%_ProjectStd2019Retail%" EQU "YES" ((echo Project Standard 2019 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectStd2019))
  if "%_ProjectStd2019Volume%" EQU "YES" ((echo Project Standard 2019 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectStd2019))
  if "%_ProjectStd2021Retail%" EQU "YES" ((echo Project Standard 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectStd2021))
  if "%_ProjectStd2021Volume%" EQU "YES" ((echo Project Standard 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectStd2021))
  if "%_ProjectStd2024Retail%" EQU "YES" ((echo Project Standard 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectStd2024))
  if "%_ProjectStd2024Volume%" EQU "YES" ((echo Project Standard 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation ProjectStd2024))
  
  if "%_WordRetail%" EQU "YES" ((echo Word 2016 SingleApp ------------------ ProductVersion : %o16version%)&&(call :CheckKMSActivation Word))
  if "%_WordVolume%" EQU "YES" ((echo Word 2016 SingleApp ------------------ ProductVersion : %o16version%)&&(call :CheckKMSActivation Word))
  if "%_Word2019Retail%" EQU "YES" ((echo Word 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Word2019))
  if "%_Word2019Volume%" EQU "YES" ((echo Word 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Word2019))
  if "%_Word2021Retail%" EQU "YES" ((echo Word 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Word2021))
  if "%_Word2021Volume%" EQU "YES" ((echo Word 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Word2021))
  if "%_Word2024Retail%" EQU "YES" ((echo Word 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Word2024))
  if "%_Word2024Volume%" EQU "YES" ((echo Word 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Word2024))
  
  if "%_VisioProRetail%" EQU "YES" ((echo Visio Professional 2016 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioPro))
  if "%_VisioProVolume%" EQU "YES" ((echo Visio Professional 2016 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioPro))
  if "%_VisioProXVolume%" EQU "YES" ((echo Visio Professional 2016 C2R --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioProXC2R))
  if "%_VisioPro2019Retail%" EQU "YES" ((echo Visio Professional 2019 ---- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioPro2019))
  if "%_VisioPro2019Volume%" EQU "YES" ((echo Visio Professional 2019 ---- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioPro2019))
  if "%_VisioPro2021Retail%" EQU "YES" ((echo Visio Professional 2021 ---- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioPro2021))
  if "%_VisioPro2021Volume%" EQU "YES" ((echo Visio Professional 2021 ---- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioPro2021))
  if "%_VisioPro2024Retail%" EQU "YES" ((echo Visio Professional 2024 ---- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioPro2024))
  if "%_VisioPro2024Volume%" EQU "YES" ((echo Visio Professional 2024 ---- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioPro2024))
  
  if "%_VisioStdRetail%" EQU "YES" ((echo Visio Standard 2016 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioSTD))
  if "%_VisioStdVolume%" EQU "YES" ((echo Visio Standard 2016 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioSTD))
  if "%_VisioStdXVolume%" EQU "YES" ((echo Visio Standard 2016 C2R --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioStdXC2R))
  if "%_VisioStd2019Retail%" EQU "YES" ((echo Visio Standard 2019 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioSTD2019))
  if "%_VisioStd2019Volume%" EQU "YES" ((echo Visio Standard 2019 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioStd2019))
  if "%_VisioStd2021Retail%" EQU "YES" ((echo Visio Standard 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioStd2021))
  if "%_VisioStd2021Volume%" EQU "YES" ((echo Visio Standard 2021 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioStd2021))
  if "%_VisioStd2024Retail%" EQU "YES" ((echo Visio Standard 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioStd2024))
  if "%_VisioStd2024Volume%" EQU "YES" ((echo Visio Standard 2024 --- ProductVersion: %o16version%)&&(call :CheckKMSActivation VisioStd2024))
  
  if "%_PublisherRetail%" EQU "YES" ((echo Publisher 2016 Single App --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Publisher))
  if "%_PublisherVolume%" EQU "YES" ((echo Publisher 2016 Single App --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Publisher))
  if "%_Publisher2019Retail%" EQU "YES" ((echo Publisher 2019 Single App --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Publisher2019))
  if "%_Publisher2019Volume%" EQU "YES" ((echo Publisher 2019 Single App --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Publisher2019))
  if "%_Publisher2021Retail%" EQU "YES" ((echo Publisher 2021 Single App --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Publisher2021))
  if "%_Publisher2021Volume%" EQU "YES" ((echo Publisher 2021 Single App --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Publisher2021))
  if "%_Publisher2024Retail%" EQU "YES" ((echo Publisher 2024 Single App --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Publisher2024))
  if "%_Publisher2024Volume%" EQU "YES" ((echo Publisher 2024 Single App --- ProductVersion: %o16version%)&&(call :CheckKMSActivation Publisher2024))
  
  if "%_SkypeForBusinessRetail%" EQU "YES" ((echo Skype For Business 2016 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation SkypeForBusiness))
  if "%_SkypeForBusinessVolume%" EQU "YES" ((echo Skype For Business 2016 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation SkypeForBusiness))
  if "%_SkypeForBusiness2019Retail%" EQU "YES" ((echo Skype For Business 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation SkypeForBusiness2019))
  if "%_SkypeForBusiness2019Volume%" EQU "YES" ((echo Skype For Business 2019 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation SkypeForBusiness2019))
  if "%_SkypeForBusiness2021Retail%" EQU "YES" ((echo Skype For Business 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation SkypeForBusiness2021))
  if "%_SkypeForBusiness2021Volume%" EQU "YES" ((echo Skype For Business 2021 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation SkypeForBusiness2021))
  if "%_SkypeForBusiness2024Retail%" EQU "YES" ((echo Skype For Business 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation SkypeForBusiness2024))
  if "%_SkypeForBusiness2024Volume%" EQU "YES" ((echo Skype For Business 2024 SingleApp --- ProductVersion: %o16version%)&&(call :CheckKMSActivation SkypeForBusiness2024))
  
  echo:
  echo:
  if not defined debugMode if not defined AutoTask pause
  goto:Office16VnextInstall
::===============================================================================================================
::===============================================================================================================
:CheckKMSActivation
::===============================================================================================================
  set "Product=%1"
  set "LicStatus=9"
  set "PartialProductKey=XXXXX"
  set "LicStatusText=(---UNKNOWN---)           "
  set /a "GraceMin=0"
  set "EvalEndDate=00000000"
  set "activationtext=unknown"
  set "PartProdKey=not set"
  
  set "wmiSearch=Name like '%%%%!Product!%%%%' and PartialProductKey is not NULL"
  set "info=EvaluationEndDate,GracePeriodRemaining,ID,LicenseFamily,LicenseStatus,PartialProductKey"
  if %WinBuild% GEQ 9200 call :Query "!info!" "!slp!"  "!wmiSearch!"
  if %WinBuild% LSS 9200 call :Query "!info!" "!ospp!" "!wmiSearch!"
  if not exist "%Res______%" exit /b
  
  for /f "tokens=1,2,3,4,5,6,7,8 delims=," %%g in ('type "%Res______%"') do (
  	set "EvalEndDate=%%g"
  	set "GraceMin=%%h"
  	set "ID=%%i"
  	set "LicFamily=%%j"
  	set "LicStatus=%%k"
  	set "PartialProductKey=%%l"
  )
  
  set /a GraceDays=!GraceMin!/1440
  set "EvalEndDate=!EvalEndDate:~0,8!"
  set "EvalEndDate=!EvalEndDate:~4,2!/!EvalEndDate:~6,2!/!EvalEndDate:~0,4!"
  if "!LicStatus!" EQU "0" (set "LicStatusText=(---UNLICENSED---)        ")
  if "!LicStatus!" EQU "1" (set "LicStatusText=(---LICENSED---)          ")
  if "!LicStatus!" EQU "2" (set "LicStatusText=(---OOB_GRACE---)         ")
  if "!LicStatus!" EQU "3" (set "LicStatusText=(---OOT_GRACE---)         ")
  if "!LicStatus!" EQU "4" (set "LicStatusText=(---NONGENUINE_GRACE---)  ")
  if "!LicStatus!" EQU "5" (set "LicStatusText=(---NOTIFICATIONS---)     ")
  if "!LicStatus!" EQU "6" (set "LicStatusText=(---EXTENDED_GRACE---)    ")
  echo:
  echo License Family: !LicFamily!
  echo:
  echo Activation status: !LicStatus!  !LicStatusText! PartialProductKey: !PartialProductKey!
  if "!EvalEndDate!" NEQ "01/01/1601" (set "activationtext=Product's activation is time-restricted")
  if "!EvalEndDate!" EQU "01/01/1601" (set "activationtext=Product is permanently activated")
  if !LicStatus! EQU 1 if !GraceMin! EQU 0 ((echo:)&&(echo Remaining Retail activation period: !activationtext!))
  if !LicStatus! GEQ 1 if !GraceDays! GEQ 1 (echo:)
  if !LicStatus! GEQ 1 if !GraceDays! GEQ 1 %PowerShellEXE% -noprofile -command "!pswindowtitle!"; Write-Host "Remaining KMS activation period: '!GraceDays!' days left '-' License expires:' '" -nonewline; Get-Date -date $(Get-Date).AddMinutes(!GraceMin!) -Format (Get-Culture).DateTimeFormat.ShortDatePattern
  if "!EvalEndDate!" NEQ "00/00/0000" if "!EvalEndDate!" NEQ "01/01/1601" ((echo:)&&(echo Evaluation/Preview timebomb active - Office product end-of-life: !EvalEndDate!))
  echo ____________________________________________________________________________
  echo:
  goto :eof
::===============================================================================================================
::===============================================================================================================
:ChangeUpdPath
  call :CheckOfficeApplications
   
::===============================================================================================================
  set "CDNBaseUrl=not set"
  set "UpdateUrl=not set"
  set "UpdateBranch=not set"
  set "installtrigger=0"
  set "channeltrigger=0"
  set "restrictbuild=newest available"
  set "updatetoversion="
  cls
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! CHANGE INSTALLED OFFICE UPDATE-PATH !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  
  if "%ProPlusVLFound%" EQU "YES" ((echo:)&&(echo CHANGE OFFICE UPDATE-PATH is not possible for native VLSC Volume version)&&(echo:)&&(pause)&&(goto:Office16VnextInstall))
  if "%StandardVLFound%" EQU "YES" ((echo:)&&(echo CHANGE OFFICE UPDATE-PATH is not possible for native VLSC Volume version)&&(echo:)&&(pause)&&(goto:Office16VnextInstall))
  if "%ProjectProVLFound%" EQU "YES" ((echo:)&&(echo CHANGE OFFICE UPDATE-PATH is not possible for native VLSC Volume version)&&(echo:)&&(pause)&&(goto:Office16VnextInstall))
  if "%VisioProVLFound%" EQU "YES" ((echo:)&&(echo CHANGE OFFICE UPDATE-PATH is not possible for native VLSC Volume version)&&(echo:)&&(pause)&&(goto:Office16VnextInstall))
  if "%_UWPappINSTALLED%" EQU "YES" ((echo:)&&(echo CHANGE OFFICE UPDATE-PATH is not possible for Office UWP Appx Store Apps)&&(echo:)&&(pause)&&(goto:Office16VnextInstall))
  
  if "%_MondoRetail%" EQU "YES"                (echo Office Mondo Grande Suite ------------ ProductVersion : %o16version%)
  if "%_MondoVolume%" EQU "YES"                (echo Office Mondo Grande Suite ------------ ProductVersion : %o16version%)
  
  if "%_AppxAccess%" EQU "YES"                 (echo Access UWP Appx ---------------------- ProductVersion : %o16version%)
  if "%_AppxExcel%" EQU "YES"                  (echo Excel UWP Appx ----------------------- ProductVersion : %o16version%)
  if "%_AppxOneNote%" EQU "YES"                (echo OneNote UWP Appx --------------------- ProductVersion : %o16version%)
  if "%_AppxOutlook%" EQU "YES"                (echo Outlook UWP Appx --------------------- ProductVersion : %o16version%)
  if "%_AppxPowerPoint%" EQU "YES"             (echo PowerPoint UWP Appx ------------------ ProductVersion : %o16version%)
  if "%_AppxProject%" EQU "YES"                (echo Project professional UWP Appx -------- ProductVersion : %o16version%)
  if "%_AppxPublisher%" EQU "YES"              (echo Publisher UWP Appx ------------------- ProductVersion : %o16version%)
  if "%_AppxSkypeForBusiness%" EQU "YES"       (echo Skype UWP Appx ----------------------- ProductVersion : %o16version%)
  if "%_AppxVisio%" EQU "YES"                  (echo Visio professional UWP Appx ---------- ProductVersion : %o16version%)
  if "%_AppxWinword%" EQU "YES"                (echo Word UWP Appx ------------------------ ProductVersion : %o16version%)
  
  if "%_PersonalRetail%" EQU "YES"             (echo Office Personal 2016 Retail ---------- ProductVersion : %o16version%)
  if "%_Personal2019Retail%" EQU "YES"         (echo Office Personal 2019 Retail ---------- ProductVersion : %o16version%)
  if "%_Personal2021Retail%" EQU "YES"         (echo Office Personal 2021 Retail ---------- ProductVersion : %o16version%)
  if "%_Personal2024Retail%" EQU "YES"         (echo Office Personal 2024 Retail ---------- ProductVersion : %o16version%)
  
  if "%_HomeBusinessRetail%" EQU "YES" 		 (echo Microsoft Home And Business ---------- ProductVersion : %o16version%)
  if "%_HomeBusiness2019Retail%" EQU "YES" 	 (echo Microsoft Home And Business 2019 ----- ProductVersion : %o16version%)
  if "%_HomeBusiness2021Retail%" EQU "YES" 	 (echo Microsoft Home And Business 2021 ----- ProductVersion : %o16version%)
  if "%_HomeBusiness2024Retail%" EQU "YES" 	 (echo Microsoft Home And Business 2024 ----- ProductVersion : %o16version%)
  
  if "%_HomeStudentRetail%" EQU "YES" 		 (echo Microsoft Home And Student ----------- ProductVersion : %o16version%)
  if "%_HomeStudent2019Retail%" EQU "YES" 	 (echo Microsoft Home And Student 2019 ------ ProductVersion : %o16version%)
  if "%_HomeStudent2021Retail%" EQU "YES" 	 (echo Microsoft Home And Student 2021 ------ ProductVersion : %o16version%)
  if "%_HomeStudent2024Retail%" EQU "YES" 	 (echo Microsoft Home And Student 2024 ------ ProductVersion : %o16version%)
  
  if "%_O365BusinessEEANoTeamsRetail%" EQU "YES"         (echo Microsoft 365 Apps for Business ------ ProductVersion : %o16version%)
  if "%_O365BusinessRetail%" EQU "YES"         (echo Microsoft 365 Apps for Business ------ ProductVersion : %o16version%)
  if "%_O365HomePremRetail%" EQU "YES" 		 (echo Microsoft 365 Home Premium retail ---- ProductVersion : %o16version%)
  if "%_O365ProPlusEEANoTeamsRetail%" EQU "YES"          (echo Microsoft 365 Apps for Enterprise ---- ProductVersion : %o16version%)
  if "%_O365ProPlusRetail%" EQU "YES"          (echo Microsoft 365 Apps for Enterprise ---- ProductVersion : %o16version%)
  if "%_O365SmallBusPremRetail%" EQU "YES" 	 (echo Microsoft 365 Small Business retail -- ProductVersion : %o16version%)
  if "%_O365AppsBasicRetail%" EQU "YES" 	 (echo Microsoft 365 Basic retail -- ProductVersion : %o16version%)
  
  if "%_ProfessionalRetail%" EQU "YES" 		 (echo Professional Retail ------------------ ProductVersion : %o16version%)
  if "%_Professional2019Retail%" EQU "YES" 	 (echo Professional 2019 Retail ------------- ProductVersion : %o16version%)
  if "%_Professional2021Retail%" EQU "YES" 	 (echo Professional 2021 Retail ------------- ProductVersion : %o16version%)
  if "%_Professional2024Retail%" EQU "YES" 	 (echo Professional 2024 Retail ------------- ProductVersion : %o16version%)
  
  if "%_ProPlusRetail%" EQU "YES"              (echo Office Professional Plus 2016 -------- ProductVersion : %o16version%)
  if "%_ProPlusVolume%" EQU "YES"              (echo Office Professional Plus 2016 -------- ProductVersion : %o16version%)
  if "%_ProPlus2019Retail%" EQU "YES"          (echo Office Professional Plus 2019 -------- ProductVersion : %o16version%)
  if "%_ProPlus2019Volume%" EQU "YES"          (echo Office Professional Plus 2019 -------- ProductVersion : %o16version%)
  if "%_ProPlus2021Retail%" EQU "YES"          (echo Office Professional Plus 2021 -------- ProductVersion : %o16version%)
  if "%_ProPlus2021Volume%" EQU "YES"          (echo Office Professional Plus 2021 -------- ProductVersion : %o16version%)
  if "%_ProPlusSPLA2021Volume%" EQU "YES"      (echo Office Professional Plus 2021 -------- ProductVersion : %o16version%)
  if "%_ProPlus2024Retail%" EQU "YES"          (echo Office Professional Plus 2024 -------- ProductVersion : %o16version%)
  if "%_ProPlus2024Volume%" EQU "YES"          (echo Office Professional Plus 2024 -------- ProductVersion : %o16version%)
  if "%_ProPlusSPLA2024Volume%" EQU "YES"      (echo Office Professional Plus 2024 -------- ProductVersion : %o16version%)
  
  if "%_AccessRetail%" EQU "YES"               (echo Access 2016 SingleApp ---------------- ProductVersion : %o16version%)
  if "%_AccessVolume%" EQU "YES"               (echo Access 2016 SingleApp ---------------- ProductVersion : %o16version%)  
  if "%_Access2019Retail%" EQU "YES"           (echo Access 2019 SingleApp ---------------- ProductVersion : %o16version%)
  if "%_Access2019Volume%" EQU "YES"           (echo Access 2019 SingleApp ---------------- ProductVersion : %o16version%)
  if "%_Access2021Retail%" EQU "YES"           (echo Access 2021 SingleApp ---------------- ProductVersion : %o16version%)
  if "%_Access2021Volume%" EQU "YES"           (echo Access 2021 SingleApp ---------------- ProductVersion : %o16version%)
  if "%_Access2024Retail%" EQU "YES"           (echo Access 2024 SingleApp ---------------- ProductVersion : %o16version%)
  if "%_Access2024Volume%" EQU "YES"           (echo Access 2024 SingleApp ---------------- ProductVersion : %o16version%)

  if "%_ExcelRetail%" EQU "YES"                (echo Excel 2016 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_ExcelVolume%" EQU "YES"                (echo Excel 2016 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_Excel2019Retail%" EQU "YES"            (echo Excel 2019 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_Excel2019Volume%" EQU "YES"            (echo Excel 2019 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_Excel2021Retail%" EQU "YES"            (echo Excel 2021 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_Excel2021Volume%" EQU "YES"            (echo Excel 2021 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_Excel2024Retail%" EQU "YES"            (echo Excel 2024 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_Excel2024Volume%" EQU "YES"            (echo Excel 2024 SingleApp ----------------- ProductVersion : %o16version%)
  
  if "%_OneNoteRetail%" EQU "YES"              (echo OneNote 2016 SingleApp --------------- ProductVersion : %o16version%)
  if "%_OneNoteVolume%" EQU "YES"              (echo OneNote 2016 SingleApp --------------- ProductVersion : %o16version%)
  if "%_OneNote2021Retail%" EQU "YES"          (echo OneNote 2021 SingleApp --------------- ProductVersion : %o16version%)
  if "%_OneNote2024Retail%" EQU "YES"          (echo OneNote 2024 SingleApp --------------- ProductVersion : %o16version%)
  
  if "%_OutlookRetail%" EQU "YES"              (echo Outlook 2016 SingleApp --------------- ProductVersion : %o16version%)
  if "%_OutlookVolume%" EQU "YES"              (echo Outlook 2016 SingleApp --------------- ProductVersion : %o16version%)
  if "%_Outlook2019Retail%" EQU "YES"          (echo Outlook 2019 SingleApp --------------- ProductVersion : %o16version%)
  if "%_Outlook2019Volume%" EQU "YES"          (echo Outlook 2019 SingleApp --------------- ProductVersion : %o16version%)
  if "%_Outlook2021Retail%" EQU "YES"          (echo Outlook 2021 SingleApp --------------- ProductVersion : %o16version%)
  if "%_Outlook2021Volume%" EQU "YES"          (echo Outlook 2021 SingleApp --------------- ProductVersion : %o16version%)
  if "%_Outlook2024Retail%" EQU "YES"          (echo Outlook 2024 SingleApp --------------- ProductVersion : %o16version%)
  if "%_Outlook2024Volume%" EQU "YES"          (echo Outlook 2024 SingleApp --------------- ProductVersion : %o16version%)
  
  if "%_PowerPointRetail%" EQU "YES"           (echo PowerPoint 2016 SingleApp ------------ ProductVersion : %o16version%)
  if "%_PowerPointVolume%" EQU "YES"           (echo PowerPoint 2016 SingleApp ------------ ProductVersion : %o16version%)
  if "%_PowerPoint2019Retail%" EQU "YES"       (echo PowerPoint 2019 SingleApp ------------ ProductVersion : %o16version%)
  if "%_PowerPoint2019Volume%" EQU "YES"       (echo PowerPoint 2019 SingleApp ------------ ProductVersion : %o16version%)
  if "%_PowerPoint2021Retail%" EQU "YES"       (echo PowerPoint 2021 SingleApp ------------ ProductVersion : %o16version%)
  if "%_PowerPoint2021Volume%" EQU "YES"       (echo PowerPoint 2021 SingleApp ------------ ProductVersion : %o16version%)
  if "%_PowerPoint2024Retail%" EQU "YES"       (echo PowerPoint 2024 SingleApp ------------ ProductVersion : %o16version%)
  if "%_PowerPoint2024Volume%" EQU "YES"       (echo PowerPoint 2024 SingleApp ------------ ProductVersion : %o16version%)
  
  if "%_WordRetail%" EQU "YES"                 (echo Word 2016 SingleApp ------------------ ProductVersion : %o16version%)
  if "%_WordVolume%" EQU "YES"                 (echo Word 2016 SingleApp ------------------ ProductVersion : %o16version%)
  if "%_Word2019Retail%" EQU "YES"             (echo Word 2019 SingleApp ------------------ ProductVersion : %o16version%)
  if "%_Word2019Volume%" EQU "YES"             (echo Word 2019 SingleApp ------------------ ProductVersion : %o16version%)
  if "%_Word2021Retail%" EQU "YES"             (echo Word 2021 SingleApp ------------------ ProductVersion : %o16version%)
  if "%_Word2021Volume%" EQU "YES"             (echo Word 2021 SingleApp ------------------ ProductVersion : %o16version%)
  if "%_Word2024Retail%" EQU "YES"             (echo Word 2024 SingleApp ------------------ ProductVersion : %o16version%)
  if "%_Word2024Volume%" EQU "YES"             (echo Word 2024 SingleApp ------------------ ProductVersion : %o16version%)
  
  if "%_PublisherRetail%" EQU "YES"            (echo Publisher 2016 SingleApp ------------- ProductVersion : %o16version%)
  if "%_PublisherVolume%" EQU "YES"            (echo Publisher 2016 SingleApp ------------- ProductVersion : %o16version%)  
  if "%_Publisher2019Retail%" EQU "YES"        (echo Publisher 2019 SingleApp ------------- ProductVersion : %o16version%)
  if "%_Publisher2019Volume%" EQU "YES"        (echo Publisher 2019 SingleApp ------------- ProductVersion : %o16version%)
  if "%_Publisher2021Retail%" EQU "YES"        (echo Publisher 2021 SingleApp ------------- ProductVersion : %o16version%)
  if "%_Publisher2021Volume%" EQU "YES"        (echo Publisher 2021 SingleApp ------------- ProductVersion : %o16version%)
  if "%_Publisher2024Retail%" EQU "YES"        (echo Publisher 2024 SingleApp ------------- ProductVersion : %o16version%)
  if "%_Publisher2024Volume%" EQU "YES"        (echo Publisher 2024 SingleApp ------------- ProductVersion : %o16version%)
  
  if "%_SkypeForBusinessRetail%" EQU "YES"     (echo Skype 2016 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_SkypeforBusinessVolume%" EQU "YES"     (echo Skype 2016 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_SkypeForBusiness2019Retail%" EQU "YES" (echo Skype 2019 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_SkypeForBusiness2019Volume%" EQU "YES" (echo Skype 2019 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_SkypeForBusiness2021Retail%" EQU "YES" (echo Skype 2021 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_SkypeForBusiness2021Volume%" EQU "YES" (echo Skype 2021 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_SkypeForBusiness2024Retail%" EQU "YES" (echo Skype 2024 SingleApp ----------------- ProductVersion : %o16version%)
  if "%_SkypeForBusiness2024Volume%" EQU "YES" (echo Skype 2024 SingleApp ----------------- ProductVersion : %o16version%)
  
  if "%_VisioStdRetail%" EQU "YES"       		 (echo Visio Standard 2016 ------------------ ProductVersion : %o16version%)
  if "%_VisioStdVolume%" EQU "YES"       		 (echo Visio Standard 2016 ------------------ ProductVersion : %o16version%)
  if "%_VisioStdXVolume%" EQU "YES"       	 (echo Visio Standard 2016 C2R -------------- ProductVersion : %o16version%)
  if "%_VisioStd2019Retail%" EQU "YES"     	 (echo Visio Standard 2019 ------------------ ProductVersion : %o16version%)
  if "%_VisioStd2019Volume%" EQU "YES"         (echo Visio Standard 2019 ------------------ ProductVersion : %o16version%)
  if "%_VisioStd2021Retail%" EQU "YES"         (echo Visio Standard 2021 ------------------ ProductVersion : %o16version%)
  if "%_VisioStd2021Volume%" EQU "YES"         (echo Visio Standard 2021 ------------------ ProductVersion : %o16version%)
  if "%_VisioStd2024Retail%" EQU "YES"         (echo Visio Standard 2024 ------------------ ProductVersion : %o16version%)
  if "%_VisioStd2024Volume%" EQU "YES"         (echo Visio Standard 2024 ------------------ ProductVersion : %o16version%)

  if "%_VisioProRetail%" EQU "YES"             (echo Visio professional 2016 -------------- ProductVersion : %o16version%)
  if "%_VisioProVolume%" EQU "YES"             (echo Visio professional 2016 -------------- ProductVersion : %o16version%)
  if "%_VisioProXVolume%" EQU "YES"		 	 (echo Visio professional 2016 C2R ---------- ProductVersion : %o16version%)
  if "%_VisioPro2019Retail%" EQU "YES"         (echo Visio professional 2019 -------------- ProductVersion : %o16version%)
  if "%_VisioPro2019Volume%" EQU "YES"         (echo Visio professional 2019 -------------- ProductVersion : %o16version%)
  if "%_VisioPro2021Retail%" EQU "YES"         (echo Visio professional 2021 -------------- ProductVersion : %o16version%)
  if "%_VisioPro2021Volume%" EQU "YES"         (echo Visio professional 2021 -------------- ProductVersion : %o16version%)
  if "%_VisioPro2024Retail%" EQU "YES"         (echo Visio Standard 2024 ------------------ ProductVersion : %o16version%)
  if "%_VisioPro2024Volume%" EQU "YES"         (echo Visio Standard 2024 ------------------ ProductVersion : %o16version%)
  
  if "%_ProjectProRetail%" EQU "YES"           (echo Project professional 2016 ------------ ProductVersion : %o16version%)
  if "%_ProjectProVolume%" EQU "YES"           (echo Project professional 2016 ------------ ProductVersion : %o16version%)
  if "%_ProjectProXVolume%" EQU "YES"		 	 (echo Project professional 2016 C2R -------- ProductVersion : %o16version%)
  if "%_ProjectPro2019Retail%" EQU "YES"       (echo Project professional 2019 ------------ ProductVersion : %o16version%)
  if "%_ProjectPro2019Volume%" EQU "YES"       (echo Project professional 2019 ------------ ProductVersion : %o16version%)
  if "%_ProjectPro2021Retail%" EQU "YES"       (echo Project professional 2021 ------------ ProductVersion : %o16version%)
  if "%_ProjectPro2021Volume%" EQU "YES"       (echo Project professional 2021 ------------ ProductVersion : %o16version%)
  if "%_ProjectPro2024Retail%" EQU "YES"       (echo Project Standard 2024 ---------------- ProductVersion : %o16version%)
  if "%_ProjectPro2024Volume%" EQU "YES"       (echo Project Standard 2024 ---------------- ProductVersion : %o16version%)
  
  if "%_ProjectStdRetail%" EQU "YES"       	 (echo Project Standard 2016 ---------------- ProductVersion : %o16version%)
  if "%_ProjectStdVolume%" EQU "YES"       	 (echo Project Standard 2016 ---------------- ProductVersion : %o16version%)
  if "%_ProjectStdXVolume%" EQU "YES"		 	 (echo Project Standard 2016 C2R ------------ ProductVersion : %o16version%)
  if "%_ProjectStd2019Retail%" EQU "YES"     	 (echo Project Standard 2019 ---------------- ProductVersion : %o16version%)
  if "%_ProjectStd2019Volume%" EQU "YES"       (echo Project Standard 2019 ---------------- ProductVersion : %o16version%)
  if "%_ProjectStd2021Retail%" EQU "YES"       (echo Project Standard 2021 ---------------- ProductVersion : %o16version%)
  if "%_ProjectStd2021Volume%" EQU "YES"       (echo Project Standard 2021 ---------------- ProductVersion : %o16version%)
  if "%_ProjectStd2024Retail%" EQU "YES"       (echo Project Standard 2024 ---------------- ProductVersion : %o16version%)
  if "%_ProjectStd2024Volume%" EQU "YES"       (echo Project Standard 2024 ---------------- ProductVersion : %o16version%)
  
  echo ____________________________________________________________________________
  echo:
  for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\Configuration" /v "CDNBaseUrl" 2^>nul') DO (Set "CDNBaseUrl=%%B")
  call:DecodeChannelName %CDNBaseUrl%
  echo Distribution-Channel:
  echo %ChannelName%
  echo:
  echo CDNBase-Url:
  echo %CDNBaseUrl%
  echo:
  for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\Configuration" /v "UpdateChannel" 2^>nul') DO (Set "UpdateUrl=%%B")
  call:DecodeChannelName %UpdateUrl%
  echo Updates-Channel:
  echo %ChannelName%
  echo:
  for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\Configuration" /v "UpdateUrl" 2^>nul') DO (Set "UpdateUrl=%%B")
  echo Updates-Url:
  echo %UpdateUrl%
  echo:
  echo Group-Policy defined UpdateBranch:
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate" /v "UpdateBranch" 2^>nul') DO (Set "UpdateBranch=%%B")
  echo %UpdateBranch%
  echo ____________________________________________________________________________
  echo:
  echo Possible Office Update-Channel ID VALUES:
  echo 1 = Current (Retail/RTM)
  echo 2 = CurrentPreview (Office Insider SLOW)
  echo 3 = BetaChannel (Office Insider FAST)
  echo 4 = MonthlyEnterprise
  echo 5 = SemiAnnual (Business)
  echo 6 = SemiAnnualPreview (Business Insider)
  echo 7 = PerpetualVL2019 (Office 2019 Volume)
  echo 8 = PerpetualVL2021 (Office 2021 Volume)
  echo 9 = PerpetualVL2024 (Office 2024 Volume)
  echo 10 = DogfoodDevMain (MS Internal Use Only)
  echo X = exit to Main Menu
  echo:
  set /p channeltrigger=Set New Update-Channel-ID (1,2,3,4,5,6,7,8,9) or X ^>
  if "!channeltrigger!" EQU "1" (
  	set "latestfile=latest_Current_build.txt"
  	set "UpdateUrl=http://officecdn.microsoft.com/%Region%/492350f6-3a01-4f97-b9c0-c7c6ddf67d60"
  	set "UpdateBranch=Current"
  	if not exist !latestfile! call :CheckNewVersion Current 492350f6-3a01-4f97-b9c0-c7c6ddf67d60
  	goto:UpdateChannelSel
  )
  if "!channeltrigger!" EQU "2" (
  	set "latestfile=latest_CurrentPreview_build.txt"
  	set "UpdateUrl=http://officecdn.microsoft.com/%Region%/64256afe-f5d9-4f86-8936-8840a6a4f5be"
  	set "UpdateBranch=CurrentPreview"
  	if not exist !latestfile! call :CheckNewVersion CurrentPreview 64256afe-f5d9-4f86-8936-8840a6a4f5be
  	goto:UpdateChannelSel
  )
  if "!channeltrigger!" EQU "3" (
  	set "latestfile=latest_BetaChannel_build.txt"
  	set "UpdateUrl=http://officecdn.microsoft.com/%Region%/5440fd1f-7ecb-4221-8110-145efaa6372f"
  	set "UpdateBranch=BetaChannel"
  	if not exist !latestfile! call :CheckNewVersion BetaChannel 5440fd1f-7ecb-4221-8110-145efaa6372f
  	goto:UpdateChannelSel
  )
  if "!channeltrigger!" EQU "4" (
  	set "latestfile=latest_MonthlyEnterprise_build.txt"
  	set "UpdateUrl=http://officecdn.microsoft.com/%Region%/55336b82-a18d-4dd6-b5f6-9e5095c314a6"
  	set "UpdateBranch=MonthlyEnterprise"
  	if not exist !latestfile! call :CheckNewVersion MonthlyEnterprise 55336b82-a18d-4dd6-b5f6-9e5095c314a6
  	goto:UpdateChannelSel
  )
  if "!channeltrigger!" EQU "5" (
  	set "latestfile=latest_SemiAnnual_build.txt"
  	set "UpdateUrl=http://officecdn.microsoft.com/%Region%/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"
  	set "UpdateBranch=SemiAnnual"
  	if not exist !latestfile! call :CheckNewVersion SemiAnnual 7ffbc6bf-bc32-4f92-8982-f9dd17fd3114
  	goto:UpdateChannelSel
  )
  if "!channeltrigger!" EQU "6" (
  	set "latestfile=latest_SemiAnnualPreview_build.txt"
  	set "UpdateUrl=http://officecdn.microsoft.com/%Region%/b8f9b850-328d-4355-9145-c59439a0c4cf"
  	set "UpdateBranch=SemiAnnualPreview"
  	if not exist !latestfile! call :CheckNewVersion CSemiAnnualPreview b8f9b850-328d-4355-9145-c59439a0c4cf
  	goto:UpdateChannelSel
  )
  if "!channeltrigger!" EQU "7" (
  	set "latestfile=latest_PerpetualVL2019_build.txt"
  	set "UpdateUrl=http://officecdn.microsoft.com/%Region%/f2e724c1-748f-4b47-8fb8-8e0d210e9208"
  	set "UpdateBranch=PerpetualVL2019"
  	if not exist !latestfile! call :CheckNewVersion PerpetualVL2019 f2e724c1-748f-4b47-8fb8-8e0d210e9208
  	goto:UpdateChannelSel
  )
  if "!channeltrigger!" EQU "8" (
  	set "latestfile=latest_PerpetualVL2021_build.txt"
  	set "UpdateUrl=http://officecdn.microsoft.com/%Region%/5030841d-c919-4594-8d2d-84ae4f96e58e"
  	set "UpdateBranch=PerpetualVL2021"
  	if not exist !latestfile! call :CheckNewVersion PerpetualVL2021 5030841d-c919-4594-8d2d-84ae4f96e58e
  	goto:UpdateChannelSel
  )
  if "!channeltrigger!" EQU "9" (
  	set "latestfile=latest_PerpetualVL2024_build.txt"
  	set "UpdateUrl=http://officecdn.microsoft.com/%Region%/7983BAC0-E531-40CF-BE00-FD24FE66619C"
  	set "UpdateBranch=PerpetualVL2024"
  	if not exist !latestfile! call :CheckNewVersion PerpetualVL2024 7983BAC0-E531-40CF-BE00-FD24FE66619C
  	goto:UpdateChannelSel
  )
  if "!channeltrigger!" EQU "10" (
  	set "latestfile=latest_DogfoodDevMain_build.txt"
  	set "UpdateUrl=http://officecdn.microsoft.com/%Region%/ea4a4090-de26-49d7-93c1-91bff9e53fc3"
  	set "UpdateBranch=not set"
  	if not exist !latestfile! call :CheckNewVersion DogfoodDevMain ea4a4090-de26-49d7-93c1-91bff9e53fc3
  	goto:UpdateChannelSel
  )
  if /I "!channeltrigger!" EQU "X" (goto:Office16VnextInstall)
  goto:ChangeUpdPath
::===============================================================================================================
:UpdateChannelSel
  echo:
  set /a countx=0
  cd /D "%OfficeRToolpath%"
  for /F "tokens=*" %%a in (!latestfile!) do (
  	SET /a countx=!countx! + 1
  	set var!countx!=%%a
  )
  set "o16upg1build=%var1%"
  set "o16upg2build=%var2%"
  echo Manually enter any build-nummer such as %o16upg2build%(prior build)
  echo or simply press return for updating to: %o16upg1build%(newest build)
  set /p restrictbuild=Set Office update build ^>
  if "%restrictbuild%" NEQ "newest available" set "updatetoversion=updatetoversion=%restrictbuild%"
  call :DecodeChannelName %UpdateUrl%
  echo ____________________________________________________________________________
  echo:
  echo New Update-Configuration will be set to:
  echo:
  echo Distribution-Channel : %ChannelName%
  echo Update To Version    : %restrictbuild%
:Error_Check_1_VALIDATE
  echo:
  set "installtrigger="
  set /p installtrigger=(ENTER) to proceed, (R)estart update, (E)xit to main menu ^>
  if defined installtrigger (
    ((echo !installtrigger!|%multinul% findstr /i /r "^[R]$ ^[E]$") && (goto :Error_Check_1_PASS) || (goto :Error_Check_1_VALIDATE))
    goto :Error_Check_1_VALIDATE
  )
:Error_Check_1_PASS	
    if /i "!installtrigger!" EQU "R" goto:ChangeUpdPath
  if /I "!installtrigger!" EQU "E" goto:Office16VnextInstall
::===============================================================================================================
:ChangeUpdateConf
  reg add %hC2r%\Configuration /v CDNBaseUrl /d %UpdateUrl% /f %MultiNul%
  reg add %hC2r%\Configuration /v UpdateUrl /d %UpdateUrl% /f %MultiNul%
  reg add %hC2r%\Configuration /v UpdateChannel /d %UpdateUrl% /f %MultiNul%
  reg add %hC2r%\Configuration /v UpdateChannelChanged /d True /f %MultiNul%
  if "%UpdateBranch%" EQU "not set" %REGEXE% delete HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /f %MultiNul%
  if "%UpdateBranch%" NEQ "not set" %REGEXE% add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d %UpdateBranch% /f %MultiNul%
  reg delete %hC2r%\Configuration /v UpdateToVersion /f %MultiNul%
  reg delete %hC2r%\Updates /v UpdateToVersion /f %MultiNul%
  if "%restrictbuild%" NEQ "newest available" (("%CommonProgramFiles%\microsoft shared\ClickToRun\OfficeC2RClient.exe" /update user %updatetoversion% updatepromptuser=True displaylevel=True)&&(goto:Office16VnextInstall))
  "%CommonProgramFiles%\microsoft shared\ClickToRun\OfficeC2RClient.exe" /update user updatepromptuser=True displaylevel=True %MultiNul%
  %MultiNul% del /q latest*.txt
  goto:Office16VnextInstall
::===============================================================================================================
::===============================================================================================================
:DecodeChannelName
  set "ChannelName=%1"
  set "ChannelName=%ChannelName:~-36%"
  if /i "%ChannelName%" EQU "492350f6-3a01-4f97-b9c0-c7c6ddf67d60" (set "ChannelName=Current (Retail/RTM)")&&(goto:eof)
  if /i "%ChannelName%" EQU "64256afe-f5d9-4f86-8936-8840a6a4f5be" (set "ChannelName=CurrentPreview (Office Insider SLOW)")&&(goto:eof)
  if /i "%ChannelName%" EQU "5440fd1f-7ecb-4221-8110-145efaa6372f" (set "ChannelName=BetaChannel (Office Insider FAST)")&&(goto:eof)
  if /i "%ChannelName%" EQU "55336b82-a18d-4dd6-b5f6-9e5095c314a6" (set "ChannelName=MonthlyEnterprise")&&(goto:eof)
  if /i "%ChannelName%" EQU "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" (set "ChannelName=SemiAnnual (Business)")&&(goto:eof)
  if /i "%ChannelName%" EQU "b8f9b850-328d-4355-9145-c59439a0c4cf" (set "ChannelName=SemiAnnualPreview (Business Insider)")&&(goto:eof)
  if /i "%ChannelName%" EQU "f2e724c1-748f-4b47-8fb8-8e0d210e9208" (set "ChannelName=PerpetualVL2019 (Office 2019 Volume)")&&(goto:eof)
  if /i "%ChannelName%" EQU "5030841d-c919-4594-8d2d-84ae4f96e58e" (set "ChannelName=PerpetualVL2021 (Office 2021 Volume)")&&(goto:eof)
  if /i "%ChannelName%" EQU "7983BAC0-E531-40CF-BE00-FD24FE66619C" (set "ChannelName=PerpetualVL2024 (Office 2024 Volume)")&&(goto:eof)
  if /i "%ChannelName%" EQU "ea4a4090-de26-49d7-93c1-91bff9e53fc3" (set "ChannelName=DogfoodDevMain (MS Internal Use Only)")&&(goto:eof)
  set "ChannelName=Non_Standard_Channel (Manual_Override)"
  goto:eof
::===============================================================================================================
::===============================================================================================================
:DisableTelemetry
::===============================================================================================================
  call :CheckOfficeApplications
   
::===============================================================================================================
  cls
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! DISABLE ACQUISITION OF TELEMETRY DATA !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  echo Scheduler:  4 Office Telemetry related Tasks were set / changed
  schtasks /Change /TN "Microsoft\Office\Office Automatic Updates" /Disable %MultiNul%
  schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /Disable %MultiNul%
  schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /Disable %MultiNul%
  schtasks /Change /TN "Microsoft\Office\Office ClickToRun Service Monitor" /Disable %MultiNul%
  echo:
  echo Registry:  29 Office Telemetry related User Keys were set / changed
  REG ADD HKCU\Software\Microsoft\Office\Common\ClientTelemetry /v DisableTelemetry /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Common /v sendcustomerdata /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Common\Feedback /v enabled /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Common\Feedback /v includescreenshot /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Outlook\Options\Mail /v EnableLogging /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Word\Options /v EnableLogging /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Common /v qmenable /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Common /v updatereliabilitydata /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Common\General /v shownfirstrunoptin /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Common\General /v skydrivesigninoption /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Common\ptwatson /v ptwoptin /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\Firstrun /v disablemovie /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM /v Enablelogging /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM /v EnableUpload /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM /v EnableFileObfuscation /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications /v accesssolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications /v olksolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications /v onenotesolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications /v pptsolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications /v projectsolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications /v publishersolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications /v visiosolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications /v wdsolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications /v xlsolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v agave /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v appaddins /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v comaddins /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v documentfiles /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v templatefiles /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v templatefiles /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKCU\Software\Policies\Microsoft\office\16.0\common\privacy /v disconnectedstate /t REG_DWORD /d 2 /f %MultiNul%
  REG ADD HKCU\Software\Policies\Microsoft\office\16.0\common\privacy /v usercontentdisabled /t REG_DWORD /d 2 /f %MultiNul%
  REG ADD HKCU\Software\Policies\Microsoft\office\16.0\common\privacy /v downloadcontentdisabled /t REG_DWORD /d 2 /f %MultiNul%
  REG ADD HKCU\Software\Policies\Microsoft\office\16.0\common\privacy /v ControllerConnectedServicesEnabled /t REG_DWORD /d 2 /f %MultiNul%
  REG ADD HKCU\Software\Policies\Microsoft\office\16.0\common\clienttelemetry /v sendtelemetry /t REG_DWORD /d 3 /f %MultiNul%
  echo:
  echo Registry:  23 Office Telemetry related Machine Group Policies were set / changed
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\Common /v qmenable /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\Common /v updatereliabilitydata /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\Common\General /v shownfirstrunoptin /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\Common\General /v skydrivesigninoption /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\Common\ptwatson /v ptwoptin /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\Firstrun /v disablemovie /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM /v Enablelogging /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM /v EnableUpload /t REG_DWORD /d 0 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM /v EnableFileObfuscation /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications /v accesssolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications /v olksolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications /v onenotesolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications /v pptsolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications /v projectsolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications /v publishersolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications /v visiosolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications /v wdsolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications /v xlsolution /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v agave /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v appaddins /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v comaddins /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v documentfiles /t REG_DWORD /d 1 /f %MultiNul%
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes /v templatefiles /t REG_DWORD /d 1 /f %MultiNul%
  echo:
  echo Registry:  1 Office BING search service registry key was set to disabled
  REG ADD HKLM\Software\Policies\Microsoft\Office\16.0\common\officeupdate /v preventbinginstall /t REG_DWORD /d 1 /f > nul 2>&1
  echo ____________________________________________________________________________
  echo:
    echo:
  timeout /t 4
    goto:Office16VnextInstall
::===============================================================================================================
::===============================================================================================================
:ResetRepair
  call :CheckOfficeApplications
   
::===============================================================================================================
::===============================================================================================================
  cls
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! RESET / REPAIR OFFICE !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
::===============================================================================================================
    echo ____________________________________________________________________________
  echo:
  echo Removing Office xrm-license files...
  echo (Retail-/Grace-licenses will be refreshed by Office Quick-/Online-Repair)
  echo:
  "%OfficeRToolpath%\Data\Bin\cleanospp.exe" -Licenses
  echo ____________________________________________________________________________
  echo:
  echo Removing Office product keys...
  echo (Retail grace key will be installed after next Office apps start)
  echo:
  "%OfficeRToolpath%\Data\Bin\cleanospp.exe" -PKey
  echo ____________________________________________________________________________
  echo:
  echo Starting official Office repair program...
  echo (select option "QUICK REPAIR")
  "%CommonProgramFiles%\Microsoft Shared\ClickToRun\OfficeClickToRun.exe" scenario=repair platform=%repairplatform% culture=%repairlang%
  echo:
    echo ____________________________________________________________________________
  echo:
::===============================================================================================================
  call :CheckOfficeApplications
::===============================================================================================================
  timeout /t 4
    goto:Office16VnextInstall
::===============================================================================================================
::===============================================================================================================
:InstallO16
  
  set pInfo=
  set XML_MODE=
  if %FORCE_XML% EQU 1 (
    set XML_MODE=*
  )
  if %WinBuild% LSS 10240 (
    set XML_MODE=*
  )
  
  set "mo16install=0"
  
  set "of36homePrem=0"
  set "of36ppinstall=0"
  set "of36bsinstall=0"
  
  set "Pr16disable=0"
  set "ac16disable=0"
  set "ex16disable=0"
  set "od16disable=0"
  set "ol16disable=0"
  set "on16disable=0"
  set "pb16disable=0"
  set "pp16disable=0"
  set "st16disable=0"
  set "vs16disable=0"
  set "wd16disable=0"
  
  set "ac16install=0"
  set "ac19install=0"
  set "ac21install=0"
  set "ac24install=0"
  
  set "ex16install=0"
  set "ex19install=0"
  set "ex21install=0"
  set "ex24install=0"
  
  set "of16install=0"
  set "of19install=0"
  set "of21install=0"
  set "of24install=0"

  set "ol16install=0"
  set "ol19install=0"
  set "ol21install=0"
  set "ol24install=0"
  
  set "on16install=0"
  set "on21install=0"
  set "on24install=0"
  
  set "pb16install=0"
  set "pb19install=0"
  set "pb21install=0"
  set "pb24install=0"
  
  set "pp16install=0"
  set "pp19install=0"
  set "pp21install=0"
  set "pp24install=0"
  
  set "pr16install=0"
  set "pr19install=0"
  set "pr21install=0"
  set "pr24install=0"
  
  set "sk16install=0"
  set "sk19install=0"
  set "sk21install=0"
  set "sk24install=0"
  
  set "vi16install=0"
  set "vi19install=0"
  set "vi21install=0"
  set "vi24install=0"
  
  set "wd16install=0"
  set "wd19install=0"
  set "wd21install=0"
  set "wd24install=0"
  
  set "sn19install=0"
  set "sn21install=0"
  set "sn24install=0"
  
  set "bad_path="
  set "bsbsdisable=0"
  set "createpackage=0"
  set "downpath=not set"
  set "excludedapps=0"
  set "installtrigger=not set"
  set "productkeys=0"
  set "productstoadd=0"
  set "product_list="
  set "type=Retail"
  
  rem reset language default value
  set default=
  set ProofingTools=
  set Multi_Proof_Lang=
  
  rem reset language default value
  set default=
  set LangPackTools=
  set Multi_Lang_Pack=
  
  rem reset language default value
  set "id_LIST="
  set "countVal="
  set "MULTI_lang="
  set "MULTI_lang_IDS="
  set "isopath=not set"
   
:InstallO16Loop
  cls
  if defined OnlineInstaller (
    goto :InstSuites )
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! SELECT OFFICE FULL SUITE / SINGLE APPS !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  set "searchdirpattern=16."
  if defined inidownpath set "downpath=!inidownpath!"
  echo !downpath! | %SingleNul% find /i "not set" && (
  	set "downpath=%SystemDrive%\Downloads"
  )
  if defined AutoPilotMode if !_Action! EQU 2 (
    set "downpath=!_Location!"
    goto :Skip_x1CF_A
  )
  set /p downpath=Set Office Package Download Path ^= "!downpath!" ^>
  set "isopath=!downpath!"
  
  if "%inidownpath%" NEQ "!downpath!" ((echo Office install package download path changed)&&(echo old path "%inidownpath%" -- new path "!downpath!")&&(echo:))
  if defined AutoSaveToIni goto :begistensesAx
  if defined DontSaveToIni goto :hedumbletonicAx
  if "%inidownpath%" NEQ "!downpath!" set /p installtrigger=Save new path to %buildINI%? (1/0) ^>
  if "!installtrigger!" EQU "0" goto:hedumbletonicAx
  if /I "!installtrigger!" EQU "X" goto:hedumbletonicAx
:begistensesAx
  set "inidownpath=!downpath!"
  echo -------------------------------->%buildINI%
  echo ^:^: default download-path>>%buildINI%
  echo %inidownpath%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-language>>%buildINI%
  echo %inidownlang%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo ^:^: default download-architecture>>%buildINI%
  echo %inidownarch%>>%buildINI%
  echo -------------------------------->>%buildINI%
  echo Download path saved.
::===============================================================================================================
:hedumbletonicAx
  
  
:Skip_x1CF_A
  set "downpath=!downpath:"=!"
  if /I "!downpath!" EQU "X" ((set "downpath=not set")&&(goto:Office16VnextInstall))
  set "downdrive=!downpath:~0,2!"
  if "!downdrive:~-1!" NEQ ":" (set "downpath=not set" & goto:InstallO16Loop)
  cd /d !downdrive! %MultiNul% || (set "downpath=not set" & goto:InstallO16Loop)
  set "downdrive=!downpath:~0,3!"
  if "!downdrive:~-1!" EQU "\" (set "downpath=!downdrive!!downpath:~3!") else (set "downpath=!downdrive:~0,2!\!downpath:~2!")
  if "!downpath:~-1!" EQU "\" set "downpath=!downpath:~0,-1!"
::===============================================================================================================
  cd /d "!downdrive!\" %MultiNul%
  cd /d "!downpath!" %MultiNul%
  set /a countx=0
  
  if defined AutoPilotMode if !_Action! EQU 2 (
    goto :Xfg34f_1
  )
  echo:
  echo List of available installation packages
:Xfg34f_1
    set "bad_path=True"
  
  REM if exist "!downpath!\*!searchdirpattern!*" (
  	REM for /F "tokens=*" %%a in ('dir "!downpath!" /ad /b ^| find /i "%searchdirpattern%"') do (
  	for /F "tokens=*" %%a in ('2^>nul dir "!downpath!" /ad /b') do (
  	    if defined AutoPilotMode if !_Action! EQU 2 (
  		  if /i "%%a" EQU "!_Name!" (
  		    if exist "%%a\Office\Data\16.*" set "bad_path="
  		    SET /a countx=!countx! + 1
  			set packagelist!countx!=%%a
  			goto :Yuz23_a
  		  )
  		)
  		if not defined AutoPilotMode if exist "%%a\Office\Data\16.*" (
  			echo:
  			SET /a countx=!countx! + 1
  			set packagelist!countx!=%%a
  			echo !countx!   %%a
  		)
  	)
  REM )
  
  set "Zz=%~dp0Data\Bin\7z.exe"
  
  set "forCmd=dir "!downpath!" /b | find /i ".iso""
  for /f "tokens=*" %%$ in ('"!forCmd!"') do (
  
  	if defined AutoPilotMode if !_Action! EQU 2 (
  	  set "PACKAGE=%%$"
  	  set "PACKAGE_FIXED=!PACKAGE:~0,-4!"
  	  if /i "!PACKAGE_FIXED!" EQU "!_Name!" (
  		%SingleNulV2% "!Zz!" l "!PACKAGE!" "Office\Data" | %SingleNul% find /i "Office\Data\16." && (
  			if not exist "!downpath!\!PACKAGE_FIXED!\Office\Data\16.*" (
  				set "bad_path="
  				SET /a countx=!countx! + 1
  				set packagelist!countx!=!PACKAGE_FIXED!
  			)
  		)
  		goto :Yuz23_a
  	  )
  	)
  
  	REM echo "%%$" | %SingleNul% find /i "16." && (
  		set "PACKAGE=%%$"
  		set "PACKAGE_FIXED=!PACKAGE:~0,-4!"
  		%SingleNulV2% "!Zz!" l "!PACKAGE!" "Office\Data" | %SingleNul% find /i "Office\Data\16." && (
  			if not exist "!downpath!\!PACKAGE_FIXED!\Office\Data\16.*" (
  				echo:
  				SET /a countx=!countx! + 1
  				set packagelist!countx!=!PACKAGE_FIXED!
  				echo !countx!   !PACKAGE_FIXED!
  			)
  		)
  	REM )
  )
  
  set "forCmd=dir "!downpath!" /b | find /i ".IMG""
  for /f "tokens=*" %%$ in ('"!forCmd!"') do (
  
  	if defined AutoPilotMode if !_Action! EQU 2 (
  	  set "PACKAGE=%%$"
  	  set "PACKAGE_FIXED=!PACKAGE:~0,-4!"
  	  if /i "!PACKAGE_FIXED!" EQU "!_Name!" (
  		%SingleNulV2% "!Zz!" l "!PACKAGE!" "Office\Data" | %SingleNul% find /i "Office\Data\16." && (
  			if not exist "!downpath!\!PACKAGE_FIXED!\Office\Data\16.*" (
  				set "bad_path="
  				SET /a countx=!countx! + 1
  				set packagelist!countx!=!PACKAGE_FIXED!
  			)
  		)
  		goto :Yuz23_a
  	  )
  	)
  
  	REM echo "%%$" | %SingleNul% find /i "16." && (
  		set "PACKAGE=%%$"
  		set "PACKAGE_FIXED=!PACKAGE:~0,-4!"
  		%SingleNulV2% "!Zz!" l "!PACKAGE!" "Office\Data" | %SingleNul% find /i "Office\Data\16." && (
  			if not exist "!downpath!\!PACKAGE_FIXED!\Office\Data\16.*" (
  				echo:
  				SET /a countx=!countx! + 1
  				set packagelist!countx!=!PACKAGE_FIXED!
  				echo !countx!   !PACKAGE_FIXED!
  			)
  		)
  	REM )
  )
  
  if %countx% GTR 0 goto:PackageFound
  echo:
  echo ERROR ### No install packages found
  echo:
  %SingleNul% timeout 2
  if defined Auto_Pilot_RET (
    pause
    goto :Office16VnextInstall
  )
  if defined AutoPilotMode if !_Action! EQU 2 (
    pause
    goto :eof
  )
  goto :InstallO16Loop
::===============================================================================================================

:Yuz23_a

if not defined bad_path (
  set /a "packnum=!countx!"
  goto :PackageFound_SKIP
)

if !countx! EQU 0 (
echo:
echo ERROR ### Folder not exist
echo:
)

if defined Auto_Pilot_RET (
  pause
  goto :Office16VnextInstall
)
if defined AutoPilotMode if !_Action! EQU 2 (
  pause
  goto :eof
)

:PackageFound
  echo:
  echo:
  set /a packnum=0
  set /p packnum=Enter package number ^>
  if /I "%packnum%" EQU "X" goto:Office16VnextInstall
  if %packnum% EQU 0 ((set "searchdirpattern=not set")&&(goto:InstallO16Loop))
  if %packnum% GTR %countx% ((set "searchdirpattern=not set")&&(goto:InstallO16Loop))
  echo:

:PackageFound_SKIP
  set "downpath=!downpath!\!packagelist%packnum%!"
  set "installpath=!downpath!"
  
  if not exist "%installpath%\Office\Data\16.*" (
  	if not exist "%installpath%.iso" if not exist "%installpath%.img" (
  		(echo:)&&(echo ERROR: Missing files.)&&(echo:)&&(pause)&&(
  		  if defined Auto_Pilot_RET goto :Office16VnextInstall
  		  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  		  goto:InstallO16
  		)
  	)
  	md "%installpath%" %MultiNul%
  	if exist "%installpath%.iso" (
  		%Zz% x -y -o"%installpath%" "%installpath%.iso" "Office" %MultiNul% || (
  			rd/s/q "%installpath%" %MultiNul%
  			(echo:)&&(echo ERROR: Fail to extract files from ISO.)&&(echo:)&&(pause)&&(
  			  if defined Auto_Pilot_RET goto :Office16VnextInstall
  			  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  		      goto:InstallO16
  			)
  		)
  	)
  	if exist "%installpath%.IMG" (
  		%Zz% x -y -o"%installpath%" "%installpath%.IMG" "Office" %MultiNul% || (
  			rd/s/q "%installpath%" %MultiNul%
  			(echo:)&&(echo ERROR: Fail to extract files from IMG.)&&(echo:)&&(pause)&&(
  			  if defined Auto_Pilot_RET goto :Office16VnextInstall
  			  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  		      goto:InstallO16
  			)
  		)
  	)
  	if not exist "%installpath%\Office\Data\16.*" (
  		rd/s/q "%installpath%" %MultiNul%
  		(echo:)&&(echo ERROR: Missing files.)&&(echo:)&&(pause)&&(
  		  if defined Auto_Pilot_RET goto :Office16VnextInstall
  		  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  		  goto:InstallO16
  		)
  	)
  )
  
  if "%installpath:~-1%" EQU "\" set "installpath=%installpath:~0,-1%"
  set countx=0
  cd /d "!downpath!"
  goto :GetInfoFromFolder
  
:GetInfoFromFolder_Done
  cd /D "%OfficeRToolpath%"
  if "%winx%" EQU "Bin" if "!o16arch!" EQU "x64" ((echo:)&&(echo ERROR ### You can't install x64/64bit Office on x86/32bit Windows)&&(echo:)&&(pause)&&(
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode if !_Action! EQU 2 goto :eof
    goto:InstallO16
  ))
::===============================================================================================================
:InstSuites
  if not defined OnlineInstaller goto:InstSuites_2
  
  if defined AutoPilotMode if !_Action! EQU 3 (
    set "distribchannel=!_channel!"
    set "o16build=!_Version!"
    if /i !distribchannel! EQU Current (
      set "o16updlocid=492350f6-3a01-4f97-b9c0-c7c6ddf67d60"
    )
    if /i !distribchannel! EQU CurrentPreview (
      set "o16updlocid=64256afe-f5d9-4f86-8936-8840a6a4f5be"
    )
    if /i !distribchannel! EQU BetaChannel (
      set "o16updlocid=5440fd1f-7ecb-4221-8110-145efaa6372f"
    )
    if /i !distribchannel! EQU MonthlyEnterprise (
      set "o16updlocid=55336b82-a18d-4dd6-b5f6-9e5095c314a6"
    )
    if /i !distribchannel! EQU SemiAnnual (
      set "o16updlocid=7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"
    )
    if /i !distribchannel! EQU SemiAnnualPreview (
      set "o16updlocid=b8f9b850-328d-4355-9145-c59439a0c4cf"
    )
    if /i !distribchannel! EQU PerpetualVL2019 (
      set "o16updlocid=f2e724c1-748f-4b47-8fb8-8e0d210e9208"
    )
    if /i !distribchannel! EQU PerpetualVL2021 (
      set "o16updlocid=5030841d-c919-4594-8d2d-84ae4f96e58e"
    )
	if /i !distribchannel! EQU PerpetualVL2024 (
      set "o16updlocid=7983BAC0-E531-40CF-BE00-FD24FE66619C"
    )
	if /i !distribchannel! EQU DogfoodDevMain (
      set "o16updlocid=ea4a4090-de26-49d7-93c1-91bff9e53fc3"
    )
    if /i !_Version! EQU AUTO (
    call :CheckNewVersion !distribchannel! !o16updlocid!
  	set "o16build=!o16latestbuild!"
  	echo "!o16latestbuild!"|%SingleNul% find /i "not set" && (
  	  echo:
  	  echo ERROR ### Fail to fetch version information
  	  echo:
  	  if not defined debugMode if not defined AutoTask (
	    pause
	    goto :Office16VnextInstall
	  )
  	  goto :TheEndIsNear
   ))
    set "o16downloadloc=officecdn.microsoft.com.edgesuite.net/%region%/!o16updlocid!/Office/Data"
    
    REM echo:
    REM echo o16build       is !o16build!
    REM echo o16updlocid    is !o16updlocid!
    echo:
    goto :SelFullSuite_X2x
  )
  
  cls
  echo:
  echo "Public known" standard distribution channels
  echo Channel Name                                    - Internal Naming   Index-#
  echo ___________________________________________________________________________
  echo:
  echo Current (Retail/RTM)                            - (Production::CC)       (1)
  echo CurrentPreview (Office Insider SLOW)            - (Insiders::CC)         (2)
  echo BetaChannel (Office Insider FAST)               - (Insiders::DEVMAIN)    (3)
  echo MonthlyEnterprise                               - (Production::MEC)      (4)
  echo SemiAnnual (Business)                           - (Production::DC)       (5)
  echo SemiAnnualPreview (Business Insider)            - (Insiders::FRDC)       (6)
  echo PerpetualVL2019                                 - (Production::LTSC)     (7)
  echo PerpetualVL2021                                 - (Production::LTSC2021) (8)
  echo PerpetualVL2024                                 - (Production::LTSC2024) (9)
  echo DogfoodDevMain                                  - (Dogfood::DevMain)     (D)
  echo Exit to Main Menu                                                        (X)

:InstSuites_X
  echo:
  set /a channeltrigger=1
  set /p channeltrigger=Set Channel-Index-# (1,2,3,4,5,6,7,8,9) or X or press return for Current ^>
  (echo !channeltrigger!| %MultiNul% findstr /i /r "^[1-9]$ ^[d]$ ^[x]$ ^[m]$") && (
    if "!channeltrigger!" EQU "1" goto:ChanSel1X
    if "!channeltrigger!" EQU "2" goto:ChanSel2X
    if "!channeltrigger!" EQU "3" goto:ChanSel3X
    if "!channeltrigger!" EQU "4" goto:ChanSel4X
    if "!channeltrigger!" EQU "5" goto:ChanSel5X
    if "!channeltrigger!" EQU "6" goto:ChanSel6X
    if "!channeltrigger!" EQU "7" goto:ChanSel7X
    if "!channeltrigger!" EQU "8" goto:ChanSel8X
	if "!channeltrigger!" EQU "9" goto:ChanSel9X
	if /i "!channeltrigger!" EQU "D" goto:ChanSel10X
    if /i "!channeltrigger!" EQU "X" ((set "o16updlocid=not set")&&(set "o16build=not set")&&(goto:Office16VnextInstall))
  ) || (goto :InstSuites_X)
  goto :InstSuites_X
  
:ChanSel1X
  set "o16updlocid=492350f6-3a01-4f97-b9c0-c7c6ddf67d60"
  call :CheckNewVersion Current !o16updlocid!
  set "distribchannel=Current"
  set "o16build=!o16latestbuild!"	
  goto:InstSuites_2X
::===============================================================================================================
:ChanSel2X
  set "o16updlocid=64256afe-f5d9-4f86-8936-8840a6a4f5be"
  call :CheckNewVersion CurrentPreview !o16updlocid!
  set "distribchannel=CurrentPreview"
  set "o16build=!o16latestbuild!"
  goto:InstSuites_2X
::===============================================================================================================
:ChanSel3X
  set "o16updlocid=5440fd1f-7ecb-4221-8110-145efaa6372f"
  call :CheckNewVersion BetaChannel !o16updlocid!
  set "distribchannel=BetaChannel"
  set "o16build=!o16latestbuild!"
  goto:InstSuites_2X
::===============================================================================================================
:ChanSel4X
  set "o16updlocid=55336b82-a18d-4dd6-b5f6-9e5095c314a6"
  call :CheckNewVersion MonthlyEnterprise !o16updlocid!
  set "distribchannel=MonthlyEnterprise"
  set "o16build=!o16latestbuild!"
  goto:InstSuites_2X
::===============================================================================================================
:ChanSel5X
  set "o16updlocid=7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"
  call :CheckNewVersion SemiAnnual !o16updlocid!
  set "distribchannel=SemiAnnual"
  set "o16build=!o16latestbuild!"
  goto:InstSuites_2X
::===============================================================================================================
:ChanSel6X
  set "o16updlocid=b8f9b850-328d-4355-9145-c59439a0c4cf"
  call :CheckNewVersion SemiAnnualPreview !o16updlocid!
  set "distribchannel=SemiAnnualPreview"
  set "o16build=!o16latestbuild!"
  goto:InstSuites_2X
::===============================================================================================================
:ChanSel7X
  set "o16updlocid=f2e724c1-748f-4b47-8fb8-8e0d210e9208"
  call :CheckNewVersion PerpetualVL2019 !o16updlocid!
  set "distribchannel=PerpetualVL2019"
  set "o16build=!o16latestbuild!"
  goto:InstSuites_2X
::===============================================================================================================
:ChanSel8X
  set "o16updlocid=5030841d-c919-4594-8d2d-84ae4f96e58e"
  call :CheckNewVersion PerpetualVL2021 !o16updlocid!
  set "distribchannel=PerpetualVL2021"
  set "o16build=!o16latestbuild!"
  goto:InstSuites_2X
::===============================================================================================================
:ChanSel9X
  set "o16updlocid=7983BAC0-E531-40CF-BE00-FD24FE66619C"
  call :CheckNewVersion PerpetualVL2024 !o16updlocid!
  set "o16build=!o16latestbuild!"
  set "distribchannel=PerpetualVL2024"
  goto:InstSuites_2X
::===============================================================================================================
:ChanSel10X
  set "o16updlocid=ea4a4090-de26-49d7-93c1-91bff9e53fc3"
  call :CheckNewVersion DogfoodDevMain !o16updlocid!
  set "distribchannel=DogfoodDevMain"
  set "o16build=!o16latestbuild!"
  goto:InstSuites_2X
  
:InstSuites_2X
  echo "!o16latestbuild!"|%SingleNul% find /i "not set" && (
  	if not defined debugMode if not defined AutoTask pause
  	goto :Office16VnextInstall
  )

:InstSuites_2
  set "instmethod=XML"
  if %WinBuild% GEQ 10240 (
    if %FORCE_XML% EQU 0 (
	  set "instmethod=C2R"
  ))
  cd /D "%OfficeRToolpath%"
  cls
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! SELECT OFFICE FULL SUITE - SINGLE APPS !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  goto :SelFullSuite

:SelFullSuite_X2x
  set "instmethod=XML"
  if %WinBuild% GEQ 10240 (
    if %FORCE_XML% EQU 0 (
	  set "instmethod=C2R"
  ))
  cd /D "%OfficeRToolpath%"
    if defined AutoPilotMode if !_Action! EQU 3 (
    goto :InstSuitesXz_XZZ
  )
::===============================================================================================================
:SelFullSuite
  if defined AutoPilotMode if !_Action! EQU 2 (
    goto :InstSuitesXz_XZZ
  )
  echo:
  echo Select full Office Suite for install:
  echo:
  call :Print "0.) Single Apps Install (no full suite)" "%BB_Blue%"
  echo:
  call :Print "1.) Office Professional Plus 2016 Retail" "%BB_Blue%"
  echo:
  call :Print "2.) Office Professional Plus 2019 Volume" "%BB_Blue%"
  echo:
  call :Print "3.) Office Professional Plus 2021 Volume" "%BB_Blue%"
  echo:
  call :Print "4.) Office Professional Plus 2024 Volume" "%BB_Blue%"
  
  echo:
  call :Print "5.) Office 2016 Mondo" "%BB_Red%"
  echo:
  call :Print "6.) Microsoft 365 Home Premium" "%BB_Red%"
  echo:
  call :Print "7.) Microsoft 365 Business Premium" "%BB_Red%"
  echo:
  call :Print "8.) Microsoft 365 Professional Plus" "%BB_Red%"
  
  echo:
  call :Print "9.) Visio-Project 2016 Retail" "%BB_Green%"
  echo:
  call :Print "10.) Visio-Project 2019 Volume" "%BB_Green%"
  echo:
  call :Print "11.) Visio-Project 2021 Volume" "%BB_Green%"
  echo:
  call :Print "12.) Visio-Project 2024 Volume" "%BB_Green%"
  echo:
  
:InstSuitesXz
  echo:
  
  (set "21_24_Support=")
  if %WinBuild% GEQ 9600 if %o16build:~5,5% GEQ 14000 (set "21_24_Support=True")
  
  set /p installtrigger=Enter 1..9,0 or x to exit ^>
  (echo !installtrigger!| %MultiNul% findstr /i /r "^[0-9]$ ^[1][0-9]$ ^[x]$ ^[p]$") && (
    if /i "!installtrigger!" EQU "X" (goto:Office16VnextInstall)
    if "!installtrigger!" EQU "0" (goto:SingleAppsInstall)
    if "!installtrigger!" EQU "1" ((set "type=Retail")&&(set "of16install=1")&&(goto:InstallExclusions))
    if "!installtrigger!" EQU "2" ((set "type=Volume")&&(set "of19install=1")&&(goto:InstallExclusions))
    if "!installtrigger!" EQU "3" (if defined 21_24_Support ((set "type=Volume")&&(set "of21install=1")&&(goto:InstallExclusions)))
    if "!installtrigger!" EQU "4" (if defined 21_24_Support ((set "type=Volume")&&(set "of24install=1")&&(goto:InstallExclusions)))
    if "!installtrigger!" EQU "5" ((set "type=Retail")&&(set "mo16install=1")&&(goto:InstallExclusions))
    if "!installtrigger!" EQU "6" ((set "type=Retail")&&(set "of36homePrem=1")&&(goto:InstallExclusions))
    if "!installtrigger!" EQU "7" ((set "type=Retail")&&(set "of36bsinstall=1")&&(goto:InstallExclusions))
    if "!installtrigger!" EQU "8" ((set "type=Retail")&&(set "of36ppinstall=1")&&(goto:InstallExclusions))
    if "!installtrigger!" EQU "9" ((set "type=Retail")&&(goto:InstVi16Pr16))
    if "!installtrigger!" EQU "10" ((set "type=Volume")&&(goto:InstVi19Pr19))
    if "!installtrigger!" EQU "11" (if defined 21_24_Support ((set "type=Volume")&&(goto:InstVi21Pr21)))
    if "!installtrigger!" EQU "12" (if defined 21_24_Support ((set "type=Volume")&&(goto:InstVi24Pr24)))
  )
  goto :InstSuitesXz

:InstSuitesXz_XZZ

if /i !distribchannel! EQU PerpetualVL2019 (
  set "type=Volume"
)
if /i !distribchannel! EQU PerpetualVL2021 (
  set "type=Volume"
)
if /i !distribchannel! EQU PerpetualVL2024 (
  set "type=Volume"
)

if /i !_Type! EQU Full (
  for %%$ in (!_Products!) do (
    
	  if /i %%$ EQU ProPlus (
		set "type=Retail"
		set "of16install=1"
	  )
	  
	  if /i %%$ EQU ProPlus2019 (
		set "type=Volume"
		set "of19install=1"
	  )
	  
	  if /i %%$ EQU ProPlus2021 (
		set "type=Volume"
		set "of21install=1"
	  )
	  
	  if /i %%$ EQU ProPlus2024 (
		set "type=Volume"
		set "of24install=1"
	  )
	  
	  if /i %%$ EQU Mondo (
		set "type=Retail"
		set "mo16install=1"
	  )
	  
	  if /i %%$ EQU O365HomePrem (
		set "type=Retail"
		set "of36homePrem=1"
	  )
	  
	  if /i %%$ EQU O365Business (
		set "type=Retail"
		set "of36bsinstall=1"
	  )
	  
	  if /i %%$ EQU O365ProPlus (
		set "type=Retail"
		set "of36ppinstall=1"
	  )
	  
	  if /i %%$ EQU VisioPro (
	    set "type=Volume"
		set "vi16install=1"
	  )
	  
	  if /i %%$ EQU VisioPro2019 (
	    set "type=Volume"
		set "vi19install=1"
	  )
	  
	  if /i %%$ EQU VisioPro2021 (
	    set "type=Volume"
		set "vi21install=1"
	  )
	  
	  if /i %%$ EQU VisioPro2024 (
	    set "type=Volume"
		set "vi24install=1"
	  )
	  
	  if /i %%$ EQU ProjectPro (
	    set "type=Volume"
		set "pr16install=1"
	  )
	  
	  if /i %%$ EQU ProjectPro2019 (
	    set "type=Volume"
		set "pr19install=1"
	  )
	  
	  if /i %%$ EQU ProjectPro2021 (
	    set "type=Volume"
		set "pr21install=1"
	  )
	  
	  if /i %%$ EQU ProjectPro2024 (
	    set "type=Volume"
		set "pr24install=1"
	  )
  )

  if "!pr24install!"  NEQ "0" ((set "pr16install=0")&&(set "pr19install=0")&&(set "pr21install=0"))
  if "!pr21install!"  NEQ "0" ((set "pr16install=0")&&(set "pr19install=0")&&(set "pr24install=0"))
  if "!pr19install!"  NEQ "0" ((set "pr16install=0")&&(set "pr21install=0")&&(set "pr24install=0"))
  if "!pr16install!"  NEQ "0" ((set "pr19install=0")&&(set "pr21install=0")&&(set "pr24install=0"))

  if "!vi24install!"  NEQ "0" ((set "vi16install=0")&&(set "vi19install=0")&&(set "vi21install=0"))
  if "!vi21install!"  NEQ "0" ((set "vi16install=0")&&(set "vi19install=0")&&(set "vi24install=0"))
  if "!vi19install!"  NEQ "0" ((set "vi16install=0")&&(set "vi21install=0")&&(set "vi24install=0"))
  if "!vi16install!"  NEQ "0" ((set "vi19install=0")&&(set "vi21install=0")&&(set "vi24install=0"))

  if "!mo16install!"  NEQ "0" ((set "of16install=0")&&(set "of19install=0")&&(set "of21install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))

  if "!of36ppinstall!"  NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of21install=0")&&(set "of19install=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))
  if "!of36bsinstall!"  NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of21install=0")&&(set "of19install=0")&&(set "of36ppinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))
  if "!of36homePrem!" NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of21install=0")&&(set "of19install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of24install=0"))

  if "!of24install!"  NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of19install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of21install=0"))
  if "!of21install!"  NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of19install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))
  if "!of19install!"  NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of21install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))
  if "!of16install!"  NEQ "0" ((set "mo16install=0")&&(set "of19install=0")&&(set "of21install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))

)

if /i !_Type! EQU Single (
 for %%$ in (!_Products!) do (
    
  if /i %%$ EQU Word (
    set "wd16install=1"
  )
  
  if /i %%$ EQU Word2019 (
    set "wd19install=1"
  )
  
  if /i %%$ EQU Word2021 (
    set "wd21install=1"
  )
  
  if /i %%$ EQU Word2024 (
    set "wd24install=1"
  )
  
  if /i %%$ EQU Excel (
    set "ex16install=1"
  )
  
  if /i %%$ EQU Excel2019 (
    set "ex19install=1"
  )
  
  if /i %%$ EQU Excel2021 (
    set "ex21install=1"
  )
  
  if /i %%$ EQU Excel2024 (
    set "ex24install=1"
  )
  
  if /i %%$ EQU PowerPoint (
    set "pp16install=1"
  )
  
  if /i %%$ EQU PowerPoint2019 (
    set "pp19install=1"
  )
  
  if /i %%$ EQU PowerPoint2021 (
    set "pp21install=1"
  )
  
  if /i %%$ EQU PowerPoint2024 (
    set "pp24install=1"
  )
  
  if /i %%$ EQU Access (
    set "ac16install=1"
  )
  
  if /i %%$ EQU Access2019 (
    set "ac19install=1"
  )
  
  if /i %%$ EQU Access2021 (
    set "ac21install=1"
  )
  
  if /i %%$ EQU Access2024 (
    set "ac24install=1"
  )
  
  if /i %%$ EQU Outlook (
    set "ol16install=1"
  )
  
  if /i %%$ EQU Outlook2019 (
    set "ol19install=1"
  )
  
  if /i %%$ EQU Outlook2021 (
    set "ol21install=1"
  )
  
  if /i %%$ EQU Outlook2024 (
    set "ol24install=1"
  )
  
  if /i %%$ EQU Publisher (
    set "pb16install=1"
  )
  
  if /i %%$ EQU Publisher2019 (
    set "pb19install=1"
  )
  
  if /i %%$ EQU Publisher2021 (
    set "pb21install=1"
  )
  
  if /i %%$ EQU Publisher2024 (
    set "pb24install=1"
  )
  
  if /i %%$ EQU VisioPro (
    set "vi16install=1"
  )
  
  if /i %%$ EQU VisioPro2019 (
    set "vi19install=1"
  )
  
  if /i %%$ EQU VisioPro2021 (
    set "vi21install=1"
  )
  
  if /i %%$ EQU VisioPro2024 (
    set "vi24install=1"
  )
  
  if /i %%$ EQU ProjectPro (
    set "pr16install=1"
  )
  
  if /i %%$ EQU ProjectPro2019 (
    set "pr19install=1"
  )
  
  if /i %%$ EQU ProjectPro2021 (
    set "pr21install=1"
  )
  
  if /i %%$ EQU ProjectPro2024 (
    set "pr24install=1"
  )
  
  if /i %%$ EQU SkypeForBusiness (
    set "sk16install=1"
  )
  
  if /i %%$ EQU SkypeForBusiness2019 (
    set "sk19install=1"
  )
  
  if /i %%$ EQU SkypeForBusiness2021 (
    set "sk21install=1"
  )
  
  if /i %%$ EQU SkypeForBusiness2024 (
    set "sk24install=1"
  )
  
  if /i %%$ EQU OneNote (
    set "on16install=1"
  )
  
  if /i %%$ EQU OneNote2021Retail (
    set "on21install=1"
  )
  
  if /i %%$ EQU OneNote2024Retail (
    set "on24install=1"
  )
  )

  if "!on16install!" NEQ "0" ((set "on21install=0")&(set "on24install=0"))
  if "!on21install!" NEQ "0" ((set "on16install=0")&(set "on24install=0"))
  if "!on24install!" NEQ "0" ((set "on16install=0")&(set "on21install=0"))

  if "!wd16install!" NEQ "0" ((set "wd19install=0")&&(set "wd21install=0")&&(set "wd24install=0"))
  if "!wd19install!" NEQ "0" ((set "wd16install=0")&&(set "wd21install=0")&&(set "wd24install=0"))
  if "!wd21install!" NEQ "0" ((set "wd16install=0")&&(set "wd19install=0")&&(set "wd24install=0"))
  if "!wd24install!" NEQ "0" ((set "wd16install=0")&&(set "wd19install=0")&&(set "wd21install=0"))

  if "!ex16install!" NEQ "0" ((set "ex19install=0")&&(set "ex21install=0")&&(set "ex24install=0"))
  if "!ex19install!" NEQ "0" ((set "ex16install=0")&&(set "ex21install=0")&&(set "ex24install=0"))
  if "!ex21install!" NEQ "0" ((set "ex16install=0")&&(set "ex19install=0")&&(set "ex24install=0"))
  if "!ex24install!" NEQ "0" ((set "ex16install=0")&&(set "ex19install=0")&&(set "ex21install=0"))

  if "!pp16install!" NEQ "0" ((set "pp19install=0")&&(set "pp21install=0")&&(set "pp24install=0"))
  if "!pp19install!" NEQ "0" ((set "pp16install=0")&&(set "pp21install=0")&&(set "pp24install=0"))
  if "!pp21install!" NEQ "0" ((set "pp16install=0")&&(set "pp19install=0")&&(set "pp24install=0"))
  if "!pp24install!" NEQ "0" ((set "pp16install=0")&&(set "pp19install=0")&&(set "pp21install=0"))

  if "!ac16install!" NEQ "0" ((set "ac19install=0")&&(set "ac21install=0")&&(set "ac24install=0"))
  if "!ac19install!" NEQ "0" ((set "ac16install=0")&&(set "ac21install=0")&&(set "ac24install=0"))
  if "!ac21install!" NEQ "0" ((set "ac16install=0")&&(set "ac19install=0")&&(set "ac24install=0"))
  if "!ac24install!" NEQ "0" ((set "ac16install=0")&&(set "ac19install=0")&&(set "ac21install=0"))

  if "!ol16install!" NEQ "0" ((set "ol19install=0")&&(set "ol21install=0")&&(set "ol24install=0"))
  if "!ol19install!" NEQ "0" ((set "ol16install=0")&&(set "ol21install=0")&&(set "ol24install=0"))
  if "!ol21install!" NEQ "0" ((set "ol16install=0")&&(set "ol19install=0")&&(set "ol24install=0"))
  if "!ol24install!" NEQ "0" ((set "ol16install=0")&&(set "ol19install=0")&&(set "ol21install=0"))

  if "!pb16install!" NEQ "0" ((set "pb19install=0")&&(set "pb21install=0")&&(set "pb24install=0"))
  if "!pb19install!" NEQ "0" ((set "pb16install=0")&&(set "pb21install=0")&&(set "pb24install=0"))
  if "!pb21install!" NEQ "0" ((set "pb16install=0")&&(set "pb19install=0")&&(set "pb24install=0"))
  if "!pb24install!" NEQ "0" ((set "pb16install=0")&&(set "pb19install=0")&&(set "pb21install=0"))

  if "!sk16install!" NEQ "0" ((set "sk19install=0")&&(set "sk21install=0")&&(set "sk24install=0"))
  if "!sk19install!" NEQ "0" ((set "sk16install=0")&&(set "sk21install=0")&&(set "sk24install=0"))
  if "!sk21install!" NEQ "0" ((set "sk16install=0")&&(set "sk19install=0")&&(set "sk24install=0"))
  if "!sk24install!" NEQ "0" ((set "sk16install=0")&&(set "sk19install=0")&&(set "sk21install=0"))

  if "!vi16install!" NEQ "0" ((set "vi19install=0")&&(set "vi21install=0")&&(set "vi24install=0"))
  if "!vi19install!" NEQ "0" ((set "vi16install=0")&&(set "vi21install=0")&&(set "vi24install=0"))
  if "!vi21install!" NEQ "0" ((set "vi16install=0")&&(set "vi19install=0")&&(set "vi24install=0"))
  if "!vi24install!" NEQ "0" ((set "vi16install=0")&&(set "vi19install=0")&&(set "vi21install=0"))

  if "!pr16install!" NEQ "0" ((set "pr19install=0")&&(set "pr21install=0")&&(set "pr24install=0"))
  if "!pr19install!" NEQ "0" ((set "pr16install=0")&&(set "pr21install=0")&&(set "pr24install=0"))
  if "!pr21install!" NEQ "0" ((set "pr16install=0")&&(set "pr19install=0")&&(set "pr24install=0"))
  if "!pr24install!" NEQ "0" ((set "pr16install=0")&&(set "pr19install=0")&&(set "pr21install=0"))
)

if defined _Exclude (
  for %%$ in (!_Exclude!) do (
    if /i %%$ EQU Word (
    set wd16disable=1
  )
  
  if /i %%$ EQU Excel (
    set ex16disable=1
  )
  
  if /i %%$ EQU PowerPoint (
    set pp16disable=1
  )
  
  if /i %%$ EQU Access (
    set ac16disable=1
  )
  
  if /i %%$ EQU Outlook (
    set ol16disable=1
  )
  
  if /i %%$ EQU Publisher (
    set pb16disable=1
  )
  
  if /i %%$ EQU OneNote (
    set on16disable=1
  )
  
  if /i %%$ EQU Skype (
    set st16disable=1
  )
  
  if /i %%$ EQU OneDrive (
    set od16disable=1
  )
  
  if /i %%$ EQU Bing (
    set bsbsdisable=1
  )
  
  if /i %%$ EQU Visio (
    set vs16disable=1
  )
  
  if /i %%$ EQU Project (
    set Pr16disable=1
  )
  )
)
if defined AutoPilotMode (
  if !_Action! EQU 2 (
    goto :OfficeC2RXMLInstall_XZZ
  )
  if !_Action! EQU 3 (
    goto :OnlineInstaller_Language_MENU_NEW
  )
)

::===============================================================================================================
:SingleAppsInstall
  echo:
  set "installtrigger="
  set /p installtrigger=Which "version" for Single App to install (1=2016, 2=2019, 3=2021, 4=2024) ^>
  (echo !installtrigger!| %MultiNul% findstr /i /r "^[1-4]$") && (
    goto :SingleAppsInstall_VERIFIED
  )
  goto :SingleAppsInstall

:SingleAppsInstall_VERIFIED
  if /I "!installtrigger!" EQU "X" goto:Office16VnextInstall
  if "!installtrigger!" EQU "1" goto:SingleApps2016Install
  if "!installtrigger!" EQU "2" goto:SingleApps2019Install
  if defined 21_24_Support if "!installtrigger!" EQU "3" goto :SingleApps2021Install
  if defined 21_24_Support if "!installtrigger!" EQU "4" goto :SingleApps2024Install
  goto:SingleAppsInstall
  
:SingleApps2016Install
  timeout 2 /nobreak %SingleNul%
  echo:
  echo %hMenu_I%
  echo ########################################
  echo:
  
  if defined WordSingleApp (
  	set wd16install=1
  	echo Set Word 2016 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Word 2016 Single App Install ^> SKIP
  	) else (
  		set /p wd16install=Set Word 2016 Single App Install ^>
  	if /I "%wd16install%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined ExcelSingleApp (
  	set ex16install=1
  	echo Set Excel 2016 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Excel 2016 Single App Install ^> SKIP
  	) else (
  		set /p ex16install=Set Excel 2016 Single App Install ^>
  		if /I "%ex16install%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined PowerPointSingleApp (
  	set pp16install=1
  	echo Set PowerPoint 2016 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Powerpoint 2016 Single App Install ^> SKIP
  	) else (
  		set /p pp16install=Set Powerpoint 2016 Single App Install ^>
  		if /I "%pp16install%" EQU "X" goto:Office16VnextInstall

  	)
  )
  
  if defined AccessSingleApp (
  	set ac16install=1
  	echo Set Access 2016 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Access 2016 Single App Install ^> SKIP
  	) else (
  		set /p ac16install=Set Access 2016 Single App Install ^>
  		if /I "%ac16install%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined OutlookSingleApp (
  	set ol16install=1
  	echo Set Outlook 2016 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Outlook 2016 Single App Install ^> SKIP
  	) else (
  		set /p ol16install=Set Outlook 2016 Single App Install ^>
  		if /I "%ol16install%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined PublisherSingleApp (
  	set pb16install=1
  	echo Set Publisher 2016 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Publisher 2016 Single App Install ^> SKIP
  	) else (
  		set /p pb16install=Set Publisher 2016 Single App Install ^>
  		if /I "%pb16install%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined SkypeSingleApp (
  	set sk16install=1
  	echo Set Skype For Business 2016 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Skype For Business 2016 Single App Install ^> SKIP
  	) else (
  		set /p sk16install=Set Skype For Business 2016 Single App Install ^>
  		if /I "%sk16install%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined OneNoteSingleApp (
  	set on16install=1
  	echo Set OneNote 2016 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set OneNote 2016 Single App Install ^> SKIP
  	) else (
  		set /p on16install=Set OneNote 2016 Single App Install ^>
  		if /I "%on16install%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  goto:InstVi16Pr16_
  
:SingleApps2019Install

  timeout 2 /nobreak %SingleNul%
  echo:
  echo %hMenu_I%
  echo ########################################
  echo:
  
  set "sn19install=1"
  (set "type=Volume")
  
  if defined WordSingleApp (
  	set wd19install=1
  	echo Set Word 2019 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Word 2019 Single App Install ^> SKIP
  	) else (
  		set /p wd19install=Set Word 2019 Single App Install ^>
  	if /I "%wd19install%" EQU "X" goto:Office19VnextInstall
  	)
  )
  
  if defined ExcelSingleApp (
  	set ex19install=1
  	echo Set Excel 2019 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Excel 2019 Single App Install ^> SKIP
  	) else (
  		set /p ex19install=Set Excel 2019 Single App Install ^>
  		if /I "%ex19install%" EQU "X" goto:Office19VnextInstall
  	)
  )
  
  if defined PowerPointSingleApp (
  	set pp19install=1
  	echo Set PowerPoint 2019 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Powerpoint 2019 Single App Install ^> SKIP
  	) else (
  		set /p pp19install=Set Powerpoint 2019 Single App Install ^>
  		if /I "%pp19install%" EQU "X" goto:Office19VnextInstall

  	)
  )
  
  if defined AccessSingleApp (
  	set ac19install=1
  	echo Set Access 2019 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Access 2019 Single App Install ^> SKIP
  	) else (
  		set /p ac19install=Set Access 2019 Single App Install ^>
  		if /I "%ac19install%" EQU "X" goto:Office19VnextInstall
  	)
  )
  
  if defined OutlookSingleApp (
  	set ol19install=1
  	echo Set Outlook 2019 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Outlook 2019 Single App Install ^> SKIP
  	) else (
  		set /p ol19install=Set Outlook 2019 Single App Install ^>
  		if /I "%ol19install%" EQU "X" goto:Office19VnextInstall
  	)
  )
  
  if defined PublisherSingleApp (
  	set pb19install=1
  	echo Set Publisher 2019 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Publisher 2019 Single App Install ^> SKIP
  	) else (
  		set /p pb19install=Set Publisher 2019 Single App Install ^>
  		if /I "%pb19install%" EQU "X" goto:Office19VnextInstall
  	)
  )
  
  if defined SkypeSingleApp (
  	set sk19install=1
  	echo Set Skype For Business 2019 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Skype For Business 2019 Single App Install ^> SKIP
  	) else (
  		set /p sk19install=Set Skype For Business 2019 Single App Install ^>
  		if /I "%sk19install%" EQU "X" goto:Office19VnextInstall
  	)
  )
  
  goto:InstVi19Pr19_
  
:SingleApps2021Install
  
  timeout 2 /nobreak %SingleNul%
  echo:
  echo %hMenu_I%
  echo ########################################
  echo:
  
  set "sn21install=1"
  (set "type=Volume")
  
  if defined WordSingleApp (
  	set wd21install=1
  	echo Set Word 2021 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Word 2021 Single App Install ^> SKIP
  	) else (
  		set /p wd21install=Set Word 2021 Single App Install ^>
  	if /I "%wd21install%" EQU "X" goto:Office21VnextInstall
  	)
  )
  
  if defined ExcelSingleApp (
  	set ex21install=1
  	echo Set Excel 2021 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Excel 2021 Single App Install ^> SKIP
  	) else (
  		set /p ex21install=Set Excel 2021 Single App Install ^>
  		if /I "%ex21install%" EQU "X" goto:Office21VnextInstall
  	)
  )
  
  if defined PowerPointSingleApp (
  	set pp21install=1
  	echo Set PowerPoint 2021 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Powerpoint 2021 Single App Install ^> SKIP
  	) else (
  		set /p pp21install=Set Powerpoint 2021 Single App Install ^>
  		if /I "%pp21install%" EQU "X" goto:Office21VnextInstall

  	)
  )
  
  if defined AccessSingleApp (
  	set ac21install=1
  	echo Set Access 2021 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Access 2021 Single App Install ^> SKIP
  	) else (
  		set /p ac21install=Set Access 2021 Single App Install ^>
  		if /I "%ac21install%" EQU "X" goto:Office21VnextInstall
  	)
  )
  
  if defined OutlookSingleApp (
  	set ol21install=1
  	echo Set Outlook 2021 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Outlook 2021 Single App Install ^> SKIP
  	) else (
  		set /p ol21install=Set Outlook 2021 Single App Install ^>
  		if /I "%ol21install%" EQU "X" goto:Office21VnextInstall
  	)
  )
  
  if defined PublisherSingleApp (
  	set pb21install=1
  	echo Set Publisher 2021 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Publisher 2021 Single App Install ^> SKIP
  	) else (
  		set /p pb21install=Set Publisher 2021 Single App Install ^>
  		if /I "%pb21install%" EQU "X" goto:Office21VnextInstall
  	)
  )
  
  if defined OneNoteSingleApp (
  	set on21install=1
  	echo Set OneNote 2021 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set OneNote 2021 Single App Install ^> SKIP
  	) else (
  		set /p on21install=Set OneNote 2021 Single App Install ^>
  		if /I "%on21install%" EQU "X" goto:Office21VnextInstall
  	)
  )
  
  if defined SkypeSingleApp (
  	set sk21install=1
  	echo Set Skype For Business 2021 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Skype For Business 2021 Single App Install ^> SKIP
  	) else (
  		set /p sk21install=Set Skype For Business 2021 Single App Install ^>
  		if /I "%sk21install%" EQU "X" goto:Office21VnextInstall
  	)
  )
  
  goto:InstVi21Pr21_
  
:SingleApps2024Install
  
  timeout 2 /nobreak %SingleNul%
  echo:
  echo %hMenu_I%
  echo ########################################
  echo:
  
  set "sn24install=1"
  (set "type=Volume")
  
  if defined WordSingleApp (
  	set wd24install=1
  	echo Set Word 2024 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Word 2024 Single App Install ^> SKIP
  	) else (
  		set /p wd24install=Set Word 2024 Single App Install ^>
  	if /I "%wd24install%" EQU "X" goto:Office24VnextInstall
  	)
  )
  
  if defined ExcelSingleApp (
  	set ex24install=1
  	echo Set Excel 2024 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Excel 2024 Single App Install ^> SKIP
  	) else (
  		set /p ex24install=Set Excel 2024 Single App Install ^>
  		if /I "%ex24install%" EQU "X" goto:Office24VnextInstall
  	)
  )
  
  if defined PowerPointSingleApp (
  	set pp24install=1
  	echo Set PowerPoint 2024 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Powerpoint 2024 Single App Install ^> SKIP
  	) else (
  		set /p pp24install=Set Powerpoint 2024 Single App Install ^>
  		if /I "%pp24install%" EQU "X" goto:Office24VnextInstall

  	)
  )
  
  if defined AccessSingleApp (
  	set ac24install=1
  	echo Set Access 2024 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Access 2024 Single App Install ^> SKIP
  	) else (
  		set /p ac24install=Set Access 2024 Single App Install ^>
  		if /I "%ac24install%" EQU "X" goto:Office24VnextInstall
  	)
  )
  
  if defined OutlookSingleApp (
  	set ol24install=1
  	echo Set Outlook 2024 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Outlook 2024 Single App Install ^> SKIP
  	) else (
  		set /p ol24install=Set Outlook 2024 Single App Install ^>
  		if /I "%ol24install%" EQU "X" goto:Office24VnextInstall
  	)
  )
  
  if defined PublisherSingleApp (
  	set pb24install=1
  	echo Set Publisher 2024 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Publisher 2024 Single App Install ^> SKIP
  	) else (
  		set /p pb24install=Set Publisher 2024 Single App Install ^>
  		if /I "%pb24install%" EQU "X" goto:Office24VnextInstall
  	)
  )
  
  if defined OneNoteSingleApp (
  	set on24install=1
  	echo Set OneNote 2024 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set OneNote 2024 Single App Install ^> SKIP
  	) else (
  		set /p on24install=Set OneNote 2024 Single App Install ^>
  		if /I "%on24install%" EQU "X" goto:Office24VnextInstall
  	)
  )
  
  if defined SkypeSingleApp (
  	set sk24install=1
  	echo Set Skype For Business 2024 Single App Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Set Skype For Business 2024 Single App Install ^> SKIP
  	) else (
  		set /p sk24install=Set Skype For Business 2024 Single App Install ^>
  		if /I "%sk24install%" EQU "X" goto:Office24VnextInstall
  	)
  )
  
  goto:InstVi24Pr24_
::===============================================================================================================
:InstallExclusions

  if "!mo16install!"  NEQ "0" ((set "of16install=0")&&(set "of19install=0")&&(set "of21install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))
  if "!of36ppinstall!"  NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of21install=0")&&(set "of19install=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))
  if "!of36homePrem!" NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of21install=0")&&(set "of19install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of24install=0"))
  if "!of36bsinstall!"  NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of21install=0")&&(set "of19install=0")&&(set "of36ppinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))

  if "!of16install!"  NEQ "0" ((set "mo16install=0")&&(set "of19install=0")&&(set "of21install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))
  if "!of19install!"  NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of21install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))
  if "!of21install!"  NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of19install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of24install=0"))
  if "!of24install!"  NEQ "0" ((set "mo16install=0")&&(set "of16install=0")&&(set "of19install=0")&&(set "of36ppinstall=0")&&(set "of36bsinstall=0")&&(set "of36homePrem=0")&&(set "of21install=0"))

  if "!pr16install!"  NEQ "0" ((set "pr19install=0")&&(set "pr21install=0")&&(set "pr24install=0"))
  if "!pr19install!"  NEQ "0" ((set "pr16install=0")&&(set "pr21install=0")&&(set "pr24install=0"))
  if "!pr21install!"  NEQ "0" ((set "pr16install=0")&&(set "pr19install=0")&&(set "pr24install=0"))
  if "!pr24install!"  NEQ "0" ((set "pr16install=0")&&(set "pr19install=0")&&(set "pr21install=0"))
  
  if "!vi16install!"  NEQ "0" ((set "vi19install=0")&&(set "vi21install=0")&&(set "vi24install=0"))
  if "!vi19install!"  NEQ "0" ((set "vi16install=0")&&(set "vi21install=0")&&(set "vi24install=0"))
  if "!vi21install!"  NEQ "0" ((set "vi16install=0")&&(set "vi19install=0")&&(set "vi24install=0"))
  if "!vi24install!"  NEQ "0" ((set "vi16install=0")&&(set "vi19install=0")&&(set "vi21install=0"))  
  
  echo:
  echo Full Suite Install Exclusion List - Disable not needed Office Programs
  echo:
  echo %hMenu_D%
  echo ########################################
  echo:
  
  if defined WordDISABLEApp (
  	set wd16disable=1
  	echo Disable Word Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Disable Word Install ^> SKIP
  	) else (
  		set /p wd16disable=Disable Word Install ^>
  		if /I "%wd16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined ExcelDISABLEApp (
  	set ex16disable=1
  	echo Disable Excel Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable Excel Install ^> SKIP
  	) else (
  		set /p ex16disable=Disable Excel Install ^>
  		if /I "%ex16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined PowerpointDISABLEApp (
  	set pp16disable=1
  	echo Disable Powerpoint Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable Powerpoint Install ^> SKIP
  	) else (
  		set /p pp16disable=Disable Powerpoint Install ^>
  		if /I "%pp16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined AccessDISABLEApp (
  	set ac16disable=1
  	echo Disable Access Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable Access Install ^> SKIP
  	) else (
  		set /p ac16disable=Disable Access Install ^>
  		if /I "%ac16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined OutlookDISABLEApp (
  	set ol16disable=1
  	echo Disable Outlook Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable Outlook Install ^> SKIP
  	) else (
  		set /p ol16disable=Disable Outlook Install ^>
  		if /I "%ol16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined PublisherDISABLEApp (
  	set pb16disable=1
  	echo Disable Publisher Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable Publisher Install ^> SKIP
  	) else (
  		set /p pb16disable=Disable Publisher Install ^>
  		if /I "%pb16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined OneNoteDISABLEApp (
  	set on16disable=1
  	echo Disable OneNote Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable OneNote Install ^> SKIP
  	) else (
  		set /p on16disable=Disable OneNote Install ^>
  		if /I "%on16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined SkypeDISABLEApp (
  	set st16disable=1
  	echo Disable Teams and Skype for Business Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable Teams and Skype for Business Install ^> SKIP
  	) else (
  		set /p st16disable=Disable Teams and Skype for Business Install ^>
  		if /I "%st16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined Teams if not defined SkypeDISABLEApp (
  	set st16disable=1
  	echo Disable Teams and Skype for Business Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable Teams and Skype for Business Install ^> SKIP
  	) else (
  		set /p st16disable=Disable Teams and Skype for Business Install ^>
  		if /I "%st16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined OneDriveDISABLEApp (
  	set od16disable=1
  	echo Disable OneDrive Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable OneDrive Install ^> SKIP
  	) else (
  		set /p od16disable=Disable OneDrive Install ^>
  		if /I "%od16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if defined BingDISABLEApp (
  	set bsbsdisable=1
  	echo Disable Bing Search Background Service Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable Bing Search Background Service Install ^> SKIP
  	) else (
  		set /p bsbsdisable=Disable Bing Search Background Service Install ^>
  		if /I "%bsbsdisable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if "%mo16install%" NEQ "0" if defined Visiodisable (
  	set vs16disable=1
  	echo Disable Visio Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable Visio Install ^> SKIP
  	) else (
  		set /p vs16disable=Disable Visio Install ^>
  		if /I "%vs16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )
  
  if "%mo16install%" NEQ "0" if defined Projectdisable (
  	set Pr16disable=1
  	echo Disable Project Install ^> TRUE
  ) else (	
  	if defined Auto_Skip (
  		echo Disable Project Install ^> SKIP
  	) else (
  		set /p Pr16disable=Disable Project Install ^>
  		if /I "%Pr16disable%" EQU "X" goto:Office16VnextInstall
  	)
  )

::===============================================================================================================
  
  if "%mo16install%" NEQ "0" goto:InstViPrEnd
  if "%of16install%" NEQ "0" goto:InstVi16Pr16
  if "%of19install%" NEQ "0" goto:InstVi19Pr19
  if "%of21install%" NEQ "0" goto:InstVi21Pr21
  if "%of24install%" NEQ "0" goto:InstVi24Pr24
  
  if defined 21_24_Support (
    goto:InstVi24Pr24
  )
  
  :: 1 - Not mondo suite
  :: 2 - WinBuild LSS 9600
  :: 3 - o16build LSS 14000
  :: can install visio-project 2016-2019 only
  :: i say ,,, choice 2019 ,,, better then 2016
  
  goto:InstVi19Pr19

::===============================================================================================================
  
:InstVi16Pr16
  timeout 2 /nobreak %SingleNul%
  echo:
  echo %hMenu_I%
  echo ########################################
  echo:
:InstVi16Pr16_
  
  if defined VisioSingleApp (
  	set vi16install=1
  	echo Set Visio 2016 Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Visio 2016 Install ^> SKIP
  	) else (
  		set /p vi16install=Set Visio 2016 Install ^>
  	)
  )
  
  if defined ProjectSingleApp (
  	set pr16install=1
  	echo Set Project 2016 Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Project 2016 Install ^> SKIP
  	) else (
  		set /p pr16install=Set Project 2016 Install ^>
  	)
  )
  
  goto:InstViPrEnd
  
:InstVi19Pr19
  timeout 2 /nobreak %SingleNul%
  echo:
  echo %hMenu_I%
  echo ########################################
  echo:
:InstVi19Pr19_

  if defined VisioSingleApp (
  	set vi19install=1
  	echo Set Visio 2019 Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Visio 2019 Install ^> SKIP
  	) else (
  		set /p vi19install=Set Visio 2019 Install ^>
  	)
  )
  
  if defined ProjectSingleApp (
  	set pr19install=1
  	echo Set Project 2019 Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Project 2019 Install ^> SKIP
  	) else (
  		set /p pr19install=Set Project 2019 Install ^>
  	)
  )
  
  goto:InstViPrEnd
  
:InstVi21Pr21
  timeout 2 /nobreak %SingleNul%
  echo:
  echo %hMenu_I%
  echo ########################################
  echo:
:InstVi21Pr21_

  if defined VisioSingleApp (
  	set vi21install=1
  	echo Set Visio 2021 Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Visio 2021 Install ^> SKIP
  	) else (
  		set /p vi21install=Set Visio 2021 Install ^>
  	)
  )
  
  if defined ProjectSingleApp (
  	set pr21install=1
  	echo Set Project 2021 Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Project 2021 Install ^> SKIP
  	) else (
  		set /p pr21install=Set Project 2021 Install ^>
  	)
  )
  
  goto:InstViPrEnd
  
:InstVi24Pr24
  timeout 2 /nobreak %SingleNul%
  echo:
  echo %hMenu_I%
  echo ########################################
  echo:
:InstVi24Pr24_

  if defined VisioSingleApp (
  	set vi24install=1
  	echo Set Visio 2024 Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Visio 2024 Install ^> SKIP
  	) else (
  		set /p vi24install=Set Visio 2024 Install ^>
  	)
  )
  
  if defined ProjectSingleApp (
  	set pr24install=1
  	echo Set Project 2024 Install ^> TRUE
  ) else (
  	if defined Auto_Skip (
  		echo Project 2024 Install ^> SKIP
  	) else (
  		set /p pr24install=Set Project 2024 Install ^>
  	)
  )
  
  goto:InstViPrEnd
  
::===============================================================================================================
:InstViPrEnd
  %SingleNul% timeout 2 /nobreak
  echo ____________________________________________________________________________
  echo:
::===============================================================================================================
  if "!o16updlocid!" EQU "492350f6-3a01-4f97-b9c0-c7c6ddf67d60" (echo Source Channel: "Current" - !o16build! -Setup-)&&(goto:PendSetupContinue)
  if "!o16updlocid!" EQU "64256afe-f5d9-4f86-8936-8840a6a4f5be" (echo Source Channel: "CurrentPreview" - !o16build! -Setup-)&&(goto:PendSetupContinue)
  if "!o16updlocid!" EQU "5440fd1f-7ecb-4221-8110-145efaa6372f" (echo Source Channel: "BetaChannel" - !o16build! -Setup-)&&(goto:PendSetupContinue)
  if "!o16updlocid!" EQU "55336b82-a18d-4dd6-b5f6-9e5095c314a6" (echo Source Channel: "MonthlyEnterprise" - !o16build! -Setup-)&&(goto:PendSetupContinue)
  if "!o16updlocid!" EQU "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" (echo Source Channel: "SemiAnnual" - !o16build! -Setup-)&&(goto:PendSetupContinue)
  if "!o16updlocid!" EQU "b8f9b850-328d-4355-9145-c59439a0c4cf" (echo Source Channel: "SemiAnnualPreview" - !o16build! -Setup-)&&(goto:PendSetupContinue)
  if "!o16updlocid!" EQU "f2e724c1-748f-4b47-8fb8-8e0d210e9208" (echo Source Channel: "PerpetualVL2019" - !o16build! -Setup-)&&(goto:PendSetupContinue)
  if "!o16updlocid!" EQU "5030841d-c919-4594-8d2d-84ae4f96e58e" (echo Source Channel: "PerpetualVL2021" - !o16build! -Setup-)&&(goto:PendSetupContinue)
  if "!o16updlocid!" EQU "7983BAC0-E531-40CF-BE00-FD24FE66619C" (echo Source Channel: "PerpetualVL2024" - !o16build! -Setup-)&&(goto:PendSetupContinue)
  if "!o16updlocid!" EQU "ea4a4090-de26-49d7-93c1-91bff9e53fc3" (echo Source Channel: "DogfoodDevMain" - !o16build! -Setup-)&&(goto:PendSetupContinue)
  echo "Manual_Override:" !o16updlocid! - !o16build! -Setup-
::===============================================================================================================
:PendSetupContinue
  cls
  echo:
  
  call :PrintTitle "The following programs are selected for install"
  echo:
  
  if "%ac16install%" NEQ "0" goto:PendSetupSingleApp
  if "%ac19install%" NEQ "0" goto:PendSetupSingleApp
  if "%ac21install%" NEQ "0" goto:PendSetupSingleApp
  if "%ac24install%" NEQ "0" goto:PendSetupSingleApp
  
  if "%ex16install%" NEQ "0" goto:PendSetupSingleApp
  if "%ex19install%" NEQ "0" goto:PendSetupSingleApp
  if "%ex21install%" NEQ "0" goto:PendSetupSingleApp
  if "%ex24install%" NEQ "0" goto:PendSetupSingleApp
  
  if "%ol16install%" NEQ "0" goto:PendSetupSingleApp
  if "%ol19install%" NEQ "0" goto:PendSetupSingleApp
  if "%ol21install%" NEQ "0" goto:PendSetupSingleApp
  if "%ol24install%" NEQ "0" goto:PendSetupSingleApp
  
  if "%pb16install%" NEQ "0" goto:PendSetupSingleApp
  if "%pb19install%" NEQ "0" goto:PendSetupSingleApp
  if "%pb21install%" NEQ "0" goto:PendSetupSingleApp
  if "%pb24install%" NEQ "0" goto:PendSetupSingleApp
  
  if "%pp16install%" NEQ "0" goto:PendSetupSingleApp
  if "%pp19install%" NEQ "0" goto:PendSetupSingleApp
  if "%pp21install%" NEQ "0" goto:PendSetupSingleApp
  if "%pp24install%" NEQ "0" goto:PendSetupSingleApp
  
  if "%sk16install%" NEQ "0" goto:PendSetupSingleApp
  if "%sk19install%" NEQ "0" goto:PendSetupSingleApp
  if "%sk21install%" NEQ "0" goto:PendSetupSingleApp
  if "%sk24install%" NEQ "0" goto:PendSetupSingleApp
  
  if "%wd16install%" NEQ "0" goto:PendSetupSingleApp
  if "%wd19install%" NEQ "0" goto:PendSetupSingleApp
  if "%wd21install%" NEQ "0" goto:PendSetupSingleApp
  if "%wd24install%" NEQ "0" goto:PendSetupSingleApp
  
  if "%on16install%" NEQ "0" goto:PendSetupSingleApp
  if "%on21install%" NEQ "0" goto:PendSetupSingleApp
  if "%on24install%" NEQ "0" goto:PendSetupSingleApp
  
::===============================================================================================================
  if "%of16install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Office Professional Plus 2016" -foreground "Green")&&(goto:PendSetupFullSuite)
  if "%of19install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Office Professional Plus 2019 Volume" -foreground "Green")&&(goto:PendSetupFullSuite)
  if "%of21install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Office Professional Plus 2021 Volume" -foreground "Green")&&(goto:PendSetupFullSuite)
  if "%of24install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Office Professional Plus 2024 Volume" -foreground "Green")&&(goto:PendSetupFullSuite)
  if "%of36ppinstall%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Office 365 ProPlus" -foreground "Green")&&(goto:PendSetupFullSuite)
  if "%of36bsinstall%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Office 365 Business Premium" -foreground "Green")&&(goto:PendSetupFullSuite)
  if "%of36homePrem%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Office 365 Home Premium" -foreground "Green")&&(goto:PendSetupFullSuite)
  if "%mo16install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Mondo 2016 Grande Suite" -foreground "Green")&&(goto:PendSetupFullSuite)
  goto:PendSetupProjectVisio

:PendSetupFullSuite
  if "%wd16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: Word" -foreground "Red")
  if "%wd16disable%" EQU "0" (echo --^> Enabled:  Word)
  if "%ex16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: Excel" -foreground "Red")
  if "%ex16disable%" EQU "0" (echo --^> Enabled:  Excel)
  if "%pp16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: Powerpoint" -foreground "Red")
  if "%pp16disable%" EQU "0" (echo --^> Enabled:  PowerPoint)
  if "%ac16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: Access" -foreground "Red")
  if "%ac16disable%" EQU "0" (echo --^> Enabled:  Access)
  if "%ol16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: Outlook" -foreground "Red")
  if "%ol16disable%" EQU "0" (echo --^> Enabled:  Outlook)
  if "%pb16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: Publisher" -foreground "Red")
  if "%pb16disable%" EQU "0" (echo --^> Enabled:  Publisher)
  if "%on16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: OneNote" -foreground "Red")
  if "%on16disable%" EQU "0" (echo --^> Enabled:  OneNote)
  if "%st16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: Teams / Skype For Business" -foreground "Red")
  if "%st16disable%" EQU "0" (echo --^> Enabled:  Teams / Skype For Business)
  if "%od16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: OneDrive For Business" -foreground "Red")
  if "%od16disable%" EQU "0" (echo --^> Enabled:  OneDrive For Business)
  if "%bsbsdisable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: Bing Search Background Service" -foreground "Red")
  if "%bsbsdisable%" EQU "0" (echo --^> Enabled:  Bing Search Background Service)
  
  if "%mo16install%" NEQ "0" if "%Pr16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: Project" -foreground "Red")
  if "%mo16install%" NEQ "0" if "%Pr16disable%" EQU "0" (echo --^> Enabled:  Project)
  if "%mo16install%" NEQ "0" if "%vs16disable%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "--> Disabled: Visio" -foreground "Red")
  if "%mo16install%" NEQ "0" if "%vs16disable%" EQU "0" (echo --^> Enabled:  Visio)
  
  goto:PendSetupProjectVisio
::===============================================================================================================
:PendSetupSingleApp	

  if "%ac16install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Access 2016 Single App" -foreground "Green")
  if "%ac19install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Access 2019 Single App" -foreground "Green")
  if "%ac21install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Access 2021 Single App" -foreground "Green")
  if "%ac24install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Access 2024 Single App" -foreground "Green")
  
  if "%ex16install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Excel 2016 Single App" -foreground "Green")
  if "%ex19install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Excel 2019 Single App" -foreground "Green")
  if "%ex21install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Excel 2021 Single App" -foreground "Green")
  if "%ex24install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Excel 2024 Single App" -foreground "Green")
  
  if "%ol16install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Outlook 2016 Single App" -foreground "Green")
  if "%ol19install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Outlook 2019 Single App" -foreground "Green")
  if "%ol21install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Outlook 2021 Single App" -foreground "Green")
  if "%ol24install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Outlook 2024 Single App" -foreground "Green")
  
  if "%on16install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "OneNote 2016 Single App" -foreground "Green")
  if "%on21install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "OneNote 2021 Single App" -foreground "Green")
  if "%on24install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "OneNote 2024 Single App" -foreground "Green")
  
  if "%pb16install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Publisher 2016 Single App" -foreground "Green")
  if "%pb19install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Publisher 2019 Single App" -foreground "Green")
  if "%pb21install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Publisher 2021 Single App" -foreground "Green")
  if "%pb24install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Publisher 2024 Single App" -foreground "Green")
  
  if "%pp16install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "PowerPoint 2016 Single App" -foreground "Green")
  if "%pp19install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "PowerPoint 2019 Single App" -foreground "Green")
  if "%pp21install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "PowerPoint 2021 Single App" -foreground "Green")
  if "%pp24install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "PowerPoint 2024 Single App" -foreground "Green")
  
  if "%sk16install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Skype For Business 2016 Single App" -foreground "Green")
  if "%sk19install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Skype For Business 2019 Single App" -foreground "Green")
  if "%sk21install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Skype For Business 2021 Single App" -foreground "Green")
  if "%sk24install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Skype For Business 2024 Single App" -foreground "Green")
  
  if "%wd16install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Word 2016 Single App" -foreground "Green")
  if "%wd19install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Word 2019 Single App" -foreground "Green")
  if "%wd21install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Word 2021 Single App" -foreground "Green")
  if "%wd24install%" NEQ "0" (%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Word 2024 Single App" -foreground "Green")
  
::===============================================================================================================
:PendSetupProjectVisio
  
  if "%pr16install%" NEQ "0" (echo:)&&(%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Project Professional 2016" -foreground "Green")
  if "%pr19install%" NEQ "0" (echo:)&&(%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Project Professional 2019 Volume" -foreground "Green")
  if "%pr21install%" NEQ "0" (echo:)&&(%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Project Professional 2021 Volume" -foreground "Green")
  if "%pr24install%" NEQ "0" (echo:)&&(%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Project Professional 2024 Volume" -foreground "Green")
  
  if "%vi16install%" NEQ "0" (echo:)&&(%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Visio Professional 2016" -foreground "Green")
  if "%vi19install%" NEQ "0" (echo:)&&(%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Visio Professional 2019 Volume" -foreground "Green")
  if "%vi21install%" NEQ "0" (echo:)&&(%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Visio Professional 2021 Volume" -foreground "Green")
  if "%vi24install%" NEQ "0" (echo:)&&(%PowerShellEXE% -noprofile -command "%pswindowtitle%"; Write-Host "Visio Professional 2024 Volume" -foreground "Green")
  
::===============================================================================================================
if not defined OnlineInstaller goto :OnlineInstaller_NEXT
  :ChannelSelected_xd
  echo:
  set "o16buildCKS=!o16build!"
    set /p o16build=Set Office Build - or press return for !o16build! ^>
  echo "!o16build!" | %SingleNul% findstr /r "%ver_reg%" || (set "o16build=!o16buildCKS!" & goto :ChannelSelected_xd)
:OnlineInstaller_Language_MENU
  call :MainLangSelection
  
:OnlineInstaller_Language_MENU_Loop
  echo:
  
  set MULTI_lang=
  if /i "!o16lang!" EQU "not set" call :CheckSystemLanguage
:OnlineInstaller_Language_MENU_NEW
  if defined AutoPilotMode (
    if !_Action! EQU 3 set "MULTI_lang=!_Language!"
  ) else (
    REM set /p o16lang=Set Language Value - or press return for !o16lang! ^>
    set /p MULTI_lang=Set Language[s] Value[s] - or press return for !o16lang! ^> 
  )
  
  set "o16lang=!o16lang:, =!"
  set "o16lang=!o16lang:,=!"
  if defined o16lang if /i "x!o16lang:~0,1!" EQU "x " set "o16lang=!o16lang:~1!"
  if defined o16lang if /i "!o16lang:-1!x" EQU " x" set "o16lang=!o16lang:~0,-1!"
  
  call :SetO16Language
  if defined langnotfound (
  	set "o16lang=not set"
  	goto:OnlineInstaller_Language_MENU_Loop
  )
  
  REM if defined MULTI_lang set "MULTI_lang=!MULTI_lang:-=,!"
  if defined MULTI_lang set "MULTI_lang=!MULTI_lang:;=,!"
  if defined MULTI_lang set "MULTI_lang=!MULTI_lang:#=,!"
  
  set LANG_TEST=
  set /a LANG_COUNT=0
  if defined MULTI_lang (
  	set "XWtf=!MULTI_lang: =$!"
  	for %%a in (!XWtf!) do (
  		set "newVal=%%a"
  		set "newVal=!newVal:$= !"
  		call :verify_LANG_XXA !newVal!
  ))
  
  if !LANG_COUNT! EQU 1 (
  	set "o16lang=!MULTI_lang!"
  	set MULTI_lang=
  	set "o16lang=!o16lang:, =!"
  	set "o16lang=!o16lang:,=!"
  	if defined o16lang if /i "x!o16lang:~0,1!" EQU "x " set "o16lang=!o16lang:~1!"
  	if defined o16lang if /i "!o16lang:-1!x" EQU " x" set "o16lang=!o16lang:~0,-1!"
  	call :SetO16Language
  )
  if defined AutoPilotMode if !_Action! EQU 3 (
    goto :JJX31
  )
  
  if defined XML_MODE (
    echo:
    call :AllLangSelection
  )
  
:OnlineInstaller_Language_MENU_Loop_Y
  if defined XML_MODE (
    echo:
  )
:JJX31
  set default=
  set LangPackTools=
  set Multi_Lang_Pack=
  
  if not defined AutoPilotMode if defined Language_Pack (
  	echo Default Language[s] Pack Value[s] ^> %Language_Pack%
  	set "Multi_Lang_Pack=%Language_Pack%"
  	set "default=/ Press {ENTER} to Skip "
  )
  if defined XML_MODE if not defined AutoPilotMode (
    set /p Multi_Lang_Pack=Set Language[s] Pack Value[s] !default!^> 
  )
  if defined AutoPilotMode if !_Action! EQU 3 (
    if defined _lang_pack (
      set "Multi_Lang_Pack=!_lang_pack!"
    ) else (
  	goto :JJX34
    )
  )
  REM if defined Multi_Lang_Pack set "Multi_Lang_Pack=!Multi_Lang_Pack:-=,!"
  if defined Multi_Lang_Pack set "Multi_Lang_Pack=!Multi_Lang_Pack:;=,!"
  if defined Multi_Lang_Pack set "Multi_Lang_Pack=!Multi_Lang_Pack:#=,!"
  
  set LANG_TEST=
  set /a LANG_COUNT=0
  if defined Multi_Lang_Pack (
  	set "XWtf=!Multi_Lang_Pack: =$!"
  	for %%a in (!XWtf!) do (
  		set "newVal=%%a"
  		set "newVal=!newVal:$= !"
  		call :verify_LANG_XXAB !newVal!
  	)
  )
  
  if defined AutoPilotMode if !_Action! EQU 3 (
    goto :JJX34
  )
  
  if defined XML_MODE (
    echo:
    call :ProofLangSelection
  )
  
:OnlineInstaller_Language_MENU_Loop_X
  if defined XML_MODE (
    echo:
  )
  
:JJX34
  set default=
  set ProofingTools=
  set Multi_Proof_Lang=
  if not defined AutoPilotMode if defined PROOF_LANG (
  	echo Default Proofing Language[s] Value[s] ^> !PROOF_LANG!
  	set "Multi_Proof_Lang=!PROOF_LANG!"
  	set "default=/ Press {ENTER} to Skip "
  )
  
  if defined XML_MODE if not defined AutoPilotMode (
    set /p Multi_Proof_Lang=Set Proofing Language[s] Value[s] !default!^> 
  )
  
  if defined AutoPilotMode if !_Action! EQU 3 (
    if defined _proof_tool (
      set "Multi_Proof_Lang=!_proof_tool!"
  	) else (
  	goto :OfficeC2RXMLInstall_XZZ
    )
  )
  REM if defined Multi_Proof_Lang set "Multi_Proof_Lang=!Multi_Proof_Lang:-=,!"
  if defined Multi_Proof_Lang set "Multi_Proof_Lang=!Multi_Proof_Lang:;=,!"
  if defined Multi_Proof_Lang set "Multi_Proof_Lang=!Multi_Proof_Lang:#=,!"
  
  set LANG_TEST=
  set /a LANG_COUNT=0
  if defined Multi_Proof_Lang (
  	set "XWtf=!Multi_Proof_Lang: =$!"
  	for %%a in (!XWtf!) do (
  		set "newVal=%%a"
  		set "newVal=!newVal:$= !"
  		call :verify_LANG_XXAZ !newVal!
  	)
  )
  
  if defined AutoPilotMode if !_Action! EQU 3 (
    set "downpath=%windir%\Temp"
  	set "installpath=%windir%\Temp"
    goto :OfficeC2RXMLInstall_XZZ
  )

:OnlineInstaller_ARCH_MENU
  if /i '%PROCESSOR_ARCHITECTURE%' EQU 'x86' 		(IF NOT DEFINED PROCESSOR_ARCHITEW6432 set sBit=86)
  if /i '%PROCESSOR_ARCHITECTURE%' EQU 'x86' 		(IF DEFINED PROCESSOR_ARCHITEW6432 set sBit=64)
  if /i '%PROCESSOR_ARCHITECTURE%' EQU 'AMD64' 	set sBit=64
  if /i '%PROCESSOR_ARCHITECTURE%' EQU 'IA64' 	set sBit=64
  
  set "o16arch=x!sBit!"
  if defined inidownarch ((echo "!inidownarch!" | %SingleNul% find /i "not set") || set "o16arch=!inidownarch!")
  if /i '!o16arch!' EQU 'Multi' set "o16arch=x!sBit!"	
  if /i 'x!sBit!' NEQ '!o16arch!' (if /i '!sBit!' EQU '86' (set "o16arch=x!sBit!"))
  
  echo:
  set /p o16arch=Set architecture to install (x86 or x64) - or press return for !o16arch! ^>
  if /i "!o16arch!" EQU "x86" goto :OnlineInstaller_NEXT
  if /i "!o16arch!" EQU "x64" goto :OnlineInstaller_NEXT
  goto :OnlineInstaller_ARCH_MENU
  
:OnlineInstaller_NEXT
  
  REM cls
  echo:
  echo ____________________________________________________________________________
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! Pending Install (SUMMARY) !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  if "!o16updlocid!" EQU "492350f6-3a01-4f97-b9c0-c7c6ddf67d60" echo   Channel-ID: !o16updlocid! (Current) && goto:ZetaXX112
  if "!o16updlocid!" EQU "64256afe-f5d9-4f86-8936-8840a6a4f5be" echo   Channel-ID: !o16updlocid! (CurrentPreview) && goto:ZetaXX112
  if "!o16updlocid!" EQU "5440fd1f-7ecb-4221-8110-145efaa6372f" echo   Channel-ID: !o16updlocid! (BetaChannel) && goto:ZetaXX112
  if "!o16updlocid!" EQU "55336b82-a18d-4dd6-b5f6-9e5095c314a6" echo   Channel-ID: !o16updlocid! (MonthlyEnterprise) && goto:ZetaXX112
  if "!o16updlocid!" EQU "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" echo   Channel-ID: !o16updlocid! (SemiAnnual) && goto:ZetaXX112
  if "!o16updlocid!" EQU "b8f9b850-328d-4355-9145-c59439a0c4cf" echo   Channel-ID: !o16updlocid! (SemiAnnualPreview) && goto:ZetaXX112
  if "!o16updlocid!" EQU "f2e724c1-748f-4b47-8fb8-8e0d210e9208" echo   Channel-ID: !o16updlocid! (PerpetualVL2019) && goto:ZetaXX112
  if "!o16updlocid!" EQU "5030841d-c919-4594-8d2d-84ae4f96e58e" echo   Channel-ID: !o16updlocid! (PerpetualVL2021) && goto:ZetaXX112
  if "!o16updlocid!" EQU "7983BAC0-E531-40CF-BE00-FD24FE66619C" echo   Channel-ID: !o16updlocid! (PerpetualVL2024) && goto:ZetaXX112
  if "!o16updlocid!" EQU "ea4a4090-de26-49d7-93c1-91bff9e53fc3" echo   Channel-ID: !o16updlocid! (DogfoodDevMain) && goto:ZetaXX112
  echo Channel-ID:   !o16updlocid! (Manual_Override)
::===============================================================================================================
:ZetaXX112
  echo Office Build: !o16build!
  if not defined MULTI_lang 			echo     Language: !o16lang! (%langtext%)
  if     defined MULTI_lang 			echo     Language: !MULTI_lang!
  if     defined Multi_Lang_Pack 		echo    Lang Pack: !Multi_Lang_Pack!
  if     defined Multi_Proof_Lang       echo  Proof Tools: !Multi_Proof_Lang!
  
  echo Architecture: !o16arch!
  echo ____________________________________________________________________________
  echo:
  
  							    set "menuX=(ENTER) to Install, (C)reate install Package, (R)estart installation, (E)xit to main menu >"
  if defined createIso 		    set "menuX=(ENTER) to Create ISO, (R)estart installation, (E)xit to main menu >"
  if defined OnlineInstaller 	set "menuX=(ENTER) to Install, (R)estart installation, (E)xit to main menu >"
  
                              set "regi="^[C]$ ^[R]$ ^[E]$""
  if defined createIso 		  set "regi="^[R]$ ^[E]$""
  if defined OnlineInstaller  set "regi="^[R]$ ^[E]$""

:Error_Check_4_VALIDATE
  echo:
  set "installtrigger="
  set /p installtrigger=!menuX!
  if defined installtrigger (
    ((echo !installtrigger!|%multinul% findstr /i /r !REGI!) && (goto :Error_Check_4_PASS) || (goto :Error_Check_4_VALIDATE))
    goto :Error_Check_4_VALIDATE
  )
:Error_Check_4_PASS
  cls
  echo:
  if /i "!installtrigger!" EQU "C" set "createpackage=1"
  if /i "!installtrigger!" EQU "R" goto:InstallO16
  if /i "!installtrigger!" EQU "E" goto:Office16VnextInstall

::===============================================================================================================
:OfficeC2RXMLInstall

  REM cls
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! INSTALL OFFICE FULL SUITE / SINGLE APPS !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:

:OfficeC2RXMLInstall_XZZ	
  
  if %NT_X% GEQ 10 if /i !distribchannel! NEQ PerpetualVL2019 (
  	  rem echo: & echo Change To Compatible mode & echo:
  	  if !pr19install! EQU 1 set "setup=Bin\setup.exe" 
      if !vi19install! EQU 1 set "setup=Bin\setup.exe" 
  	  if !sn19install! EQU 1 set "setup=Bin\setup.exe" 
      if !of19install! EQU 1 set "setup=Bin\setup.exe" 
  )
  if %NT_X% GEQ 10 if /i !distribchannel! NEQ PerpetualVL2021 (
      rem echo: & echo Change To Compatible mode & echo:
      if !pr21install! EQU 1 set "setup=Bin\setup.exe" 
      if !vi21install! EQU 1 set "setup=Bin\setup.exe" 
  	  if !sn21install! EQU 1 set "setup=Bin\setup.exe" 
      if !of21install! EQU 1 set "setup=Bin\setup.exe" 
  )
  
  if %WinBuild% GEQ 10240 (
    if %FORCE_XML% EQU 0 (
	  set "instmethod=C2R"
  ))

  if /i "!o16arch!" EQU "x64" (set "o16a=64") else (set "o16a=32")
  if /i "!instmethod!" EQU "XML" echo Creating setup files & echo "setup.exe", "configure%o16a%.xml" and "start_setup.cmd"
  if /i "!instmethod!" EQU "C2R" echo Creating setup files & echo "start_setup.cmd"
  
  if defined OnlineInstaller (
  	set "downpath=%windir%\Temp"
  	set "installpath=%windir%\Temp"
  )
  
  echo:
  echo in Installpath:
  echo "%installpath%"
  echo:
  
  if /i "!instmethod!" EQU "XML" set "oxml=!downpath!\configure%o16a%.xml"
  if /i "!instmethod!" EQU "XML" copy "%OfficeRToolpath%\Data\%setup%" "!downpath!\setup.exe" /Y %MultiNul%
  if /i "!instmethod!" EQU "XML" (set "channel= channel="!distribchannel!"")
  if /i "!instmethod!" EQU "C2R" if exist "!downpath!\setup*.exe" del /s /q "!downpath!\setup*.exe" %MultiNul%
  if /i "!distribchannel!" EQU "Manual_Override" (set "channel=")
  rem if /i "!distribchannel!" EQU "DogfoodDevMain" (set "channel=")
  if exist "!downpath!\configure*.xml" del /s /q "!downpath!\configure*.xml" %MultiNul%
  
  set "obat=!downpath!\start_setup.cmd"
  set "ops1=!downpath!\Offline_Install.ps1"
  
  if "!instmethod!" EQU "XML" (
    %MultiNul% copy "%OfficeRToolpath%\Data\start_setup_xml.cmd" "!obat!" /Y
  )
  if "!instmethod!" EQU "C2R" (
    if defined OnlineInstaller (
      goto:Skip_Create )
    %MultiNul% copy "%OfficeRToolpath%\Data\start_setup_c2r.cmd" "!obat!" /Y
	%MultiNul% copy "%OfficeRToolpath%\Data\PS1\Office_Offline_Install.ps1" "!ops1!" /Y
  )
  
:Skip_Create
  if not defined MULTI_lang (
    goto :Skip_M_L )
  set "id_LIST="
  set "XWtf=!MULTI_lang: =$!"
  for %%a in (!XWtf!) do (
  	set "newVal=%%a"
  	set "newVal=!newVal:$= !"
  	call :GENERATE_LANG_ID_LIST !newVal!
  )

:Skip_M_L
  if not defined id_LIST (
    set "id_LIST=!o16lang!"
  )
  set "id_LIST=!id_LIST: =_!"
  if "!id_LIST:~0,1!" EQU "_" (
    set "id_LIST=!id_LIST:~1!"
  )
  
  if "!instmethod!" EQU "C2R" (
    goto :CreateC2RConfig
  )
  if "!instmethod!" EQU "XML" (
    goto :CreateXMLConfig
  )
  goto:InstallO16
  
::===============================================================================================================
:CreateXMLConfig
  if /i "!o16arch!" EQU "Multi" (
    goto :CreateXMLConfig_M
  )
  call :generateXML
  goto:CreateStartSetupBatch

:CreateXMLConfig_M  
  :: create x32 profile
  set "o16a=32"
  set "oxml=!downpath!\configure32.xml"
  call :generateXML
  :: create x64 profile
  set "o16a=64"
  set "oxml=!downpath!\configure64.xml"
  call :generateXML
  goto:CreateStartSetupBatch
  
::===============================================================================================================
::===============================================================================================================
:CreateC2RConfig
  if "%mo16install%" NEQ "0" (
    set "product_list=!product_list!,Mondo%type%"
  	set "productstoadd=!productstoadd!^^|Mondo%type%.16_!!id_LIST!!_x-none"
  	set "productID=Mondo%type%"
  )

  if "%of16install%" NEQ "0" (
    set "product_list=!product_list!,ProPlus%type%"
  	set "productstoadd=!productstoadd!^^|ProPlus%type%.16_!!id_LIST!!_x-none"
  	set "productID=ProPlus%type%"
  )
  
  if "%of19install%" NEQ "0" (
    set "product_list=!product_list!,ProPlus2019%type%"
  	set "productstoadd=!productstoadd!^^|ProPlus2019%type%.16_!!id_LIST!!_x-none"
  	set "productID=ProPlus2019%type%"
  )
  
  if "%of21install%" NEQ "0" (
    set "product_list=!product_list!,ProPlus2021%type%"
  	set "productstoadd=!productstoadd!^^|ProPlus2021%type%.16_!!id_LIST!!_x-none"
  	set "productID=ProPlus2021%type%"
  )
  if "%of24install%" NEQ "0" (
    set "product_list=!product_list!,ProPlus2024%type%"
  	set "productstoadd=!productstoadd!^^|ProPlus2024%type%.16_!!id_LIST!!_x-none"
  	set "productID=ProPlus2024%type%"
  )
  if "%of36ppinstall%" NEQ "0" (
    set "product_list=!product_list!,O365ProPlus%type%"
  	set "productstoadd=!productstoadd!^^|O365ProPlus%type%.16_!!id_LIST!!_x-none"
  	set "productID=O365ProPlus%type%"
  )
  if "%of36bsinstall%" NEQ "0" (
    set "product_list=!product_list!,O365Business%type%"
    set "productstoadd=!productstoadd!^^|O365Business%type%.16_!!id_LIST!!_x-none"
    set "productID=O365Business%type%"
  )
  if "%of36homePrem%" NEQ "0" (
    set "product_list=!product_list!,O365HomePrem%type%"
    set "productstoadd=!productstoadd!^^|O365HomePrem%type%.16_!!id_LIST!!_x-none"
    set "productID=O365HomePrem%type%"
  )
  if "%wd16disable%" NEQ "0" set "excludedapps=!excludedapps!,word"
  if "%ex16disable%" NEQ "0" set "excludedapps=!excludedapps!,excel"
  if "%pp16disable%" NEQ "0" set "excludedapps=!excludedapps!,powerpoint"
  if "%ac16disable%" NEQ "0" set "excludedapps=!excludedapps!,access"
  if "%ol16disable%" NEQ "0" set "excludedapps=!excludedapps!,outlook"
  if "%pb16disable%" NEQ "0" set "excludedapps=!excludedapps!,publisher"
  if "%on16disable%" NEQ "0" set "excludedapps=!excludedapps!,onenote"
  if "%st16disable%" NEQ "0" set "excludedapps=!excludedapps!,lync"
  if "%st16disable%" NEQ "0" set "excludedapps=!excludedapps!,teams"
  if "%od16disable%" NEQ "0" set "excludedapps=!excludedapps!,groove"
  if "%od16disable%" NEQ "0" set "excludedapps=!excludedapps!,onedrive"
  if "%bsbsdisable%" NEQ "0" set "excludedapps=!excludedapps!,bing"
  
  if "%mo16install%" NEQ "0" if "%vs16disable%" NEQ "0" set "excludedapps=!excludedapps!,Visio"
  if "%mo16install%" NEQ "0" if "%Pr16disable%" NEQ "0" set "excludedapps=!excludedapps!,Project"
  
  if "!excludedapps:~0,2!" EQU "0," (set "excludedapps=%productID%.excludedapps.16^=!excludedapps:~2!") else (set "excludedapps=")
::===============================================================================================================		
  
  if "%pr16install%" NEQ "0" set "productstoadd=!productstoadd!^^|ProjectPro%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,ProjectPro%type%"
  if "%pr19install%" NEQ "0" set "productstoadd=!productstoadd!^^|ProjectPro2019%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,ProjectPro2019%type%"
  if "%pr21install%" NEQ "0" set "productstoadd=!productstoadd!^^|ProjectPro2021%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,ProjectPro2021%type%"
  if "%pr24install%" NEQ "0" set "productstoadd=!productstoadd!^^|ProjectPro2024%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,ProjectPro2024%type%"
  
  if "%vi16install%" NEQ "0" set "productstoadd=!productstoadd!^^|VisioPro%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,VisioPro%type%"
  if "%vi19install%" NEQ "0" set "productstoadd=!productstoadd!^^|VisioPro2019%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,VisioPro2019%type%"
  if "%vi21install%" NEQ "0" set "productstoadd=!productstoadd!^^|VisioPro2021%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,VisioPro2021%type%"
  if "%vi24install%" NEQ "0" set "productstoadd=!productstoadd!^^|VisioPro2024%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,VisioPro2024%type%"
  
::===============================================================================================================
  
  if "%ac16install%" NEQ "0" set "productstoadd=!productstoadd!^^|Access%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Access%type%"
  if "%ac19install%" NEQ "0" set "productstoadd=!productstoadd!^^|Access2019%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Access2019%type%"
  if "%ac21install%" NEQ "0" set "productstoadd=!productstoadd!^^|Access2021%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Access2021%type%"
  if "%ac24install%" NEQ "0" set "productstoadd=!productstoadd!^^|Access2024%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Access2024%type%"
  
  if "%ex16install%" NEQ "0" set "productstoadd=!productstoadd!^^|Excel%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Excel%type%"
  if "%ex19install%" NEQ "0" set "productstoadd=!productstoadd!^^|Excel2019%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Excel2019%type%"
  if "%ex21install%" NEQ "0" set "productstoadd=!productstoadd!^^|Excel2021%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Excel2021%type%"
  if "%ex24install%" NEQ "0" set "productstoadd=!productstoadd!^^|Excel2024%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Excel2024%type%"
  
  if "%ol16install%" NEQ "0" set "productstoadd=!productstoadd!^^|Outlook%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Outlook%type%"
  if "%ol19install%" NEQ "0" set "productstoadd=!productstoadd!^^|Outlook2019%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Outlook2019%type%"
  if "%ol21install%" NEQ "0" set "productstoadd=!productstoadd!^^|Outlook2021%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Outlook2021%type%"
  if "%ol24install%" NEQ "0" set "productstoadd=!productstoadd!^^|Outlook2024%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Outlook2024%type%"
  
  if "%on16install%" NEQ "0" set "productstoadd=!productstoadd!^^|OneNote%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,OneNote%type%"
  if "%on21install%" NEQ "0" set "productstoadd=!productstoadd!^^|OneNote2021%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,OneNote2021%type%"
  if "%on24install%" NEQ "0" set "productstoadd=!productstoadd!^^|OneNote2024%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,OneNote2024%type%"
  
  if "%pb16install%" NEQ "0" set "productstoadd=!productstoadd!^^|Publisher%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Publisher%type%"
  if "%pb19install%" NEQ "0" set "productstoadd=!productstoadd!^^|Publisher2019%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Publisher2019%type%"
  if "%pb21install%" NEQ "0" set "productstoadd=!productstoadd!^^|Publisher2021%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Publisher2021%type%"
  if "%pb24install%" NEQ "0" set "productstoadd=!productstoadd!^^|Publisher2024%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Publisher2024%type%"
  
  if "%pp16install%" NEQ "0" set "productstoadd=!productstoadd!^^|PowerPoint%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,PowerPoint%type%"
  if "%pp19install%" NEQ "0" set "productstoadd=!productstoadd!^^|PowerPoint2019%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,PowerPoint2019%type%"
  if "%pp21install%" NEQ "0" set "productstoadd=!productstoadd!^^|PowerPoint2021%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,PowerPoint2021%type%"
  if "%pp24install%" NEQ "0" set "productstoadd=!productstoadd!^^|PowerPoint2024%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,PowerPoint2024%type%"
  
  if "%sk16install%" NEQ "0" set "productstoadd=!productstoadd!^^|SkypeForBusiness%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,SkypeForBusiness%type%"
  if "%sk19install%" NEQ "0" set "productstoadd=!productstoadd!^^|SkypeForBusiness2019%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,SkypeForBusiness2019%type%"
  if "%sk21install%" NEQ "0" set "productstoadd=!productstoadd!^^|SkypeForBusiness2021%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,SkypeForBusiness2021%type%"
  if "%sk24install%" NEQ "0" set "productstoadd=!productstoadd!^^|SkypeForBusiness2024%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,SkypeForBusiness2024%type%"
  
  if "%wd16install%" NEQ "0" set "productstoadd=!productstoadd!^^|Word%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Word%type%"
  if "%wd19install%" NEQ "0" set "productstoadd=!productstoadd!^^|Word2019%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Word2019%type%"
  if "%wd21install%" NEQ "0" set "productstoadd=!productstoadd!^^|Word2021%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Word2021%type%"
  if "%wd24install%" NEQ "0" set "productstoadd=!productstoadd!^^|Word2024%type%.16_!!id_LIST!!_x-none" & set "product_list=!product_list!,Word2024%type%"
  
  goto :CreateStartSetupBatch

::===============================================================================================================
:CreateStartSetupBatch
  
  :: if online install, move next ..
  if "!instmethod!" EQU "C2R" (
    if defined OnlineInstaller (
	  goto:UpdateBranch
  ))
  
  REM using set /p instead ^ ^ ^ ^ ^ ^ ^
  set "var_a= :: Set Group Policy value "UpdateBranch" in registry for "!distribchannel!""
  set "var_b=reg add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d !distribchannel! /f %MultiNul%"
  if "!distribchannel!" EQU "DogfoodDevMain"  set "var_b=reg delete HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /f %MultiNul%"
  if "!distribchannel!" EQU "Manual_Override" set "var_b=reg delete HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /f %MultiNul%"	
  
  echo:                    >>"%obat%"
  (echo|set /p ="!var_a!") >>"%obat%"
  echo:                    >>"%obat%"
  (echo|set /p ="!var_b!") >>"%obat%"
  echo:                    >>"%obat%"
  
  echo ^:^:=============================================================================================================== >>"%obat%"
 
  if "!instmethod!" EQU "C2R" (
	>>"%pInfo%" echo %o16lang%
	>>"%pInfo%" echo !id_LIST!
	>>"%pInfo%" echo !product_list!
	if defined excludedapps (
	  >>"%pInfo%" echo !excludedapps!
	)
	>>"%obat%" echo powershell -nop -ep bypass -f Offline_Install.ps1 "%%instupdlocid%%" "%%instversion%%" "%%oApps%%" "%%o16lang%%" "%%id_LIST%%" "%%exclude%%"
    rem >>"%obat%" echo start "" /MIN "%%CommonProgramFiles%%\Microsoft Shared\ClickToRun\OfficeClickToRun.exe" platform=%%instarch1%% culture=%o16lang% productstoadd=!productstoadd:~3! !excludedapps! cdnbaseurl.16=http://officecdn.microsoft.com/%Region%/%%instupdlocid%% baseurl.16="%%installfolder%%" version.16=%%instversion%% mediatype.16=Local sourcetype.16=Local updatesenabled.16=True acceptalleulas.16=True displaylevel=True bitnessmigration=False deliverymechanism=%%instupdlocid%% flt.useoutlookshareaddon=unknown flt.useofficehelperaddon=unknown
  )
  
  if "!instmethod!" EQU "XML" (
    >>"%obat%" echo ^>nul 2^>^&1 del /q %%windir%%\temp\S_ID.txt
    >>"%obat%" echo set ID_C=@^(start setup.exe -WorkingDirectory '%%installfolder%%' -Args '/configure configure%%instarch2%%.xml' -Verb RunAs -WindowStyle hidden -passthru^).ID
    >>"%obat%" echo for /f "usebackq tokens=*" %%%%# in ^(`"%%SingleNulV2%% "%PowerShellEXE%" -nop -c %%ID_C%%"`^) do set "S_ID=%%%%#"
    >>"%obat%" echo if defined S_ID ^>%%windir%%\temp\S_ID.txt echo ^^!S_ID^^!
  )
  
  echo exit >>"%obat%"
  echo ^:^:=============================================================================================================== >>"%obat%"
  
  if defined createIso (
  	set "createIso="
  	echo ----------------------------------------------------------------------------
  	echo Please Wait for ISO Creation...
  	echo ----------------------------------------------------------------------------
  	%SingleNulV2% "%OfficeRToolpath%\Data\Bin\oscdimg.exe" -m -u1 "!downpath!" "!downpath!.iso" || (
  	  	cls & echo:
  	  	call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! INSTALL OFFICE FULL SUITE / SINGLE APPS !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  	  	echo: & echo:
  	  	echo ERROR ### Iso Creation Failed
  	  	echo:
  	  	goto:InstDone
  	)
  	echo.
  	echo ----------------------------------------------------------------------------
    echo ISO Created Successfully at
  	echo !isopath!
  	echo ----------------------------------------------------------------------------
	echo:
  	goto:InstDone
  )

  if /i "%createpackage%" EQU "1" goto:InstDone

:UpdateBranch
::===============================================================================================================
  if "!distribchannel!" EQU "Current" %REGEXE% add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d !distribchannel! /f %MultiNul%
  if "!distribchannel!" EQU "CurrentPreview" %REGEXE% add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d !distribchannel! /f %MultiNul%
  if "!distribchannel!" EQU "BetaChannel" %REGEXE% add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d !distribchannel! /f %MultiNul%
  if "!distribchannel!" EQU "MonthlyEnterprise" %REGEXE% add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d !distribchannel! /f %MultiNul%
  if "!distribchannel!" EQU "SemiAnnual" %REGEXE% add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d !distribchannel! /f %MultiNul%
  if "!distribchannel!" EQU "SemiAnnualPreview" %REGEXE% add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d !distribchannel! /f %MultiNul%
  if "!distribchannel!" EQU "PerpetualVL2019" %REGEXE% add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d !distribchannel! /f %MultiNul%
  if "!distribchannel!" EQU "PerpetualVL2021" %REGEXE% add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d !distribchannel! /f %MultiNul%
  if "!distribchannel!" EQU "PerpetualVL2024" %REGEXE% add HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /d !distribchannel! /f %MultiNul%
  if "!distribchannel!" EQU "DogfoodDevMain" %REGEXE% delete HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /f %MultiNul%
  if "!distribchannel!" EQU "Manual_Override" %REGEXE% delete HKLM\Software\Policies\Microsoft\Office\16.0\Common\OfficeUpdate /v UpdateBranch /f %MultiNul%
  cd /D "%installpath%"
  
  :: if online install, move next ..
  if defined OnlineInstaller (
    goto :online_Ins
  )
  :: start installation
  %multinul% timeout /t 2
  start "" /I /MIN "%obat%"
  :: check progress of installation
  %multinul% timeout /t 3
  if exist %windir%\temp\S_ID.txt (
  	set "S_ID="
  	<%windir%\temp\S_ID.txt set /p S_ID=
  	if defined NT_X if %NT_X% GEQ 10 (
  	  if "!Wait_Till_Finish!" EQU "1" (
  		%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Setup_Complete.ps1"
  )))
  goto :InstDone

:online_Ins

  if "!instmethod!" EQU "C2R" (
	if defined excludedapps (
	  %SingleNulV2%  %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Office_Online_Install.ps1" "!distribchannel!" "!o16build!" "!product_list!" "!o16lang!" "!id_LIST!" "!excludedapps!"
	) else (
	  %SingleNulV2%  %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Office_Online_Install.ps1" "!distribchannel!" "!o16build!" "!product_list!" "!o16lang!" "!id_LIST!"
	)
    goto:InstDone
  )
  
  if "!instmethod!" EQU "XML" (
  	set "S_ID="
  	set COMMAND="@(start '%windir%\Temp\setup.exe' -Args '/configure !oxml!' -Verb RunAs -WindowStyle hidden -passthru).ID"
  	for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c !COMMAND!"`) do set "S_ID=%%#"
  	
  	rem check for no W7.
  	if defined NT_X if %NT_X% GEQ 10 (
  	  if "!Wait_Till_Finish!" EQU "1" (
  		%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Setup_Complete.ps1"
  )))
  goto :InstDone
  
::===============================================================================================================
:InstDone
  echo ____________________________________________________________________________
  echo:
  echo:
  timeout /t 4
  if defined Auto_Pilot_RET (
    goto :Office16VnextInstall
  )
  if defined AutoPilotMode (
    goto :eof
  )
    goto:Office16VnextInstall
::===============================================================================================================
::===============================================================================================================
:CheckOfficeApplications
  
  rem Basic stuff
  
  set "installpath16=not set" & set "officepath3=not set"
  set "o16version=not set"    & set "o16arch=not set"
  
  rem msi apps
  
  set "ProPlusVLFound=NO"     & set "ProjectProVLFound=NO"
  set "StandardVLFound=NO"    & set "VisioProVLFound=NO"
  
  rem UWP apps
  
  set "_UWPappINSTALLED=NO"
  set "_AppxAccess=NO"        & set "_AppxExcel=NO"
  set "_AppxOneNote=NO"       & set "_AppxOutlook=NO"
  set "_AppxPowerPoint=NO"    & set "_AppxProject=NO"
  set "_AppxPublisher=NO"     & set "_AppxSkypeForBusiness=NO"
  set "_AppxVisio=NO"         & set "_AppxWinword=NO"
  
  rem packages only
  
  set "_MondoRetail=NO"       & set "_MondoVolume=NO"
  
  set "_HomeBusinessRetail=NO"
  set "_HomeBusiness2019Retail=NO"
  set "_HomeBusiness2021Retail=NO"
  set "_HomeBusiness2024Retail=NO"
  
  set "_HomeStudentRetail=NO"
  set "_HomeStudent2019Retail=NO"
  set "_HomeStudent2021Retail=NO"
  set "_HomeStudent2024Retail=NO"
  
  set "_O365BusinessRetail=NO"
  set "_O365BusinessVolume=NO"
  set "_O365HomePremRetail=NO"
  set "_O365ProPlusRetail=NO"
  set "_O365ProPlusVolume=NO"
  set "_O365SmallBusPremRetail=NO"
  set "_O365AppsBasicRetail=NO"
  
  set "_O365ProPlusEEANoTeamsRetail=NO"
  set "_O365BusinessEEANoTeamsRetail=NO"
  
  set "_PersonalRetail=NO"
  set "_Personal2019Retail=NO"
  set "_Personal2021Retail=NO"
  set "_Personal2024Retail=NO"
  
  set "_ProfessionalRetail=NO"
  set "_Professional2019Retail=NO"
  set "_Professional2021Retail=NO"	
  set "_Professional2024Retail=NO"	
  
  set "_ProPlusVolume=NO"              & set "_ProPlusRetail=NO"
  set "_ProPlus2019Volume=NO"          & set "_ProPlus2019Retail=NO"
  set "_ProPlus2021Volume=NO"          & set "_ProPlus2021Retail=NO"  & set "_ProPlusSPLA2021Volume=NO"
  set "_ProPlus2024Volume=NO"          & set "_ProPlus2024Retail=NO"  & set "_ProPlusSPLA2024Volume=NO"
  
  set "_StandardRetail=NO"             & set "_StandardVolume=NO"
  set "_Standard2019Retail=NO"         & set "_Standard2019Volume=NO"
  set "_Standard2021Retail=NO"         & set "_Standard2021Volume=NO" & set "_StandardSPLA2021Volume=NO"
  set "_Standard2024Retail=NO"         & set "_Standard2024Volume=NO" & set "_StandardSPLA2024Volume=NO"
  
  rem single products only
  	
  set "_WordVolume=NO"                 & set "_WordRetail=NO"
  set "_Word2019Volume=NO"             & set "_Word2019Retail=NO"
  set "_Word2021Volume=NO"             & set "_Word2021Retail=NO"
  set "_Word2024Volume=NO"             & set "_Word2024Retail=NO"
  
  set "_ExcelVolume=NO"                & set "_ExcelRetail=NO"
  set "_Excel2019Volume=NO"            & set "_Excel2019Retail=NO"
  set "_Excel2021Volume=NO"            & set "_Excel2021Retail=NO"
  set "_Excel2024Volume=NO"            & set "_Excel2024Retail=NO"
  
  set "_PowerPointVolume=NO"           & set "_PowerPointRetail=NO"
  set "_PowerPoint2019Volume=NO"       & set "_PowerPoint2019Retail=NO"
  set "_PowerPoint2021Volume=NO"       & set "_PowerPoint2021Retail=NO"
  set "_PowerPoint2024Volume=NO"       & set "_PowerPoint2024Retail=NO"
  
  set "_AccessVolume=NO"               & set "_AccessRetail=NO"
  set "_Access2019Volume=NO"           & set "_Access2019Retail=NO"
  set "_Access2021Volume=NO"           & set "_Access2021Retail=NO"
  set "_Access2024Volume=NO"           & set "_Access2024Retail=NO"
  
  set "_OutlookVolume=NO"              & set "_OutlookRetail=NO"
  set "_Outlook2019Volume=NO"          & set "_Outlook2019Retail=NO"
  set "_Outlook2021Volume=NO"          & set "_Outlook2021Retail=NO"
  set "_Outlook2024Volume=NO"          & set "_Outlook2024Retail=NO"
  
  set "_OneNoteVolume=NO"              & set "_OneNoteRetail=NO"
  set "_OneNote2021Retail=NO"          & set "_OneNote2024Retail=NO"
  
  set "_SkypeForBusinessVolume=NO"     & set "_SkypeForBusinessRetail=NO"
  set "_SkypeForBusiness2019Volume=NO" & set "_SkypeForBusiness2019Retail=NO"
  set "_SkypeForBusiness2021Volume=NO" & set "_SkypeForBusiness2021Retail=NO"
  set "_SkypeForBusiness2024Volume=NO" & set "_SkypeForBusiness2024Retail=NO"
  
  set "_PublisherVolume=NO"            & set "_PublisherRetail=NO"
  set "_Publisher2019Volume=NO"        & set "_Publisher2019Retail=NO"
  set "_Publisher2021Volume=NO"        & set "_Publisher2021Retail=NO"
  set "_Publisher2024Volume=NO"        & set "_Publisher2024Retail=NO"
  
  set "_ProjectProRetail=NO"           & set "_ProjectProVolume=NO" & set "_ProjectProXVolume=NO"
  set "_ProjectPro2019Retail=NO"       & set "_ProjectPro2019Volume=NO"
  set "_ProjectPro2021Retail=NO"       & set "_ProjectPro2021Volume=NO"
  set "_ProjectPro2024Retail=NO"       & set "_ProjectPro2024Volume=NO"
  
  set "_ProjectStdRetail=NO"           & set "_ProjectStdVolume=NO" & set "_ProjectStdXVolume=NO"
  set "_ProjectStd2019Retail=NO"       & set "_ProjectStd2019Volume=NO"
  set "_ProjectStd2021Retail=NO"       & set "_ProjectStd2021Volume=NO"
  set "_ProjectStd2024Retail=NO"       & set "_ProjectStd2024Volume=NO"
  
  set "_VisioProRetail=NO"             & set "_VisioProVolume=NO"   & set "_VisioProXVolume=NO"
  set "_VisioPro2019Retail=NO"         & set "_VisioPro2019Volume=NO"
  set "_VisioPro2021Retail=NO"         & set "_VisioPro2021Volume=NO"
  set "_VisioPro2024Retail=NO"         & set "_VisioPro2024Volume=NO"
  
  set "_VisioStdRetail=NO"             & set "_VisioStdVolume=NO"   & set "_VisioStdXVolume=NO"
  set "_VisioStd2019Retail=NO"         & set "_VisioStd2019Volume=NO"
  set "_VisioStd2021Retail=NO"         & set "_VisioStd2021Volume=NO"
  set "_VisioStd2024Retail=NO"         & set "_VisioStd2024Volume=NO"
  
  reg query "%hC2r%\Configuration" /v "InstallationPath" %MultiNul%
  if %errorlevel% EQU 0 ( call :CheckOffice16C2R & goto:CheckOfficeApplications_ )
  
  reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Common\InstallRoot" /v "Path" %MultiNul%
  if %errorlevel% EQU 0 ( call :CheckOfficeVL32onW64 & goto:CheckOfficeApplications_ )
  
  reg query "HKLM\Software\Microsoft\Office\16.0\Common\InstallRoot" /v "Path" %MultiNul%
  if %errorlevel% EQU 0 ( call :CheckOfficeVL32W32orVL64W64 & goto:CheckOfficeApplications_ )
  
  %MultiNul% reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\msoxmled.exe"
  if %errorlevel% EQU 0 (
  	set "default="
  	for /f "tokens=1,2,* delims= " %%a in ('"reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\msoxmled.exe" /ve"') do set "default=%%c"
  	if defined default if exist "!default!" (
  		set "_UWPappINSTALLED=YES"
  		call :CheckAppxOffice16UWP
  		goto:CheckOfficeApplications_
  	)
  )
  
  (echo:) && (echo Supported Office 2016/2019/2021 product not found) && (echo:) && (pause) && (goto:Office16VnextInstall)

:CheckOfficeApplications_
  
  if "!_MondoVolume!" EQU "YES" set "_MondoRetail=NO"
  
  if "!_OneNoteVolume!" EQU "YES" set "_OneNoteRetail=NO"
  
  if "!_ProPlusVolume!"     EQU "YES" set "_ProPlusRetail=NO"
  if "!_ProPlus2019Volume!" EQU "YES" set "_ProPlus2019Retail=NO"
  if "!_ProPlus2021Volume!" EQU "YES" ((set "_ProPlus2021Retail=NO") & (set "_ProPlusSPLA2021Volume=NO"))
  if "!_ProPlus2024Volume!" EQU "YES" ((set "_ProPlus2024Retail=NO") & (set "_ProPlusSPLA2024Volume=NO"))
  
  if "!_StandardVolume!"     EQU "YES" set "_StandardRetail=NO"
  if "!_Standard2019Volume!" EQU "YES" set "_Standard2019Retail=NO"
  if "!_Standard2021Volume!" EQU "YES" ((set "_Standard2021Retail=NO") & (set "_StandardSPLA2021Volume=NO"))
  if "!_Standard2024Volume!" EQU "YES" ((set "_Standard2024Retail=NO") & (set "_StandardSPLA2024Volume=NO"))
  
  if "!_ProjectProVolume!"     EQU "YES" ((set "_ProjectProRetail=NO") & (set "_ProjectProXVolume=NO"))
  if "!_ProjectPro2019Volume!" EQU "YES" set "_ProjectPro2019Retail=NO"
  if "!_ProjectPro2021Volume!" EQU "YES" (set "_ProjectPro2021Retail=NO")
  if "!_ProjectPro2024Volume!" EQU "YES" (set "_ProjectPro2024Retail=NO")
  
  if "!_ProjectStdVolume!"     EQU "YES" ((set "_ProjectStdRetail=NO") & (set "_ProjectStdXVolume=NO"))
  if "!_ProjectStd2019Volume!" EQU "YES" set "_ProjectStd2019Retail=NO"
  if "!_ProjectStd2021Volume!" EQU "YES" (set "_ProjectStd2021Retail=NO")
  if "!_ProjectStd2024Volume!" EQU "YES" (set "_ProjectStd2024Retail=NO")
  
  if "!_VisioProVolume!"     EQU "YES" ((set "_VisioProRetail=NO") & (set "_VisioProXVolume=NO"))
  if "!_VisioPro2019Volume!" EQU "YES" set "_VisioPro2019Retail=NO"
  if "!_VisioPro2021Volume!" EQU "YES" (set "_VisioPro2021Retail=NO")
  if "!_VisioPro2024Volume!" EQU "YES" (set "_VisioPro2024Retail=NO")
  
  if "!_VisioStdVolume!"     EQU "YES" ((set "_VisioStdRetail=NO") & (set "_VisioStdXVolume=NO"))
  if "!_VisioStd2019Volume!" EQU "YES" set "_VisioStd2019Retail=NO"
  if "!_VisioStd2021Volume!" EQU "YES" (set "_VisioStd2021Retail=NO")
  if "!_VisioStd2024Volume!" EQU "YES" (set "_VisioStd2024Retail=NO")
  
  if "!_WordVolume!"     EQU "YES" set "_WordRetail=NO"
  if "!_Word2019Volume!" EQU "YES" set "_Word2019Retail=NO"
  if "!_Word2021Volume!" EQU "YES" set "_Word2021Retail=NO"
  if "!_Word2024Volume!" EQU "YES" set "_Word2024Retail=NO"
  
  if "!_ExcelVolume!"     EQU "YES" set "_ExcelRetail=NO"
  if "!_Excel2019Volume!" EQU "YES" set "_Excel2019Retail=NO"
  if "!_Excel2021Volume!" EQU "YES" set "_Excel2021Retail=NO"
  if "!_Excel2024Volume!" EQU "YES" set "_Excel2024Retail=NO"

  if "!_PowerpointVolume!"     EQU "YES" set "_PowerpointRetail=NO"
  if "!_Powerpoint2019Volume!" EQU "YES" set "_Powerpoint2019Retail=NO"
  if "!_Powerpoint2021Volume!" EQU "YES" set "_Powerpoint2021Retail=NO"
  if "!_Powerpoint2024Volume!" EQU "YES" set "_Powerpoint2024Retail=NO"
  
  if "!_OutlookVolume!"     EQU "YES" set "_OutlookRetail=NO"
  if "!_Outlook2019Volume!" EQU "YES" set "_Outlook2019Retail=NO"
  if "!_Outlook2021Volume!" EQU "YES" set "_Outlook2021Retail=NO"
  if "!_Outlook2024Volume!" EQU "YES" set "_Outlook2024Retail=NO"
  
  if "!_AccessVolume!"     EQU "YES" set "_AccessRetail=NO"
  if "!_Access2019Volume!" EQU "YES" set "_Access2019Retail=NO"
  if "!_Access2021Volume!" EQU "YES" set "_Access2021Retail=NO"
  if "!_Access2024Volume!" EQU "YES" set "_Access2024Retail=NO"

  if "!_PublisherVolume!"     EQU "YES" set "_PublisherRetail=NO"
  if "!_Publisher2019Volume!" EQU "YES" set "_Publisher2019Retail=NO"
  if "!_Publisher2021Volume!" EQU "YES" set "_Publisher2021Retail=NO"
  if "!_Publisher2024Volume!" EQU "YES" set "_Publisher2024Retail=NO"
  
  if "!_SkypeForBusinessVolume!"     EQU "YES" set "_SkypeForBusinessRetail=NO"
  if "!_SkypeForBusiness2019Volume!" EQU "YES" set "_SkypeForBusiness2019Retail=NO"
  if "!_SkypeForBusiness2021Volume!" EQU "YES" set "_SkypeForBusiness2021Retail=NO"
  if "!_SkypeForBusiness2024Volume!" EQU "YES" set "_SkypeForBusiness2024Retail=NO"
  
  goto:eof
  
::===============================================================================================================
::===============================================================================================================

:CheckAppxOffice16UWP
  for /F "tokens=9 delims=\_() " %%A IN ('reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\msoxmled.exe" /ve 2^>nul') DO (set "o16version=%%A")
  for /F "tokens=4" %%A IN ('reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\msoxmled.exe" /ve 2^>nul') DO (set "installpath16=%%A")
  set "installpath16=C:\Program !installpath16!"
  set "installpath16=!installpath16:~0,-35!"
  
  call :check_UWP winword  _AppxWinword
  call :check_UWP excel    _AppxExcel
  call :check_UWP powerpnt _AppxPowerPoint
  call :check_UWP msaccess _AppxAccess
  call :check_UWP mspub    _AppxPublisher
  call :check_UWP outlook  _AppxOutlook
  call :check_UWP lync     _AppxSkypeForBusiness
  call :check_UWP onenote  _AppxOneNote
  call :check_UWP visio    _AppxVisio
  call :check_UWP winproj  _AppxProject	
  goto:eof
  
:check_UWP
  set "default="
  for /f "tokens=1,2,* delims= " %%a in ('"%SingleNulV2% reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\%1.exe" /ve"') do set "default=%%c"
  if defined default if exist "!default!" set "%2=YES"
  goto :eof
  
::===============================================================================================================
::===============================================================================================================
  
:CheckOffice16C2R
  for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\Configuration" /v "Platform" 2^>nul') DO (set "o16arch=%%B")
  for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\Configuration" /v "InstallationPath" 2^>nul') DO (Set "installpath16=%%B")
  set "officepath3=%installpath16%\Office16"
  for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\Configuration" /v "ProductReleaseIds" 2^>nul') DO (Set "Office16AppsInstalled=%%B")
  for %%$ IN (%Office16AppsInstalled%) DO set "_%%$=YES"
  for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\ProductReleaseIDs" /v "ActiveConfiguration" 2^>nul') DO (set "o16activeconf=%%B")
  for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\ProductReleaseIDs\%o16activeconf%" /v "Modifier" 2^>nul') DO (set "o16version=%%B")
  set "o16version=%o16version:~0,16%"
  if "%o16version:~15,1%" EQU "|" set "o16version=%o16version:~0,14%"
  if "%o16version:~4,1%"  EQU "|" for /F "tokens=2,*" %%A IN ('reg query "%hC2r%\Configuration" /v "VersionToReport" 2^>nul') DO (set "o16version=%%B")
  goto:eof
::===============================================================================================================
::===============================================================================================================
:CheckOfficeVL32onW64
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Wow6432Node\Microsoft\Office\16.0\Common\InstalledPackages\90160000-0011-0000-0000-0000000FF1CE" /ve 2^>nul') DO (Set "ProPlusVLFound=%%B") %MultiNul%
  if "%ProPlusVLFound:~-39%" EQU "Microsoft Office Professional Plus 2016" ((set "ProPlusVLFound=YES")&&(set "_ProPlusRetail=YES"))
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Wow6432Node\Microsoft\Office\16.0\Common\InstalledPackages\90160000-0012-0000-0000-0000000FF1CE" /ve 2^>nul') DO (Set "StandardVLFound=%%B") %MultiNul%
  if "%StandardVLFound:~-30%" EQU "Microsoft Office Standard 2016" ((set "StandardVLFound=YES")&&(set "_StandardRetail=YES"))
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Wow6432Node\Microsoft\Office\16.0\Common\InstalledPackages\90160000-003B-0000-0000-0000000FF1CE" /ve 2^>nul') DO (Set "ProjectProVLFound=%%B") %MultiNul%
  if "%ProjectProVLFound:~-35%" EQU "Microsoft Project Professional 2016" ((set "ProjectProVLFound=YES")&&(set "_ProjectProRetail=YES"))
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Wow6432Node\Microsoft\Office\16.0\Common\InstalledPackages\90160000-0051-0000-0000-0000000FF1CE" /ve 2^>nul') DO (Set "VisioProVLFound=%%B") %MultiNul%
  if "%VisioProVLFound:~-33%" EQU "Microsoft Visio Professional 2016" ((set "VisioProVLFound=YES")&&(set "_VisioProRetail=YES"))
  if "%_ProPlusRetail%" EQU "YES" goto:OfficeVL32onW64Path
  if "%_StandardRetail%" EQU "YES" goto:OfficeVL32onW64Path
  if "%_ProjectProRetail%" EQU "YES" goto:OfficeVL32onW64Path
  if "%_VisioProRetail%" EQU "YES" goto:OfficeVL32onW64Path
  goto:Office16VnextInstall
::===============================================================================================================
:OfficeVL32onW64Path
  set "o16arch=x86"
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Wow6432Node\Microsoft\Office\16.0\Common\InstallRoot" /v "Path" 2^>nul') DO (Set "installpath16=%%B") %MultiNul%
  set "officepath3=%installpath16%"
  set "checkversionpath=%CommonProgramFiles(x86)%"
  set "checkversionpath=%checkversionpath:\=\\%"
  set "MSO=%checkversionpath%\\Microsoft Shared\\OFFICE16\\MSO.dll"
  
  if defined WMI_PS (
    set FileVersion="@(Get-ItemProperty -lit '!MSO:\\=\!').VersionInfo.FileVersion" 
    for /f "usebackq tokens=*" %%A in (`"2>nul powershell -nop -c !FileVersion!"`) do set "o16version=%%A"
  )
  if defined WMI_VB (
    >%Res______% %CscriptEXE% "%VB_Help%" "/DATA_FILE" "!MSO!"
    for /f "tokens=1 delims=," %%g in ('type "%Res______%"') do set o16version=%%g
  )
  if defined WMI_CO (
    for /F "tokens=2,* delims==" %%A IN ('"wmic datafile where name='!MSO!' get version /format:list" 2^>nul') do set o16version=%%A
  )
  goto:eof
::===============================================================================================================
:CheckOfficeVL32W32orVL64W64
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Microsoft\Office\16.0\Common\InstalledPackages\90160000-0011-0000-0000-0000000FF1CE" /ve 2^>nul') DO (Set "ProPlusVLFound=%%B") %MultiNul%
  if "%ProPlusVLFound:~-39%" EQU "Microsoft Office Professional Plus 2016" ((set "ProPlusVLFound=YES")&&(set "_ProPlusRetail=YES"))
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Microsoft\Office\16.0\Common\InstalledPackages\90160000-0012-0000-0000-0000000FF1CE" /ve 2^>nul') DO (Set "StandardVLFound=%%B") %MultiNul%
  if "%StandardVLFound:~-30%" EQU "Microsoft Office Standard 2016" ((set "StandardVLFound=YES")&&(set "_StandardRetail=YES"))
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Wow6432Node\Microsoft\Office\16.0\Common\InstalledPackages\90160000-003B-0000-0000-0000000FF1CE" /ve 2^>nul') DO (Set "ProjectProVLFound=%%B") %MultiNul%
  if "%ProjectProVLFound:~-35%" EQU "Microsoft Project Professional 2016" ((set "ProjectProVLFound=YES")&&(set "_ProjectProRetail=YES"))
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Wow6432Node\Microsoft\Office\16.0\Common\InstalledPackages\90160000-0051-0000-0000-0000000FF1CE" /ve 2^>nul') DO (Set "VisioProVLFound=%%B") %MultiNul%
  if "%VisioProVLFound:~-33%" EQU "Microsoft Visio Professional 2016" ((set "VisioProVLFound=YES")&&(set "_VisioProRetail=YES"))
  if "%_ProPlusRetail%" EQU "YES" (set "o16arch=x86")&&(goto:OfficeVL32VL64Path)
  if "%_StandardRetail%" EQU "YES" (set "o16arch=x86")&&(goto:OfficeVL32VL64Path)
  if "%_ProjectProRetail%" EQU "YES" (set "o16arch=x86")&&(goto:OfficeVL32VL64Path)
  if "%_VisioProRetail%" EQU "YES" (set "o16arch=x86")&&(goto:OfficeVL32VL64Path)
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Microsoft\Office\16.0\Common\InstalledPackages\90160000-0011-0000-1000-0000000FF1CE" /ve 2^>nul') DO (Set "ProPlusVLFound=%%B") %MultiNul%
  if "%ProPlusVLFound:~-39%" EQU "Microsoft Office Professional Plus 2016" ((set "ProPlusVLFound=YES")&&(set "_ProPlusRetail=YES"))
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Microsoft\Office\16.0\Common\InstalledPackages\90160000-0012-0000-1000-0000000FF1CE" /ve 2^>nul') DO (Set "StandardVLFound=%%B") %MultiNul%
  if "%StandardVLFound:~-30%" EQU "Microsoft Office Standard 2016" ((set "StandardVLFound=YES")&&(set "_StandardRetail=YES"))
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Wow6432Node\Microsoft\Office\16.0\Common\InstalledPackages\90160000-003B-0000-1000-0000000FF1CE" /ve 2^>nul') DO (Set "ProjectProVLFound=%%B") %MultiNul%
  if "%ProjectProVLFound:~-35%" EQU "Microsoft Project Professional 2016" ((set "ProjectProVLFound=YES")&&(set "_ProjectProRetail=YES"))
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Wow6432Node\Microsoft\Office\16.0\Common\InstalledPackages\90160000-0051-0000-1000-0000000FF1CE" /ve 2^>nul') DO (Set "VisioProVLFound=%%B") %MultiNul%
  if "%VisioProVLFound:~-33%" EQU "Microsoft Visio Professional 2016" ((set "VisioProVLFound=YES")&&(set "_VisioProRetail=YES"))
  if "%_ProPlusRetail%" EQU "YES" (set "o16arch=x64")&&(goto:OfficeVL32VL64Path)
  if "%_StandardRetail%" EQU "YES" (set "o16arch=x64")&&(goto:OfficeVL32VL64Path)
  if "%_ProjectProRetail%" EQU "YES" (set "o16arch=x64")&&(goto:OfficeVL32VL64Path)
  if "%_VisioProRetail%" EQU "YES" (set "o16arch=x64")&&(goto:OfficeVL32VL64Path)
  goto:Office16VnextInstall
::===============================================================================================================
:OfficeVL32VL64Path
  for /F "tokens=2,*" %%A IN ('reg query "HKLM\Software\Microsoft\Office\16.0\Common\InstallRoot" /v "Path" 2^>nul') DO (Set "installpath16=%%B") %MultiNul%
  set "officepath3=%installpath16%"
  set "checkversionpath=%CommonProgramFiles%"
  set "checkversionpath=%checkversionpath:\=\\%"
  set "MSO=%checkversionpath%\\Microsoft Shared\\OFFICE16\\MSO.dll"
  
  if defined WMI_PS (
    set FileVersion="@(Get-ItemProperty -lit '!MSO:\\=\!').VersionInfo.FileVersion" 
    for /f "usebackq tokens=*" %%A in (`"2>nul powershell -nop -c !FileVersion!"`) do set "o16version=%%A"
  )
  if defined WMI_VB (
    >%Res______% %CscriptEXE% "%VB_Help%" "/DATA_FILE" "!MSO!"
    for /f "tokens=1 delims=," %%g in ('type "%Res______%"') do set o16version=%%g
  )
  if defined WMI_CO (
    for /F "tokens=2,* delims==" %%A IN ('"wmic datafile where name='!MSO!' get version /format:list" 2^>nul') do set o16version=%%A
  )
  goto:eof
::===============================================================================================================
::===============================================================================================================
:Convert16Activate
::===============================================================================================================
  
  call :CheckOfficeApplications
   
::===============================================================================================================
  cls
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! CONVERT / CHANGE OFFICE TO VOLUME !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  echo Installation path:
  echo "%installpath16%"
  echo ____________________________________________________________________________
  echo:
  echo Office Suites:
  set /a countx=0
  echo:

if "%_HomeBusinessRetail%" EQU "YES" 			   ((echo Microsoft Home And Business                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_HomeBusiness2019Retail%" EQU "YES" 		   ((echo Microsoft Home And Business 2019           = "FOUND")&&(set /a countx=!countx! + 1))
if "%_HomeBusiness2021Retail%" EQU "YES" 		   ((echo Microsoft Home And Business 2021           = "FOUND")&&(set /a countx=!countx! + 1))
if "%_HomeBusiness2024Retail%" EQU "YES" 		   ((echo Microsoft Home And Business 2024           = "FOUND")&&(set /a countx=!countx! + 1))

if "%_HomeStudentRetail%" EQU "YES" 			   ((echo Microsoft Home And Student                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_HomeStudent2019Retail%" EQU "YES" 		   ((echo Microsoft Home And Student 2019            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_HomeStudent2021Retail%" EQU "YES" 		   ((echo Microsoft Home And Student 2021            = "FOUND")&&(set /a countx=!countx! + 1))	
if "%_HomeStudent2024Retail%" EQU "YES" 		   ((echo Microsoft Home And Student 2024            = "FOUND")&&(set /a countx=!countx! + 1))	

if "%_MondoRetail%" EQU "YES" 				   ((echo Office Mondo Grande Suite                  = "FOUND")&&(set /a countx=!countx! + 1))
if "%_MondoVolume%" EQU "YES" 				   ((echo Office Mondo Grande Suite                  = "FOUND")&&(set /a countx=!countx! + 1))

if "%_O365BusinessEEANoTeamsRetail%" EQU "YES"   ((echo Microsoft 365 Apps for Business            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_O365BusinessRetail%" EQU "YES" 			   ((echo Microsoft 365 Apps for Business            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_O365HomePremRetail%" EQU "YES" 			   ((echo Microsoft 365 Home Premium retail          = "FOUND")&&(set /a countx=!countx! + 1))
if "%_O365ProPlusEEANoTeamsRetail%" EQU "YES"    ((echo Microsoft 365 Apps for Enterprise          = "FOUND")&&(set /a countx=!countx! + 1))
if "%_O365ProPlusRetail%" EQU "YES" 			   ((echo Microsoft 365 Apps for Enterprise          = "FOUND")&&(set /a countx=!countx! + 1))
if "%_O365SmallBusPremRetail%" EQU "YES" 		   ((echo Microsoft 365 Small Business retail        = "FOUND")&&(set /a countx=!countx! + 1))
if "%_O365AppsBasicRetail%" EQU "YES" 		   ((echo Microsoft 365 Basic retail        = "FOUND")&&(set /a countx=!countx! + 1))

if "%_PersonalRetail%" EQU "YES" 				   ((echo Office Personal 2016 Retail                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Personal2019Retail%" EQU "YES" 			   ((echo Office Personal 2019 Retail                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Personal2021Retail%" EQU "YES" 			   ((echo Office Personal 2021 Retail                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Personal2024Retail%" EQU "YES" 			   ((echo Office Personal 2024 Retail                = "FOUND")&&(set /a countx=!countx! + 1))

if "%_ProPlusRetail%" EQU "YES" 				   ((echo Office Professional Plus 2016              = "FOUND")&&(set /a countx=!countx! + 1))
if "%_ProPlusVolume%" EQU "YES" 				   ((echo Office Professional Plus 2016              = "FOUND")&&(set /a countx=!countx! + 1))
if "%_ProPlus2019Retail%" EQU "YES" 			   ((echo Office Professional Plus 2019              = "FOUND")&&(set /a countx=!countx! + 1)) 
if "%_ProPlus2019Volume%" EQU "YES"              ((echo Office Professional Plus 2019              = "FOUND")&&(set /a countx=!countx! + 1))
if "%_ProPlus2021Retail%" EQU "YES" 			   ((echo Office Professional Plus 2021              = "FOUND")&&(set /a countx=!countx! + 1)) 
if "%_ProPlus2021Volume%" EQU "YES"              ((echo Office Professional Plus 2021              = "FOUND")&&(set /a countx=!countx! + 1))
if "%_ProPlusSPLA2021Volume%" EQU "YES" 		   ((echo Office Professional Plus 2021              = "FOUND")&&(set /a countx=!countx! + 1))
if "%_ProPlus2024Retail%" EQU "YES" 			   ((echo Office Professional Plus 2024              = "FOUND")&&(set /a countx=!countx! + 1)) 
if "%_ProPlus2024Volume%" EQU "YES"              ((echo Office Professional Plus 2024              = "FOUND")&&(set /a countx=!countx! + 1))
if "%_ProPlusSPLA2024Volume%" EQU "YES" 		   ((echo Office Professional Plus 2024              = "FOUND")&&(set /a countx=!countx! + 1))

if "%_ProfessionalRetail%" EQU "YES" 			   ((echo Professional 2016 Retail                   = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Professional2019Retail%" EQU "YES" 		   ((echo Professional 2019 Retail                   = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Professional2021Retail%" EQU "YES" 		   ((echo Professional 2021 Retail                   = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Professional2024Retail%" EQU "YES" 		   ((echo Professional 2024 Retail                   = "FOUND")&&(set /a countx=!countx! + 1))

if "%_StandardRetail%" EQU "YES" 				   ((echo Office Standard 2016                       = "FOUND")&&(set /a countx=!countx! + 1))
if "%_StandardVolume%" EQU "YES" 				   ((echo Office Standard 2016                       = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Standard2019Retail%" EQU "YES" 			   ((echo Office Standard 2019                       = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Standard2019Volume%" EQU "YES" 			   ((echo Office Standard 2019                       = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Standard2021Retail%" EQU "YES" 			   ((echo Office Standard 2021                       = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Standard2021Volume%" EQU "YES" 			   ((echo Office Standard 2021                       = "FOUND")&&(set /a countx=!countx! + 1))
if "%_StandardSPLA2021Volume%" EQU "YES" 		   ((echo Office Standard 2021                       = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Standard2024Retail%" EQU "YES" 			   ((echo Office Standard 2024                       = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Standard2024Volume%" EQU "YES" 			   ((echo Office Standard 2024                       = "FOUND")&&(set /a countx=!countx! + 1))
if "%_StandardSPLA2024Volume%" EQU "YES" 		   ((echo Office Standard 2024                       = "FOUND")&&(set /a countx=!countx! + 1))

  if !countx! EQU 0                                 (echo Office Full Suite installation             = "NOT FOUND")
  echo ____________________________________________________________________________
  echo:
  echo Additional Apps:
  set /a countx=0
  
if "%_AppxProject%" EQU "YES" ((echo:)&&			(echo Project Pro UWP Appx                       = "FOUND")&&(set /a countx=!countx! + 2))
if "%_AppxVisio%" EQU "YES" ((echo:)&&				(echo Visio Pro UWP Appx                         = "FOUND")&&(set /a countx=!countx! + 1))

if "%_ProjectProRetail%" EQU "YES" ((echo:)&&		(echo Project Pro 2016                           = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectProVolume%" EQU "YES" ((echo:)&&		(echo Project Pro 2016                           = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectProXVolume%" EQU "YES" ((echo:)&&		(echo Project Professional 2016 C2R              = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectPro2019Retail%" EQU "YES" ((echo:)&&	(echo Project Pro 2019                           = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectPro2019Volume%" EQU "YES" ((echo:)&&	(echo Project Pro 2019                           = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectPro2021Retail%" EQU "YES" ((echo:)&&	(echo Project Pro 2021                           = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectPro2021Volume%" EQU "YES" ((echo:)&&	(echo Project Pro 2021                           = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectPro2024Retail%" EQU "YES" ((echo:)&&	(echo Project Pro 2024                           = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectPro2024Volume%" EQU "YES" ((echo:)&&	(echo Project Pro 2024                           = "FOUND")&&(set /a countx=!countx! + 2))

if "%_ProjectStdRetail%" EQU "YES" ((echo:)&&		(echo Project Standard 2016                      = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectStdVolume%" EQU "YES" ((echo:)&&		(echo Project Standard 2016                      = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectStdXVolume%" EQU "YES" ((echo:)&&		(echo Project Standard 2016 C2R                  = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectStd2019Retail%" EQU "YES" ((echo:)&&	(echo Project Standard 2019                      = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectStd2019Volume%" EQU "YES" ((echo:)&&	(echo Project Standard 2019                      = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectStd2021Retail%" EQU "YES" ((echo:)&&	(echo Project Standard 2021                      = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectStd2021Volume%" EQU "YES" ((echo:)&&	(echo Project Standard 2021                      = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectStd2024Retail%" EQU "YES" ((echo:)&&	(echo Project Standard 2024                      = "FOUND")&&(set /a countx=!countx! + 2))
if "%_ProjectStd2024Volume%" EQU "YES" ((echo:)&&	(echo Project Standard 2024                      = "FOUND")&&(set /a countx=!countx! + 2))

if "%_VisioProRetail%" EQU "YES" ((echo:)&&			(echo Visio Pro 2016                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_VisioProVolume%" EQU "YES" ((echo:)&&			(echo Visio Pro 2016                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_VisioProXVolume%" EQU "YES" ((echo:)&&		(echo Visio Professional 2016 C2R                = "FOUND")&&(set /a countx=!countx! + 2))
if "%_VisioPro2019Retail%" EQU "YES" ((echo:)&&		(echo Visio Pro 2019                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_VisioPro2019Volume%" EQU "YES" ((echo:)&&		(echo Visio Pro 2019                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_VisioPro2021Retail%" EQU "YES" ((echo:)&&		(echo Visio Pro 2021                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_VisioPro2021Volume%" EQU "YES" ((echo:)&&		(echo Visio Pro 2021                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_VisioPro2024Retail%" EQU "YES" ((echo:)&&		(echo Visio Pro 2024                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_VisioPro2024Volume%" EQU "YES" ((echo:)&&		(echo Visio Pro 2024                             = "FOUND")&&(set /a countx=!countx! + 1))

if "%_VisioStdRetail%" EQU "YES" ((echo:)&&			(echo Visio Standard 2016                        = "FOUND")&&(set /a countx=!countx! + 2))
if "%_VisioStdVolume%" EQU "YES" ((echo:)&&			(echo Visio Standard 2016                        = "FOUND")&&(set /a countx=!countx! + 2))
if "%_VisioStdXVolume%" EQU "YES" ((echo:)&&		(echo Visio Standard 2016 C2R                    = "FOUND")&&(set /a countx=!countx! + 2))
if "%_VisioStd2019Retail%" EQU "YES" ((echo:)&&		(echo Visio Standard 2019                        = "FOUND")&&(set /a countx=!countx! + 2))
if "%_VisioStd2019Volume%" EQU "YES" ((echo:)&&		(echo Visio Standard 2019                        = "FOUND")&&(set /a countx=!countx! + 2))
if "%_VisioStd2021Retail%" EQU "YES" ((echo:)&&		(echo Visio Standard 2021                        = "FOUND")&&(set /a countx=!countx! + 2))
if "%_VisioStd2021Volume%" EQU "YES" ((echo:)&&		(echo Visio Standard 2021                        = "FOUND")&&(set /a countx=!countx! + 2))
if "%_VisioStd2024Retail%" EQU "YES" ((echo:)&&		(echo Visio Standard 2024                        = "FOUND")&&(set /a countx=!countx! + 2))
if "%_VisioStd2024Volume%" EQU "YES" ((echo:)&&		(echo Visio Standard 2024                        = "FOUND")&&(set /a countx=!countx! + 2))

  if !countx! EQU 0 ((echo:)&&						(echo Visio and Project Installation             = "NOT FOUND"))
  echo ____________________________________________________________________________
  echo:
  echo Single Apps:
  set /a countx=0

if "%_AppxAccess%" EQU "YES" ((echo:)&&				(echo Access UWP Appx                            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_AppxExcel%" EQU "YES" ((echo:)&&				(echo Excel UWP Appx                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_AppxOneNote%" EQU "YES" ((echo:)&&			(echo OneNote UWP Appx                           = "FOUND")&&(set /a countx=!countx! + 1))
if "%_AppxOutlook%" EQU "YES" ((echo:)&&			(echo Outlook UWP Appx                           = "FOUND")&&(set /a countx=!countx! + 1))
if "%_AppxPowerPoint%" EQU "YES" ((echo:)&&			(echo PowerPoint UWP Appx                        = "FOUND")&&(set /a countx=!countx! + 1))
if "%_AppxPublisher%" EQU "YES" ((echo:)&&			(echo Publisher UWP Appx                         = "FOUND")&&(set /a countx=!countx! + 1))
if "%_AppxSkypeForBusiness%" EQU "YES" ((echo:)&&	(echo Skype UWP Appx                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_AppxWinword%" EQU "YES" ((echo:)&&			(echo Word UWP Appx                              = "FOUND")&&(set /a countx=!countx! + 1))
  
if "%_AccessRetail%" EQU "YES" ((echo:)&&			(echo Access 2016                                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_AccessVolume%" EQU "YES" ((echo:)&&			(echo Access 2016                                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Access2019Retail%" EQU "YES" ((echo:)&&		(echo Access 2019                                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Access2019Volume%" EQU "YES" ((echo:)&&		(echo Access 2019                                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Access2021Retail%" EQU "YES" ((echo:)&&		(echo Access 2021                                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Access2021Volume%" EQU "YES" ((echo:)&&		(echo Access 2021                                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Access2024Retail%" EQU "YES" ((echo:)&&		(echo Access 2024                                = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Access2024Volume%" EQU "YES" ((echo:)&&		(echo Access 2024                                = "FOUND")&&(set /a countx=!countx! + 1))

if "%_ExcelRetail%" EQU "YES" ((echo:)&&			(echo Excel 2016                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_ExcelVolume%" EQU "YES" ((echo:)&&			(echo Excel 2016                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Excel2019Retail%" EQU "YES" ((echo:)&&		(echo Excel 2019                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Excel2019Volume%" EQU "YES" ((echo:)&&		(echo Excel 2019                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Excel2021Retail%" EQU "YES" ((echo:)&&		(echo Excel 2021                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Excel2021Volume%" EQU "YES" ((echo:)&&		(echo Excel 2021                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Excel2024Retail%" EQU "YES" ((echo:)&&		(echo Excel 2024                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Excel2024Volume%" EQU "YES" ((echo:)&&		(echo Excel 2024                                 = "FOUND")&&(set /a countx=!countx! + 1))

if "%_OneNoteRetail%" EQU "YES" ((echo:)&&			(echo OneNote 2016                               = "FOUND")&&(set /a countx=!countx! + 1))
if "%_OneNoteVolume%" EQU "YES" ((echo:)&&			(echo OneNote 2016                               = "FOUND")&&(set /a countx=!countx! + 1))
if "%_OneNote2021Retail%" EQU "YES" ((echo:)&&		(echo OneNote 2021                               = "FOUND")&&(set /a countx=!countx! + 1))
if "%_OneNote2024Retail%" EQU "YES" ((echo:)&&		(echo OneNote 2024                               = "FOUND")&&(set /a countx=!countx! + 1))

if "%_OutlookRetail%" EQU "YES" ((echo:)&&			(echo Outlook 2016                               = "FOUND")&&(set /a countx=!countx! + 1))
if "%_OutlookVolume%" EQU "YES" ((echo:)&&			(echo Outlook 2016                               = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Outlook2019Retail%" EQU "YES" ((echo:)&&		(echo Outlook 2019                               = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Outlook2019Volume%" EQU "YES" ((echo:)&&		(echo Outlook 2019                               = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Outlook2021Retail%" EQU "YES" ((echo:)&&		(echo Outlook 2021                               = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Outlook2021Volume%" EQU "YES" ((echo:)&&		(echo Outlook 2021                               = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Outlook2024Retail%" EQU "YES" ((echo:)&&		(echo Outlook 2024                               = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Outlook2024Volume%" EQU "YES" ((echo:)&&		(echo Outlook 2024                               = "FOUND")&&(set /a countx=!countx! + 1))

if "%_PowerPointRetail%" EQU "YES" ((echo:)&&		(echo PowerPoint 2016                            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_PowerPointVolume%" EQU "YES" ((echo:)&&		(echo PowerPoint 2016                            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_PowerPoint2019Retail%" EQU "YES" ((echo:)&&	(echo PowerPoint 2019                            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_PowerPoint2019Volume%" EQU "YES" ((echo:)&&	(echo PowerPoint 2019                            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_PowerPoint2021Retail%" EQU "YES" ((echo:)&&	(echo PowerPoint 2021                            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_PowerPoint2021Volume%" EQU "YES" ((echo:)&&	(echo PowerPoint 2021                            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_PowerPoint2024Retail%" EQU "YES" ((echo:)&&	(echo PowerPoint 2024                            = "FOUND")&&(set /a countx=!countx! + 1))
if "%_PowerPoint2024Volume%" EQU "YES" ((echo:)&&	(echo PowerPoint 2024                            = "FOUND")&&(set /a countx=!countx! + 1))

if "%_PublisherRetail%" EQU "YES" ((echo:)&&		(echo Publisher 2016                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_PublisherVolume%" EQU "YES" ((echo:)&&		(echo Publisher 2016                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Publisher2019Retail%" EQU "YES" ((echo:)&&	(echo Publisher 2019                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Publisher2019Volume%" EQU "YES" ((echo:)&&	(echo Publisher 2019                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Publisher2021Retail%" EQU "YES" ((echo:)&&	(echo Publisher 2021                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Publisher2021Volume%" EQU "YES" ((echo:)&&	(echo Publisher 2021                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Publisher2024Retail%" EQU "YES" ((echo:)&&	(echo Publisher 2024                             = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Publisher2024Volume%" EQU "YES" ((echo:)&&	(echo Publisher 2024                             = "FOUND")&&(set /a countx=!countx! + 1))

if "%_SkypeForBusinessRetail%" EQU "YES"     ((echo:)&&	(echo Skype 2016                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_SkypeForBusinessVolume%" EQU "YES"     ((echo:)&&	(echo Skype 2016                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_SkypeForBusiness2019Retail%" EQU "YES" ((echo:)&& (echo Skype 2019                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_SkypeForBusiness2019Volume%" EQU "YES" ((echo:)&&	(echo Skype 2019                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_SkypeForBusiness2021Retail%" EQU "YES" ((echo:)&&	(echo Skype 2021                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_SkypeForBusiness2021Volume%" EQU "YES" ((echo:)&&	(echo Skype 2021                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_SkypeForBusiness2024Retail%" EQU "YES" ((echo:)&&	(echo Skype 2024                                 = "FOUND")&&(set /a countx=!countx! + 1))
if "%_SkypeForBusiness2024Volume%" EQU "YES" ((echo:)&&	(echo Skype 2024                                 = "FOUND")&&(set /a countx=!countx! + 1))

if "%_WordRetail%" EQU "YES" ((echo:)&&				(echo Word 2016                                  = "FOUND")&&(set /a countx=!countx! + 1))
if "%_WordVolume%" EQU "YES" ((echo:)&&				(echo Word 2016                                  = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Word2019Retail%" EQU "YES" ((echo:)&&			(echo Word 2019                                  = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Word2019Volume%" EQU "YES" ((echo:)&&			(echo Word 2019                                  = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Word2021Retail%" EQU "YES" ((echo:)&&			(echo Word 2021                                  = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Word2021Volume%" EQU "YES" ((echo:)&&			(echo Word 2021                                  = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Word2024Retail%" EQU "YES" ((echo:)&&			(echo Word 2024                                  = "FOUND")&&(set /a countx=!countx! + 1))
if "%_Word2024Volume%" EQU "YES" ((echo:)&&			(echo Word 2024                                  = "FOUND")&&(set /a countx=!countx! + 1))

  if !countx! EQU 0 ((echo:)&&						(echo Single Apps installation                   = "NOT FOUND"))
  echo ____________________________________________________________________________
  echo:
  echo:
  if not defined debugMode if not defined AutoTask pause
::===============================================================================================================
  cls
  echo:
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! CONVERT / CHANGE OFFICE TO VOLUME !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  echo #### CLEANUP (Removing Office Retail-Trial-Grace Keys and Licenses)
  echo:
  "%OfficeRToolpath%\Data\Bin\cleanospp.exe"
::===============================================================================================================
::	WIN10 Insider/Preview activation failure workaround
  if not exist "%windir%\System32\spp\store_test\2.0\tokens.dat" (
    goto :Bypass_10_Check )
  
  call :Print "**** An Insider edition was detected." "%BB_Red%"
  call :Print "**** A workaround for KMS activation is needed" "%BB_Red%"
  echo:||echo.
  echo - Stopping license service "sppsvc"...
  call :StopService "sppsvc"
  echo - Deleting license file "tokens.dat"...
  del /q "%windir%\System32\spp\store_test\2.0\tokens.dat" %MultiNul%
  echo - Starting license service "sppsvc"...
  call :StartService "sppsvc"
  echo - Recreating license file "tokens.dat". Please wait...
  
  if not defined External_IP (
    if /i "!Act_Engine!" EQU "VL" (
      call :Load_DLL ))
	
  call :CleanRegistryKeys
  if     defined External_IP (
    call :UpdateRegistryKeys %External_IP% %External_PORT%
  )
  if not defined External_IP (
    call :UpdateRegistryKeys %KMSHostIP% %KMSPort%
  )
  
  if defined WMI_VB (
    %MultiNul% %CscriptEXE% //Nologo //B %SlmgrEXE% /rilc
    %MultiNul% %CscriptEXE% //Nologo //B %SlmgrEXE% /ato )
	
  if defined WMI_PS (
	%MultiNul% "%PowerShellEXE%" -nop -ep bypass -file "%PS_Help%" "/rilc"
	%MultiNul% "%PowerShellEXE%" -nop -ep bypass -file "%PS_Help%" "/ato" )
	
  if defined WMI_CO (
    if defined WMI_VB_FAILURE (
      %MultiNul% "%PowerShellEXE%" -nop -ep bypass -file "%PS_Help%" "/rilc"
	  %MultiNul% "%PowerShellEXE%" -nop -ep bypass -file "%PS_Help%" "/ato"
	) else (
      %MultiNul% %CscriptEXE% //Nologo //B %SlmgrEXE% /rilc
      %MultiNul% %CscriptEXE% //Nologo //B %SlmgrEXE% /ato
  ))
  
  if not defined External_IP (
      if /i "!Act_Engine!" EQU "VL"  (
	    call :UnLoad_DLL ))

  echo - License file successfully recreated
  echo:
	
:Bypass_10_Check
  %singlenul% timeout /t 2
::===============================================================================================================
  call :Office16ConversionLoop
::===============================================================================================================	
  
  ::	Change name of installed Office 2019 Retail products from Retail to Volume
  del /q "%windir%\Temp\ONAME_CHANGE*.REG" %MultiNul%
  %REGEXE% export %hC2r%\Configuration "%windir%\Temp\ONAME_CHANGE.REG" /Y %MultiNul%
  if exist "%windir%\Temp\ONAME_CHANGE.REG" (
  	%MultiNul% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\Convert_RT_VL.ps1"
  	%MultiNul% %REGEXE% delete %hC2r%\Configuration /f
  	%MultiNul% %REGEXE% import "%windir%\Temp\ONAME_CHANGE.REG"
  	%MultiNul% del /q "%windir%\Temp\ONAME_CHANGE*.REG"
  )
  
::===============================================================================================================
  echo:
  
  set ohook_found=
  for %%# in (15 16) do (
    for %%A in ("%ProgramFiles%" "%ProgramW6432%" "%ProgramFiles(x86)%") do (
      %MultiNul% dir "%%~A\Microsoft Office\Office%%#\sppc*dll" /AL /b && set ohook_found=* ))

  for %%# in (System SystemX86) do (
    for %%G in ("Office 15" "Office") do (
      for %%A in ("%ProgramFiles%" "%ProgramW6432%" "%ProgramFiles(x86)%") do (
	    %MultiNul% dir "%%~A\Microsoft %%~G\root\vfs\%%#\sppc*dll" /AL /b && set ohook_found=*)))
	
  if defined ohook_found (
    echo MAS - Ohook found ...
	echo No activation is needed
	echo.
	timeout /t 4
    goto:Office16VnextInstall
  )
  
  call :PrintTitle "!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK! ACTIVATION !PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!!PAD_CHNK!"
  echo:
  CHOICE /C AE /M "Would You Like to [A]ctivate OR [E]nd ?"
  if !errorlevel! EQU 1 goto:KMSActivation_ACT_WARPER_X
  
  echo:
  timeout /t 4
  goto:Office16VnextInstall
::===============================================================================================================
::===============================================================================================================
:Office16Activate
  set /a "GraceMin=0"
  if %WinBuild% GEQ 9200 (
  	set "ID=%1"
  	set "subKey=0ff1ce15-a989-479d-af46-f275c6370663"
  )
  if %WinBuild% LSS 9200 (
  	set "ID=%1"
  	set "subKey=0ff1ce15-a989-479d-af46-f275c6370663"
  )
  
  if /i "!Act_Engine!" EQU "ZeroCID" (
    %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\ZeroCID.ps1"
	echo:
    goto:eof
  )
  
  if /i "!Act_Engine!" EQU "KMS4K" (
    %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\KMS4K.ps1"
	echo:
    goto:eof
  )
  
  rem call :UpdateRegistryKeys %KMSHostIP% %KMSPort%
  set "lastErr="
  if defined WMI_CO (
    %MultiNul% wmic path !A_CLASS! where ID='!ID!' call activate
	set "lastErr=!errorlevel!"
    if /i !lastErr! neq 0 (
	  cmd /c exit /b !lastErr!
	  set "lastErr=!=exitcode!" )
  )
  if defined WMI_VB (
    set "activationCMD=%CscriptEXE% //nologo "%VB_Help%" "/ACTIVATE" "!A_CLASS!" "%1""
  )
  if defined WMI_PS (
    set "activationCMD="%PowerShellEXE%" -nop -ep bypass -file "%PS_Help%" "/ACTIVATE" "!A_CLASS!" "%1""
  )
  
  :: case of WMI_PS WMI_VB
  if not defined lastErr (
    for /f "tokens=1,2 delims=: " %%x in ('"!activationCMD!"') do set "lastErr=%%y"
  )
  if /i '!lastErr!' EQU '0' (echo Activation !ID! Successful) else (echo Activation !ID! Failed [0x!lastErr!])
  REM call :CleanRegistryKeys
  echo:
  goto:eof
::===============================================================================================================
::===============================================================================================================
:SetO16Language

  %MultiNul% del /q "%windir%\Temp\tmp"
  set langnotfound=***
  >"%windir%\Temp\tmp" call :Language_List
  
  rem %%g=English %%h=1033 %%i=en-us %%j:0409	
  for /f "tokens=1,2,3,4 delims=*" %%g in ('type "%windir%\Temp\tmp"') do (
  	
  	if /i '!o16lang!' EQU '%%i' (
  		set langtext=%%g
  		set o16lcid=%%h
  		set langnotfound=
  	)
  	
  	if /i '!o16lang!' EQU '%%g' (
  		set langtext=%%g
  		set o16lcid=%%h
  		set o16lang=%%i
  		set langnotfound=
  	)
  )
  
  %MultiNul% del /q "%windir%\Temp\tmp"
    goto:eof
  
:SetP16Language
  %MultiNul% del /q "%windir%\Temp\tmp"
  set p_langnotfound=***
  >"%windir%\Temp\tmp" call :Language_List
  
  rem %%g=English %%h=1033 %%i=en-us %%j:0409	
  for /f "tokens=1,2,3,4 delims=*" %%g in ('type "%windir%\Temp\tmp"') do (
  	
  	if /i '!p16lang!' EQU '%%i' (
  		set p16lcid=%%h
  		set p_langtext=%%g
  		set p_langnotfound=
  	)
  	
  	if /i '!p16lang!' EQU '%%g' (
  		set p16lcid=%%h
  		set p16lang=%%i
  		set p_langtext=%%g
  		set p_langnotfound=
  	)
  )
  
  %MultiNul% del /q "%windir%\Temp\tmp"
    goto:eof
  
:SetL16Language
  %MultiNul% del /q "%windir%\Temp\tmp"
  set L_langnotfound=***
  >"%windir%\Temp\tmp" call :Language_List
  
  rem %%g=English %%h=1033 %%i=en-us %%j:0409	
  for /f "tokens=1,2,3,4 delims=*" %%g in ('type "%windir%\Temp\tmp"') do (
  	
  	if /i '!L16lang!' EQU '%%i' (
  		set L16lcid=%%h
  		set L_langtext=%%g
  		set L_langnotfound=
  	)
  	
  	if /i '!L16lang!' EQU '%%g' (
  		set L16lcid=%%h
  		set L16lang=%%i
  		set L_langtext=%%g
  		set L_langnotfound=
  	)
  )
  
  %MultiNul% del /q "%windir%\Temp\tmp"
    goto:eof
::===============================================================================================================
::===============================================================================================================
:ConvertOffice16
  echo #### %1 found
  echo:
  set "ADD_="
  
  echo %1 |%SingleNul% find /i "ProPlus2021" && set "ADD_=1"
  echo %1 |%SingleNul% find /i "ProPlus2024" && set "ADD_=1"  
  echo %1 |%SingleNul% find /i "Standard2024" && set "ADD_=1"
  echo %1 |%SingleNul% find /i "ProjectPro2021" && set "ADD_=1"
  echo %1 |%SingleNul% find /i "ProjectPro2024" && set "ADD_=1"
  
  rem un-nececery s*** ......................
  rem but keep it anyway ....................
  
  REM echo %1 | %SingleNul% find /i "mondo" && (
  	REM set "root="
  	REM if exist "%ProgramFiles%\Microsoft Office\root"			set "root=%ProgramFiles%\Microsoft Office\root"
  	REM if exist "%ProgramFiles(x86)%\Microsoft Office\root"	set "root=%ProgramFiles(x86)%\Microsoft Office\root"
  	REM if defined root (
  		REM if exist "!root!\Integration\integrator.exe" (
  			REM echo Integrate Mondo License
  			REM %MultiNul% "!root!\Integration\integrator" /I /License PRIDName=MondoVolume.16 PidKey=HFTND-W9MK4-8B7MJ-B6C4G-XQBR2
  			REM echo:
  		REM )
  	REM )
  REM )
  
  if "%3" EQU "_AE2" goto :ConvertOffice2021_AE2
::================================================================================================================
  echo %1 |%SingleNul% find /i "C2R" && (
    call :Install_LICENSE "%1VL_KMS_ClientC2R-ul.xrm-ms"
  	call :Install_LICENSE "%1VL_KMS_ClientC2R-ul-oob.xrm-ms"
  	call :Install_LICENSE "%1VL_KMS_ClientC2R-ppd.xrm-ms"
  ) || (
    call :Install_LICENSE "%1VL_KMS_Client%2-ul.xrm-ms"
    call :Install_LICENSE "%1VL_KMS_Client%2-ul-oob.xrm-ms"
    call :Install_LICENSE "%1VL_KMS_Client%2-ppd.xrm-ms"
	
	if /i "%~2" EQU "" (
	  call :Install_LICENSE "%1VL_MAK-pl.xrm-ms"
      call :Install_LICENSE "%1VL_MAK-ppd.xrm-ms"
      call :Install_LICENSE "%1VL_MAK-ul-oob.xrm-ms"
      call :Install_LICENSE "%1VL_MAK-ul-phn.xrm-ms"
	) else (
      call :Install_LICENSE "%1VL_MAK_AE!ADD_!-pl.xrm-ms"
      call :Install_LICENSE "%1VL_MAK_AE!ADD_!-ppd.xrm-ms"
      call :Install_LICENSE "%1VL_MAK_AE!ADD_!-ul-oob.xrm-ms"
      call :Install_LICENSE "%1VL_MAK_AE!ADD_!-ul-phn.xrm-ms"
	)
  )
  echo:
  %singlenul% timeout /t 2
  goto:eof
::===============================================================================================================
:ConvertOffice2021_AE2
  call :Install_LICENSE "%1VL_KMS_Client%2-ul.xrm-ms"
  call :Install_LICENSE "%1VL_KMS_Client%2-ul-oob.xrm-ms"
  call :Install_LICENSE "%1VL_KMS_Client%2-ppd.xrm-ms"

  call :Install_LICENSE "%1VL_MAK_AE!ADD_!-pl.xrm-ms"
  call :Install_LICENSE "%1VL_MAK_AE!ADD_!-ppd.xrm-ms"
  call :Install_LICENSE "%1VL_MAK_AE!ADD_!-ul-oob.xrm-ms"
  call :Install_LICENSE "%1VL_MAK_AE!ADD_!-ul-phn.xrm-ms"
  
  echo:
  %singlenul% timeout /t 2
  goto:eof
::===============================================================================================================
::===============================================================================================================
:ConvertGeneral16
  echo #### Office General Client found
  echo:
  call :Install_LICENSE "pkeyconfig-office.xrm-ms"
  call :Install_LICENSE "pkeyconfig-office-client15.xrm-ms"
  call :Install_LICENSE "client-issuance-root.xrm-ms"
  call :Install_LICENSE "client-issuance-stil.xrm-ms"
  call :Install_LICENSE "client-issuance-ul.xrm-ms"
  call :Install_LICENSE "client-issuance-ul-oob.xrm-ms"
  call :Install_LICENSE "client-issuance-root-bridge-test.xrm-ms"
  call :Install_LICENSE "client-issuance-bridge-office.xrm-ms"
  
  echo:
  %singlenul% timeout /t 2
  goto:eof
::===============================================================================================================
::===============================================================================================================
:Office16ConversionLoop
  
  call :ConvertGeneral16
  
  if "%_MondoRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_MondoVolume%" EQU "YES" call :ConvertOffice16 Mondo
  
  if "%_AppxVisio%" EQU "YES" call :ConvertOffice16 VisioPro
  if "%_AppxProject%" EQU "YES" call :ConvertOffice16 ProjectPro
  if "%_UWPappINSTALLED%" EQU "YES" call :ConvertOffice16 Mondo

  if "%_PersonalRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_Personal2019Retail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_Personal2021Retail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_Personal2024Retail%" EQU "YES" call :ConvertOffice16 Mondo
  
  if "%_O365BusinessEEANoTeamsRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_O365BusinessRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_O365HomePremRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_O365ProPlusEEANoTeamsRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_O365ProPlusRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_O365SmallBusPremRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_O365AppsBasicRetail%" EQU "YES" call :ConvertOffice16 Mondo
  
  
  if "%_AccessRetail%" EQU "YES" call :ConvertOffice16 Access
  if "%_AccessVolume%" EQU "YES" call :ConvertOffice16 Access
  if "%_Access2019Retail%" EQU "YES" call :ConvertOffice16 Access2019 _AE
  if "%_Access2019Volume%" EQU "YES" call :ConvertOffice16 Access2019 _AE
  if "%_Access2021Retail%" EQU "YES" call :ConvertOffice16 Access2021 _AE _AE2
  if "%_Access2021Volume%" EQU "YES" call :ConvertOffice16 Access2021 _AE _AE2
  if "%_Access2024Retail%" EQU "YES" call :ConvertOffice16 Access2024 _AE _AE2
  if "%_Access2024Volume%" EQU "YES" call :ConvertOffice16 Access2024 _AE _AE2
  
  if "%_ExcelRetail%" EQU "YES" call :ConvertOffice16 Excel
  if "%_ExcelVolume%" EQU "YES" call :ConvertOffice16 Excel
  if "%_Excel2019Retail%" EQU "YES" call :ConvertOffice16 Excel2019 _AE
  if "%_Excel2019Volume%" EQU "YES" call :ConvertOffice16 Excel2019 _AE
  if "%_Excel2021Retail%" EQU "YES" call :ConvertOffice16 Excel2021 _AE _AE2
  if "%_Excel2021Volume%" EQU "YES" call :ConvertOffice16 Excel2021 _AE _AE2
  if "%_Excel2024Retail%" EQU "YES" call :ConvertOffice16 Excel2024 _AE _AE2
  if "%_Excel2024Volume%" EQU "YES" call :ConvertOffice16 Excel2024 _AE _AE2
  
  if "%_HomeBusinessRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_HomeBusiness2019Retail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_HomeBusiness2021Retail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_HomeBusiness2024Retail%" EQU "YES" call :ConvertOffice16 Mondo
  
  if "%_HomeStudentRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_HomeStudent2019Retail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_HomeStudent2021Retail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_HomeStudent2024Retail%" EQU "YES" call :ConvertOffice16 Mondo
  
  if "%_ProfessionalRetail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_Professional2019Retail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_Professional2021Retail%" EQU "YES" call :ConvertOffice16 Mondo
  if "%_Professional2024Retail%" EQU "YES" call :ConvertOffice16 Mondo
  
  if "%_StandardRetail%" EQU "YES" call :ConvertOffice16 Standard
  if "%_StandardVolume%" EQU "YES" call :ConvertOffice16 Standard
  if "%_Standard2019Retail%" EQU "YES" call :ConvertOffice16 Standard2019 _AE
  if "%_Standard2019Volume%" EQU "YES" call :ConvertOffice16 Standard2019 _AE
  if "%_Standard2021Retail%" EQU "YES" call :ConvertOffice16 Standard2021 _AE _AE2
  if "%_Standard2021Volume%" EQU "YES" call :ConvertOffice16 Standard2021 _AE _AE2
  if "%_StandardSPLA2021Volume%" EQU "YES" call :ConvertOffice16 Standard2021 _AE _AE2
  if "%_Standard2024Retail%" EQU "YES" call :ConvertOffice16 Standard2024 _AE _AE2
  if "%_Standard2024Volume%" EQU "YES" call :ConvertOffice16 Standard2024 _AE _AE2
  if "%_StandardSPLA2024Volume%" EQU "YES" call :ConvertOffice16 Standard2024 _AE _AE2
  
  if "%_ProPlusRetail%" EQU "YES" call :ConvertOffice16 ProPlus
  if "%_ProPlusVolume%" EQU "YES" call :ConvertOffice16 ProPlus
  if "%_ProPlus2019Retail%" EQU "YES" call :ConvertOffice16 ProPlus2019 _AE
  if "%_ProPlus2019Volume%" EQU "YES" call :ConvertOffice16 ProPlus2019 _AE
  if "%_ProPlus2021Retail%" EQU "YES" call :ConvertOffice16 ProPlus2021 _AE _AE2
  if "%_ProPlus2021Volume%" EQU "YES" call :ConvertOffice16 ProPlus2021 _AE _AE2
  if "%_ProPlusSPLA2021Volume%" EQU "YES" call :ConvertOffice16 ProPlus2021 _AE _AE2
  if "%_ProPlus2024Retail%" EQU "YES" call :ConvertOffice16 ProPlus2024 _AE _AE2
  if "%_ProPlus2024Volume%" EQU "YES" call :ConvertOffice16 ProPlus2024 _AE _AE2
  if "%_ProPlusSPLA2024Volume%" EQU "YES" call :ConvertOffice16 ProPlus2024 _AE _AE2
  
  if "%_OneNoteRetail%" EQU "YES" call :ConvertOffice16 OneNote
  if "%_OneNoteVolume%" EQU "YES" call :ConvertOffice16 OneNote
  if "%_OneNote2021Retail%" EQU "YES" call :ConvertOffice16 OneNote
  if "%_OneNote2024Retail%" EQU "YES" call :ConvertOffice16 OneNote

  if "%_OutlookRetail%" EQU "YES" call :ConvertOffice16 Outlook
  if "%_OutlookVolume%" EQU "YES" call :ConvertOffice16 Outlook  
  if "%_Outlook2019Retail%" EQU "YES" call :ConvertOffice16 Outlook2019 _AE
  if "%_Outlook2019Volume%" EQU "YES" call :ConvertOffice16 Outlook2019 _AE
  if "%_Outlook2021Retail%" EQU "YES" call :ConvertOffice16 Outlook2021 _AE _AE2
  if "%_Outlook2021Volume%" EQU "YES" call :ConvertOffice16 Outlook2021 _AE _AE2
  if "%_Outlook2024Retail%" EQU "YES" call :ConvertOffice16 Outlook2024 _AE _AE2
  if "%_Outlook2024Volume%" EQU "YES" call :ConvertOffice16 Outlook2024 _AE _AE2
  
  if "%_PowerPointRetail%" EQU "YES" call :ConvertOffice16 PowerPoint
  if "%_PowerPointVolume%" EQU "YES" call :ConvertOffice16 PowerPoint
  if "%_PowerPoint2019Retail%" EQU "YES" call :ConvertOffice16 PowerPoint2019 _AE
  if "%_PowerPoint2019Volume%" EQU "YES" call :ConvertOffice16 PowerPoint2019 _AE
  if "%_PowerPoint2021Retail%" EQU "YES" call :ConvertOffice16 PowerPoint2021 _AE _AE2
  if "%_PowerPoint2021Volume%" EQU "YES" call :ConvertOffice16 PowerPoint2021 _AE _AE2
  if "%_PowerPoint2024Retail%" EQU "YES" call :ConvertOffice16 PowerPoint2024 _AE _AE2
  if "%_PowerPoint2024Volume%" EQU "YES" call :ConvertOffice16 PowerPoint2024 _AE _AE2

  if "%_WordRetail%" EQU "YES" call :ConvertOffice16 Word
  if "%_WordVolume%" EQU "YES" call :ConvertOffice16 Word  
  if "%_Word2019Retail%" EQU "YES" call :ConvertOffice16 Word2019 _AE
  if "%_Word2019Volume%" EQU "YES" call :ConvertOffice16 Word2019 _AE
  if "%_Word2021Retail%" EQU "YES" call :ConvertOffice16 Word2021 _AE _AE2
  if "%_Word2021Volume%" EQU "YES" call :ConvertOffice16 Word2021 _AE _AE2
  if "%_Word2024Retail%" EQU "YES" call :ConvertOffice16 Word2024 _AE _AE2
  if "%_Word2024Volume%" EQU "YES" call :ConvertOffice16 Word2024 _AE _AE2

  if "%_ProjectProRetail%" EQU "YES" call :ConvertOffice16 ProjectPro
  if "%_ProjectProVolume%" EQU "YES" call :ConvertOffice16 ProjectPro
  if "%_ProjectProXVolume%" EQU "YES" call :ConvertOffice16 ProjectProXC2R
  if "%_ProjectPro2019Retail%" EQU "YES" call :ConvertOffice16 ProjectPro2019 _AE
  if "%_ProjectPro2019Volume%" EQU "YES" call :ConvertOffice16 ProjectPro2019 _AE
  if "%_ProjectPro2021Retail%" EQU "YES" call :ConvertOffice16 ProjectPro2021 _AE _AE2
  if "%_ProjectPro2021Volume%" EQU "YES" call :ConvertOffice16 ProjectPro2021 _AE _AE2
  if "%_ProjectPro2024Retail%" EQU "YES" call :ConvertOffice16 ProjectPro2024 _AE _AE2
  if "%_ProjectPro2024Volume%" EQU "YES" call :ConvertOffice16 ProjectPro2024 _AE _AE2
  
  if "%_ProjectStdRetail%" EQU "YES" call :ConvertOffice16 ProjectStd
  if "%_ProjectStdVolume%" EQU "YES" call :ConvertOffice16 ProjectStd
  if "%_ProjectStdXVolume%" EQU "YES" call :ConvertOffice16 ProjectStdXC2R
  if "%_ProjectStd2019Retail%" EQU "YES" call :ConvertOffice16 ProjectStd2019 _AE
  if "%_ProjectStd2019Volume%" EQU "YES" call :ConvertOffice16 ProjectStd2019 _AE
  if "%_ProjectStd2021Retail%" EQU "YES" call :ConvertOffice16 ProjectStd2021 _AE _AE2
  if "%_ProjectStd2021Volume%" EQU "YES" call :ConvertOffice16 ProjectStd2021 _AE _AE2
  if "%_ProjectStd2024Retail%" EQU "YES" call :ConvertOffice16 ProjectStd2024 _AE _AE2
  if "%_ProjectStd2024Volume%" EQU "YES" call :ConvertOffice16 ProjectStd2024 _AE _AE2
  
  if "%_PublisherRetail%" EQU "YES" call :ConvertOffice16 Publisher
  if "%_PublisherVolume%" EQU "YES" call :ConvertOffice16 Publisher
  if "%_Publisher2019Retail%" EQU "YES" call :ConvertOffice16 Publisher2019 _AE
  if "%_Publisher2019Volume%" EQU "YES" call :ConvertOffice16 Publisher2019 _AE
  if "%_Publisher2021Retail%" EQU "YES" call :ConvertOffice16 Publisher2021 _AE _AE2
  if "%_Publisher2021Volume%" EQU "YES" call :ConvertOffice16 Publisher2021 _AE _AE2
  if "%_Publisher2024Retail%" EQU "YES" call :ConvertOffice16 Publisher2024 _AE _AE2
  if "%_Publisher2024Volume%" EQU "YES" call :ConvertOffice16 Publisher2024 _AE _AE2
  
  if "%_SkypeForBusinessRetail%" EQU "YES" call :ConvertOffice16 SkypeForBusiness
  if "%_SkypeForBusinessVolume%" EQU "YES" call :ConvertOffice16 SkypeForBusiness
  if "%_SkypeForBusiness2019Retail%" EQU "YES" call :ConvertOffice16 SkypeForBusiness2019 _AE
  if "%_SkypeForBusiness2019Volume%" EQU "YES" call :ConvertOffice16 SkypeForBusiness2019 _AE
  if "%_SkypeForBusiness2021Retail%" EQU "YES" call :ConvertOffice16 SkypeForBusiness2021 _AE _AE2
  if "%_SkypeForBusiness2021Volume%" EQU "YES" call :ConvertOffice16 SkypeForBusiness2021 _AE _AE2
  if "%_SkypeForBusiness2024Retail%" EQU "YES" call :ConvertOffice16 SkypeForBusiness2024 _AE _AE2
  if "%_SkypeForBusiness2024Volume%" EQU "YES" call :ConvertOffice16 SkypeForBusiness2024 _AE _AE2
  
  if "%_VisioProRetail%" EQU "YES" call :ConvertOffice16 VisioPro
  if "%_VisioProVolume%" EQU "YES" call :ConvertOffice16 VisioPro
  if "%_VisioProXVolume%" EQU "YES" call :ConvertOffice16 VisioProXC2R
  if "%_VisioPro2019Retail%" EQU "YES" call :ConvertOffice16 VisioPro2019 _AE
  if "%_VisioPro2019Volume%" EQU "YES" call :ConvertOffice16 VisioPro2019 _AE
  if "%_VisioPro2021Retail%" EQU "YES" call :ConvertOffice16 VisioPro2021 _AE _AE2
  if "%_VisioPro2021Volume%" EQU "YES" call :ConvertOffice16 VisioPro2021 _AE _AE2
  if "%_VisioPro2024Retail%" EQU "YES" call :ConvertOffice16 VisioPro2024 _AE _AE2
  if "%_VisioPro2024Volume%" EQU "YES" call :ConvertOffice16 VisioPro2024 _AE _AE2

  if "%_VisioStdRetail%" EQU "YES" call :ConvertOffice16 VisioStd
  if "%_VisioStdVolume%" EQU "YES" call :ConvertOffice16 VisioStd
  if "%_VisioStdXVolume%" EQU "YES" call :ConvertOffice16 VisioStdXC2R
  if "%_VisioStd2019Retail%" EQU "YES" call :ConvertOffice16 VisioStd2019 _AE
  if "%_VisioStd2019Volume%" EQU "YES" call :ConvertOffice16 VisioStd2019 _AE
  if "%_VisioStd2021Retail%" EQU "YES" call :ConvertOffice16 VisioStd2021 _AE _AE2
  if "%_VisioStd2021Volume%" EQU "YES" call :ConvertOffice16 VisioStd2021 _AE _AE2
  if "%_VisioStd2024Retail%" EQU "YES" call :ConvertOffice16 VisioStd2024 _AE _AE2
  if "%_VisioStd2024Volume%" EQU "YES" call :ConvertOffice16 VisioStd2024 _AE _AE2
  
  echo #### INSTALLING GVLK
  
  if "%_MondoRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Office Mondo 2016 Grande Suite"
  if "%_MondoVolume%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Office Mondo 2016 Grande Suite"
  
  if "%_AppxVisio%" EQU "YES" call :OfficeGVLKInstall "PD3PC-RHNGV-FXJ29-8JK7D-RJRJK","VisioPro UWP Appx"
  if "%_AppxProject%" EQU "YES" call :OfficeGVLKInstall "YG9NW-3K39V-2T3HJ-93F3Q-G83KT","ProjectPro UWP Appx"
  if "%_UWPappINSTALLED%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Office UWP Appxs"
  
  if "%_StandardRetail%" EQU "YES" call :OfficeGVLKInstall "JNRGM-WHDWX-FJJG3-K47QV-DRTFM","Office Standard 2016"
  if "%_StandardVolume%" EQU "YES" call :OfficeGVLKInstall "JNRGM-WHDWX-FJJG3-K47QV-DRTFM","Office Standard 2016"
  if "%_Standard2019Retail%" EQU "YES" call :OfficeGVLKInstall "6NWWJ-YQWMR-QKGCB-6TMB3-9D9HK","Office Standard 2019"
  if "%_Standard2019Volume%" EQU "YES" call :OfficeGVLKInstall "6NWWJ-YQWMR-QKGCB-6TMB3-9D9HK","Office Standard 2019"
  if "%_Standard2021Retail%" EQU "YES" call :OfficeGVLKInstall "KDX7X-BNVR8-TXXGX-4Q7Y8-78VT3","Office Standard 2021"
  if "%_Standard2021Volume%" EQU "YES" call :OfficeGVLKInstall "KDX7X-BNVR8-TXXGX-4Q7Y8-78VT3","Office Standard 2021"
  if "%_StandardSPLA2021Volume%" EQU "YES" call :OfficeGVLKInstall "KDX7X-BNVR8-TXXGX-4Q7Y8-78VT3","Office Standard 2021"
  if "%_Standard2024Retail%" EQU "YES" call :OfficeGVLKInstall "V28N4-JG22K-W66P8-VTMGK-H6HGR","Office Standard 2024"
  if "%_Standard2024Volume%" EQU "YES" call :OfficeGVLKInstall "V28N4-JG22K-W66P8-VTMGK-H6HGR","Office Standard 2024"
  if "%_StandardSPLA2024Volume%" EQU "YES" call :OfficeGVLKInstall "V28N4-JG22K-W66P8-VTMGK-H6HGR","Office Standard 2024"
  
  if "%_PersonalRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Office Personal 2016 Retail"
  if "%_Personal2019Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Office Personal 2019 Retail"
  if "%_Personal2021Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Office Personal 2021 Retail"
  if "%_Personal2024Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Office Personal 2024 Retail"
  
  if "%_O365BusinessEEANoTeamsRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft 365 Apps for Business"
  if "%_O365BusinessRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft 365 Apps for Business"
  if "%_O365HomePremRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft 365 Home Premium retail"
  if "%_O365ProPlusEEANoTeamsRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft 365 Apps for Enterprise"
  if "%_O365ProPlusRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft 365 Apps for Enterprise"
  if "%_O365SmallBusPremRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft 365 Small Business retail"
  if "%_O365AppsBasicRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft 365 Basic retail"
  
  if "%_HomeBusinessRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft Home And Business"
  if "%_HomeBusiness2019Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft Home And Business 2019"	
  if "%_HomeBusiness2021Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft Home And Business 2021"
  if "%_HomeBusiness2024Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft Home And Business 2024"
  
  if "%_HomeStudentRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft Home And Student"
  if "%_HomeStudent2019Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft Home And Student 2019"	
  if "%_HomeStudent2021Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft Home And Student 2021"
  if "%_HomeStudent2024Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Microsoft Home And Student 2024"
  
  if "%_ProfessionalRetail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Professional 2016 Retail"
  if "%_Professional2019Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Professional 2019 Retail"
  if "%_Professional2021Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Professional 2021 Retail"
  if "%_Professional2024Retail%" EQU "YES" call :OfficeGVLKInstall "HFTND-W9MK4-8B7MJ-B6C4G-XQBR2","Professional 2024 Retail"
  
  if "%_ProPlusRetail%" EQU "YES" call :OfficeGVLKInstall "XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99","Office Professional Plus 2016"
  if "%_ProPlusVolume%" EQU "YES" call :OfficeGVLKInstall "XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99","Office Professional Plus 2016"
  if "%_ProPlus2019Retail%" EQU "YES" call :OfficeGVLKInstall "NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP","Office Professional Plus 2019"
  if "%_ProPlus2019Volume%" EQU "YES" call :OfficeGVLKInstall "NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP","Office Professional Plus 2019"
  if "%_ProPlus2021Retail%" EQU "YES" call :OfficeGVLKInstall "FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH","Office Professional Plus 2021"
  if "%_ProPlus2021Volume%" EQU "YES" call :OfficeGVLKInstall "FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH","Office Professional Plus 2021"
  if "%_ProPlusSPLA2021Volume%" EQU "YES" call :OfficeGVLKInstall "FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH","Office Professional Plus 2021"
  if "%_ProPlus2024Retail%" EQU "YES" call :OfficeGVLKInstall "XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB","Office Professional Plus 2024"
  if "%_ProPlus2024Volume%" EQU "YES" call :OfficeGVLKInstall "XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB","Office Professional Plus 2024"
  if "%_ProPlusSPLA2024Volume%" EQU "YES" call :OfficeGVLKInstall "XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB","Office Professional Plus 2024"
  
  if "%_WordRetail%" EQU "YES" call :OfficeGVLKInstall "WXY84-JN2Q9-RBCCQ-3Q3J3-3PFJ6","Word 2016"
  if "%_WordVolume%" EQU "YES" call :OfficeGVLKInstall "WXY84-JN2Q9-RBCCQ-3Q3J3-3PFJ6","Word 2016"
  if "%_Word2019Retail%" EQU "YES" call :OfficeGVLKInstall "PBX3G-NWMT6-Q7XBW-PYJGG-WXD33","Word 2019"
  if "%_Word2019Volume%" EQU "YES" call :OfficeGVLKInstall "PBX3G-NWMT6-Q7XBW-PYJGG-WXD33","Word 2019"
  if "%_Word2021Retail%" EQU "YES" call :OfficeGVLKInstall "TN8H9-M34D3-Y64V9-TR72V-X79KV","Word 2021"
  if "%_Word2021Volume%" EQU "YES" call :OfficeGVLKInstall "TN8H9-M34D3-Y64V9-TR72V-X79KV","Word 2021"
  if "%_Word2024Retail%" EQU "YES" call :OfficeGVLKInstall "MQ84N-7VYDM-FXV7C-6K7CC-VFW9J","Word 2024"
  if "%_Word2024Volume%" EQU "YES" call :OfficeGVLKInstall "MQ84N-7VYDM-FXV7C-6K7CC-VFW9J","Word 2024"
  
  if "%_ExcelRetail%" EQU "YES" call :OfficeGVLKInstall "9C2PK-NWTVB-JMPW8-BFT28-7FTBF","Excel 2016"
  if "%_ExcelVolume%" EQU "YES" call :OfficeGVLKInstall "9C2PK-NWTVB-JMPW8-BFT28-7FTBF","Excel 2016"
  if "%_Excel2019Retail%" EQU "YES" call :OfficeGVLKInstall "TMJWT-YYNMB-3BKTF-644FC-RVXBD","Excel 2019"
  if "%_Excel2019Volume%" EQU "YES" call :OfficeGVLKInstall "TMJWT-YYNMB-3BKTF-644FC-RVXBD","Excel 2019"
  if "%_Excel2021Retail%" EQU "YES" call :OfficeGVLKInstall "NWG3X-87C9K-TC7YY-BC2G7-G6RVC","Excel 2021"
  if "%_Excel2021Volume%" EQU "YES" call :OfficeGVLKInstall "NWG3X-87C9K-TC7YY-BC2G7-G6RVC","Excel 2021"
  if "%_Excel2024Retail%" EQU "YES" call :OfficeGVLKInstall "F4DYN-89BP2-WQTWJ-GR8YC-CKGJG","Excel 2024"
  if "%_Excel2024Volume%" EQU "YES" call :OfficeGVLKInstall "F4DYN-89BP2-WQTWJ-GR8YC-CKGJG","Excel 2024"
  
  if "%_AccessRetail%" EQU "YES" call :OfficeGVLKInstall "GNH9Y-D2J4T-FJHGG-QRVH7-QPFDW","Access 2016"
  if "%_AccessVolume%" EQU "YES" call :OfficeGVLKInstall "GNH9Y-D2J4T-FJHGG-QRVH7-QPFDW","Access 2016"
  if "%_Access2019Retail%" EQU "YES" call :OfficeGVLKInstall "9N9PT-27V4Y-VJ2PD-YXFMF-YTFQT","Access 2019"
  if "%_Access2019Volume%" EQU "YES" call :OfficeGVLKInstall "9N9PT-27V4Y-VJ2PD-YXFMF-YTFQT","Access 2019"
  if "%_Access2021Retail%" EQU "YES" call :OfficeGVLKInstall "WM8YG-YNGDD-4JHDC-PG3F4-FC4T4","Access 2021"
  if "%_Access2021Volume%" EQU "YES" call :OfficeGVLKInstall "WM8YG-YNGDD-4JHDC-PG3F4-FC4T4","Access 2021"
  if "%_Access2024Retail%" EQU "YES" call :OfficeGVLKInstall "82FTR-NCHR7-W3944-MGRHM-JMCWD","Access 2024"
  if "%_Access2024Volume%" EQU "YES" call :OfficeGVLKInstall "82FTR-NCHR7-W3944-MGRHM-JMCWD","Access 2024"
  
  if "%_OneNoteVolume%" EQU "YES"     call :OfficeGVLKInstall "DR92N-9HTF2-97XKM-XW2WJ-XW3J6","OneNote 2016"
  if "%_OneNoteRetail%" EQU "YES"     call :OfficeGVLKInstall "DR92N-9HTF2-97XKM-XW2WJ-XW3J6","OneNote 2016"
  if "%_OneNote2021Retail%" EQU "YES" call :OfficeGVLKInstall "DR92N-9HTF2-97XKM-XW2WJ-XW3J6","OneNote 2021"
  if "%_OneNote2024Retail%" EQU "YES" call :OfficeGVLKInstall "DR92N-9HTF2-97XKM-XW2WJ-XW3J6","OneNote 2024"
  
  if "%_OutlookRetail%" EQU "YES" call :OfficeGVLKInstall "R69KK-NTPKF-7M3Q4-QYBHW-6MT9B","Outlook 2016"
  if "%_OutlookVolume%" EQU "YES" call :OfficeGVLKInstall "R69KK-NTPKF-7M3Q4-QYBHW-6MT9B","Outlook 2016"
  if "%_Outlook2019Retail%" EQU "YES" call :OfficeGVLKInstall "7HD7K-N4PVK-BHBCQ-YWQRW-XW4VK","Outlook 2019"
  if "%_Outlook2019Volume%" EQU "YES" call :OfficeGVLKInstall "7HD7K-N4PVK-BHBCQ-YWQRW-XW4VK","Outlook 2019"
  if "%_Outlook2021Retail%" EQU "YES" call :OfficeGVLKInstall "C9FM6-3N72F-HFJXB-TM3V9-T86R9","Outlook 2021"
  if "%_Outlook2021Volume%" EQU "YES" call :OfficeGVLKInstall "C9FM6-3N72F-HFJXB-TM3V9-T86R9","Outlook 2021"
  if "%_Outlook2024Retail%" EQU "YES" call :OfficeGVLKInstall "D2F8D-N3Q3B-J28PV-X27HD-RJWB9","Outlook 2024"
  if "%_Outlook2024Volume%" EQU "YES" call :OfficeGVLKInstall "D2F8D-N3Q3B-J28PV-X27HD-RJWB9","Outlook 2024"
  
  if "%_PowerPointRetail%" EQU "YES" call :OfficeGVLKInstall "J7MQP-HNJ4Y-WJ7YM-PFYGF-BY6C6","PowerPoint 2016"
  if "%_PowerPointVolume%" EQU "YES" call :OfficeGVLKInstall "J7MQP-HNJ4Y-WJ7YM-PFYGF-BY6C6","PowerPoint 2016"
  if "%_PowerPoint2019Retail%" EQU "YES" call :OfficeGVLKInstall "RRNCX-C64HY-W2MM7-MCH9G-TJHMQ","PowerPoint 2019"
  if "%_PowerPoint2019Volume%" EQU "YES" call :OfficeGVLKInstall "RRNCX-C64HY-W2MM7-MCH9G-TJHMQ","PowerPoint 2019"
  if "%_PowerPoint2021Retail%" EQU "YES" call :OfficeGVLKInstall "TY7XF-NFRBR-KJ44C-G83KF-GX27K","PowerPoint 2021"
  if "%_PowerPoint2021Volume%" EQU "YES" call :OfficeGVLKInstall "TY7XF-NFRBR-KJ44C-G83KF-GX27K","PowerPoint 2021"
  if "%_PowerPoint2024Retail%" EQU "YES" call :OfficeGVLKInstall "CW94N-K6GJH-9CTXY-MG2VC-FYCWP","PowerPoint 2024"
  if "%_PowerPoint2024Volume%" EQU "YES" call :OfficeGVLKInstall "CW94N-K6GJH-9CTXY-MG2VC-FYCWP","PowerPoint 2024"

  if "%_SkypeForBusinessRetail%"     EQU "YES" call :OfficeGVLKInstall "869NQ-FJ69K-466HW-QYCP2-DDBV6","Skype For Business 2016"
  if "%_SkypeForBusinessVolume%"     EQU "YES" call :OfficeGVLKInstall "869NQ-FJ69K-466HW-QYCP2-DDBV6","Skype For Business 2016"
  if "%_SkypeForBusiness2021Retail%" EQU "YES" call :OfficeGVLKInstall "HWCXN-K3WBT-WJBKY-R8BD9-XK29P","Skype For Business 2021"
  if "%_SkypeForBusiness2021Volume%" EQU "YES" call :OfficeGVLKInstall "HWCXN-K3WBT-WJBKY-R8BD9-XK29P","Skype For Business 2021"
  if "%_SkypeForBusiness2024Retail%" EQU "YES" call :OfficeGVLKInstall "4NKHF-9HBQF-Q3B6C-7YV34-F64P3","Skype For Business 2024"
  if "%_SkypeForBusiness2024Volume%" EQU "YES" call :OfficeGVLKInstall "4NKHF-9HBQF-Q3B6C-7YV34-F64P3","Skype For Business 2024"
  
  if "%_PublisherRetail%" EQU "YES" call :OfficeGVLKInstall "F47MM-N3XJP-TQXJ9-BP99D-8K837","Publisher 2016"
  if "%_PublisherVolume%" EQU "YES" call :OfficeGVLKInstall "F47MM-N3XJP-TQXJ9-BP99D-8K837","Publisher 2016"
  if "%_Publisher2019Retail%" EQU "YES" call :OfficeGVLKInstall "G2KWX-3NW6P-PY93R-JXK2T-C9Y9V","Publisher 2019"
  if "%_Publisher2019Volume%" EQU "YES" call :OfficeGVLKInstall "G2KWX-3NW6P-PY93R-JXK2T-C9Y9V","Publisher 2019"
  if "%_Publisher2021Retail%" EQU "YES" call :OfficeGVLKInstall "2MW9D-N4BXM-9VBPG-Q7W6M-KFBGQ","Publisher 2021"
  if "%_Publisher2021Volume%" EQU "YES" call :OfficeGVLKInstall "2MW9D-N4BXM-9VBPG-Q7W6M-KFBGQ","Publisher 2021"
  if "%_Publisher2024Retail%" EQU "YES" call :OfficeGVLKInstall "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE","Publisher 2024"
  if "%_Publisher2024Volume%" EQU "YES" call :OfficeGVLKInstall "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE","Publisher 2024"
  
  if "%_ProjectProRetail%" EQU "YES" call :OfficeGVLKInstall "YG9NW-3K39V-2T3HJ-93F3Q-G83KT","Project Professional 2016"
  if "%_ProjectProVolume%" EQU "YES" call :OfficeGVLKInstall "YG9NW-3K39V-2T3HJ-93F3Q-G83KT","Project Professional 2016"
  if "%_ProjectProXVolume%" EQU "YES" call :OfficeGVLKInstall "WGT24-HCNMF-FQ7XH-6M8K7-DRTW9","Project Professional 2016 C2R"
  if "%_ProjectPro2019Retail%" EQU "YES" call :OfficeGVLKInstall "B4NPR-3FKK7-T2MBV-FRQ4W-PKD2B","Project Professional 2019"
  if "%_ProjectPro2019Volume%" EQU "YES" call :OfficeGVLKInstall "B4NPR-3FKK7-T2MBV-FRQ4W-PKD2B","Project Professional 2019"
  if "%_ProjectPro2021Retail%" EQU "YES" call :OfficeGVLKInstall "FTNWT-C6WBT-8HMGF-K9PRX-QV9H8","Project Professional 2021"
  if "%_ProjectPro2021Volume%" EQU "YES" call :OfficeGVLKInstall "FTNWT-C6WBT-8HMGF-K9PRX-QV9H8","Project Professional 2021"
  if "%_ProjectPro2024Retail%" EQU "YES" call :OfficeGVLKInstall "FQQ23-N4YCY-73HQ3-FM9WC-76HF4","Project Pro 2024"
  if "%_ProjectPro2024Volume%" EQU "YES" call :OfficeGVLKInstall "FQQ23-N4YCY-73HQ3-FM9WC-76HF4","Project Pro 2024"
  
  if "%_ProjectStdRetail%" EQU "YES" call :OfficeGVLKInstall "GNFHQ-F6YQM-KQDGJ-327XX-KQBVC","Project Standard"
  if "%_ProjectStdVolume%" EQU "YES" call :OfficeGVLKInstall "GNFHQ-F6YQM-KQDGJ-327XX-KQBVC","Project Standard"
  if "%_ProjectStdXVolume%" EQU "YES" call :OfficeGVLKInstall "D8NRQ-JTYM3-7J2DX-646CT-6836M","Project Standard C2R"
  if "%_ProjectStd2019Retail%" EQU "YES" call :OfficeGVLKInstall "C4F7P-NCP8C-6CQPT-MQHV9-JXD2M","Project Standard 2019"
  if "%_ProjectStd2019Volume%" EQU "YES" call :OfficeGVLKInstall "C4F7P-NCP8C-6CQPT-MQHV9-JXD2M","Project Standard 2019"
  if "%_ProjectStd2021Retail%" EQU "YES" call :OfficeGVLKInstall "J2JDC-NJCYY-9RGQ4-YXWMH-T3D4T","Project Standard 2021"
  if "%_ProjectStd2021Volume%" EQU "YES" call :OfficeGVLKInstall "J2JDC-NJCYY-9RGQ4-YXWMH-T3D4T","Project Standard 2021"
  if "%_ProjectStd2024Retail%" EQU "YES" call :OfficeGVLKInstall "PD3TT-NTHQQ-VC7CY-MFXK3-G87F8","Project Standard 2024"
  if "%_ProjectStd2024Volume%" EQU "YES" call :OfficeGVLKInstall "PD3TT-NTHQQ-VC7CY-MFXK3-G87F8","Project Standard 2024"
  
  if "%_VisioProRetail%" EQU "YES" call :OfficeGVLKInstall "PD3PC-RHNGV-FXJ29-8JK7D-RJRJK","Visio Professional 2016"
  if "%_VisioProVolume%" EQU "YES" call :OfficeGVLKInstall "PD3PC-RHNGV-FXJ29-8JK7D-RJRJK","Visio Professional 2016"
  if "%_VisioProXVolume%" EQU "YES" call :OfficeGVLKInstall "69WXN-MBYV6-22PQG-3WGHK-RM6XC","Visio Professional 2016 C2R"
  if "%_VisioPro2019Retail%" EQU "YES" call :OfficeGVLKInstall "9BGNQ-K37YR-RQHF2-38RQ3-7VCBB","Visio Professional 2019"
  if "%_VisioPro2019Volume%" EQU "YES" call :OfficeGVLKInstall "9BGNQ-K37YR-RQHF2-38RQ3-7VCBB","Visio Professional 2019"
  if "%_VisioPro2021Retail%" EQU "YES" call :OfficeGVLKInstall "KNH8D-FGHT4-T8RK3-CTDYJ-K2HT4","Visio Professional 2021"
  if "%_VisioPro2021Volume%" EQU "YES" call :OfficeGVLKInstall "KNH8D-FGHT4-T8RK3-CTDYJ-K2HT4","Visio Professional 2021"
  if "%_VisioPro2024Retail%" EQU "YES" call :OfficeGVLKInstall "B7TN8-FJ8V3-7QYCP-HQPMV-YY89G","Visio Pro 2024"
  if "%_VisioPro2024Volume%" EQU "YES" call :OfficeGVLKInstall "B7TN8-FJ8V3-7QYCP-HQPMV-YY89G","Visio Pro 2024"
  
  if "%_VisioStdRetail%" EQU "YES" call :OfficeGVLKInstall "7WHWN-4T7MP-G96JF-G33KR-W8GF4","Visio Standard"
  if "%_VisioStdVolume%" EQU "YES" call :OfficeGVLKInstall "7WHWN-4T7MP-G96JF-G33KR-W8GF4","Visio Standard"
  if "%_VisioStdXVolume%" EQU "YES" call :OfficeGVLKInstall "NY48V-PPYYH-3F4PX-XJRKJ-W4423","Visio Standard C2R"
  if "%_VisioStd2019Retail%" EQU "YES" call :OfficeGVLKInstall "7TQNQ-K3YQQ-3PFH7-CCPPM-X4VQ2","Visio Standard 2019"
  if "%_VisioStd2019Volume%" EQU "YES" call :OfficeGVLKInstall "7TQNQ-K3YQQ-3PFH7-CCPPM-X4VQ2","Visio Standard 2019"
  if "%_VisioStd2021Retail%" EQU "YES" call :OfficeGVLKInstall "MJVNY-BYWPY-CWV6J-2RKRT-4M8QG","Visio Standard 2021"
  if "%_VisioStd2021Volume%" EQU "YES" call :OfficeGVLKInstall "MJVNY-BYWPY-CWV6J-2RKRT-4M8QG","Visio Standard 2021"
  if "%_VisioStd2024Retail%" EQU "YES" call :OfficeGVLKInstall "JMMVY-XFNQC-KK4HK-9H7R3-WQQTV","Visio Standard 2024"
  if "%_VisioStd2024Volume%" EQU "YES" call :OfficeGVLKInstall "JMMVY-XFNQC-KK4HK-9H7R3-WQQTV","Visio Standard 2024"
  
  goto:eof
::===============================================================================================================
::===============================================================================================================
:OfficeGVLKInstall

  set "s_key=%~1"
  set "s_name=%~2"
  
  echo:
  echo !s_name!
  %MultiNul% del /q %windir%\temp\result
  if defined WMI_PS (
    >%windir%\temp\result 2>&1 "%PowerShellEXE%" -nop -ep bypass -file "%PS_Help%" "/InstallProductKey" !s_key!
  )
  if defined WMI_VB (
    >%windir%\temp\result 2>&1 %CscriptEXE% "%OfficeRToolpath%\Data\vbs\ospp.vbs" /inpkey:!s_key!
  )
  if defined WMI_CO (
    >%windir%\temp\result 2>&1 wmic path !S_CLASS! where __CLASS='!S_CLASS!' call InstallProductKey ProductKey="!s_key!"
  )
  
  set HRESULT=1
  type %windir%\temp\result | %MultiNul% find /i "Error:0"    && set HRESULT=0
  type %windir%\temp\result | %MultiNul% find /i "successful" && set HRESULT=0
  
  if !HRESULT! EQU 0 (
    echo Successfully installed !s_key!
  ) else (
    echo Installing !s_key! failed
  )
  goto:eof
  
::===============================================================================================================
::===============================================================================================================
:TheEndIsNear
  %SingleNulV2% %PowerShellEXE% -nop -c "Remove-MpPreference -ExclusionPath '%~dp0','%~dp0Data\','%~dp0Data\core\','%~dp0Data\Bin\'"
  echo:
  echo:
  echo Ending OfficeRTool ...
  timeout /t 4
  exit
::===============================================================================================================

:CleanRegistryKeys

rem OSPP.VBS Nethood
rem OSPP.VBS Nethood
rem OSPP.VBS Nethood

%MultiNul% %REGEXE% delete "%OSPP_USER%" /f /v KeyManagementServiceName
%MultiNul% %REGEXE% delete "%OSPP_USER%" /f /v KeyManagementServicePort
%MultiNul% %REGEXE% delete "%OSPP_USER%" /f /v DisableDnsPublishing
%MultiNul% %REGEXE% delete "%OSPP_USER%" /f /v DisableKeyManagementServiceHostCaching

%MultiNul% %REGEXE% delete "%OSPP_HKLM%" /f /v KeyManagementServiceName
%MultiNul% %REGEXE% delete "%OSPP_HKLM%" /f /v KeyManagementServicePort
%MultiNul% %REGEXE% delete "%OSPP_HKLM%" /f /v DisableDnsPublishing
%MultiNul% %REGEXE% delete "%OSPP_HKLM%" /f /v DisableKeyManagementServiceHostCaching

rem SLMGR.VBS Nethood
rem SLMGR.VBS Nethood
rem SLMGR.VBS Nethood

%MultiNul% %REGEXE% delete "%XSPP_USER%" /f /v KeyManagementServiceName
%MultiNul% %REGEXE% delete "%XSPP_USER%" /f /v KeyManagementServicePort
%MultiNul% %REGEXE% delete "%XSPP_USER%" /f /v DisableDnsPublishing
%MultiNul% %REGEXE% delete "%XSPP_USER%" /f /v DisableKeyManagementServiceHostCaching

%MultiNul% %REGEXE% delete "%XSPP_HKLM_X32%" /f /v KeyManagementServiceName
%MultiNul% %REGEXE% delete "%XSPP_HKLM_X32%" /f /v KeyManagementServicePort
%MultiNul% %REGEXE% delete "%XSPP_HKLM_X32%" /f /v DisableDnsPublishing
%MultiNul% %REGEXE% delete "%XSPP_HKLM_X32%" /f /v DisableKeyManagementServiceHostCaching

%MultiNul% %REGEXE% delete "%XSPP_HKLM_X64%" /f /v KeyManagementServiceName
%MultiNul% %REGEXE% delete "%XSPP_HKLM_X64%" /f /v KeyManagementServicePort
%MultiNul% %REGEXE% delete "%XSPP_HKLM_X64%" /f /v DisableDnsPublishing
%MultiNul% %REGEXE% delete "%XSPP_HKLM_X64%" /f /v DisableKeyManagementServiceHostCaching

rem WMI Nethood -- Create SubKey under SPP KEY
rem WMI Nethood -- Create SubKey under SPP KEY
rem WMI Nethood -- Create SubKey under SPP KEY

for %%# in (55c92734-d682-4d71-983e-d6ec3f16059f, 0ff1ce15-a989-479d-af46-f275c6370663, 59a52881-a989-479d-af46-f275c6370663) do (
  %MultiNul% %REGEXE% delete "%XSPP_USER%\%%#" /f
  %MultiNul% %REGEXE% delete "%XSPP_HKLM_X32%\%%#" /f
  %MultiNul% %REGEXE% delete "%XSPP_HKLM_X64%\%%#" /f
)
goto :eof

:UpdateLangFromIni
  set "inidownpath=!var3!"
  if "%inidownpath:~-1%" EQU " " set "inidownpath=%inidownpath:~0,-1%"
  set "downpath=!inidownpath!"
  set "inidownlang=!var6!"
  if "%inidownlang:~-1%" EQU " " set "inidownlang=%inidownlang:~0,-1%"
  set "o16lang=!inidownlang!"
  set "inidownarch=!var9!"
  if "%inidownarch:~-1%" EQU " " set "inidownarch=%inidownarch:~0,-1%"
  set "o16arch=!inidownarch!"
  call :UpdateSystemLanguge
  goto :eof

:updateRegistryKeys

rem OSPP.VBS Nethood
rem OSPP.VBS Nethood
rem OSPP.VBS Nethood

%MultiNul% %REGEXE% add "%OSPP_USER%" /f /v KeyManagementServiceName /t REG_SZ /d "%1"
%MultiNul% %REGEXE% add "%OSPP_USER%" /f /v KeyManagementServicePort /t REG_SZ /d "%2"
%MultiNul% %REGEXE% add "%OSPP_USER%" /f /v DisableDnsPublishing /t REG_DWORD /d 0
%MultiNul% %REGEXE% add "%OSPP_USER%" /f /v DisableKeyManagementServiceHostCaching /t REG_DWORD /d 0

%MultiNul% %REGEXE% add "%OSPP_HKLM%" /f /v KeyManagementServiceName /t REG_SZ /d "%1"
%MultiNul% %REGEXE% add "%OSPP_HKLM%" /f /v KeyManagementServicePort /t REG_SZ /d "%2"
%MultiNul% %REGEXE% add "%OSPP_HKLM%" /f /v DisableDnsPublishing /t REG_DWORD /d 0
%MultiNul% %REGEXE% add "%OSPP_HKLM%" /f /v DisableKeyManagementServiceHostCaching /t REG_DWORD /d 0

rem SLMGR.VBS Nethood
rem SLMGR.VBS Nethood
rem SLMGR.VBS Nethood

%MultiNul% %REGEXE% add "%XSPP_USER%" /f /v KeyManagementServiceName /t REG_SZ /d "%1"
%MultiNul% %REGEXE% add "%XSPP_USER%" /f /v KeyManagementServicePort /t REG_SZ /d "%2"
%MultiNul% %REGEXE% add "%XSPP_USER%" /f /v DisableDnsPublishing /t REG_DWORD /d 0
%MultiNul% %REGEXE% add "%XSPP_USER%" /f /v DisableKeyManagementServiceHostCaching /t REG_DWORD /d 0

%MultiNul% %REGEXE% add "%XSPP_HKLM_X32%" /f /v KeyManagementServiceName /t REG_SZ /d "%1"
%MultiNul% %REGEXE% add "%XSPP_HKLM_X32%" /f /v KeyManagementServicePort /t REG_SZ /d "%2"
%MultiNul% %REGEXE% add "%XSPP_HKLM_X32%" /f /v DisableDnsPublishing /t REG_DWORD /d 0
%MultiNul% %REGEXE% add "%XSPP_HKLM_X32%" /f /v DisableKeyManagementServiceHostCaching /t REG_DWORD /d 0

%MultiNul% %REGEXE% add "%XSPP_HKLM_X64%" /f /v KeyManagementServiceName /t REG_SZ /d "%1"
%MultiNul% %REGEXE% add "%XSPP_HKLM_X64%" /f /v KeyManagementServicePort /t REG_SZ /d "%2"
%MultiNul% %REGEXE% add "%XSPP_HKLM_X64%" /f /v DisableDnsPublishing /t REG_DWORD /d 0
%MultiNul% %REGEXE% add "%XSPP_HKLM_X64%" /f /v DisableKeyManagementServiceHostCaching /t REG_DWORD /d 0

rem WMI Nethood -- Create SubKey under SPP KEY
rem WMI Nethood -- Create SubKey under SPP KEY
rem WMI Nethood -- Create SubKey under SPP KEY

%MultiNul% %REGEXE% add "%XSPP_USER%\!subKey!\!Id!" /f /v KeyManagementServiceName /t REG_SZ /d "%1"
%MultiNul% %REGEXE% add "%XSPP_USER%\!subKey!\!Id!" /f /v KeyManagementServicePort /t REG_SZ /d "%2"

%MultiNul% %REGEXE% add "%XSPP_HKLM_X32%\!subKey!\!Id!" /f /v KeyManagementServiceName /t REG_SZ /d "%1"
%MultiNul% %REGEXE% add "%XSPP_HKLM_X32%\!subKey!\!Id!" /f /v KeyManagementServicePort /t REG_SZ /d "%2"

%MultiNul% %REGEXE% add "%XSPP_HKLM_X64%\!subKey!\!Id!" /f /v KeyManagementServiceName /t REG_SZ /d "%1"
%MultiNul% %REGEXE% add "%XSPP_HKLM_X64%\!subKey!\!Id!" /f /v KeyManagementServicePort /t REG_SZ /d "%2"

goto :eof

:Query
%MultiNul% del /q "%Res______%"

if /i '%3' EQU '' (
  if defined WMI_PS (
    >"%Res______%" "%PowerShellEXE%" -nop -ep bypass -file "%PS_Help%" "/QUERY_BASIC" %1 %2
  )
  if defined WMI_VB (
	>"%Res______%" %CscriptEXE% /nologo "%VB_Help%" "/QUERY_BASIC" %1 %2
  )
  if defined WMI_CO (
	>"%Res______%" wmic path %~2 get %~1 /format:%CSV_TA%
  )
)

if /i '%3' NEQ '' (
  if defined WMI_PS (
    >"%Res______%" "%PowerShellEXE%" -nop -ep bypass -file "%PS_Help%" "/QUERY_ADVENCED" %1 %2 %3
  )
  if defined WMI_VB (
	>"%Res______%" %CscriptEXE% /nologo "%VB_Help%" "/QUERY_ADVENCED" %1 %2 %3
  )
  if defined WMI_CO (
	>"%Res______%" wmic path %~2 where ^(%~3^) get %~1 /format:%CSV_TA%
  )
)

call :QUERY_CHECK
goto :eof

:QUERY_CHECK
if defined ERROR_2 (
  goto :eof
)

set "e_Val=!SIGNATURE!"
set "ERROR_2=!ERROR_1!"
set "SHIT_LIST=team Follow visit"
for /f "tokens=1,2" %%# in ('"%SingleNulV2% "%valueTool%" "!OfficeRToolpath!\!OfficeRToolname!""') do set "c_Val=%%#"
goto :eof

:: NEW 2024 SKU from abbodi1406
:: https://forums.mydigitallife.net/threads/87688/page-7#post-1824043

:Channel_List
echo Manual_Override*ea4a4090-de26-49d7-93c1-91bff9e53fc3
echo Manual_Override*f3260cf1-a92c-4c75-b02e-d64c0a86a968
echo Manual_Override*c4a7726f-06ea-48e2-a13a-9d78849eb706
echo Manual_Override*834504cc-dc55-4c6d-9e71-e024d0253f6d
echo Manual_Override*5462eee5-1e97-495b-9370-853cd873bb07
echo Manual_Override*f4f024c8-d611-4748-a7e0-02b6e754c0fe
echo Manual_Override*b61285dd-d9f7-41f2-9757-8f61cba4e9c8
echo Manual_Override*9a3b7ff2-58ed-40fd-add5-1e5158059d1c
echo Manual_Override*86752282-5841-4120-ac80-db03ae6b5fdb
echo Manual_Override*2e148de9-61c8-4051-b103-4af54baffbb4
echo Manual_Override*12f4f6ad-fdea-4d2a-a90f-17496cc19a48
echo Manual_Override*0002c1ba-b76b-4af9-b1ee-ae2ad587371f
echo Manual_Override*C02D8FE6-5242-4DA8-972F-82EE55E00671
echo Manual_Override*20481F5C-C268-4624-936C-52EB39DDBD97
echo Current*492350f6-3a01-4f97-b9c0-c7c6ddf67d60
echo CurrentPreview*64256afe-f5d9-4f86-8936-8840a6a4f5be
echo BetaChannel*5440fd1f-7ecb-4221-8110-145efaa6372f
echo MonthlyEnterprise*55336b82-a18d-4dd6-b5f6-9e5095c314a6
echo SemiAnnual*7ffbc6bf-bc32-4f92-8982-f9dd17fd3114
echo SemiAnnualPreview*b8f9b850-328d-4355-9145-c59439a0c4cf
echo PerpetualVL2019*f2e724c1-748f-4b47-8fb8-8e0d210e9208
echo PerpetualVL2021*5030841d-c919-4594-8d2d-84ae4f96e58e
echo PerpetualVL2024*7983BAC0-E531-40CF-BE00-FD24FE66619C
echo DogfoodDevMain*ea4a4090-de26-49d7-93c1-91bff9e53fc3
goto :eof

:Language_List
echo Afrikaans*1078*af-za*0436
echo Albanian*1052*sq-al*041c
echo Amharic*1118*am-et*045e
echo Arabic*1025*ar-sa*0401
echo Armenian*1067*hy-am*042b
echo Assamese*1101*as-in*044d
echo Azerbaijani Latin*1068*az-latn-az*042c
echo Bangla Bangladesh*2117*bn-bd*0845
echo Bangla Bengali India*1093*bn-in*0445
echo Basque Basque*1069*eu-es*042d
echo Belarusian*1059*be-by*0423
echo Bosnian*5146*bs-latn-ba*0141a
echo Bulgarian*1026*bg-bg*0402
echo Catalan Valencia*2051*ca-es-valencia*0803
echo Catalan*1027*ca-es*0403
echo Chinese Simplified*2052*zh-cn*0804
echo Chinese Traditional*1028*zh-tw*0404
echo Croatian*1050*hr-hr*041a
echo Czech*1029*cs-cz*0405
echo Danish*1030*da-dk*0406
echo Dari*1164*prs-af*048c
echo Dutch*1043*nl-nl*0413
echo English UK*2057*en-GB*0809
echo English*1033*en-us*0409
echo Estonian*1061*et-ee*0425
echo Filipino*1124*fil-ph*0464
echo Finnish*1035*fi-fi*040b
echo French Canada*3084*fr-CA*0C0C
echo French*1036*fr-fr*040c
echo Galician*1110*gl-es*0456
echo Georgian*1079*ka-ge*0437
echo German*1031*de-de*0407
echo Greek*1032*el-gr*0408
echo Gujarati*1095*gu-in*0447
echo Hausa Nigeria*1128*ha-Latn-NG*0468
echo Hebrew*1037*he-il*040d
echo Hindi*1081*hi-in*0439
echo Hungarian*1038*hu-hu*040e
echo Icelandic*1039*is-is*040f
echo Igbo*1136*ig-NG*0470
echo Indonesian*1057*id-id*0421
echo Irish*2108*ga-ie*083c
echo Italian*1040*it-it*0410
echo Japanese*1041*ja-jp*0411
echo Kannada*1099*kn-in*044b
echo Kazakh*1087*kk-kz*043f
echo Khmer*1107*km-kh*0453
echo KiSwahili*1089*sw-ke*0441
echo Kinyarwanda*1159*rw-RW*0487
echo Konkani*1111*kok-in*0457
echo Korean*1042*ko-kr*0412
echo Kyrgyz*1088*ky-kg*0440
echo Latvian*1062*lv-lv*0426
echo Lithuanian*1063*lt-lt*0427
echo Luxembourgish*1134*lb-lu*046e
echo Macedonian*1071*mk-mk*042f
echo Malay Latin*1086*ms-my*043e
echo Malayalam*1100*ml-in*044c
echo Maltese*1082*mt-mt*043a
echo Maori*1153*mi-nz*0481
echo Marathi*1102*mr-in*044e
echo Mongolian*1104*mn-mn*0450
echo Nepali*1121*ne-np*0461
echo Norwedian Nynorsk*2068*nn-no*0814
echo Norwegian Bokmal*1044*nb-no*0414
echo Odia*1096*or-in*0448
echo Pashto*1123*ps-AF*0463
echo Persian*1065*fa-ir*0429
echo Polish*1045*pl-pl*0415
echo Portuguese Brazilian*1046*pt-br*0416
echo Portuguese Portugal*2070*pt-pt*0816
echo Punjabi Gurmukhi*1094*pa-in*0446
echo Quechua*3179*quz-pe*0c6b
echo Romanian*1048*ro-ro*0418
echo Romansh*1047*rm-CH*0417
echo Russian*1049*ru-ru*0419
echo Setswana*1074*tn-ZA*0432
echo Scottish Gaelic*1169*gd-gb*0491
echo Serbian Bosnia*7194*sr-cyrl-ba*01c1a
echo Serbian Serbia*10266*sr-cyrl-rs*0281a
echo Serbian*9242*sr-latn-rs*0241a
echo Sesotho sa Leboa*1132*nso-ZA*046C
echo Sindhi Arabic*2137*sd-arab-pk*0859
echo Sinhala*1115*si-lk*045b
echo Slovak*1051*sk-sk*041b
echo Slovenian*1060*sl-si*0424
echo Spanish*3082*es-es*0c0a
echo Spanish Mexico*2058*es-MX*080A
echo Swedish*1053*sv-se*041d
echo Tamil*1097*ta-in*0449
echo Tatar Cyrillic*1092*tt-ru*0444
echo Telugu*1098*te-in*044a
echo Thai*1054*th-th*041e
echo Turkish*1055*tr-tr*041f
echo Turkmen*1090*tk-tm*0442
echo Ukrainian*1058*uk-ua*0422
echo Urdu*1056*ur-pk*0420
echo Uyghur*1152*ug-cn*0480
echo Uzbek*1091*uz-latn-uz*0443
echo Vietnamese*1066*vi-vn*042a
echo Welsh*1106*cy-gb*0452
echo Wolof*1160*wo-SN*0488
echo Yoruba*1130*yo-NG*046A
echo isiXhosa*1076*xh-ZA*0434
echo isiZulu*1077*zu-ZA*0435
goto :eof

:Auto_Pilot
    cls
  call :Change_Size 85 42
  
  echo:
  set /a count=0
  set "Profile="
  set "Bad_Path_2="
  set "xml_list=%windir%\temp\xml_list"
  
  if not exist Profiles\*.xml (
    set "Bad_Path_2=true"
    goto :Zibi_1_x
  )
  
  
  %multinul% del /q %xml_list%
  dir /a /b profiles\*.xml > %xml_list%
  for /f "tokens=*" %%$ in ('type %xml_list%') do set /a count+=1
  
  if !count! LSS 1 (
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode  goto :eof
    goto :TheEndIsNear
  )
  
  if !count! LSS 2 (
    (<%xml_list% set /p profile=)
    goto :Auto_Pilot_MENU_VNEXT
  )
  
  echo Multiple XML found
  echo:
  
  set /a count=0
  for /f "tokens=*" %%$ in ('type %xml_list%') do (
    set /a count+=1
    set "Profile_!count!=%%$"
    if !count! LSS 10 echo [#!count!] :: %%$
    if !count! GEQ 10 echo [!count!] :: %%$
  )
  
  echo:
:Auto_Pilot_MENU_MULTI_XML
  set regi="^^[1-!COUNT!]$"
  Set /p "id=Choice [ID:] from the list, [X] to Exit: "
  if not defined ID goto :Auto_Pilot_MENU_MULTI_XML
  
  if /i !id! EQU X (
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode  goto :eof
    goto :TheEndIsNear
  )
  
    (echo !ID!|%multinul% findstr /i /r !regi!)||goto :Auto_Pilot_MENU_MULTI_XML
  set "profile=!Profile_%ID%!"
  
:Auto_Pilot_MENU_VNEXT
  cls
  echo:
  %SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\XML_PARSER.ps1"
  echo:
:Auto_Pilot_MENU
  set "id="
  %multinul% timeout 1 /nobreak
  Set /p "id=Choice [ID:] from the list, [X] to Exit: "
  if not defined id goto :Auto_Pilot_MENU
  
  if /i !id! EQU X (
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode  goto :eof
    goto :TheEndIsNear
  )
  echo !id!|%multinul% findstr /i /r "^[1-9]$ ^[1-9][0-9]$ ^[X]$"||goto :Auto_Pilot_MENU
    
  for %%$ in (Name,action,Version, channel,Language, Location) do (
    set "_%%$="
    for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\XML_PARSER.ps1" !id! %%$ -Extract"`) do set "_%%$=%%#"
    if not defined _%%$ (
  	echo ERROR ### Fail to fetch nececery info
  	echo:
      goto :Auto_Pilot_MENU
    )
  )
  
  if !_action! NEQ 1 for %%$ in (Type,Products) do (
    set "_%%$="
    for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\XML_PARSER.ps1" !id! %%$ -Extract"`) do set "_%%$=%%#"
    if not defined _%%$ (
  	echo ERROR ### Fail to fetch nececery info
  	echo:
      goto :Auto_Pilot_MENU
    )
  )
  
  if !_action! EQU 1 for %%$ in (System) do (
    set "_%%$="
    for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\XML_PARSER.ps1" !id! %%$ -Extract"`) do set "_%%$=%%#"
    if not defined _%%$ (
  	echo ERROR ### Fail to fetch nececery info
  	echo:
      goto :Auto_Pilot_MENU
    )
  )
  
  for %%$ in (Exclude, lang_pack, proof_tool) do (
    set "_%%$="
    for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\XML_PARSER.ps1" !id! %%$ -Extract"`) do set "_%%$=%%#"
  )
  
  echo:
  echo ### Validate configuration
  
  set "verified="
  for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -ep bypass -file "%ScriptDir%\XML_PARSER.ps1" !id! NULL -Verify"`) do set "verified=%%#"
  
  if not defined verified (
    echo ### Bad Configuration FILE
    echo:
    pause
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode  goto :eof
    goto :TheEndIsNear
  )
  
  if defined verified if /i !verified! NEQ True (
    echo:
    echo ### Bad Configuration FILE
    echo:
    pause
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode  goto :eof
    goto :TheEndIsNear
  )
  
  set AutoPilotMode=True
  
  echo:
  
  if !_Action! EQU 1 (
    call :DownloadO16Offline
  )
  
  if !_Action! EQU 2 (
    set "OnlineInstaller="
    call :InstallO16
  )
  
  if !_Action! EQU 3 (
    set "OnlineInstaller=defined"
    call :InstallO16
  )
  
:Zibi_1_x
  if defined Bad_Path_2 (
    echo:
    echo Missing files
    echo:
    pause
  )
  
  if defined Auto_Pilot_RET goto :Office16VnextInstall
  if defined AutoPilotMode  goto :eof
  goto :TheEndIsNear

:Get-WinUserLanguageList_Warper

::reset values
set SysLanIdHex=

:: plan A ~ using pure P/S code
rem first 4 letter's is what we need :)
set COMMAND="@(Get-WinUserLanguageList)[0][0].InputMethodTips.Substring(0,4)"
for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c !COMMAND!"`) do set "SysLanIdHex=%%#"

:: plan B ~ hard way ..... but it's worked ...
if not defined SysLanIdHex call :Get-WinUserLanguageList

:: Result
if defined SysLanIdHex call :convertLanHexToDec

goto :eof
:Get-WinUserLanguageList
set xVal=
set SysLanCD=
set SysLanIdHex=
%MultiNul% %REGEXE% query "HKEY_CURRENT_USER\Control Panel\International\User Profile" /v Languages || goto :eof
for /f "tokens=3 delims= " %%g in ('reg query "HKEY_CURRENT_USER\Control Panel\International\User Profile" /v Languages ^| find /i "REG_MULTI_SZ"') do set xVal=%%g
if defined xVal 		(for /f "tokens=1 delims=\0" %%g in ('echo !xVal!') do set SysLanIdHex=%%g)
if defined SysLanIdHex 	(for /f "tokens=1 delims= " %%g in ('reg query "HKEY_CURRENT_USER\Control Panel\International\User Profile\!SysLanIdHex!" ^| find /i "000"') do set SysLanIdHex=%%g)
if defined SysLanIdHex 	(for /f "tokens=1 delims=:" %%g in ('echo !SysLanIdHex!') do set SysLanIdHex=%%g)
goto :eof
:convertLanHexToDec
:: %%g=English %%h=1033 %%i=en-us %%j:0409
>"%windir%\Temp\tmp" call :Language_List
for /f "tokens=1,2,3,4 delims=*" %%g in ('type "%windir%\Temp\tmp"') do (
  if 	/i '%%j' EQU '!SysLanIdHex!' (
  	set SysLanCD=%%i
  	goto :convertLanHexToDec_
  )	
)
:convertLanHexToDec_
goto :eof

:CheckSystemLanguage
set var=&set var=%*
if not defined var (

  :: using Get-WinUserLanguageList Function Cmd Warper
  if defined SysLanCD (
  	call :CheckSystemLanguage %SysLanCD%
  	goto :eof
  )
  
  :: Using HKCR :: PreferredUILanguages Value
  %MultiNul% %REGEXE% query "HKEY_CURRENT_USER\Control Panel\Desktop" /v PreferredUILanguages && (
  	REM echo Using HKCR :: PreferredUILanguages Value
  	for /f "tokens=1,3" %%g in ('reg query "HKEY_CURRENT_USER\Control Panel\Desktop" /v PreferredUILanguages') do (
  		if /i '%%g' EQU 'PreferredUILanguages' call :CheckSystemLanguage %%h
  	)
  	goto :eof
  )
  
  :: Using HKLM:: PreferredUILanguages Value
  %MultiNul% %REGEXE% query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MUI\Settings" /v PreferredUILanguages && (
  	REM echo Using HKLM:: PreferredUILanguages Value
  	for /f "tokens=1,3" %%g in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\SYSTEM\CurrentControlSet\Control\MUI\Settings" /v PreferredUILanguages') do (
  		if /i '%%g' EQU 'PreferredUILanguages' call :CheckSystemLanguage %%h
  	)
  	goto :eof
  )
  
  :: using dism :: get-intl
  REM echo using dism :: get-intl
  for /f "tokens=4,6" %%g  in ('dism /online /get-intl') do (
  	if /i '%%g' EQU 'language' call :CheckSystemLanguage %%h
  )
  goto :eof
)
if defined var (
  	
  :: %%g=English %%h=1033 %%i=en-us %%j:0409
  >"%windir%\Temp\tmp" call :Language_List
  for /f "tokens=1,2,3 delims=*" %%g in ('type "%windir%\Temp\tmp"') do (
  	if /i '%var%' EQU '%%i' (
  		set langtext=%%g
  		set o16lcid=%%h
  		set o16lang=%%i
  		goto :CheckSystemLanguage_
  	)
  )
)
:CheckSystemLanguage_
goto :eof

:UpdateSystemLanguge
rem %%g=English %%h=1033 %%i=en-us %%j:0409
set "langFound="
>"%windir%\Temp\tmp" call :Language_List
for /f "tokens=1,2,3,4 delims=*" %%g in ('type "%windir%\Temp\tmp"') do (
  if /i "!o16lang!" EQU "%%i" (
  	set langtext=%%g
  	set o16lcid=%%h
  	set langFound=***
  )
)
if not defined langFound (
  set "o16lang=en-US"
  set "langtext=Default Language"
    set "o16lcid=1033"
)
goto :eof

:Install_LICENSE
if %WinBuild% GEQ 9200 ( 
  set "Args=/ilc"
  set "Licence_Tool=%SlmgrEXE%"
)
if %WinBuild% LSS 9200 (
  set "Args=/inslic"
  set "Licence_Tool=%OfficeRToolpath%\Data\vbs\ospp.vbs"
)

if defined WMI_PS (
  set "ERR_PATTERN=Error:0"
  >%windir%\temp\result 2>&1 "%PowerShellEXE%" -nop -ep bypass -file "%PS_Help%" "/InstallLicense" "%OfficeRToolpath%\Data\Licenses\%~1"
)
if defined WMI_VB (
  set "ERR_PATTERN=installed successfully"
  >%windir%\temp\result 2>&1 %CscriptEXE% "!Licence_Tool!" "!Args!" "%OfficeRToolpath%\Data\Licenses\%~1"
)
if defined WMI_CO (
  if %WinBuild% GEQ 9200 (
    set "ERR_PATTERN=Error:0"
    >%windir%\temp\result 2>&1 "%PowerShellEXE%" -nop -ep bypass -file "%PS_Help%" "/InstallLicense" "%OfficeRToolpath%\Data\Licenses\%~1"
  )
  if %WinBuild% LSS 9200 (
	set "ERR_PATTERN=installed successfully"
    >%windir%\temp\result 2>&1 %CscriptEXE% "!Licence_Tool!" "!Args!" "%OfficeRToolpath%\Data\Licenses\%~1"
  )
)

type %windir%\temp\result | %MultiNul% find /i "!ERR_PATTERN!" && (
  echo Successfully installed `%~1`
) || (
  echo Installing `%~1` failed
)
goto:eof

:GetInfoFromFolder
  for %%g in (lLngID, multiLang, MultiL, MultiM, x32, x64, lang, version, ChannelName, ChannelID, channeltrigger) do set %%g=
  if exist office\data\v64.cab (set "x64=*"&set "lBit=64")
  if exist office\data\v32.cab (set "x32=*"&set "lBit=32")
  if not defined x64 (
  	if not defined x32 (
  		echo:
  		echo Download incomplete - Package unusable - Redo download [1.a]
  		echo:
  		if not defined debugMode if not defined AutoTask pause
  		if defined Auto_Pilot_RET goto :Office16VnextInstall
  		if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  		goto:InstallO16Loop
  	)
  )
  
  %MultiNul% dir /ad /b "office\data\16*" && (
  	for /f "tokens=*" %%g in ('dir /ad /b "office\data\16*"') do set "version=%%g"
  )
  
  echo "!version!" | %SingleNul% findstr /r "%ver_reg%" || (
  	(echo:)&&(echo Download incomplete - Package unusable - Redo download [1.b])&&(echo:)&&(pause)&&(
  	  if defined Auto_Pilot_RET goto :Office16VnextInstall
  	  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  	  goto:InstallO16Loop
  	)
  )
  
  if not defined version (echo:)&&(echo Download incomplete - Package unusable - Redo download [1.c])&&(echo:)&&(pause)&&(
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode if !_Action! EQU 2 goto :eof
    goto:InstallO16Loop
  )
  if defined x64 (
  	if defined x32 (
  		set "x64="
  		set "MultiM=XXX"
  		set "lBit=32"
  	)
  )
  
  %MultiNul% del /q "%windir%\Temp\tmp"
  >"%windir%\Temp\tmp" call :Language_List
  
  for /f "tokens=1,2,3 delims=*" %%g in ('type "%windir%\Temp\tmp"') do (	
  	if exist "office\data\!version!\i%lBit%%%h.cab" (
  		set "lLngID=%%h"
  		if not defined multiLang (
  			set "multiLang=!lLngID!"
  		) else (
  			(echo '!multiLang!' |%SingleNul% find /i "!lLngID!") || (set "multiLang=!multiLang!,!lLngID!")
  		)
  	)
  )
  
  set "id_LIST="
  set /a count=0
  set "countVal="
  set "MULTI_lang="
  set "MULTI_lang_IDS="
  
  set "id_LIST_X="
  
  if defined AutoPilotMode if !_Action! EQU 2 (
    if /i !_Language! NEQ AUTO (
  	  set "id_LIST_X=%_Language:,= %"
  	  goto :ZraabboyX_2
  ))
  
  if defined lLngID (
  	if defined multiLang (
  		if /i '!lLngID!' NEQ '!multiLang!' call :Verify_MULTI_LANGUAGE
  	)
  ) else (
  	(echo:)&&(echo Download incomplete - Package unusable - Redo download [1.d])&&(echo:)&&(pause)&&(
  	  if defined Auto_Pilot_RET goto :Office16VnextInstall
  	  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  	  goto:InstallO16Loop
  	)
  )
  
  call :ConvertIDtoXXFormat !lLngID!
  set "lang=!langId_New!"

:ZraabboyX_2
  if defined x32 set "CabFile=Office\Data\v32.cab"
  if defined x64 set "CabFile=Office\Data\v64.cab"
  
  (%SingleNul% expand !CabFile! -F:VersionDescriptor.xml "%windir%\Temp") || (
  	(echo:)&&(echo Download incomplete - Package unusable - Redo download [1.e])&&(echo:)&&(pause)&&(
  	  if defined Auto_Pilot_RET goto :Office16VnextInstall
  	  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  	  goto:InstallO16Loop
  	)
  )
  
  if not exist "%windir%\Temp\VersionDescriptor.xml" (
  	(echo:)&&(echo Download incomplete - Package unusable - Redo download [1.f])&&(echo:)&&(pause)&&(
  	  if defined Auto_Pilot_RET goto :Office16VnextInstall
  	  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  	  goto:InstallO16Loop
  	)
  )
  
  set "DeliveryMechanism="
  for /f "tokens=*" %%# in ('type "%windir%\Temp\VersionDescriptor.xml"^|find /i "DeliveryMechanism"') do set "DeliveryMechanism=%%#"
  
  if not defined DeliveryMechanism (
  	(echo:)&&(echo Download incomplete - Package unusable - Redo download [1.g])&&(echo:)&&(pause)&&(
  	  if defined Auto_Pilot_RET goto :Office16VnextInstall
  	  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  	  goto:InstallO16Loop
  	)
  )
  set "DeliveryMechanism=!DeliveryMechanism:~28,-2!"
  
  rem %%g Name, %%h Channel
  >"%windir%\Temp\tmp" call :Channel_List
  for /f "tokens=1,2 delims=*" %%g in ('type "%windir%\Temp\tmp"') do (
  	(echo !DeliveryMechanism! | %SingleNul% find /i "%%h") && (
  		set "ChannelName=%%g"
  		set "ChannelID=%%h"
  	)
  )
  
  if not defined ChannelName (
  	(echo:)&&(echo Download incomplete - Package unusable - Redo download [1.h])&&(echo:)&&(pause)&&(
  	  if defined Auto_Pilot_RET goto :Office16VnextInstall
  	  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  	  goto:InstallO16Loop
  	)
  )
  
  set "pInfo=!cd!\package.info"
  %TripleNul% echo.>package.info && (
  	>package.info echo !ChannelName!
  	>>package.info echo !version!
  	
  	if defined MultiL (
  		>>package.info echo Multi
  	) else (
  		>>package.info echo !lang!
  	)
  	if defined MultiM (
  		>>package.info echo Multi
  	) else (
  		if defined x32 (
  			>>package.info echo x86
  		) else (
  			>>package.info echo x64
  		)
  	)
  	>>package.info echo !ChannelID!
  	
  ) || (
  	echo.
  	echo ERROR ### Fail to write package.info File
  	echo.
  	if not defined debugMode if not defined AutoTask pause
  	if defined Auto_Pilot_RET goto :Office16VnextInstall
  	if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  	goto:InstallO16Loop
  )
  
  set "distribchannel=!ChannelName!"
  if "%distribchannel:~-1%" EQU " " (
    set "distribchannel=%distribchannel:~0,-1%"
  )
  set "o16build=!version!"
  set "o16lang=!lang!"
  call :SetO16Language
  
  if defined MultiM (
  	set "o16arch=Multi"
  ) else (
  	if defined x32 (
  		set "o16arch=x86"
  	) else (
  		set "o16arch=x64"
  	)
  )
  set "o16updlocid=!ChannelID!"
  goto :GetInfoFromFolder_Done
  
:FindLngId
  set "langIdIDID="
  set "langIdName="
  set var=&set var=%*
  if defined var (
  	:: %%g=English %%h=1033 %%i=en-us %%j:0409
  	>"%windir%\Temp\tmp" call :Language_List
  	for /f "tokens=1,2,3 delims=*" %%g in ('type "%windir%\Temp\tmp"') do (
  		if /i '%var%' EQU '%%h' (
  			set "langIdName=%%g"
  			set "langIdIDID=%%i"
  			goto :FindLngId_
  		)
  	)
  )
  :FindLngId_
  goto :eof

:Verify_MULTI_LANGUAGE
  echo:
  echo Multi Language Found.
  echo _____________________
  echo:
  
  for %%# in (!multiLang!) do (
  	set /a count+=1
  	call :FindLngId %%#
  	echo Language [!count!] :: [%%#] !langIdName!
  	set "lang_!count!=%%#"
  	set "countVal=!countVal!,!count!"
  )
  
  if defined AutoPilotMode if !_Action! EQU 2 (
    if /i !_Language! EQU AUTO Goto :Auto_Select_All
  )

  set /a CountFinal=!count!+1
  set /a SelectAll=!count!+2
  echo Language [!CountFinal!] :: Custom Select
  echo Language [!SelectAll!] :: Select All
  set "countVal=!countVal!,!CountFinal!,!SelectAll!"
  echo:
  
  if "!Auto_Select_All!" EQU "1" (
    Goto:Auto_Select_All
  )
  
  set lLng_Choice=
  set /p lLng_Choice=Select Language ID :: 
  
  if not defined lLng_Choice (
  	(echo:)&&(echo ERROR ### Bad Choice)&&(echo:)&&(pause)&&(
  	  if defined Auto_Pilot_RET goto :Office16VnextInstall
  	  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
        goto:InstallO16Loop
  	)
  )
  
  if /i "!lLng_Choice!" EQU "%CountFinal%" (
  	call :Custom_Choice
  	goto :eof
  )
  if /i "!lLng_Choice!" EQU "%SelectAll%" (
  	call :Auto_Select_All
  	goto :eof
  )

  set lLng_found=
  FOR /L %%# IN (1,1,!count!) DO (			
  	if /i '!lLng_Choice!' EQU '%%#' (
  		set "lLngID=!lang_%%#!"
  		set lLng_found=*
  	)
  )
  
  if defined lLng_found (
  	set "MultiL=XXX"
  	goto :eof
  )
  
  (echo:)&&(echo ERROR ### Bad Choice)&&(echo:)&&(pause)&&(
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode if !_Action! EQU 2 goto :eof
    goto:InstallO16Loop
  )
  goto :eof

:Custom_Choice
echo:
set "MULTI_lang="
set "MULTI_lang_IDS="
set /p MULTI_lang=Select Language[s] Index[s] to Install: 
if defined MULTI_lang set "MULTI_lang=!MULTI_lang:-=,!"
if defined MULTI_lang set "MULTI_lang=!MULTI_lang:;=,!"

if defined MULTI_lang for %%$ in (!MULTI_lang!) do (
  set IndexFound=
  FOR /L %%# IN (1,1,!count!) DO (
  	if /i '%%$' EQU '%%#' (
  		echo "!MULTI_lang_IDS!" | %SingleNul% find /i "!lang_%%#!" || (
  			set "IndexFound=True"
  			set "MULTI_lang_IDS=!MULTI_lang_IDS!,!lang_%%#!"
  		)
  	)
  )
  if not defined IndexFound (echo:)&&(echo ERROR ### BAD USER CHOICE )&&(echo:)&&(pause)&&(
    if defined Auto_Pilot_RET goto :Office16VnextInstall
    if defined AutoPilotMode if !_Action! EQU 2 goto :eof
    goto:InstallO16Loop
  )
)

if not defined MULTI_lang_IDS (echo:)&&(echo ERROR ### BAD USER CHOICE )&&(echo:)&&(pause)&&(
  if defined Auto_Pilot_RET goto :Office16VnextInstall
  if defined AutoPilotMode if !_Action! EQU 2 goto :eof
  goto:InstallO16Loop
)

set id_LIST=
set MULTI_lang=
for %%$ in (!MULTI_lang_IDS!) do (
  call :FindLngId %%$
  if     defined MULTI_lang set "MULTI_lang=!MULTI_lang!, !langIdName!"
  if not defined MULTI_lang set "MULTI_lang=!langIdName!"
  
  if     defined id_LIST set "id_LIST=!id_LIST!, !langIdIDID!"
  if not defined id_LIST set "id_LIST=!langIdIDID!"
)
set "MultiL=XXX"
goto :eof

:Auto_Select_All
  echo:
  set "id_LIST="
  set "MULTI_lang="
  set "MULTI_lang_IDS="
  
  FOR /L %%# IN (1,1,!count!) DO (
  	set "MULTI_lang_IDS=!MULTI_lang_IDS!,!lang_%%#!"
  )

  for %%$ in (!MULTI_lang_IDS!) do (
  	call :FindLngId %%$
  	if     defined MULTI_lang set "MULTI_lang=!MULTI_lang!, !langIdName!"
  	if not defined MULTI_lang set "MULTI_lang=!langIdName!"
  	
  	if     defined id_LIST set "id_LIST=!id_LIST!, !langIdIDID!"
  	if not defined id_LIST set "id_LIST=!langIdIDID!"
  )
  
  set "MultiL=XXX"
  goto :eof
  			
:ConvertIDtoXXFormat
  set "langId_New="
  set var=&set var=%*
  if defined var (

  	:: %%g=English %%h=1033 %%i=en-us %%j:0409
  	>"%windir%\Temp\tmp" call :Language_List
  	for /f "tokens=1,2,3 delims=*" %%g in ('type "%windir%\Temp\tmp"') do (
  		if /i '%var%' EQU '%%h' (
  			set "langId_New=%%i"
  			goto :FindLngId_
  		)
  	)
  )
  :FindLngId_
  goto :eof
  
:generateXML

  if not defined MULTI_lang goto :generateXML_NEXT
  set "id_LIST="
  set "XWtf=!MULTI_lang: =$!"
  for %%a in (!XWtf!) do (
  	set "newVal=%%a"
  	set "newVal=!newVal:$= !"
  	call :GENERATE_LANG_ID_LIST !newVal!
  )

:generateXML_NEXT

   >"%oxml%" echo ^<Configuration^>
  >>"%oxml%" echo     ^<Add OfficeClientEdition="%o16a%" Version="!o16build!"%channel% ^> 
  
  if not defined id_LIST (
      set "id_LIST=!o16lang!"
    if defined id_LIST_X set "id_LIST=!id_LIST_X!"
  )
  
  if "%mo16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Mondo%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^>
  	call :Generate_Exclude_Apps
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%of16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="ProPlus%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	call :Generate_Exclude_Apps
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%of19install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="ProPlus2019%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	call :Generate_Exclude_Apps
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%of21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="ProPlus2021%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	call :Generate_Exclude_Apps
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%of24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="ProPlus2024%type%"^>
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	call :Generate_Exclude_Apps
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%of36ppinstall%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="O365ProPlus%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	call :Generate_Exclude_Apps
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%of36bsinstall%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="O365Business%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	call :Generate_Exclude_Apps
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%of36homePrem%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="O365HomePrem%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	call :Generate_Exclude_Apps
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%vi16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="VisioPro%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%vi19install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="VisioPro2019%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )

  if "%vi21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="VisioPro2021%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
 
  if "%vi24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="VisioPro2024%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%pr16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="ProjectPro%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^>
  )

  if "%pr19install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="ProjectPro2019%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^>
  )
  
  if "%pr21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="ProjectPro2021%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^>
  )
  
  if "%pr24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="ProjectPro2024%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^>
  )

  if "%wd16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Word%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%wd19install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Word2019%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%wd21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Word2021%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%wd24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Word2024%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ex16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Excel%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
    if "%ex19install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Excel2019%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ex21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Excel2021%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ex24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Excel2024%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%pp16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="PowerPoint%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^>  
  )
  
  if "%pp19install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="PowerPoint2019%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%pp21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="PowerPoint2021%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%pp24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="PowerPoint2024%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ac16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Access%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ac19install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Access2019%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ac21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Access2021%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ac24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Access2024%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ol16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Outlook%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ol19install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Outlook2019%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ol21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Outlook2021%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%ol24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Outlook2024%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%pb16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Publisher%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%pb19install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Publisher2019%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%pb21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Publisher2021%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%pb24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="Publisher2024%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%on16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="OneNote%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%on21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="OneNote2021Retail"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )

  if "%on24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="OneNote2024Retail"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%sk16install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="SkypeForBusiness%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%sk19install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="SkypeForBusiness2019%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
  
  if "%sk21install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="SkypeForBusiness2021%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )

  if "%sk24install%" NEQ "0" (
  	>>"%oxml%" echo         ^<Product ID="SkypeForBusiness2024%type%"^> 
  	for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  	>>"%oxml%" echo         ^</Product^> 
  )
 
  if not defined Multi_Proof_Lang goto :ZVX66X
  set "id_LIST="
  set "XWtf=!Multi_Proof_Lang: =$!"
  for %%a in (!XWtf!) do (
  	set "newVal=%%a"
  	set "newVal=!newVal:$= !"
  	call :GENERATE_P_LANG_ID_LIST !newVal!
  )
  >>"%oxml%" echo         ^<Product ID="ProofingTools"^> 
  for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  >>"%oxml%" echo         ^</Product^> 

:ZVX66X

  if not defined Multi_Lang_Pack goto :ZVX66Y
  set "id_LIST="
  set "XWtf=!Multi_Lang_Pack: =$!"
  for %%a in (!XWtf!) do (
  	set "newVal=%%a"
  	set "newVal=!newVal:$= !"
  	call :GENERATE_L_LANG_ID_LIST !newVal!
  )
  >>"%oxml%" echo         ^<Product ID="LanguagePack"^> 
  for %%# in (!id_LIST!) do >>"%oxml%" echo             ^<Language ID="%%#"/^> 
  >>"%oxml%" echo         ^</Product^> 

:ZVX66Y

  >>"%oxml%" echo     ^</Add^>
  >>"%oxml%" echo     ^<Property Name="ForceAppsShutdown" Value="True" /^> 
  >>"%oxml%" echo     ^<Property Name="PinIconsToTaskbar" Value="False" /^> 
  >>"%oxml%" echo     ^<Display Level="Full" AcceptEula="True" /^> 
  >>"%oxml%" echo     ^<Updates Enabled="True" UpdatePath="http://officecdn.microsoft.com/%Region%/!o16updlocid!"%channel% /^> 
  >>"%oxml%" echo ^</Configuration^>
  goto :eof

:Certification_Validation
 
  rem in case value not exist
  if not DEFINED e_Val (
    goto :eof
  )
  if defined e_Val (
    if /i '!e_Val!' EQU '!c_Val!' (
	  set "WMI_FAILURE_C="
	  goto :eof
  ))
 
  rem CERTUTIL Code
  if defined UseCertUtil (
    for %%$ in (input.txt, output.txt) do %MultiNul% del /q %windir%\temp\%%$
    echo !e_Val!>%windir%\temp\input.txt
    %MultiNul% certutil -f -decodehex %windir%\temp\input.txt %Res______%.txt && (
	  <%Res______%.txt set /p e_Val=
  ))

  rem PS Code
  if not defined UseCertUtil if defined UseHexPS (
    set "Command=-join(('!e_Val!'-split'(..)'|where{$_}|foreach{[convert]::ToByte($_,16)})-as[char[]])"
    for /f "usebackq tokens=*" %%# in (`"%SingleNulV2% %PowerShellEXE% -nop -c "!COMMAND!""`) do set "e_Val=%%#"
  )

  if defined e_Val (
    if /i '!e_Val!' EQU '!c_Val!' (
	  set "WMI_FAILURE_C="
  ))

:Generate_Exclude_Apps
  if "%wd16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Word"/^> 
  if "%ex16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Excel"/^> 
  if "%pp16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="PowerPoint"/^> 
  if "%ac16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Access"/^> 
  if "%ol16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Outlook"/^> 
  if "%pb16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Publisher"/^> 
  if "%on16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="OneNote"/^> 
  if "%st16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Lync"/^> 
  if "%st16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Teams"/^> 
  if "%od16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Groove"/^> 
  if "%od16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="OneDrive"/^> 
  if "%bsbsdisable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Bing"/^> 
  if "%vs16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Visio"/^> 
  if "%Pr16disable%" NEQ "0" >>"%oxml%" echo             ^<ExcludeApp ID="Project"/^> 
goto :eof

:verify_LANG_XXZ
  set /a LANG_COUNT +=1
  set "o16lang=%*"
  set "o16lang=!o16lang:, =!"
  set "o16lang=!o16lang:,=!"
  if defined o16lang if /i "x!o16lang:~0,1!" EQU "x " set "o16lang=!o16lang:~1!"
  if defined o16lang if /i "!o16lang:-1!x" EQU " x" set "o16lang=!o16lang:~0,-1!"
  
  call :SetO16Language
  if not defined langnotfound if     defined LANG_TEST ((echo "!LANG_TEST!" | %SingleNul% find /i "!o16lang!") && set "langnotfound=*" || set "LANG_TEST=!LANG_TEST!,!o16lang!")
  if not defined langnotfound if not defined LANG_TEST (set "LANG_TEST=!o16lang!")
  
  if defined langnotfound (
  	set "o16lang=not set"
  	goto:LangSelect_
  )
  goto :eof
  
:verify_LANG_XXA
  set /a LANG_COUNT +=1
  set "o16lang=%*"
  set "o16lang=!o16lang:, =!"
  set "o16lang=!o16lang:,=!"
  if defined o16lang if /i "x!o16lang:~0,1!" EQU "x " set "o16lang=!o16lang:~1!"
  if defined o16lang if /i "!o16lang:-1!x" EQU " x" set "o16lang=!o16lang:~0,-1!"
  
  call :SetO16Language
  if not defined langnotfound if     defined LANG_TEST ((echo "!LANG_TEST!" | %SingleNul% find /i "!o16lang!") && set "langnotfound=*" || set "LANG_TEST=!LANG_TEST!,!o16lang!")
  if not defined langnotfound if not defined LANG_TEST (set "LANG_TEST=!o16lang!")
  
  if defined langnotfound (
  	set "o16lang=not set"
  	goto:OnlineInstaller_Language_MENU_Loop
  )
  goto :eof
  
:verify_LANG_XXAZ
  set /a LANG_COUNT +=1
  set "p16lang=%*"
  set "p16lang=!p16lang:, =!"
  set "p16lang=!p16lang:,=!"
  if defined p16lang if /i "x!p16lang:~0,1!" EQU "x " set "p16lang=!p16lang:~1!"
  if defined p16lang if /i "!p16lang:-1!x" EQU " x" set "p16lang=!p16lang:~0,-1!"
  
  call :SetP16Language
  if not defined p_langnotfound if     defined LANG_TEST ((echo "!LANG_TEST!" | %SingleNul% find /i "!p16lang!") && set "p_langnotfound=*" || set "LANG_TEST=!LANG_TEST!,!p16lang!")
  if not defined p_langnotfound if not defined LANG_TEST (set "LANG_TEST=!p16lang!")
  
  if defined p_langnotfound (
  	set "p16lang=not set"
  	set "PROOF_LANG="
  	goto:OnlineInstaller_Language_MENU_Loop_X
  )
  goto :eof
  
:verify_LANG_XXAB
  set /a LANG_COUNT +=1
  set "L16lang=%*"
  set "L16lang=!L16lang:, =!"
  set "L16lang=!L16lang:,=!"
  if defined L16lang if /i "x!L16lang:~0,1!" EQU "x " set "L16lang=!L16lang:~1!"
  if defined L16lang if /i "!L16lang:-1!x" EQU " x" set "L16lang=!L16lang:~0,-1!"
  
  call :SetL16language
  if not defined L_langnotfound if     defined LANG_TEST ((echo "!LANG_TEST!" | %SingleNul% find /i "!L16lang!") && set "L_langnotfound=*" || set "LANG_TEST=!LANG_TEST!,!L16lang!")
  if not defined L_langnotfound if not defined LANG_TEST (set "LANG_TEST=!L16lang!")
  
  if defined L_langnotfound (
  	set "L16lang=not set"
  	set "Language_Pack="
  	goto:OnlineInstaller_Language_MENU_Loop_Y
  )
  goto :eof
  
:DOWNLOAD_LANG_XXZ
  set "o16lang=%*"
  set "o16lang=!o16lang:, =!"
  set "o16lang=!o16lang:,=!"
  if defined o16lang if /i "x!o16lang:~0,1!" EQU "x " set "o16lang=!o16lang:~1!"
  if defined o16lang if /i "!o16lang:-1!x" EQU " x" set "o16lang=!o16lang:~0,-1!"
  call :SetO16Language
  
  if defined multi_ARC (
  	set "o16arch=x86"
  	call :ContVNextDownload_next
  	set "o16arch=x64"
  	call :ContVNextDownload_next
  	goto :eof
  )
  
  call :ContVNextDownload_next
  goto :eof
  
:GENERATE_LANG_ID_LIST
  set "o16lang=%*"
  set "o16lang=!o16lang:, =!"
  set "o16lang=!o16lang:,=!"
  if defined o16lang if /i "x!o16lang:~0,1!" EQU "x " set "o16lang=!o16lang:~1!"
  if defined o16lang if /i "!o16lang:-1!x" EQU " x" set "o16lang=!o16lang:~0,-1!"
  call :SetO16Language
  set "id_LIST=!id_LIST! !o16lang!"
  goto :eof
  
:GENERATE_P_LANG_ID_LIST
  set "p16lang=%*"
  set "p16lang=!p16lang:, =!"
  set "p16lang=!p16lang:,=!"
  if defined p16lang if /i "x!p16lang:~0,1!" EQU "x " set "p16lang=!p16lang:~1!"
  if defined p16lang if /i "!p16lang:-1!x" EQU " x" set "p16lang=!p16lang:~0,-1!"
  call :SetP16Language
  set "id_LIST=!id_LIST!,!p16lang!"
  goto :eof
  
:GENERATE_L_LANG_ID_LIST
  set "L16lang=%*"
  set "L16lang=!L16lang:, =!"
  set "L16lang=!L16lang:,=!"
  if defined L16lang if /i "x!L16lang:~0,1!" EQU "x " set "L16lang=!L16lang:~1!"
  if defined L16lang if /i "!L16lang:-1!x" EQU " x" set "L16lang=!L16lang:~0,-1!"
  call :SetL16language
  set "id_LIST=!id_LIST!,!L16lang!"
  goto :eof
  
Rem abbodi1406 KMS VL ALL LOCAL ACTIVATION
Rem abbodi1406 KMS VL ALL LOCAL ACTIVATION
Rem abbodi1406 KMS VL ALL LOCAL ACTIVATION

:Load_DLL
set SSppHook=0
set KMSPort=1688
set KMSHostIP=!IP_ADDRESS!
set KMS_RenewalInterval=10080
set KMS_ActivationInterval=120
set KMS_HWID=0x3A1C049600B60076

set "_wApp=55c92734-d682-4d71-983e-d6ec3f16059f"
set "_oApp=0ff1ce15-a989-479d-af46-f275c6370663"
set "_oA14=59a52881-a989-479d-af46-f275c6370663"
set "IFEO=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
set "OPPk=SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform"
set "SPPk=SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
set "_TaskEx=\Microsoft\Windows\SoftwareProtectionPlatform\SvcTrigger"

if /i "%PROCESSOR_ARCHITECTURE%"=="amd64" set "xOS=x64"
if /i "%PROCESSOR_ARCHITECTURE%"=="arm64" set "xOS=A64"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if "%PROCESSOR_ARCHITEW6432%"=="" set "xOS=x86"
if /i "%PROCESSOR_ARCHITEW6432%"=="amd64" set "xOS=x64"
if /i "%PROCESSOR_ARCHITEW6432%"=="arm64" set "xOS=A64"

set "SysPath=%SystemRoot%\System32"
if exist "%SystemRoot%\Sysnative\reg.exe" (set "SysPath=%SystemRoot%\Sysnative")
set "Path=%SysPath%;%SystemRoot%;%SysPath%\Wbem;%SysPath%\WindowsPowerShell\v1.0\"
set _Hook="%SysPath%\SppExtComObjHook.dll"

for /f %%A in ('"%SingleNulV2% dir /b /ad %SysPath%\spp\tokens\skus"') do (
  if %WinBuild% GEQ 9200 if exist "%SysPath%\spp\tokens\skus\%%A\*GVLK*.xrm-ms" set SSppHook=1
  if %WinBuild% LSS 9200 if exist "%SysPath%\spp\tokens\skus\%%A\*VLKMS*.xrm-ms" set SSppHook=1
  if %WinBuild% LSS 9200 if exist "%SysPath%\spp\tokens\skus\%%A\*VL-BYPASS*.xrm-ms" set SSppHook=1
)
set OsppHook=1
sc query osppsvc %MultiNul%
if %errorlevel% EQU 1060 set OsppHook=0

set ESU_KMS=0
if %WinBuild% LSS 9200 for /f %%A in ('"%SingleNulV2% dir /b /ad %SysPath%\spp\tokens\channels"') do (
  if exist "%SysPath%\spp\tokens\channels\%%A\*VL-BYPASS*.xrm-ms" set ESU_KMS=1
)
if %ESU_KMS% EQU 1 (set "adoff=and LicenseDependsOn is NULL"&set "addon=and LicenseDependsOn is not NULL") else (set "adoff="&set "addon=")
set ESU_EDT=0
if %ESU_KMS% EQU 1 for %%A in (Enterprise,EnterpriseE,EnterpriseN,Professional,ProfessionalE,ProfessionalN,Ultimate,UltimateE,UltimateN) do (
  if exist "%SysPath%\spp\tokens\skus\Security-SPP-Component-SKU-%%A\*.xrm-ms" set ESU_EDT=1
)
if %ESU_EDT% EQU 1 set SSppHook=1
set ESU_ADD=0

if %WinBuild% GEQ 9200 (
  set OSType=Win8
  set SppVer=SppExtComObj.exe
) else if %WinBuild% GEQ 7600 (
  set OSType=Win7
  set SppVer=sppsvc.exe
) else (
  if not defined debugMode if not defined AutoTask pause
  exit /b
)
if %OSType% EQU Win8 %REGEXE% query "%IFEO%\sppsvc.exe" %MultiNul% && (
  reg delete "%IFEO%\sppsvc.exe" /f %MultiNul%
  call :StopService sppsvc
)
set _uRI=%KMS_RenewalInterval%
set _uAI=%KMS_ActivationInterval%
set _AUR=0
if exist %_Hook% dir /b /al %_Hook% %MultiNul% || (
  %REGEXE% query "%IFEO%\%SppVer%" /v VerifierFlags %MultiNul% && set _AUR=1
  if %SSppHook% EQU 0 %REGEXE% query "%IFEO%\osppsvc.exe" /v VerifierFlags %MultiNul% && set _AUR=1
)

if %_AUR% EQU 0 (
  set KMS_RenewalInterval=43200
  set KMS_ActivationInterval=43200
) else (
  set KMS_RenewalInterval=%_uRI%
  set KMS_ActivationInterval=%_uAI%
)
if %WinBuild% GEQ 9600 (
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f %MultiNul%
  if %WinBuild% EQU 14393 %REGEXE% add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoAcquireGT /t REG_DWORD /d 1 /f %MultiNul%
)

call :StopService sppsvc
if %OsppHook% NEQ 0 call :StopService osppsvc
for %%# in (SppExtComObjHookAvrf.dll,SppExtComObjHook.dll,SppExtComObjPatcher.dll,SppExtComObjPatcher.exe) do (
  if exist "%SysPath%\%%#" del /f /q "%SysPath%\%%#" %MultiNul%
  if exist "%SystemRoot%\SysWOW64\%%#" del /f /q "%SystemRoot%\SysWOW64\%%#" %MultiNul%
)
set AclReset=0
set _cphk=0
if %_AUR% EQU 1 set _cphk=1
if %_cphk% EQU 1 (
  copy /y "%OfficeRToolpath%\Data\core\%xOS%.dll" %_Hook% %MultiNul%
  goto :skipsym
)
mklink %_Hook% "%OfficeRToolpath%\Data\core\%xOS%.dll" %MultiNul%
set ERRORCODE=%ERRORLEVEL%
if %ERRORCODE% NEQ 0 goto :E_SYM
icacls %_Hook% /findsid *S-1-5-32-545 %SingleNulV2% | find /i "SppExtComObjHook.dll" %SingleNul% || (
  set AclReset=1
  icacls %_Hook% /grant *S-1-5-32-545:RX %MultiNul%
)
:skipsym
if %SSppHook% NEQ 0 call :CreateIFEOEntry %SppVer%
if %_AUR% EQU 1 (call :CreateIFEOEntry osppsvc.exe) else (if %OsppHook% NEQ 0 call :CreateIFEOEntry osppsvc.exe)
if %_AUR% EQU 1 if %OSType% EQU Win7 call :CreateIFEOEntry SppExtComObj.exe
if %_AUR% EQU 1 (
call :UpdateIFEOEntry %SppVer%
call :UpdateIFEOEntry osppsvc.exe
)
goto :eof

:UnLoad_DLL
call :StopService sppsvc
if %OsppHook% NEQ 0 call :StopService osppsvc
if %_AUR% EQU 0 call :RemoveHook
sc start sppsvc trigger=timer;sessionid=0 %MultiNul%
goto :eof

:StopService
sc query %1 | find /i "STOPPED" %SingleNul% || net stop %1 /y %MultiNul%
sc query %1 | find /i "STOPPED" %SingleNul% || sc stop %1 %MultiNul%
goto :eof


:RemoveHook
if %AclReset% EQU 1 icacls %_Hook% /reset %MultiNul%
for %%# in (SppExtComObjHookAvrf.dll,SppExtComObjHook.dll,SppExtComObjPatcher.dll,SppExtComObjPatcher.exe) do (
  if exist "%SysPath%\%%#" del /f /q "%SysPath%\%%#" %MultiNul%
  if exist "%SystemRoot%\SysWOW64\%%#" del /f /q "%SystemRoot%\SysWOW64\%%#" %MultiNul%
)
for %%# in (SppExtComObj.exe,sppsvc.exe,osppsvc.exe) do %REGEXE% query "%IFEO%\%%#" %MultiNul% && (
  call :RemoveIFEOEntry %%#
)
if %OSType% EQU Win8 schtasks /query /tn "%_TaskEx%" %MultiNul% && (
  schtasks /delete /f /tn "%_TaskEx%" %MultiNul%
)
goto :eof

:CreateIFEOEntry
reg delete "%IFEO%\%1" /f /v Debugger %MultiNul%
reg add "%IFEO%\%1" /f /v VerifierDlls /t REG_SZ /d "SppExtComObjHook.dll" %MultiNul%
reg add "%IFEO%\%1" /f /v VerifierDebug /t REG_DWORD /d 0x00000000 %MultiNul%
reg add "%IFEO%\%1" /f /v VerifierFlags /t REG_DWORD /d 0x80000000 %MultiNul%
reg add "%IFEO%\%1" /f /v GlobalFlag /t REG_DWORD /d 0x00000100 %MultiNul%
reg add "%IFEO%\%1" /f /v KMS_Emulation /t REG_DWORD /d 1 %MultiNul%
reg add "%IFEO%\%1" /f /v KMS_ActivationInterval /t REG_DWORD /d %KMS_ActivationInterval% %MultiNul%
reg add "%IFEO%\%1" /f /v KMS_RenewalInterval /t REG_DWORD /d %KMS_RenewalInterval% %MultiNul%

if /i %1 EQU SppExtComObj.exe if %WinBuild% GEQ 9600 (
  reg add "%IFEO%\%1" /f /v KMS_HWID /t REG_QWORD /d "%KMS_HWID%" %MultiNul%
)
goto :eof

:RemoveIFEOEntry
if /i %1 NEQ osppsvc.exe (
reg delete "%IFEO%\%1" /f %MultiNul%
goto :eof
)
if %OsppHook% EQU 0 (
reg delete "%IFEO%\%1" /f %MultiNul%
)
if %OsppHook% NEQ 0 for %%A in (Debugger,VerifierDlls,VerifierDebug,VerifierFlags,GlobalFlag,KMS_Emulation,KMS_ActivationInterval,KMS_RenewalInterval,Office2010,Office2013,Office2016,Office2019) do %REGEXE% delete "%IFEO%\%1" /v %%A /f %MultiNul%
reg add "HKLM\%OPPk%" /f /v KeyManagementServiceName /t REG_SZ /d "!IP_ADDRESS!" %MultiNul%
reg add "HKLM\%OPPk%" /f /v KeyManagementServicePort /t REG_SZ /d "1688" %MultiNul%
goto :eof

:UpdateIFEOEntry
reg add "%IFEO%\%1" /f /v KMS_ActivationInterval /t REG_DWORD /d %KMS_ActivationInterval% %MultiNul%
reg add "%IFEO%\%1" /f /v KMS_RenewalInterval /t REG_DWORD /d %KMS_RenewalInterval% %MultiNul%
if /i %1 EQU SppExtComObj.exe if %WinBuild% GEQ 9600 (
reg add "%IFEO%\%1" /f /v KMS_HWID /t REG_QWORD /d "%KMS_HWID%" %MultiNul%
)
if /i %1 EQU sppsvc.exe (
reg add "%IFEO%\SppExtComObj.exe" /f /v KMS_ActivationInterval /t REG_DWORD /d %KMS_ActivationInterval% %MultiNul%
reg add "%IFEO%\SppExtComObj.exe" /f /v KMS_RenewalInterval /t REG_DWORD /d %KMS_RenewalInterval% %MultiNul%
)

:UpdateOSPPEntry
if /i %1 EQU osppsvc.exe (
reg add "HKLM\%OPPk%" /f /v KeyManagementServiceName /t REG_SZ /d "%KMSHostIP%" %MultiNul%
reg add "HKLM\%OPPk%" /f /v KeyManagementServicePort /t REG_SZ /d "%KMSPort%" %MultiNul%
)
goto :eof

:StopService
:: Stop service based on parameter
sc query "%1" | find /i "STOPPED" %MultiNul% || (
  net stop "%1" /y %MultiNul%
)
sc query "%1" | find /i "STOPPED" %MultiNul% || (
  sc stop "%1" %MultiNul%
)
exit /b

:StartService
sc query "%~1" | %SingleNul% find /i "STOPPED" && %MultiNul% sc start "%~1"
sc query "%~1" | %SingleNul% find /i "RUNNING" || goto :StartService
goto:eof
