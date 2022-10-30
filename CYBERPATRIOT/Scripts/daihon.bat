@echo on
@echo off
setlocal enabledelayedexpansion
net session
if %errorlevel%==0 (
	echo Admin rights granted!
) else (
    echo Failure, no rights
	pause
    exit
)

cls
:menu
	echo "~~~~~~~~~~~~~~~~~~~~~Edited by: Sen Yakandawala 2026 GANG~~~~~~~~~~~~~~~~~~~~"
	echo "1)Set user properties				2)Set password policy"
	echo "3)Set lockout policy				4)Search for media files"
	echo "5)Automation go BRRR				6)remote Desktop Config"
	echo "7)Security options				8)Edit groups"
	echo "9)Finding file paths				10)Audit the machine"
	echo "2026)Exit							69)Reboot"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	set /p answer=Please choose an option:
		if "%answer%"=="1" goto :userProp
		if "%answer%"=="2" goto :passwdPol
		if "%answer%"=="3" goto :lockout
		if "%answer%"=="4" goto :badFiles
		if "%answer%"=="5" goto :UAC
		if "%answer%"=="6" goto :remDesk
		if "%answer%"=="7" goto :secOpt
		if "%answer%"=="8" goto :group
		if "%answer%"=="9" goto :findFiles
		if "%answer%"=="10" goto :audit
		if "%answer%"=="2026" exit
		if "%answer%"=="69" shutdown /r
		if "%answer%"=="%answer%" goto :menu
	pause

:userProp
	echo Setting password never expires
	wmic UserAccount set PasswordExpires=True
	wmic UserAccount set PasswordChangeable=True
	wmic UserAccount set PasswordRequired=True

	pause
	goto :menu

:passwdPol
	rem Sets the password policy
	rem Set complexity requirements
	echo Setting password policies
	echo Make sure to disable
	net accounts /minpwlen:8
	net accounts /maxpwage:90
	net accounts /minpwage:10
	net accounts /uniquepw:3
	net accounts /uniquepw:3
	pause
	goto :menu

:lockout
	rem Sets the lockout policy
	echo Setting the lockout policy
	net accounts /lockoutduration:30
	net accounts /lockoutthreshold:5
	net accounts /lockoutwindow:30

	pause
	goto :menu

:firewall
	rem Enables firewall
	netsh advfirewall set allprofiles state on
	netsh advfirewall reset

	pause
	goto :menu

:badFiles
	echo "1)Audio		2)Video		3)Image"
	set /p answer=Choose which file type to delete:
		if "%answer%"=="1" goto :aud
		if "%answer%"=="2" goto :vid
		if "%answer%"=="3" goto :img

:aud
	for %%drive in (C D E F) do (
	   for /R %drive:\ %%f in (*.midi *.mid *.mod *.mp3 *.mp2 *.mpa *.abs *.mpega *.au *.snd *.wav *.aiff *.aif *.sid *.flac *.ogg) do (
	       @echo del "%f"
	   )
	)

	goto :menu
:vid
	for %%drive in (C D E F) do (
	   for /R %drive:\ %%f in (*.mpeg *.mpg *.mpe *.dl *.movie *.movi *.mv *.iff *.anim5 *.anim3 *.anim7 *.avi *.vfw *.avx *.fli *.flc *.mov *.qt *.spl *.swf *.dcr *.dir *.dxr *.rpm *.rm *.smi *.ra *.ram *.rv *.wmv *.asf *.asx *.wma *.wax *.wmv *.wmx *.3gp *.mov *.mp4 *.avi *.swf *.flv *.m4v) do (
	       @echo del "%f"
	   )
	)

	goto :menu
:img
	for %%drive in (C D E F) do (
	   for /R %drive:\ %%f in (*.tiff *.tif *.rs *.im1 *.gif *.jpeg *.jpg *.jpe *.png *.rgb *.xwd *.xpm *.ppm *.pbm *.pgm *.pcx *.ico *.svg *.svgz *.tiff *.tif *.rs *.im1 *.gif *.jpeg *.jpg *.jpe *.png *.rgb *.xwd *.xpm *.ppm *.pbm *.pgm *.pcx *.ico *.svg *.svgz) do (
	       @echo del "%f"
	   )
	)

		goto :menu

:services
	echo Disabling Services
	sc stop TapiSrv
	sc config TapiSrv start= disabled
	sc stop TlntSvr
	sc config TlntSvr start= disabled
	sc stop ftpsvc
	sc config ftpsvc start= disabled
	sc stop SNMP
	sc config SNMP start= disabled
	sc stop SessionEnv
	sc config SessionEnv start= disabled
	sc stop TermService
	sc config TermService start= disabled
	sc stop UmRdpService
	sc config UmRdpService start= disabled
	sc stop SharedAccess
	sc config SharedAccess start= disabled
	sc stop remoteRegistry
	sc config remoteRegistry start= disabled
	sc stop SSDPSRV
	sc config SSDPSRV start= disabled
	sc stop W3SVC
	sc config W3SVC start= disabled
	sc stop SNMPTRAP
	sc config SNMPTRAP start= disabled
	sc stop remoteAccess
	sc config remoteAccess start= disabled
	sc stop RpcSs
	sc config RpcSs start= disabled
	sc stop HomeGroupProvider
	sc config HomeGroupProvider start= disabled
	sc stop HomeGroupListener
	sc config HomeGroupListener start= disabled

	pause
	goto :menu

:UAC
	REM Automation found from all over the interwebs, sources unknown, please open issue.
	REM Turns on UAC
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
	REM Turns off RDP
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

	REM Failsafe
	if %errorlevel%==1 netsh advfirewall firewall set service type = remotedesktop mode = disable
	REM Windows auomatic updates
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f


	echo Cleaning out the DNS cache...
	ipconfig /flushdns
	echo Writing over the hosts file...
	attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
	echo > C:\Windows\System32\drivers\etc\hosts
	if %errorlevel%==1 echo There was an error in writing to the hosts file (not running this as Admin probably)
	REM Services
	echo Showing you the services...
	net start
	echo Now writing services to a file and searching for vulnerable services...
	net start > servicesstarted.txt
	echo This is only common services, not nessecarily going to catch 100%
	REM looks to see if remote registry is on
	net start | findstr Remote Registry
	if %errorlevel%==0 (
		echo Remote Registry is running!
		echo Attempting to stop...
		net stop RemoteRegistry
		sc config RemoteRegistry start=disabled
		if %errorlevel%==1 echo Stop failed... sorry...
	) else (
		echo Remote Registry is already indicating stopped.
	)
	REM Remove all saved credentials
	cmdkey.exe /list > "%TEMP%\List.txt"
	findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
	FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
	del "%TEMP%\*.*" /s /f /q
	set SRVC_LIST=(RemoteAccess Telephony tlntsvr p2pimsvc simptcp fax msftpsvc)
		for %%i in %HITHERE% do net stop %%i
		for %%i in %HITHERE% sc config %%i start= disabled
	netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no >NUL
	netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no >NUL
	netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no >NUL
	netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no >NUL
	netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no >NUL
	netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no >NUL
	netsh advfirewall firewall set rule name="Telnet Server" new enable=no >NUL
	netsh advfirewall firewall set rule name="netcat" new enable=no >NUL
	dism /online /disable-feature /featurename:IIS-WebServerRole >NUL
	dism /online /disable-feature /featurename:IIS-WebServer >NUL
	dism /online /disable-feature /featurename:IIS-CommonHttpFeatures >NUL
	dism /online /disable-feature /featurename:IIS-HttpErrors >NUL
	dism /online /disable-feature /featurename:IIS-HttpRedirect >NUL
	dism /online /disable-feature /featurename:IIS-ApplicationDevelopment >NUL
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility >NUL
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility45 >NUL
	dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics >NUL
	dism /online /disable-feature /featurename:IIS-HttpLogging >NUL
	dism /online /disable-feature /featurename:IIS-LoggingLibraries >NUL
	dism /online /disable-feature /featurename:IIS-RequestMonitor >NUL
	dism /online /disable-feature /featurename:IIS-HttpTracing >NUL
	dism /online /disable-feature /featurename:IIS-Security >NUL
	dism /online /disable-feature /featurename:IIS-URLAuthorization >NUL
	dism /online /disable-feature /featurename:IIS-RequestFiltering >NUL
	dism /online /disable-feature /featurename:IIS-IPSecurity >NUL
	dism /online /disable-feature /featurename:IIS-Performance >NUL
	dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic >NUL
	dism /online /disable-feature /featurename:IIS-WebServerManagementTools >NUL
	dism /online /disable-feature /featurename:IIS-ManagementScriptingTools >NUL
	dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility >NUL
	dism /online /disable-feature /featurename:IIS-Metabase >NUL
	dism /online /disable-feature /featurename:IIS-HostableWebCore >NUL
	dism /online /disable-feature /featurename:IIS-StaticContent >NUL
	dism /online /disable-feature /featurename:IIS-DefaultDocument >NUL
	dism /online /disable-feature /featurename:IIS-DirectoryBrowsing >NUL
	dism /online /disable-feature /featurename:IIS-WebDAV >NUL
	dism /online /disable-feature /featurename:IIS-WebSockets >NUL
	dism /online /disable-feature /featurename:IIS-ApplicationInit >NUL
	dism /online /disable-feature /featurename:IIS-ASPNET >NUL
	dism /online /disable-feature /featurename:IIS-ASPNET45 >NUL
	dism /online /disable-feature /featurename:IIS-ASP >NUL
	dism /online /disable-feature /featurename:IIS-CGI >NUL
	dism /online /disable-feature /featurename:IIS-ISAPIExtensions >NUL
	dism /online /disable-feature /featurename:IIS-ISAPIFilter >NUL
	dism /online /disable-feature /featurename:IIS-ServerSideIncludes >NUL
	dism /online /disable-feature /featurename:IIS-CustomLogging >NUL
	dism /online /disable-feature /featurename:IIS-BasicAuthentication >NUL
	dism /online /disable-feature /featurename:IIS-HttpCompressionStatic >NUL
	dism /online /disable-feature /featurename:IIS-ManagementConsole >NUL
	dism /online /disable-feature /featurename:IIS-ManagementService >NUL
	dism /online /disable-feature /featurename:IIS-WMICompatibility >NUL
	dism /online /disable-feature /featurename:IIS-LegacyScripts >NUL
	dism /online /disable-feature /featurename:IIS-LegacySnapIn >NUL
	dism /online /disable-feature /featurename:IIS-FTPServer >NUL
	dism /online /disable-feature /featurename:IIS-FTPSvc >NUL
	dism /online /disable-feature /featurename:IIS-FTPExtensibility >NUL
	dism /online /disable-feature /featurename:TFTP >NUL
	dism /online /disable-feature /featurename:TelnetClient >NUL
	dism /online /disable-feature /featurename:TelnetServer >NUL
	reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
	reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
	reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /t
	reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d /1 /f
	reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
	reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
	reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
	reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
	REM Common Policies
	REM Restrict CD ROM drive
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
	REM Automatic Admin logon
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
	REM Logo message text
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d "Lol noobz pl0x don't hax, thx bae"
	REM Logon message title bar
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "Dnt hax me"
	REM Wipe page file from shutdown
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
	REM LOL this is a key? Disallow remote access to floppie disks
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
	REM Prevent print driver installs
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
	REM Limit local account use of blank passwords to console
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
	REM Auditing access of Global System Objects
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
	REM Auditing Backup and Restore
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
	REM Do not display last user on logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
	REM UAC setting (Prompt on Secure Desktop)
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
	REM Enable Installer Detection
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
	REM Undock without logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
	REM Maximum Machine Password Age
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
	REM Disable machine account password changes
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
	REM Require Strong Session Key
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
	REM Require Sign/Seal
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
	REM Sign Channel
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
	REM Seal Channel
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
	REM Don't disable CTRL+ALT+DEL even though it serves no purpose
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
	REM Restrict Anonymous Enumeration #1
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
	REM Restrict Anonymous Enumeration #2
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
	REM Idle Time Limit - 45 mins
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
	REM Require Security Signature - Disabled pursuant to checklist
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f
	REM Enable Security Signature - Disabled pursuant to checklist
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f
	REM Disable Domain Credential Storage
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
	REM Don't Give Anons Everyone Permissions
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
	REM SMB Passwords unencrypted to third party? How bout nah
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
	REM Null Session Pipes Cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
	REM Remotely accessible registry paths cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
	REM Remotely accessible registry paths and sub-paths cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
	REM Restict anonymous access to named pipes and shares
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
	REM Allow to use Machine ID for NTLM
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
	echo whole lotta stuff been done homie
	pause
	goto :menu

:remDesk
	rem Ask for remote desktop
	set /p answer=Do you want remote desktop enabled?[y/n]
	if /I "%answer%"=="y" (
		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
		echo RemoteDesktop has been enabled, reboot for this to take full effect.
	)
	if /I "%answer%"=="n" (
		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
		echo RemoteDesktop has been disabled, reboot for this to take full effect.
	)

	pause
	goto :menu

:secOpt
	echo Changing security options now.

	rem Restrict CD ROM drive
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

	rem Automatic Admin logon
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

	rem Logon message text
	set /p body=Please enter logon text:
		reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticetext" /v LegalNoticeText /t REG_SZ /d "%body%"

	rem Logon message title bar
	set /p subject=Please enter the title of the message:
		reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticecaption" /v LegalNoticeCaption /t REG_SZ /d "%subject%"

	rem Wipe page file from shutdown
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f

	rem Disallow remote access to floppie disks
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f

	rem Prevent print driver installs
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

	rem Limit local account use of blank passwords to console
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

	rem Auditing access of Global System Objects
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f

	rem Auditing Backup and Restore
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f

	rem Do not display last user on logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f

	rem UAC setting (Prompt on Secure Desktop)
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f

	rem Enable Installer Detection
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f

	rem Undock without logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f

	rem Maximum Machine Password Age
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f

	rem Disable machine account password changes
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f

	rem Require Strong Session Key
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f

	rem Require Sign/Seal
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f

	rem Sign Channel
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f

	rem Seal Channel
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f

	rem Don't disable CTRL+ALT+DEL even though it serves no purpose
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f

	rem Restrict Anonymous Enumeration #1
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f

	rem Restrict Anonymous Enumeration #2
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f

	rem Idle Time Limit - 45 mins
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f

	rem Require Security Signature - Disabled pursuant to checklist
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f

	rem Enable Security Signature - Disabled pursuant to checklist
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f

	rem Disable Domain Credential Storage
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f

	rem Don't Give Anons Everyone Permissions
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f

	rem SMB Passwords unencrypted to third party
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f

	rem Null Session Pipes Cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f

	rem remotely accessible registry paths cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f

	rem remotely accessible registry paths and sub-paths cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f

	rem Restict anonymous access to named pipes and shares
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f

	rem Allow to use Machine ID for NTLM
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f

	rem Enables DEP
	bcdedit.exe /set {current} nx AlwaysOn
	pause
	goto :menu

:group
	cls
	net localgroup
	set /p grp=What group would you like to check?:
	net localgroup !grp!
	set /p answer=Is there a user you would like to add or remove?[add/remove/back]:
	if "%answer%"=="add" (
		set /p userAdd=Please enter the user you would like to add:
		net localgroup !grp! !userAdd! /add
		echo !userAdd! has been added to !grp!
	)
	if "%answer%"=="remove" (
		set /p userRem=Please enter the user you would like to remove:
		net localgroup !grp! !userRem! /delete
		echo !userRem! has been removed from !grp!
	)
	if "%answer%"=="back" (
		goto :group
	)

	set /p answer=Would you like to go check again?[y/n]
	if /I "%answer%"=="y" (
		goto :group
	)
	if /I "%answer%"=="n" (
		goto :menu

:findFiles
	cd C:\
	set /p filename=Please type the file name:
	dir %filename% /s /p
	pause

	goto :menu

:audit
	echo Auditing the maching now
	auditpol /set /category:* /success:enable
	auditpol /set /category:* /failure:enable

	pause
	goto :menu

endlocal
