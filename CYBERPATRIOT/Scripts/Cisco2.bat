@echo off
setlocal enabledelayedexpansion
net session
cls
set /A PASSWORD = "" 
:menu
    cls
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "1)Hostnames		        2)Set Password(Should remain automated)"
    echo "69)Exit			    	70)Reset Script"
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    set /p answer=Please choose an option:
        if "%answer%"=="1" goto :Hostnames
        if "%answer%"=="2" goto :passwd
        if "%answer%"=="69" exit
        if "%answer%"=="70" goto :ResetScript
        if "%answer%"==%answer% goto :menu
:ResetScript
    PASSWORD = ""
    type Cisco.txt
    echo "" > Cisco.txt
    set /p aa=Continue:
    goto :menu
:Hostnames
	cls
    set /p Hostname=What is the hostname:
    echo enable >> Cisco.txt
    echo configure terminal >> Cisco.txt
    echo !PASSWORD! >> Cisco.txt
    echo hostname !Hostname! >> Cisco.txt
    type Cisco.txt
    set /p aa=Continue:
    goto :menu

:passwd
    cls
    echo enable >> Cisco.txt
    echo configure terminal >> Cisco.txt
    echo !PASSWORD! >> Cisco.txt
    set /p PASSWORD=What is the password:
    echo enable password !PASSWORD! >> Cisco.txt
    type Cisco.txt
    set /p aa=Continue:
    goto :menu
