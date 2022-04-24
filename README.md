# ProcessTokenMonitor
### Overview
ProcessTokenMonitor is command line programm, writen in c++. The main goal of this program is verify IntegrityLevel and Privileges of process token object. The program accesses token fields via winapi. Next token's objects are monitored: IntegrityLevel, Privileges (SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_SECURITY_NAME, SE_RESTORE_NAME , SE_AUDIT_NAME), UserAndGroupsCount, CapabilitiesCount.
### How to use
#### 1. Compile
Import the project in Visual Studio and compile. Or compile by another programm, all code is located in file `ProcessTokenMonitor.cpp`.
#### Or get Release binaries
Compiled for x86 and x64, tested on Windows 10.
#### 2. Run
Run with startup arguments.\
`-h` - show help message;\
`-p` - pid to monitor;\
`--defender` - find and monitor process of Windows Defender (validated against pre);\
`-t` - delay between checks.\
Use ctr-c to exit program.
### Usage example
#### Monitor attack by provided pid
`.\ProcessTokenMonitor.exe -p pid`
![Alt text](Example1.jpg?raw=true)
#### Validate and monitore MsMpEng.exe attributes
`.\ProcessTokenMonitor.exe --defender -t 1`
![Alt text](Example2.jpg?raw=true)