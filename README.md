# ProcessTokenMonitor
### Overview
The main goal of this program is verify integrity of process token object. The program accesses token fields via winapi. Next token's objects are monitored: IntegrityLevel, Privileges (SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_SECURITY_NAME, SE_RESTORE_NAME , SE_AUDIT_NAME), UserAndGroupsCount, SessionID.
### How to use
Compile this project, all code is located in file detecter.cpp.
Run with option -p pid. Use ctr-c to exit program.
### Usage example
![Alt text](Example.jpg?raw=true)