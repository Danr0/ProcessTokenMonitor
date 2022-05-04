#include <iostream>
#include <stdio.h>
#include <iostream>
#include <string>
#include <tchar.h>
#include <Windows.h>
#include <Shlobj.h>
#include <atlstr.h>
#include <process.h>
#include <strsafe.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <string>
#include <comdef.h>

void PrintHeaderMessage()
{
	std::cout << "***  Monitor programm token  ***\n";
	std::cout << "*******   Made by Danr0  *******\n";
}

char* getCmdOption(char** begin, char** end, const std::string& option)
{
	char** itr = std::find(begin, end, option);
	if (itr != end && ++itr != end)
	{
		return *itr;
	}
	return 0;
}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
	return std::find(begin, end, option) != end;
}

int GetTimeOptions(int argc, char* argv[])
{
	// Set time to sleep, default 1s
	int time_to_sleep = 10000; // default value = 10s
	if (cmdOptionExists(argv, argv + argc, "-t"))
	{
		char* arg_time = getCmdOption(argv, argv + argc, "-t");
		if (arg_time == nullptr)
		{
			printf("Invalid -t argumet");
			ExitProcess(-1);
		}
		time_to_sleep = atoi(arg_time);
	}
	return time_to_sleep;
}

void HelpOption(int argc, char* argv[])
{
	// Output help and exit
	if (cmdOptionExists(argv, argv + argc, "-h"))
	{
		std::cout << "Provide argument via startup arguments\n"
			<< "-p  pid to monitor\n"
			<< "-t  sleep time between checks (default 10 s) \n"
			<< "--defender  find and monitor MsMpEng.exe process, use default values\n";
		ExitProcess(-1);
	}
}

DWORD GetProcessIdByName(char* ProcName) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			const WCHAR* tmp_wc = entry.szExeFile;
			_bstr_t tmp_wc2(tmp_wc);
			const char* exec_filename = tmp_wc2;
			if (_stricmp(exec_filename, ProcName) == 0)
			{
				DWORD pid = entry.th32ProcessID;
				CloseHandle(snapshot);
				return pid;
			}
		}
	}
	printf("[-] ERROR: can't find process %s\n", ProcName);
	ExitProcess(-1);

}

DWORD GetPidOption(int argc, char* argv[])
{
	DWORD pid;
	// If no pid provided, get by name
	if (!cmdOptionExists(argv, argv + argc, "-p"))
	{
		pid = GetProcessIdByName((char*)"MsMpEng.exe");
	}
	else
	{
		char* pid_str = getCmdOption(argv, argv + argc, "-p");
		if (pid_str == nullptr)
		{
			printf("Invalid -p argumet");
			ExitProcess(-1);
		}
		pid = strtoul(pid_str, NULL, 10);

	}
	printf("Target PID: %d\n", pid);
	return pid;
}

BOOL WINAPI consoleHandler(DWORD signal) {

	if (signal == CTRL_C_EVENT)
		printf("Ctrl-C detected\n");
	printf("Exitting\n");
	ExitProcess(-1);

	return TRUE;
}


BOOL EnablePrivilege(LPCWSTR privilege) {
	LUID privLuid;
	if (!LookupPrivilegeValue(NULL, privilege, &privLuid)) {
		printf("[-] LookupPrivilegeValue error() : % u\n", GetLastError());
		return false;
	}
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;
	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("[-] OpenProcessToken() error : % u\n", GetLastError());
		return false;
	}
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = privLuid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, false, &tp, NULL, NULL, NULL)) {
		printf("[-] AdjustTokenPrivileges() error: %u\n", GetLastError());
		return false;
	}
	CloseHandle(hToken);
	CloseHandle(hProcess);
	return true;
}

void contextCheck() {
	if (IsUserAnAdmin()) {
		printf("[+] Administrator context found\n");
	}
	else {
		printf("[-] ERROR: run as administrator\n");
		ExitProcess(-1);
	}
	printf("Enabling SeDebugPrivilege\n");
	if (!EnablePrivilege(L"SeDebugPrivilege")) {
		printf("[-] ERROR: can't enable SeDebugPrivilege\nExiting...\n");
		ExitProcess(-1);
	}
	else {
		printf("[+] SeDebugPrivilege Enabled\n");
	}
}


BOOL CheckWindowsPrivilege(HANDLE hToken, const TCHAR* Privilege)
{
	/* Checks for Privilege and returns True or False. */
	LUID luid;
	PRIVILEGE_SET privs;
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL bResult;
	PrivilegeCheck(hToken, &privs, &bResult);
	return bResult;
}

int GetUserAndGroupsCount(HANDLE hToken)
{
	// Users and groups count check
	DWORD dwSize = 0, dwResult = 0;
	PTOKEN_GROUPS pGroupInfo;
	SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;

	if (!GetTokenInformation(hToken, TokenGroups, NULL, dwSize, &dwSize))
	{
		dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			printf("[-] GetTokenInformation Error %u\n", dwResult);
			ExitProcess(-1);
		}
	}
	pGroupInfo = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwSize);

	BOOL res = GetTokenInformation(hToken, TokenGroups, pGroupInfo, dwSize, &dwSize);
	if (res && pGroupInfo != nullptr)
	{
		int return_count = pGroupInfo->GroupCount;
		GlobalFree(pGroupInfo);
		return return_count;
	}
	else 
	{
		printf("[-] GetTokenInformation Error %u\n", GetLastError());
		GlobalFree(pGroupInfo);
		return 0;
	}
		
};

int CapabilitiesCount(HANDLE hToken)
{
	// Users and groups count check
	DWORD dwSize = 0, dwResult = 0;
	PTOKEN_GROUPS pGroupInfo;
	SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;

	if (!GetTokenInformation(hToken, TokenCapabilities, NULL, dwSize, &dwSize))
	{
		dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			printf("[-] GetTokenInformation Error %u\n", dwResult);
			ExitProcess(-1);
		}
	}
	pGroupInfo = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwSize);

	BOOL res = GetTokenInformation(hToken, TokenCapabilities, pGroupInfo, dwSize, &dwSize);
	if (res && pGroupInfo != nullptr)
	{
		int return_count = pGroupInfo->GroupCount;
		GlobalFree(pGroupInfo);
		return return_count;
	}
	else
	{
		printf("[-] GetTokenInformation Error %u\n", GetLastError());
		GlobalFree(pGroupInfo);
		return 0;
	}

};

DWORD GetIntegrityLevel(HANDLE hToken) {
	// Integrity check
	DWORD dwSize = 0, dwResult = 0;
	DWORD token_info_length = 0;
	TOKEN_MANDATORY_LABEL* token_label = NULL;

	if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &token_info_length))
	{
		
		dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			printf("[-] GetTokenInformation Error %u\n", dwResult);
			ExitProcess(-1);
		}
	}

	token_label = (TOKEN_MANDATORY_LABEL*)GlobalAlloc(LPTR, token_info_length);

	if (!GetTokenInformation(hToken, TokenIntegrityLevel, token_label, token_info_length, &token_info_length))
	{
		dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			printf("[-] GetTokenInformation Error %u\n", dwResult);
			ExitProcess(-1);
		}
	}

	if (token_label == NULL)
	{
		printf("[-] Token Label Error \n");
		GlobalFree(token_label);
		return SECURITY_MANDATORY_UNTRUSTED_RID;
	}
	else
	{
		UCHAR subAuthorityCount = *::GetSidSubAuthorityCount(token_label->Label.Sid);
		if (!subAuthorityCount)
		{ 
			dwResult = GetLastError();
			if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
				printf("[-] GetSidSubAuthorityCount Error %u\n", dwResult);
				ExitProcess(-1);
			}
		}

		DWORD integrity_level = *::GetSidSubAuthority(token_label->Label.Sid, static_cast<DWORD>(subAuthorityCount - 1));
		if (!integrity_level)
		{
			dwResult = GetLastError();
			if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
				return SECURITY_MANDATORY_UNTRUSTED_RID;
			}
		}
		GlobalFree(token_label);

		return integrity_level;
	}
	
};

struct TokenInformation
{
	BOOL starting_is_debug;
	BOOL starting_impersonate;
	BOOL starting_security;
	BOOL starting_restore;
	BOOL starting_audit;
	int starting_count;
	DWORD starting_intlvl;
	int starting_cap_count;
};

TokenInformation GetProcessInfoByPid(DWORD pid)
{
	// Get token of process by pid
	TokenInformation info;
	HANDLE hToken;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
	if (hProcess == NULL) {
		printf("OpenProcess() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("Process opened succeed!\n");
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		printf("[-] OpenProcessToken() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("Open process token succeed!\n");

	// Privileges from https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
	info.starting_is_debug = CheckWindowsPrivilege(hToken, SE_DEBUG_NAME);
	printf("Debug privilege %d\n", info.starting_is_debug);
	info.starting_impersonate = CheckWindowsPrivilege(hToken, SE_IMPERSONATE_NAME);
	printf("Impersonate privilege %d\n", info.starting_impersonate);
	info.starting_security = CheckWindowsPrivilege(hToken, SE_SECURITY_NAME);
	printf("Security privilege %d\n", info.starting_security);
	info.starting_restore = CheckWindowsPrivilege(hToken, SE_RESTORE_NAME);
	printf("Restore privilege %d\n", info.starting_restore);
	info.starting_audit = CheckWindowsPrivilege(hToken, SE_AUDIT_NAME);
	printf("Audit privilege %d\n", info.starting_audit);

	// GetUserAndGroupsCount
	info.starting_count = GetUserAndGroupsCount(hToken);
	printf("Total User and Groups count: %d\n", info.starting_count);

	// GetUserAndGroupsCount
	info.starting_cap_count = CapabilitiesCount(hToken);
	printf("Capabilities count: %d\n", info.starting_cap_count);

	// IntegrityLevel
	info.starting_intlvl = GetIntegrityLevel(hToken);
	printf("Inetgrity: %lu - ", info.starting_intlvl);
	if (info.starting_intlvl < SECURITY_MANDATORY_LOW_RID)
		printf("UNTRUSTED_INTEGRITY\n");
	else if (info.starting_intlvl < SECURITY_MANDATORY_MEDIUM_RID)
		printf("LOW_INTEGRITY\n");
	else if (info.starting_intlvl >= SECURITY_MANDATORY_MEDIUM_RID &&
		info.starting_intlvl < SECURITY_MANDATORY_HIGH_RID) {
		printf("MEDIUM_INTEGRITY\n");
	}
	else if (info.starting_intlvl >= SECURITY_MANDATORY_HIGH_RID)
		printf("HIGH_INTEGRITY\n");

	// close handlers
	CloseHandle(hToken);
	CloseHandle(hProcess);
	return info;
}

void StartMonitoringByPid(DWORD pid, int time_to_sleep, TokenInformation info)
{
	std::cout << "[+] Start monitoring!\n";
	HANDLE hToken;
	HANDLE new_hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
	bool is_modified = false;
	while (TRUE)
	{
		Sleep(time_to_sleep);
		OpenProcessToken(new_hProcess, TOKEN_QUERY, &hToken);
		if (CheckWindowsPrivilege(hToken, SE_DEBUG_NAME) != info.starting_is_debug || info.starting_audit != CheckWindowsPrivilege(hToken, SE_AUDIT_NAME) ||
			info.starting_restore != CheckWindowsPrivilege(hToken, SE_RESTORE_NAME) || info.starting_security != CheckWindowsPrivilege(hToken, SE_SECURITY_NAME)
			|| info.starting_impersonate != CheckWindowsPrivilege(hToken, SE_IMPERSONATE_NAME)) {
			printf("[!] Privileges changed!\n");
			is_modified = true;
		}
		if (GetUserAndGroupsCount(hToken) != info.starting_count) {
			printf("[!] UserAndGroups changed!\n");
			is_modified = true;
		}
		if (CapabilitiesCount(hToken) != info.starting_cap_count) {
			printf("[!] Capabilities changed!\n");
			is_modified = true;
		}
		if (GetIntegrityLevel(hToken) < info.starting_intlvl) {
			printf("[!] Integrity level changed!\n");
			is_modified = true;
		}
		// close handlers
		CloseHandle(hToken);

		if (is_modified) {
			printf("[!][!] Attack detected! [!][!]\n");
			CloseHandle(new_hProcess);
			ExitProcess(1);
		}
		else
			printf("[+] No changes detected\n");
	};
}

int main(int argc, char* argv[])
{
	PrintHeaderMessage();

	// Check for admin context
	contextCheck();

	// Set console handler
	if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
		printf("[-] ERROR: Could not set control handler");
	}

	// Get cmd options
	HelpOption(argc, argv);
	int time_to_sleep = GetTimeOptions(argc, argv);
	DWORD pid = GetPidOption(argc, argv);
	BOOL is_defender_target = (cmdOptionExists(argv, argv + argc, "--defender")
		|| (!cmdOptionExists(argv, argv + argc, "-p") && !cmdOptionExists(argv, argv + argc, "--defender")));

	TokenInformation info;
	if (is_defender_target)
	{
		//Defender default attributes
		info.starting_is_debug = TRUE;
		info.starting_impersonate = TRUE;
		info.starting_security = TRUE;
		info.starting_restore = TRUE;
		info.starting_audit = FALSE;
		info.starting_count = 11;
		info.starting_intlvl = SECURITY_MANDATORY_HIGH_RID;
		info.starting_cap_count = 0;
	}
	else
	{
		info = GetProcessInfoByPid(pid);
	}

	StartMonitoringByPid(pid, time_to_sleep, info);
}