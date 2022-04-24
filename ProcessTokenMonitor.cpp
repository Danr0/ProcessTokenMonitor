// detecter.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
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
		}
	}
	// Allocate the buffer.
	pGroupInfo = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwSize);

	// Call GetTokenInformation again to get the group information.
	BOOL res = GetTokenInformation(hToken, TokenGroups, pGroupInfo, dwSize, &dwSize);
	if (res && pGroupInfo != nullptr)
		return pGroupInfo->GroupCount;
	else 
	{
		printf("[-] GetTokenInformation Error %u\n", GetLastError());
		return 0;
	}
		
};

DWORD GetIntegrityLevel(HANDLE hToken) {
	// Integrity check
	DWORD dwSize = 0, dwResult = 0;
	DWORD token_info_length = 256;

	auto token_label_bytes = std::make_unique<char[]>(token_info_length);
	TOKEN_MANDATORY_LABEL* token_label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(token_label_bytes.get());

	if (!GetTokenInformation(hToken, TokenIntegrityLevel, token_label, token_info_length, &token_info_length))
	{
		dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			printf("[-] GetTokenInformation Error %u\n", dwResult);
		}
		printf("UNTRUSTED_INTEGRITY\n");
		return SECURITY_MANDATORY_UNTRUSTED_RID;
	}

	DWORD integrity_level = *::GetSidSubAuthority(
		token_label->Label.Sid, static_cast<DWORD>(*::GetSidSubAuthorityCount(token_label->Label.Sid) - 1));

	return integrity_level;

};

DWORD GetSessionID(HANDLE hToken) {
	DWORD dwSize = 0, dwResult = 0;
	DWORD token_session_id = -1;
	if (!GetTokenInformation(hToken, TokenSessionId, nullptr, 0, &token_session_id))
	{
		dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			printf("[-] GetTokenInformation Error %u\n", dwResult);
		}
	}
	return token_session_id;
}

int main(int argc, char* argv[])
{
	std::cout << "***  Monitor programm token  ***\n";
	std::cout << "*******   Made by Danr0  *******\n";

	// Set console handler
	if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
		printf("[-] ERROR: Could not set control handler");
	}

	// Output help and exit
	if (cmdOptionExists(argv, argv + argc, "-h"))
	{
		std::cout << "Provide argument via startup arguments\n"
			<< "-p  pid to monitor\n"
			<< "-t  sleep time between checks (default 10 s) \n";
		ExitProcess(-1);
	}

	// Get pid to monitor 
	if (!cmdOptionExists(argv, argv + argc, "-p"))
	{
		std::cout << "[!] No require -p argument\n";
		ExitProcess(-1);
	}
	char* pid_str = getCmdOption(argv, argv + argc, "-p");
	DWORD pid = strtoul(pid_str, NULL, 10);
	printf("Target PID: %d\n", pid);

	// Set time to sleep, default 1s
	int time_to_sleep = 10000;
	if (cmdOptionExists(argv, argv + argc, "-t"))
	{
		time_to_sleep = atoi(getCmdOption(argv, argv + argc, "-t"));
	}

	// Check for admin context
	contextCheck();

	// Get token of process
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
	if (hProcess == NULL) {
		printf("OpenProcess() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("Process opened succeed!\n");
	HANDLE hToken;
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		printf("[-] OpenProcessToken() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("Open process token succeed!\n");

	// Privileges from https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
	BOOL starting_is_debug = CheckWindowsPrivilege(hToken, SE_DEBUG_NAME);
	printf("Debug privilege %d\n", starting_is_debug);
	BOOL starting_impersonate = CheckWindowsPrivilege(hToken, SE_IMPERSONATE_NAME);
	printf("Impersonate privilege %d\n", starting_impersonate);
	BOOL starting_security = CheckWindowsPrivilege(hToken, SE_SECURITY_NAME);
	printf("Security privilege %d\n", starting_security);
	BOOL starting_restore = CheckWindowsPrivilege(hToken, SE_RESTORE_NAME);
	printf("Restore privilege %d\n", starting_restore);
	BOOL starting_audit = CheckWindowsPrivilege(hToken, SE_AUDIT_NAME);
	printf("Audit privilege %d\n", starting_audit);

	// GetUserAndGroupsCount
	int starting_count = GetUserAndGroupsCount(hToken);
	printf("Total User and Groups count: %d\n", starting_count);

	// IntegrityLevel
	DWORD starting_intlvl = GetIntegrityLevel(hToken);
	printf("Inetgrity: %lu\n", starting_intlvl);
	if (starting_intlvl < SECURITY_MANDATORY_LOW_RID)
		printf("UNTRUSTED_INTEGRITY\n");

	if (starting_intlvl < SECURITY_MANDATORY_MEDIUM_RID)
		printf("LOW_INTEGRITY\n");

	if (starting_intlvl >= SECURITY_MANDATORY_MEDIUM_RID &&
		starting_intlvl < SECURITY_MANDATORY_HIGH_RID) {
		printf("MEDIUM_INTEGRITY\n");
	}

	if (starting_intlvl >= SECURITY_MANDATORY_HIGH_RID)
		printf("HIGH_INTEGRITY\n");

	// TokenSessionId
	DWORD starting_ses_id = GetSessionID(hToken);
	printf("SessionID: %lu\n", starting_ses_id);

	// close handlers
	CloseHandle(hToken);
	CloseHandle(hProcess);

	std::cout << "[+] Start monitoring!\n";
	bool is_modified = false;
	while (TRUE)
	{
		Sleep(time_to_sleep);
		HANDLE new_hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);

		OpenProcessToken(new_hProcess, TOKEN_QUERY, &hToken);
		if (CheckWindowsPrivilege(hToken, SE_DEBUG_NAME) != starting_is_debug or starting_audit != CheckWindowsPrivilege(hToken, SE_AUDIT_NAME) or
			starting_restore != CheckWindowsPrivilege(hToken, SE_RESTORE_NAME) or starting_security != CheckWindowsPrivilege(hToken, SE_SECURITY_NAME)
			or starting_impersonate != CheckWindowsPrivilege(hToken, SE_IMPERSONATE_NAME)) {
			printf("[!] Privileges changed!\n");
			is_modified = true;
		}
		if (GetUserAndGroupsCount(hToken) != starting_count) {
			printf("[!] UserAndGroups changed!\n");
			is_modified = true;
		}
		if (GetIntegrityLevel(hToken) != starting_intlvl) {
			printf("[!] Integrity level changed!\n");
			is_modified = true;
		}
		if (GetSessionID(hToken) != starting_ses_id) {
			printf("[!] Session id changed\n!");
			is_modified = true;
		}
		// close handlers
		CloseHandle(new_hProcess);
		CloseHandle(hToken);

		if (is_modified) {
			printf("[!][!] Attack detected! [!][!]\n");
			ExitProcess(1);
		}
		else
			printf("[+] No changes detected\n");
	};
}