#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <string>
#include <algorithm>
#define libinj_api __declspec(dllexport)
using namespace std;
extern "C"
{
	libinj_api	DWORD pe_getFunctionAddress32(uint64_t pId, string mod, string fn, HANDLE hProcess);
	libinj_api	DWORD getBaseAddress(uint64_t pid);
	libinj_api	DWORD getModuleBase(HANDLE hProcess, string moduleName);
	libinj_api	bool is32bit(DWORD pId);
	libinj_api  bool Inject(uint64_t pId, char *dllName, int injection_method, HANDLE h);
	libinj_api	bool Inject64(char *dllName, HANDLE h);
	libinj_api	bool Inject32(uint64_t pId, char *dllName, HANDLE h);
	libinj_api	const char* getLastError();
	libinj_api	std::string getLastErrorAsString();
	libinj_api	BOOL setPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
	bool logError(std::string log_msg, bool bypass_getlasterror);
}