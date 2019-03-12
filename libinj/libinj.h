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
	libinj_api	DWORD getFunctionAddress32(string mod, const string& functionName, HANDLE hProcess);
	libinj_api	DWORD GetBaseAddress(uint64_t pid);
	libinj_api	DWORD GetModuleBase(HANDLE hProcess, string moduleName);
	libinj_api	bool Is32Bit(DWORD pId);
	libinj_api  bool Inject(uint64_t pId, char *dllName, int injectionMethod, HANDLE h);
	libinj_api	bool Inject64(char *dllName, HANDLE h);
	libinj_api	bool Inject32(char *dllName, HANDLE h);
	libinj_api	const char* getLastError();
	libinj_api	std::string getLastErrorAsString();
	libinj_api	BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
}