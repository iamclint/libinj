#include "stdafx.h"
#include "libinj.h"
#include <Psapi.h>
#include <sstream>
#include <algorithm>
#include "ErrorLogger.h"

typedef BOOL(WINAPI *LpfnIswow64Process) (HANDLE, PBOOL);
LpfnIswow64Process fnIsWow64Process;
HANDLE proc_handle;

const char* getLastError()
{
	return ErrorLogger::LastErrorMsg.c_str();

}
BOOL SetPrivilege(const HANDLE hToken, const LPCTSTR lpszPrivilege, const BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		nullptr,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %lu\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		static_cast<PTOKEN_PRIVILEGES>(nullptr),
		static_cast<PDWORD>(nullptr)))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

bool Is32Bit(const DWORD pId)
{
	const auto procHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pId);
	auto bIsWow64 = FALSE;
	fnIsWow64Process = reinterpret_cast<LpfnIswow64Process>(GetProcAddress(GetModuleHandle("kernel32"), "IsWow64Process"));
	if (fnIsWow64Process != nullptr)
	{
		if (!fnIsWow64Process(procHandle, &bIsWow64))
		{
			//handle error
		}
	}
	CloseHandle(procHandle);
	return bIsWow64;
}

std::string getLastErrorAsString()
{
	//Get the error message, if any.
	const DWORD errorMessageId = ::GetLastError();
	if (errorMessageId == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	const size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, errorMessageId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPSTR>(&messageBuffer), 0, nullptr);

	std::string message(messageBuffer, size);
	message.erase(std::remove(message.begin(), message.end(), '\n'), message.end());
	message.erase(std::remove(message.begin(), message.end(), '\r'), message.end());
	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

bool Inject(uint64_t pId, char *dllName, int injectionMethod, HANDLE h)
{
	stringstream msg;
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		ErrorLogger::Log("OpenProcessToken Failed", true);
		return false;
	}
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		ErrorLogger::Log("SetPrivilege Failed", true);
		return false;
	}
	CloseHandle(hToken);

	switch (injectionMethod)
	{
		case 1: //loadlibary
		{
			if (!h) 
				h = OpenProcess(PROCESS_ALL_ACCESS, false, pId);
			if (h) {
				if (Is32Bit(pId))
				{
					return Inject32(dllName, h);
				}
				else {
					return Inject64(dllName, h);
				}

			} else {
				ErrorLogger::Log("Couldn't open handle to process");
				return false;
			}
		}
		case 2: //manual map
		{

		}
	default: ;
	}
	return true;
}



bool Inject32(char *dllName, HANDLE h)
{
	if (h)
	{
		stringstream msg;
		auto x = GetLastError();
		const auto loadLibraryAddress = reinterpret_cast<LPVOID>(getFunctionAddress32("kernelbase.dll", "loadlibrarya", h));

		if (ErrorLogger::Log("Failed to get kernelbase.dll, LoadLibraryA"))
			return false;

		const LPVOID dllPathPtr = VirtualAllocEx(h, nullptr, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (ErrorLogger::Log("Failed to allocate memory for the dll path"))
			return false;

		WriteProcessMemory(h, dllPathPtr, dllName, strlen(dllName), nullptr);

		if (ErrorLogger::Log("Failed to write process memory of the dllpath"))
			return false;

		const auto remoteThread = CreateRemoteThread(h, nullptr, NULL, static_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress), dllPathPtr, 0, nullptr);

		if (ErrorLogger::Log("Failed to CreateRemoteThread with the LoadLibraryA address"))
			return false;

		WaitForSingleObject(remoteThread, INFINITE);

		VirtualFreeEx(h, dllPathPtr, 0, MEM_RELEASE);

		if (ErrorLogger::Log("Failed to VirtualFreeEx memory for the dllpath"))
			return false;

		CloseHandle(remoteThread);
		CloseHandle(h);
		return true;
	}
	return false;
}

bool Inject64(char *dllName, HANDLE h)
{
	if (h)
	{
		auto x = GetLastError();
		const auto loadLibraryAddress = static_cast<LPVOID>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));

		if (ErrorLogger::Log("Failed to get kernel32.dll, LoadLibraryA"))
			return false;

		const auto dllPathPtr = VirtualAllocEx(h, nullptr, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (ErrorLogger::Log("Failed to allocate memory for the dll path"))
			return false;

		WriteProcessMemory(h, dllPathPtr, dllName, strlen(dllName), nullptr);

		if (ErrorLogger::Log("Failed to write process memory of the dllpath"))
			return false;

		const auto remoteThread = CreateRemoteThread(h, nullptr, NULL, static_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress), dllPathPtr, 0, nullptr);

		if (ErrorLogger::Log("Failed to CreateRemoteThread with the LoadLibraryA address"))
			return false;

		WaitForSingleObject(remoteThread, INFINITE);

		VirtualFreeEx(h, dllPathPtr, 0, MEM_RELEASE);

		if (ErrorLogger::Log("Failed to VirtualFreeEx memory for the dllpath"))
			return false;

		CloseHandle(remoteThread);
		CloseHandle(h);
		return true;
	}
	return false;
}

DWORD getFunctionAddress32(string mod, const string& functionName, HANDLE hProcess)
{
	DWORD modBase = GetModuleBase(hProcess, mod);
	if (modBase != 0) {
		IMAGE_DOS_HEADER dosHeaders;
		IMAGE_NT_HEADERS32 ntHeaders;
		IMAGE_EXPORT_DIRECTORY exportDirectory;
		ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(modBase), static_cast<LPVOID>(&dosHeaders), sizeof(IMAGE_DOS_HEADER), 0);
		if (dosHeaders.e_magic != IMAGE_DOS_SIGNATURE) return 0;
		ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(modBase + static_cast<DWORD>(dosHeaders.e_lfanew)), static_cast<LPVOID>(&ntHeaders), sizeof(IMAGE_NT_HEADERS32), 0);
		ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + modBase), static_cast<LPVOID>(&exportDirectory), sizeof(IMAGE_EXPORT_DIRECTORY), 0);
		for (DWORD i = 0; i < exportDirectory.NumberOfFunctions; i++)
		{
			//DWORD * ENTP = (DWORD*)((DWORD)mod + ((DWORD)EATP->AddressOfNames + (sizeof(DWORD)*i)));
			DWORD currentFunctionNamePtr;
			WORD currentFunctionNameOrdinalsPtr;
			DWORD currentFunctionVirtualAddress;

			char currentFunctionName[60];

			ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(modBase + exportDirectory.AddressOfNames + (i * sizeof(DWORD))), &currentFunctionNamePtr, sizeof(DWORD), nullptr); //get the virtual address to the name
			ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(modBase + currentFunctionNamePtr), &currentFunctionName, sizeof(currentFunctionName), nullptr); //read the name
			ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(modBase + exportDirectory.AddressOfNameOrdinals + (i * sizeof(WORD))), &currentFunctionNameOrdinalsPtr, sizeof(WORD), 0);
			ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(modBase + exportDirectory.AddressOfFunctions + (currentFunctionNameOrdinalsPtr * sizeof(DWORD))), &currentFunctionVirtualAddress, sizeof(DWORD), nullptr);

			string cName = currentFunctionName;
			transform(cName.begin(), cName.end(), cName.begin(), ::tolower);
			if (cName == functionName)
			{
				return (modBase + currentFunctionVirtualAddress);
			}
		}
	}
	return 0;
}

DWORD GetModuleBase(const HANDLE hProcess, string moduleName)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);
	EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL);
	for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
		char tmpmodName[256];
		if (GetModuleBaseName(hProcess, hMods[i], tmpmodName, sizeof(tmpmodName)))
		{

			std::string modName = tmpmodName;
			transform(modName.begin(), modName.end(), modName.begin(), ::tolower);
			if (moduleName == modName)
			{
				MODULEINFO modinf;
				GetModuleInformation(hProcess, hMods[i], &modinf, cbNeeded);
				return reinterpret_cast<DWORD>(modinf.lpBaseOfDll);
			}
		}
	}
	return 0;
}

DWORD GetBaseAddress(const uint64_t pid)
{
	MODULEENTRY32 me32;
	const auto hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	me32.dwSize = sizeof(me32);

	if (Module32First(hModule, &me32))
	{
		const auto rVal = reinterpret_cast<DWORD>(me32.modBaseAddr);
		CloseHandle(hModule);
		return rVal;
	}
	return 0;
}


