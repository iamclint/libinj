#include "stdafx.h"
#include "libinj.h"
#include <Psapi.h>
#include <sstream>
#include <algorithm>

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;
HANDLE proc_handle;
string last_error_msg;
const char* getLastError()
{
	return last_error_msg.c_str();

}
BOOL setPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
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
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
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

bool is32bit(DWORD pId)
{
	HANDLE proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pId);
	BOOL bIsWow64 = FALSE;

	//IsWow64Process is not available on all supported versions of Windows.
	//Use GetModuleHandle to get a handle to the DLL that contains the function
	//and GetProcAddress to get a pointer to the function if available.

	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle("kernel32"), "IsWow64Process");

	if (fnIsWow64Process != NULL)
	{
		if (!fnIsWow64Process(proc_handle, &bIsWow64))
		{
			//handle error
		}
	}
	CloseHandle(proc_handle);
	return bIsWow64;
}

std::string getLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);
	message.erase(std::remove(message.begin(), message.end(), '\n'), message.end());
	message.erase(std::remove(message.begin(), message.end(), '\r'), message.end());
	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

bool Inject(uint64_t pId, char *dllName, int injection_method, HANDLE h)
{
	stringstream msg;
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		logError("OpenProcessToken Failed", true);
		return false;
	}
	if (!setPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		logError("SetPrivilege Failed", true);
		return false;
	}
	CloseHandle(hToken);

	switch (injection_method)
	{
		case 1: //loadlibary
		{
			if (!h) 
				h = OpenProcess(PROCESS_ALL_ACCESS, false, pId);
			if (h) {
				if (is32bit(pId))
				{
					return Inject32(pId, dllName, h);
				}
				else {
					return Inject64(dllName, h);
				}

			} else {
				msg << "Couldn't open handle to process [" << getLastErrorAsString() << "]" << endl;
				last_error_msg = msg.str();
				return false;
			}
		}
		case 2: //manual map
		{

		}
	}
	return true;
}

DWORD prev_error = GetLastError();
bool logError(std::string log_msg, bool bypass_getlasterror = false)
{
	if (prev_error != GetLastError() || bypass_getlasterror)
	{
		stringstream msg;
		msg << log_msg << " [" << getLastErrorAsString() << "]" << endl;
		last_error_msg = msg.str();
		return true;
	}
	else {
		return false;
	}
}


bool Inject32(uint64_t pId, char *dllName, HANDLE h)
{
	if (h)
	{
		stringstream msg;
		DWORD x = GetLastError();
		LPVOID loadLibraryAddress = (LPVOID)pe_getFunctionAddress32(pId, "kernelbase.dll", "loadlibrarya", h);

		if (logError("Failed to get kernelbase.dll, LoadLibraryA"))
			return false;

		LPVOID dllPath_ptr = VirtualAllocEx(h, NULL, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (logError("Failed to allocate memory for the dll path"))
			return false;

		WriteProcessMemory(h, dllPath_ptr, dllName, strlen(dllName), NULL);

		if (logError("Failed to write process memory of the dllpath"))
			return false;

		HANDLE remoteThread = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPath_ptr, 0, NULL);

		if (logError("Failed to CreateRemoteThread with the LoadLibraryA address"))
			return false;

		WaitForSingleObject(remoteThread, INFINITE);

		VirtualFreeEx(h, dllPath_ptr, strlen(dllName), MEM_RELEASE);

		if (logError("Failed to VirtualFreeEx memory for the dllpath"))
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
		
		DWORD x = GetLastError();
		LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

		if (logError("Failed to get kernel32.dll, LoadLibraryA"))
			return false;

		LPVOID dllPath_ptr = VirtualAllocEx(h, NULL, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (logError("Failed to allocate memory for the dll path"))
			return false;

		WriteProcessMemory(h, dllPath_ptr, dllName, strlen(dllName), NULL);

		if (logError("Failed to write process memory of the dllpath"))
			return false;

		HANDLE remoteThread = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPath_ptr, 0, NULL);

		if (logError("Failed to CreateRemoteThread with the LoadLibraryA address"))
			return false;

		WaitForSingleObject(remoteThread, INFINITE);

		VirtualFreeEx(h, dllPath_ptr, 0, MEM_RELEASE);

		if (logError("Failed to VirtualFreeEx memory for the dllpath"))
			return false;

		CloseHandle(remoteThread);
		CloseHandle(h);
		return true;
	}
	return false;
}


DWORD pe_getFunctionAddress32(uint64_t pId, string mod, string fn, HANDLE hProcess)
{
	DWORD addr = getBaseAddress(pId);
	DWORD mod_base = getModuleBase(hProcess, mod);
	if (mod_base != 0) {
		DWORD EATA = 0;
		IMAGE_DOS_HEADER dos_Headers;
		IMAGE_NT_HEADERS32 nt_Headers;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER32 OptionalHeader;
		IMAGE_EXPORT_DIRECTORY EATP;
		ReadProcessMemory(hProcess, (LPVOID)mod_base, (LPVOID)&dos_Headers, sizeof(IMAGE_DOS_HEADER), 0);
		if (dos_Headers.e_magic != IMAGE_DOS_SIGNATURE) return 0;
		ReadProcessMemory(hProcess, (LPVOID)(mod_base + (DWORD)dos_Headers.e_lfanew), (LPVOID)&nt_Headers, sizeof(IMAGE_NT_HEADERS32), 0);
		OptionalHeader = nt_Headers.OptionalHeader;
		ReadProcessMemory(hProcess, (LPVOID)(OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + mod_base), (LPVOID)&EATP, sizeof(IMAGE_EXPORT_DIRECTORY), 0);
		for (DWORD i = 0; i < EATP.NumberOfFunctions; i++)
		{
			//DWORD * ENTP = (DWORD*)((DWORD)mod + ((DWORD)EATP->AddressOfNames + (sizeof(DWORD)*i)));
			DWORD current_function_name_ptr;
			WORD current_function_name_ordinals_ptr;
			DWORD current_function_virtual_address;

			char current_function_name[60];

			ReadProcessMemory(hProcess, (LPVOID)(mod_base + EATP.AddressOfNames + (i * sizeof(DWORD))), &current_function_name_ptr, sizeof(DWORD), 0); //get the virtual address to the name
			ReadProcessMemory(hProcess, (LPVOID)(mod_base + current_function_name_ptr), &current_function_name, sizeof(current_function_name), 0); //read the name
			ReadProcessMemory(hProcess, (LPVOID)(mod_base + EATP.AddressOfNameOrdinals + (i * sizeof(WORD))), &current_function_name_ordinals_ptr, sizeof(WORD), 0);
			ReadProcessMemory(hProcess, (LPVOID)(mod_base + EATP.AddressOfFunctions + (current_function_name_ordinals_ptr * sizeof(DWORD))), &current_function_virtual_address, sizeof(DWORD), 0);

			string cName = current_function_name;

			transform(cName.begin(), cName.end(), cName.begin(), ::tolower);
			if (cName == fn)
			{
				return (mod_base + current_function_virtual_address);
			}
		}
	}
	return 0;
}

DWORD getModuleBase(HANDLE hProcess, string moduleName)
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
				return (DWORD)modinf.lpBaseOfDll;
			}
		}
	}
	return 0;
}

DWORD getBaseAddress(uint64_t pid)
{
	MODULEENTRY32 ME32;
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	ME32.dwSize = sizeof(ME32);

	if (Module32First(hModule, &ME32))
	{
		DWORD rVal = (DWORD)ME32.modBaseAddr;
		CloseHandle(hModule);
		return rVal;
	}
}


