#include "stdafx.h"
#include "libinj.h"
#include <Psapi.h>

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;

bool is32bit(DWORD pId)
{
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pId);
	BOOL bIsWow64 = FALSE;

	//IsWow64Process is not available on all supported versions of Windows.
	//Use GetModuleHandle to get a handle to the DLL that contains the function
	//and GetProcAddress to get a pointer to the function if available.

	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle("kernel32"), "IsWow64Process");

	if (fnIsWow64Process != NULL)
	{
		if (!fnIsWow64Process(processHandle, &bIsWow64))
		{
			//handle error
		}
	}
	CloseHandle(processHandle);
	return bIsWow64;
}

bool Inject(uint64_t pId, char *dllName)
{
	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, pId);
	if (h) {
		if (is32bit(pId))
		{
			return Inject32(pId, dllName, h);
		}
		else {
			return Inject64(dllName, h);
		}

	}
	return false;
}

bool Inject32(uint64_t pId, char *dllName, HANDLE h)
{
	if (h)
	{
		LPVOID LoadLibAddr = (LPVOID)pe_getFunctionAddress32(pId, "kernelbase.dll", "loadlibrarya", h);
		LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		WriteProcessMemory(h, dereercomp, dllName, strlen(dllName), NULL);
		HANDLE asdc = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
		WaitForSingleObject(asdc, INFINITE);
		VirtualFreeEx(h, dereercomp, strlen(dllName), MEM_RELEASE);
		CloseHandle(asdc);
		CloseHandle(h);
		return true;
	}
	return false;
}

bool Inject64(char *dllName, HANDLE h)
{
	if (h)
	{
		LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		WriteProcessMemory(h, dereercomp, dllName, strlen(dllName), NULL);
		HANDLE asdc = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
		WaitForSingleObject(asdc, INFINITE);
		VirtualFreeEx(h, dereercomp, strlen(dllName), MEM_RELEASE);
		CloseHandle(asdc);
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


