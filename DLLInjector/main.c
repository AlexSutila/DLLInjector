#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

int get_pid(const char *proc_name) {

	PROCESSENTRY32 proc_entry;
	proc_entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	int pid = 0;

	do {
		if (strcmp(proc_name, proc_entry.szExeFile) == 0) {
			pid = proc_entry.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &proc_entry));

	CloseHandle(hSnapshot);
	return pid;
}

/**
 * 
 * argv[1]: Name of process to look for
 * argv[2]: Full path to DLL to inject
 * 
 */
int main(int argc, char **argv) {

	const char *dll_path_full = "C:\\Users\\alexs\\source\\repos\\Project1\\x64\\Release\\Project1.dll";
	const char *proc_name = "Notepad.exe";

	int pid = get_pid(proc_name);
	if (!pid) {
		printf("Could not get pid\n");
		return -1;
	}

	HANDLE proc_handle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (!proc_handle) {
		printf("Failed to obtain handle to the process\n");
		return -1;
	}

	LPVOID dll_path_remote = VirtualAllocEx(proc_handle,
		NULL,
		strlen(dll_path_full) + 1,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!dll_path_remote) {
		printf("Could not allocate space for the provided dll name in the target process\n");
		return -1;
	}

	WriteProcessMemory(proc_handle,
		dll_path_remote,
		dll_path_full,
		strlen(dll_path_full) + 1,
		NULL
	);

	HANDLE thread_handle = CreateRemoteThread(proc_handle,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)LoadLibraryA,
		dll_path_remote,
		0,
		NULL
	);
	if (!thread_handle) {
		printf("Failed to create remote thread\n");
		return -1;
	}

	WaitForSingleObject(thread_handle, INFINITE);
	CloseHandle(thread_handle);

	VirtualFreeEx(proc_handle, dll_path_remote, 0, MEM_RELEASE);
	CloseHandle(proc_handle);

	return 0;
} 