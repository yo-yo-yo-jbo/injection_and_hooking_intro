# Introduction to injection and hooking

Recently I was asked by a colleague to explain (and code) process injection and function hooking from scratch.
I thought it was a nice opportunity to share with an audience - not only how those things work, but how I conceptually approach such a task.

## The task at hand
The task is simple - code a `.dll` file that could be injected into an arbitrary process. Upon injection, it will hook a function in a certain way.  
Well, what does it mean? Let's break this down:
- A `dll` is a dynamic library - it contains code or data that might be used by anyone *loading* it. To load a DLL, use the [LoadLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) API (there are `LoadLibraryA` and `LoadLibraryW` for ANSI and Unicode paths, respectively). There are also other ways to load DLLs, but we will focus today on the simple `LoadLibraryA` API.
- `Code injection` is the act of running arbitrary code in a different address space under a chosen process. There are numerous reasons to perform code injection - some of them are malicious (like hiding from security tools or elevating privileges) and some are legitimate (for example, this is how debuggers work). Code injection for the purpose of hooking is a bit of gray area - it can be used for both malicious purposes or for good (like monitoring tools such as [API monitor](http://www.rohitab.com/apimonitor)).
- `Hooking` is the act of making some code behave differently than expected (commonly API calls). On Windows, there are numerous methods of achieving that - IAT hooking is a common practice, but in our case we will be performing inline hooking.
Breaking down this task, let's decide on the sub-tasks:
1. We will need to have some code that finds the right process ID from the process name.
2. We need to inject our DLL into a target process ID.
3. Once injected, we need to find the right function to hook and install a hook.
4. As a bonus point, our hook might want to invoke the original API call.
Since I'm lazy, I've decided to create one DLL for everything - if it's loaded to the right process it will perform the hooking (steps 3 and 4), otherwise it will attempt to inject (steps 1 and 2). With that in mind, let's get going!

## Finding the process ID
If you come from a Linux background, mapping a process name to a process ID usually requires you to traverse a directory (`/proc`) and read files. On Windows, there are APIs to perform that, and specifically, the [Process32First](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) and [Process32Next](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next) APIs.  
Before diving into the code, I feel that I have to justify my coding style:
- I prefer `C` to `C++`. I feel quite strongly about this, almost as strongly as Linus Torvalds [feels about this](http://harmful.cat-v.org/software/c++/linus).
- On Windows, there are usually two sets of APIs - one ending with an `A` for ANSI strings, and one with `W` for Unicode. I prefer to go for the Unicode ones (the ANSI ones usually simply translate the ANSI string into a wide string and call the `W` version anyway). There are also macros that expand to either the `A` or `W` version based on project preferences - I prefer to avoid those.
- My C coding style contains many remarks (even obvious ones) and a proper cleanup label. I do not use `goto` besides `goto lblCleanup`, and I make sure I only have one `return` in a function. This makes for very clean quality code, in my opinion.
- On Windows I will use the Windows common variable naming (with a prefix that hints the variable type).
Now that those concepts are agreed (?), let us start with some basic `dll` skeleton code. Every `dll` starts with a `DllMain` function, which gets 3 parameters:
- `hInstance` - the DLL `HINSTANCE` (which is a complicated way to say it's a pointer to the DLL in memory)
- `dwReason` - the reason for calling `DllMain`. There are 4 reasons: when first loading the DLL to a process, when unloading from a process, and when a new thread is attached or detached. We will care only about the first load, and also make sure thread calls aren't made with the `DisableThreadLibraryCalls` API.
- `pvReserved` - ignored.

So, here's the `DllMain` code:
```c
BOOL
WINAPI
DllMain(
	HINSTANCE hInstance,
	DWORD dwReason,
	LPVOID pvReserved
)
{
	// Unreferenced parameters
	UNREFERENCED_PARAMETER(pvReserved);

	// Only care about loading
	if (DLL_PROCESS_ATTACH == dwReason)
	{
		DisableThreadLibraryCalls(hInstance);
		MainRoutine(hInstance);
	}

	// Succeed always
	return TRUE;
}
```

The code simply calls `MainRoutine` with the `hInstance` (that I will need later), and it does so only upon the first load (`DLL_PROCESS_ATTACH`).
The `MainRoutine` function is just as easy - it will resolve the name of the executable that we are loaded into, and act accordingly:
- If it's loaded to the right process - we hook.
- Otherwise, we inject.

```c
#define PROCESS_OF_INTEREST (L"notepad.exe")

static
VOID
MainRoutine(
	HINSTANCE hInstance
)
{
	WCHAR wszExePath[MAX_PATH] = { 0 };
	PWSTR pwszSep = NULL;

	// Get the EXE path that we are loaded into
	if (0 == GetModuleFileNameW(NULL, wszExePath, ARRAYSIZE(wszExePath)))
	{
		goto lblCleanup;
	}

	// If we are not running in the right process - inject
	pwszSep = wcsrchr(wszExePath, L'\\');
	if ((NULL == pwszSep) || (0 != wcscmp(pwszSep + 1, PROCESS_OF_INTEREST)))
	{
		// INJECTION CODE GOES HERE
	}
	else
	{
		// HOOKING CODE GOES HERE
	}

lblCleanup:

	return;
}
```

The idea is to invole the `GetModuleFileNameW` to get the path of the executable we are loaded into (with `NULL` to get that for the executable) and then using the `wcsrchr` to get the last directory separator and then `wcscmp` to ensure we are loaded to the right process (`PROCESS_OF_INTEREST`).

As part of the injection code, we will need to find a process (the `PROCESS_OF_INTEREST` that was `#define`d earlier) by name and get its process ID.
This is trivially done with Windows API with the `CreateToolhelp32Snapshot`, `Process32FirstW` and `Process32NextW` APIs. There is nothing special about that functionality, but it's a nice opportunity to show how my coding style looks like:

```c
#define CLOSE_TO_VAL(obj, val, pfn)				do									\
								{									\
									if ((val) != (obj))				\
									{								\
										(VOID)(pfn)(obj);			\
										(obj) = (val);				\
									}								\
								} while (FALSE)

#define CLOSE_HANDLE(hHandle)					CLOSE_TO_VAL(hHandle, NULL, CloseHandle)

#define CLOSE_SNAPSHOT(hHandle)					do																\
								{																\
									__pragma(warning(push))										\
									__pragma(warning(disable:6387))								\
									CLOSE_TO_VAL(hHandle, INVALID_HANDLE_VALUE, CloseHandle);	\
									__pragma(warning(pop))										\
								} while (FALSE)

static
DWORD
GetTargetPid(VOID)
{
	DWORD dwPid = 0;
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 tCurrProcess = { 0 };

	// Find the right process
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (INVALID_HANDLE_VALUE == hSnap)
	{
		goto lblCleanup;
	}

	// Fetch first processs
	tCurrProcess.dwSize = sizeof(tCurrProcess);
	if (!Process32FirstW(hSnap, &tCurrProcess))
	{
		goto lblCleanup;
	}

	// Iterate all processes
	do
	{
		if (0 == wcscmp(tCurrProcess.szExeFile, PROCESS_OF_INTEREST))
		{
			dwPid = tCurrProcess.th32ProcessID;
			break;
		}
	} while (Process32NextW(hSnap, &tCurrProcess));

lblCleanup:

	// Cleanup
	CLOSE_SNAPSHOT(hSnap);

	// Return result
	return dwPid;
}
```

The function is trivial - it returns a process ID of `0` in case of failure and the right process ID in case of success.
There are some interesting macros that I've defined that, in my opinion, make my code quite elegant:
- `CLOSE_TO_VALUE` closes an object (most commonly `HANDLE` on Windows) and assigns it to a value (e.g. `NULL`) - unless it's equal to that value.
- `CLOSE_HANDLE` simply closes a `NULL`-defaulted `HANDLE` with the `CloseHandle` API.
- `CLOSE_SNAPSHOT` does the same but with `INVALID_HANDLE_VALUE`, since that's the error result for `CreateToolhelp32Snapshot`.

Convince yourself why this code is leak-free and easy to read.


