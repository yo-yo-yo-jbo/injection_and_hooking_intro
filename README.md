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









