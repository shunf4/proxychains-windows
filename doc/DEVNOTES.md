# About Cygwin

The early versions of proxychains.exe uses `CreateRemoteThread()`
to force a remote suspended process to run a thread, loading the
hook DLL and do various things.

However, in a Cygwin process, the first thread that executes must
be the one starting from the executable entry point. That is to say,
the exe-entry-point thread must be the first one (the one that
receives `DLL_PROCESS_ATTACH` notification). Otherwise, the 
exe-entry-point thread would have an extra corrupted cygtls (Cygwin
Thread Local Storage), causing it to fail when receiving signals.

Cygwin uses lots of hacks inside Win32 API framework to achieve
a UNIX style of manipulation. One of the hacks Cygwin
used, is that the first thread of every process (receiving
`DLL_PROCESS_ATTACH`) does some early initialization in DLL
entry point(init.cc), including creating a `cygthread` to simulate
the receipt of signals; later threads (including signal threads,
receiving `DLL_THREAD_ATTACH`), if they are not native `cygthread`
(not running `cygthread::stub`), will have their entry points
modified (only if previously some `cygthread` has also received
`DLL_THREAD_ATTACH` and provided key information about where
the entry points stored; see init.cc:`munge_threadfunc()`),
so that the function they run is wrapped in a wrapper
that does cygtls creation.

The old injection technique makes the exe-entry-point thread
one of the **later** threads, so terrible things happen: it is
wrapped in something that creates cygtls; then it executes
the entry point, where the runtime initailization functions
carry out the second step of cygwin process initialization,
including hacking the stack pointers, which fully invalidates
the previous cygtls.

Therefore, later when the cygtls'es is needed, they are
enumerated and checked; the invalidated cygtls causes the
thread to crash.

Switching to the method altering the entry point of the
exe-entry-point thread, obviously resolved the problem.

# About git-for-windows/busybox-w32

The git-for-windows fork of busybox-w32 shipped with MinGit-busybox
hangs when executing a shell script with pipe "|" creation, when
its `CreateProcessW()` is hooked. The reason is, its `win32/process.c`
is heavily modified compared to original version; it has a flaw in the
process creating function `mingw_spawnve()`, in which
`exit_process_on_signal()` is called. Then `exit_process_on_signal()`
calls `cull_exited_processes()`, which closes all handles related to
currently known exited process. However `shell/ash.c` still USES these
handles to do child process waiting in `waitpid_child`. This brings
about erroneous results, finally leading to an infinite waiting loop.

My fork fixes this flaw:
https://github.com/shunf4/busybox-w32

Related pull request:
https://github.com/git-for-windows/busybox-w32/pull/2

# Name Resolution

See [here](name_resolution.md).
