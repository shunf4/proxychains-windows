# Proxychains.exe - Proxychains for Windows README

[![Build 
Status](https://github.com/shunf4/proxychains.exe/workflows/C/C++%20CI/badge.svg)](https://github.com/shunf4/proxychains.exe/actions?query=workflow%3A%22C%2FC%2B%2B+CI%22)

[README](README.md) | [简体中文文档](README_zh-Hans.md)

Proxychains.exe is a proxifier for Win32(Windows) or Cygwin/Msys2 
programs. It hijacks most of the Win32 or Cygwin programs' TCP 
connection, making them through one or more SOCKS5 proxy(ies).

Proxychains.exe hooks network-related Ws2_32.dll Winsock functions in 
dynamically linked programs via injecting a DLL and redirects the 
connections through SOCKS5 proxy(ies).

Proxychains.exe is a port or rewrite of 
[proxychains4](https://github.com/haad/proxychains) or
[proxychains-ng](https://github.com/rofl0r/proxychains-ng) to Win32 and 
Cygwin. It also uses [uthash](https://github.com/troydhanson/uthash) 
for some data structures and 
[minhook](https://github.com/TsudaKageyu/minhook) for API hooking.

Proxychains.exe is tested on Windows 10 x64 1909 (18363.418), Windows 7 
x64 SP1, Windows XP x86 SP3 and Cygwin 64-bit 3.1.2. Target OS should 
have [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145) 
installed.

**WARNING: ANONYMITY IS NOT GUARANTEED!**

WARNING: this program works only on dynamically linked programs. Also 
both proxychains.exe and the program to call must be the same platform 
and architecture (use proxychains_x86.exe to call x86 program, 
proxychains_x64.exe to call x64 program; use Cygwin builds to call 
Cygwin program).

WARNING: this program is based on hacks and is at its early development 
stage. Any unexpected situation may happen during usage. The called 
program may crash, not work, produce unwanted results etc. Be careful 
when working with this tool.

WARNING: this program can be used to circumvent censorship. doing so 
can be VERY DANGEROUS in certain countries. ALWAYS MAKE SURE THAT 
PROXYCHAINS.EXE WORKS AS EXPECTED BEFORE USING IT FOR
ANYTHING SERIOUS. This involves both the program and the proxy that 
you're going to use. For example, you can connect to some "what is my 
ip" service like ifconfig.me to make sure that it's not using your real 
ip.

ONLY USE PROXYCHAINS.EXE IF YOU KNOW WHAT YOU'RE DOING. THE AUTHORS AND 
MAINTAINERS OF PROXYCHAINS DO NOT TAKE ANY RESPONSIBILITY FOR ANY ABUSE 
OR MISUSE OF THIS SOFTWARE AND THE RESULTING CONSEQUENCES.

# Build

First you need to clone this repository and run `git submodule update 
--init --recursive` in it to retrieve all submodules.

## Win32 Build

Open proxychains.exe.sln with a recent version Visual Studio (tested 
with Visual Studio 2019) with platform toolset v141_xp on a 64-bit 
Windows.

Build the whole solution and you will see DLL file and executable file 
generated under `win32_output/`.

## Cygwin/Msys2 Build

Install Cygwin/Msys2 and various build tool packages (gcc, 
w32api-headers, w32api-runtime etc). Run bash, switch to `cygwin_build` 
/ `msys_build` directory and run `make`.

# Install

Copy `proxychains*.exe`, `[cyg/msys-]proxychains_hook*.dll`  to some 
directory included in your `PATH` environment variable. You can rename 
the main executable (like `proxychains_win32_x64.exe`) to names you 
favor, like `proxychains.exe`.

Last you need to create the needed configuration file in correct place. 
See "Configuration".

# Configuration

Proxychains.exe looks for configuration in the following order:

- file listed in environment variable `PROXYCHAINS_CONF_FILE` or provided
as a `-f` argument
- `$HOME/.proxychains/proxychains.conf` (Cygwin) or 
`%USERPROFILE%\.proxychains\proxychains.conf` (Win32)
- `(SYSCONFDIR)/proxychains.conf` (Cygwin) or `(User roaming 
dir)\Proxychains\proxychains.conf` (Win32)
- `/etc/proxychains.conf` (Cygwin) or `(Global programdata 
dir)\Proxychains\proxychains.conf` (Win32)
  
For options, see `proxychains.conf`.

# Usage Example

`proxychains ssh some-server`

`proxychains "Some Path\firefox.exe"`

`proxychains /bin/curl https://ifconfig.me`

Run `proxychains -h` for more command line argument options.

# How It Works

- Main program hooks `CreateProcessW` Win32 API call.
- Main program creates child process which is intended to be called.
- After creating process, hooked `CreateProcessW` injects the Hook DLL 
into child process. When child process gets injected, it hooks the 
Win32 API call below:
  - `CreateProcessW`, so that every descendant process gets hooked;
  - `connect`, `WSAConnect` and `ConnectEx`, so that TCP connections 
get hijacked;
  - `GetAddrInfoW` series, so that Fake IP is used to trace hostnames 
you visited, allowing remote DNS resolving;
  - etc.
- Main program does not exit, but serves as a named pipe server. Child 
process communicates with the main program to exchange data including 
logs, hostnames, etc. Main program does most of the bookkeeping of Fake 
IP and presence of descendant processes.
- When all descendant processes exit, main program exits.
- Main program terminates all descendant processes when it receives a 
SIGINT (Ctrl-C).

## About Cygwin/Msys2 and Busybox

**Cygwin is fully supported since 0.6.0!**

Switching the DLL injection technique from `CreateRemoteThread()` to 
modifying the target process' entry point, proxychains.exe now supports 
proxifying Cygwin/Msys2 process perfectly. (Even when you call them 
with Win32 version of proxychains.exe). See [DevNotes](doc/DEVNOTES.md).

If you want to proxify [MinGit busybox variant](https://github.com/git-for-windows/git/releases/),
replace its `busybox.exe` with
[this version modified by me](https://github.com/shunf4/busybox-w32).
See [DevNotes](doc/DEVNOTES.md).

# To-do and Known Issues

## ConEmu Compatibility

[ConEmu](https://github.com/Maximus5/ConEmu)
[prevents](https://github.com/Maximus5/ConEmu/blob/9629fa82c8a4c817f3b6faa2161a0a9eec9285c4/src/ConEmuHk/hkProcess.cpp#L497)
its descendant processes to do `SetThreadContext()`. This means
proxychains.exe is in no way compatible with terminals based on ConEmu
(like cmder).

## To-do

- [ ] Proxify osu!lazer launcher? (#11)
- [ ] Configuration file path (#9)
- [ ] Recognize IPv4-mapped fake IPv6 address
- [ ] Resolve proxy server name by custom hosts file, or at least
declare it as not supported in docs
- [ ] Properly handle "fork-and-exit" child process ? (In this case the
descendant processes' dns queries would never succeed)
- [ ] Remote DNS resolving based on UDP associate
- [ ] Hook `sendto()`, coping with applications which do TCP fast open
- [X] IPs resolved from hosts file should also be filtered like fake ip
(fixed in 0.6.8)
- [X] Resolve encoding issue regarding Cygwin and Mintty (fixed in 0.6.7)
- [X] Fake IPs should be filtered according to types of resolved IPs
and hints in `GetAddrInfoW` and `gethostbyname`, otherwise crash may happen
(fixed in 0.6.7)
- [X] Add an option to totally prevent "DNS leak" ? (Do name lookup on
SOCKS5 server only) (fixed in 0.6.6)
- [x] Connection closure should be correctly handled in
      `Ws2_32_LoopRecv` and `Ws2_32_LoopSend` (fixed in 0.6.5)
- [x] A large part of socks5 server name possibly lost when parsing
      configuration (fixed in 0.6.5)
- [x] Correctly handle conf and hosts that start with BOM (fixed in
      0.6.5)
- [X] Detect .NET CLR programs that is AnyCPU&prefers 32-bit/targeted x86
      /targeted x64. (These are "shimatta" programs, which must be
      injected by `CreateRemoteThread()`) (fixed in 0.6.2)
- [X] `ResumeThread()` in case of error during injection (fixed in 0.6.1)
- [X] Fix choco `err_unmatched_machine` (fixed in 0.6.1)
- [X] Get rid of Offending&Matching host key confirmation when 
proxifying git/SSH, probably using a FQDN hash function (fixed in 0.6.0)
- [X] Tell the user if command line is bad under Cygwin (fixed in 0.6.4)
- [X] Inherit exit code of direct child (fixed in 0.6.4)

# Licensing

This program is free software: you can redistribute it and/or modify it 
under the terms of the GNU General Public License version 2 as 
published by the Free Software Foundation, either version 3 of the 
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but 
WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
General Public License version 2 for more details.

You should have received a copy of the GNU General Public License 
version 2 along with this program (COPYING). If not, see 
<http://www.gnu.org/licenses/>.

## Uthash

https://github.com/troydhanson/uthash

This program contains uthash as a git submodule, which is published 
under The 1-clause BSD License:

```
Copyright (c) 2008-2018, Troy D. Hanson   http://troydhanson.github.com/uthash/
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are 
met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## MinHook

https://github.com/TsudaKageyu/minhook

This program contains minhook as a git submodule, which is published 
under The 2-clause BSD License:

```
MinHook - The Minimalistic API Hooking Library for x64/x86
Copyright (C) 2009-2017 Tsuda Kageyu.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
