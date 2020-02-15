# Proxychains.exe - Proxychains for Windows README

[README](README.md) | [简体中文文档](README_zh-Hans.md)

Proxychains.exe is a proxifier for Win32(Windows) or Cygwin programs. It hijacks
most of the Win32 or Cygwin programs' TCP connection, making them through one or
more SOCKS5 proxy(ies).

Proxychains.exe hooks network-related Ws2_32.dll Winsock functions in
dynamically linked programs via injecting a DLL and redirects the connections
through SOCKS5 proxy(ies).

Proxychains.exe is a port or rewrite of
[proxychains4](https://github.com/haad/proxychains) or
[proxychains-ng](https://github.com/rofl0r/proxychains-ng) to Win32 and Cygwin.
It also uses [uthash](https://github.com/troydhanson/uthash) for some data
structures and [minhook](https://github.com/TsudaKageyu/minhook) for API 
hooking.

Proxychains.exe is tested on Windows 10 x64 1909 (18363.418), Windows XP x86 SP3
and Cygwin 64-bit 3.1.2. Target OS should have 
[Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145)
installed.

WARNING: this program works only on dynamically linked programs. Also both
proxychains.exe and the program to call must be the same platform and
architecture (use proxychains_x86.exe to call x86 program,
proxychains_x64.exe to call x64 program; use Cygwin builds to call Cygwin
program).

WARNING: this program is based on hacks and is at its early development stage.
Any unexpected situation may happen during usage. The called program may crash,
not work, producing unwanted results etc. Be careful when working with this
tool.

WARNING: this program can be used to circumvent censorship.
doing so can be VERY DANGEROUS in certain countries.

ALWAYS MAKE SURE THAT PROXYCHAINS.EXE WORKS AS EXPECTED
BEFORE USING IT FOR ANYTHING SERIOUS.

this involves both the program and the proxy that you're going to
use.

for example, you can connect to some "what is my ip" service
like ifconfig.me to make sure that it's not using your real ip.

ONLY USE PROXYCHAINS.EXE IF YOU KNOW WHAT YOU'RE DOING.

THE AUTHORS AND MAINTAINERS OF PROXYCHAINS DO NOT TAKE ANY
RESPONSIBILITY FOR ANY ABUSE OR MISUSE OF THIS SOFTWARE AND
THE RESULTING CONSEQUENCES.

# Build

First you need to clone this repository and run
`git submodule update --init --recursive` in it to retrieve all submodules.

## Win32 build

Open proxychains.exe.sln with a recent version Visual Studio (tested with
Visual Studio 2019) with platform toolset v141_xp. Build Solution and see
DLL file and executable file generated under default directory. (like
x64\Debug).

## Cygwin build

Install Cygwin and various build tool packages (gcc, w32api-headers,
w32api-runtime etc). Run Cygwin bash, switch to `cygwin-build` directory and
run `make`.

# Install

Copy `proxychains*.exe` and `[cyg]proxychains_hook*.dll` generated to some
directory included in your `PATH` environment variable. Also create the needed
configuration file in correct place. See "Configuration".

# Configuration

Proxychains.exe looks for configuration in the following order:

- file listed in environment variable `%PROXYCHAINS_CONF_FILE%` or
  `$PROXYCHAINS_CONF_FILE` or provided as a -f argument
- $HOME/.proxychains/proxychains.conf (Cygwin) or
  %USERPROFILE%\.proxychains\proxychains.conf (Win32)
- (SYSCONFDIR)/proxychains.conf (Cygwin) or
  (User roaming dir)\Proxychains\proxychains.conf (Win32)
- /etc/proxychains.conf (Cygwin) or
  (Global programdata dir)\Proxychains\proxychains.conf (Win32)
  
For options, see `proxychains.conf`.

# Usage Example

`proxychains ssh some-server`

`proxychains "Some Path\firefox.exe"`

Run `proxychains -h` for more command line argument options.

# How it works

- Main program hooks `CreateProcessW` Win32 API call.
- Main program creates child process which is intended to be called.
- After creating process, hooked `CreateProcessW` injects the Hook DLL into
  child process. When child process gets injected, it hooks the Win32 API call
  below:
  - `CreateProcessW`, so that every descendant process gets hooked;
  - `connect` and `ConnectEx`, so that TCP connections get hijacked;
  - `GetAddrInfoW` series, so that Fake IP is used to trace hostnames you
    visited, allowing remote DNS resolving;
  - etc.
- Main program does not exit, but serves as a named pipe server. Child process
  communicates with the main program to exchange data including logs, hostnames,
  etc. Main program does most of the bookkeeping of Fake IP and presence of
  descendant processes.
- When all descendant process exits, main program exits.
- Main program terminates all descendant process when it receives a SIGINT
  (Ctrl-C).

# To Do

- Remote DNS resolving based on UDP associate
- Hook `sendto()`, coping with applications which do TCP fast open

# License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as 
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License version 2 for more details.

You should have received a copy of the GNU General Public License
version 2 along with this program. If not, see
<http://www.gnu.org/licenses/>.

## Uthash

https://github.com/troydhanson/uthash

This program contains uthash as a git submodule, which is published
under The 1-clause BSD License.

## Minhook

https://github.com/TsudaKageyu/minhook

This program contains minhook as a git submodule, which is published
under The 2-clause BSD License.