# Proxychains.exe  - Proxychains for Windows 自述文件

[![构建状态](https://github.com/shunf4/proxychains.exe/workflows/C/C++%20CI/badge.svg)](https://github.com/shunf4/proxychains.exe/actions?query=workflow%3A%22C%2FC%2B%2B+CI%22)

[README](README.md) | [简体中文文档](README_zh-Hans.md)

Proxychains.exe 是一个适用于 Win32(Windows) 和 Cygwin 平台的命令行强制代理工具（Proxifier）。它能够截获大多数 Win32 或 Cygwin 程序的 TCP 连接，强制它们通过一个或多个 SOCKS5 代理隧道。

Proxychains.exe 通过给动态链接的程序注入一个 DLL，对 Ws2_32.dll 的 Winsock 函数挂钩子的方式来将应用程序的连接重定向到 SOCKS5 代理。

Proxychains.exe 是 [proxychains4](https://github.com/haad/proxychains) 或者 [proxychains-ng](https://github.com/rofl0r/proxychains-ng) 到 Win32 和 Cygwin 的移植产物。它也使用了 [uthash](https://github.com/troydhanson/uthash) 构建一些数据结构，以及使用了 [minhook](https://github.com/TsudaKageyu/minhook) 进行 API 的挂钩。

Proxychains.exe 在 Windows 10 x64 1909 (18363.418)、Windows 7 x64 SP1、Windows XP x86 SP3 和 Cygwin 64-bit 3.1.2 经过测试。注意目标操作系统需要安装 [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/zh-cn/download/details.aspx?id=48145)。

**警告：此工具不能保证匿名性！**

警告：此程序只对动态链接的程序有用。同时，Proxychains.exe 和需要运行的目标程序必须是同一架构和平台（用 proxychains_x86.exe 运行 x86 程序，用 proxychains_x64.exe 运行 x64 程序；用 Cygwin 下构建的版本来运行 Cygwin 程序）。

警告：此程序是基于 Hack 的，并且处于开发早期阶段。使用过程中可能会发生任何意外状况。被运行的程序可能会崩溃、无法工作、产生意想不到的运行结果等等。谨慎使用。

警告：此程序可能用于绕过审查。此举在某些国家或地区可能是危险、不符合法律的。 **请在用于正式用途前，确保本程序和代理正常工作。** 比如，你可以通过连接到一些查询本机 IP 的服务如 ifconfig.me ，确保你未暴露你的真实 IP 地址。 

**请在确保清楚你要执行的操作及其后果后使用本程序。**

**免责声明：本程序的作者不对任何滥用、误用此软件的行为以及其可能导致的后果负责。**

# 构建

首先你需要克隆本代码仓库，并且在其中运行 `git submodule update --init --recursive` 来拉取所有子模块的代码。

## 构建 Win32 版本

在 64 位 Windows 下使用较新版本的 Visual Studio 打开 proxychains.exe.sln （Visual Studio 2019 测试有效）。Visual Studio 应该安装 v141_xp 平台工具集。

构建整个解决方案，在 `win32_output/` 找到输出的 EXE 和 DLL 文件。

## 构建 Cygwin 版本

安装 Cygwin 和各种构建工具程序包（gcc、w32api-headers、w32api-runtime 等）。运行 Cygwin bash，切换到 `cygwin_build` 目录下，执行 `make`。

# 安装

把生成的 `proxychains*.exe`、 `[cyg/msys-]proxychains_hook*.dll` 复制到 `PATH` 环境变量包含的某个目录下。你可以把主程序（如 `proxychains_win32_x64.exe`）改为你自己喜欢的名字，如 `proxychains.exe`。

最后你还需要在正确的位置创建配置文件。参见“配置”。

# 配置

Proxychains.exe 按照以下顺序寻找配置：

- 环境变量 `%PROXYCHAINS_CONF_FILE%` 或 `$PROXYCHAINS_CONF_FILE` 或通过 -f 命令行参数指定的文件
- `$HOME/.proxychains/proxychains.conf` （Cygwin 用户主目录） 或 `%USERPROFILE%\.proxychains\proxychains.conf` （Win32 用户主目录）
- `(SYSCONFDIR)/proxychains.conf` （Cygwin） 或 `(用户的 Roaming 目录)\Proxychains\proxychains.conf` （Win32）
- `/etc/proxychains.conf` （Cygwin） 或 `(全局的 ProgramData 目录)\Proxychains\proxychains.conf` （Win32）
  
关于配置选项，参见 `proxychains.conf`。

# 用例

`proxychains ssh some-server`

`proxychains "Some Path\firefox.exe"`

`proxychains /bin/curl https://ifconfig.me`

运行 `proxychains -h` 查看更多命令行参数选项。

# 工作原理

- 主程序 Hook `CreateProcessW` Win32 API 函数调用。
- 主程序创建按照用户给定的命令行启动子进程。
- 创建进程后，挂钩后的 `CreateProcessW` 函数将 Hook DLL 注入到子进程。当子进程被注入后，它也会 Hook 如下的 Win32 API 函数调用：
  - `CreateProcessW`，这样每一个后代进程都会被注入；
  - `connect` 和 `ConnectEx`，这样就劫持了 TCP 连接；
  - `GetAddrInfoW` 系列函数，这样可以使用 Fake IP 来追踪访问的域名，用于远程 DNS 解析；
  - 等等。
- 主程序并不退出，而是作为一个命名管道服务端存在。子进程与主程序通过命名管道交换包括日志、域名等内容在内的数据。主程序实施大多数关于 Fake IP 和子进程是否还存在的簿记工作。
- 当所有后代进程退出后，主程序退出。
- 主程序收到一个 SIGINT（Ctrl-C）后，终止所有后代进程。

## 关于 Cygwin/Msys2

**Cygwin 自 0.6.0 开始完全得到支持！**

自从将 DLL 注入的方法从 `CreateRemoteThread()` 改为修改目标进程的入口点之后，proxychains.exe 现在支持完美地强制代理 Cygwin/Msys2 进程了（即使从 Win32 构建版本来调用也是这样）。详见 [DevNotes](doc/DEVNOTES.md)。

如果你想要强制代理 [MinGit busybox 版本](https://github.com/git-for-windows/git/releases/)，请将 `busybox.exe` 换成[我修改的这个版本](https://github.com/shunf4/busybox-w32)。详见 [DevNotes](doc/DEVNOTES.md)。

# To-Do 以及已知的问题

详见英文文档。

# 授权协议

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as 
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License version 2 for more details.

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
modification, are permitted provided that the following conditions are met:

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
