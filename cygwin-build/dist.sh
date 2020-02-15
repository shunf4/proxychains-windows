#!/bin/bash
# dist.sh
# Copyright (C) 2020 Feng Shun.
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as 
#   published by the Free Software Foundation, either version 3 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License version 2 for more details.
#
#   You should have received a copy of the GNU General Public License
#   version 2 along with this program. If not, see
#   <http://www.gnu.org/licenses/>.

set -euo pipefail

if [ -z "$PXCH_VERSION" ]; then
echo "Please execute \`make dist\`." >&2
exit 1
fi

echo Distributing "$PXCH_VERSION"...

cmd /c dist.bat
zip -j ../../proxychains_"$PXCH_VERSION"_win32_x64d.zip ../COPYING ../README*.md ../proxychains.conf ../x64/Debug/proxychains_x64d.exe ../x64/Debug/proxychains_hook_x64d.dll
zip -j ../../proxychains_"$PXCH_VERSION"_win32_x64.zip ../COPYING ../README*.md ../proxychains.conf ../x64/Release/proxychains_x64.exe ../x64/Release/proxychains_hook_x64.dll
zip -j ../../proxychains_"$PXCH_VERSION"_win32_x86d.zip ../COPYING ../README*.md ../proxychains.conf ../Debug/proxychains_x86d.exe ../Debug/proxychains_hook_x86d.dll
zip -j ../../proxychains_"$PXCH_VERSION"_win32_x86.zip ../COPYING ../README*.md ../proxychains.conf ../Release/proxychains_x86.exe ../Release/proxychains_hook_x86.dll
make release
zip -j ../../proxychains_"$PXCH_VERSION"_cygwin_x64.zip ../COPYING ../README*.md ../proxychains.conf proxychains_x64.exe cygproxychains_hook_x64.dll
