@rem win32_build.bat
@rem Copyright (C) 2020 Feng Shun.
@rem
@rem   This program is free software: you can redistribute it and/or modify
@rem   it under the terms of the GNU General Public License version 2 as 
@rem   published by the Free Software Foundation, either version 3 of the
@rem   License, or (at your option) any later version.
@rem
@rem   This program is distributed in the hope that it will be useful,
@rem   but WITHOUT ANY WARRANTY; without even the implied warranty of
@rem   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
@rem   GNU General Public License version 2 for more details.
@rem
@rem   You should have received a copy of the GNU General Public License
@rem   version 2 along with this program. If not, see
@rem   <http://www.gnu.org/licenses/>.

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.com" ..\proxychains.exe.sln /clean "Debug^|x64"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.com" ..\proxychains.exe.sln /clean "Debug^|x86"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.com" ..\proxychains.exe.sln /clean "Release^|x64"
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.com" ..\proxychains.exe.sln /clean "Release^|x86"

