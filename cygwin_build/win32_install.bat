@rem win32_install.bat
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

copy %cd%\..\win32_output\proxychains_win32_x64.exe %USERPROFILE%\bin\proxychains.exe || pause
copy %cd%\..\win32_output\proxychains_win32_x86.exe %USERPROFILE%\bin\proxychains32.exe || pause
copy %cd%\..\win32_output\proxychains_helper_win32_x64.exe %USERPROFILE%\bin\ || pause
copy %cd%\..\win32_output\proxychains_helper_win32_x86.exe %USERPROFILE%\bin\ || pause
copy %cd%\..\win32_output\proxychains_hook_x64.dll %USERPROFILE%\bin\ || pause
copy %cd%\..\win32_output\proxychains_hook_x86.dll %USERPROFILE%\bin\ || pause
copy %cd%\..\win32_output\proxychains_win32_x64d.exe %USERPROFILE%\bin\proxychainsd.exe || pause
copy %cd%\..\win32_output\proxychains_win32_x86d.exe %USERPROFILE%\bin\proxychains32d.exe || pause
copy %cd%\..\win32_output\proxychains_hook_x64d.dll %USERPROFILE%\bin\ || pause
copy %cd%\..\win32_output\proxychains_hook_x86d.dll %USERPROFILE%\bin\ || pause
copy %cd%\..\win32_output\proxychains_helper_win32_x64d.exe %USERPROFILE%\bin\ || pause
copy %cd%\..\win32_output\proxychains_helper_win32_x86d.exe %USERPROFILE%\bin\ || pause

copy %cd%\..\win32_output\proxychains_win32_x64.exe %USERPROFILE%\bin\px.exe || pause
copy %cd%\..\win32_output\proxychains_win32_x86.exe %USERPROFILE%\bin\px32.exe || pause
copy %cd%\..\win32_output\proxychains_win32_x64d.exe %USERPROFILE%\bin\pxd.exe || pause
copy %cd%\..\win32_output\proxychains_win32_x86d.exe %USERPROFILE%\bin\px32d.exe || pause
