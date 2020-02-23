copy %cd%\..\win32_output\proxychains_x64.exe %USERPROFILE%\bin\proxychains.exe || pause
copy %cd%\..\win32_output\proxychains_x86.exe %USERPROFILE%\bin\proxychains32.exe || pause
copy %cd%\..\win32_output\proxychains_hook_x64.dll %USERPROFILE%\bin\ || pause
copy %cd%\..\win32_output\proxychains_hook_x86.dll %USERPROFILE%\bin\ || pause
copy %cd%\..\win32_output\proxychains_x64d.exe %USERPROFILE%\bin\proxychainsd.exe || pause
copy %cd%\..\win32_output\proxychains_x86d.exe %USERPROFILE%\bin\proxychains32d.exe || pause
copy %cd%\..\win32_output\proxychains_hook_x64d.dll %USERPROFILE%\bin\ || pause
copy %cd%\..\win32_output\proxychains_hook_x86d.dll %USERPROFILE%\bin\ || pause

copy %cd%\..\win32_output\proxychains_x64.exe %USERPROFILE%\bin\px.exe || pause
copy %cd%\..\win32_output\proxychains_x86.exe %USERPROFILE%\bin\px32.exe || pause
copy %cd%\..\win32_output\proxychains_x64d.exe %USERPROFILE%\bin\pxd.exe || pause
copy %cd%\..\win32_output\proxychains_x86d.exe %USERPROFILE%\bin\px32d.exe || pause

copy %cd%\..\win32_output\proxychains_remote_function_*.bin %USERPROFILE%\bin\ || pause