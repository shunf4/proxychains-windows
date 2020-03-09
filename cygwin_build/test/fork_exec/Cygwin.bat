@echo off
setlocal enableextensions
set TERM=
cd /d "D:\work\cygwin-build\cygwin-install\bin" && .\bashh --login -i -c "cd /cygdrive/d/work/Proxychains.exe/proxychains.exe/cygwin_build/test/fork_exec; bashh"
echo %errorlevel%
pause