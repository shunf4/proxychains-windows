@echo off
setlocal enableextensions
set TERM=
cd /d "D:\work\cygwin-build\cygwin-install\bin" && .\bassh --login -i -c "cd /cygdrive/d/work/Proxychains.exe/proxychains.exe/cygwin_build/test/fork_exec; bassh"
