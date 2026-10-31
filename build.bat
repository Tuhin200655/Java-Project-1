@echo off
setlocal enabledelayedexpansion
echo Building Packet Analyzer Java...

if not exist bin mkdir bin

echo Compiling Java source files...
> sources.txt (
  for /r src\main\java %%f in (*.java) do (
    set "file=%%f"
    set "file=!file:\=/!"
    echo "!file!"
  )
)

javac -d bin @sources.txt
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    if exist sources.txt del sources.txt
    exit /b %ERRORLEVEL%
)
if exist sources.txt del sources.txt

echo Packaging JAR...
jar cfe packet-analyzer.jar com.dpi.Main -C bin .
if %ERRORLEVEL% NEQ 0 (
    echo Note: jar command not on PATH, attempting direct path...
    if exist "C:\Program Files\Java\jdk-26.0.2\bin\jar.exe" (
        "C:\Program Files\Java\jdk-26.0.2\bin\jar.exe" cfe packet-analyzer.jar com.dpi.Main -C bin .
    )
)

echo Build complete: packet-analyzer.jar
