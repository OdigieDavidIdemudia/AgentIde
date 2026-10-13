@echo off
REM ===========================================================================
REM AgentIde verification guard.
REM
REM Why this exists:
REM   modules/helpers_windows.go and modules/helpers_linux.go implement the
REM   same surface for two platforms and drift silently. A change that only
REM   compiles on the host OS looks perfectly green locally while breaking the
REM   other target. Cross-compiling both GOOS values catches that.
REM
REM   `go vet` catches shadowed errors, bad printf verbs and unreachable code
REM   that the compiler happily accepts.
REM
REM   `go test -race` catches data races across the watchdog / guardian /
REM   transport goroutines. It requires cgo, so when no C compiler is on PATH
REM   it is skipped with a warning rather than failing the run.
REM
REM Usage:  scripts\verify.bat
REM ===========================================================================

setlocal EnableExtensions
set ROOT=%~dp0..
pushd "%ROOT%" || exit /b 1
set FAILED=0

echo.
echo ===[1/5] go vet ===
call :run agent go vet ./... || set FAILED=1

echo.
echo ===[2/5] build GOOS=windows ===
set GOOS=windows
set GOARCH=amd64
call :run agent go build ./... || set FAILED=1
set GOOS=

echo.
echo ===[3/5] build GOOS=linux ===
set GOOS=linux
set GOARCH=amd64
call :run agent go build ./... || set FAILED=1
set GOOS=

echo.
echo ===[4/5] go test ===
call :run agent go test ./... || set FAILED=1

echo.
echo ===[5/5] go test -race ===
where gcc >nul 2>&1 || where clang >nul 2>&1 || where cc >nul 2>&1
if errorlevel 1 (
  echo   SKIP - no C compiler on PATH; the race detector needs cgo.
  echo          Install a toolchain, or run: CGO_ENABLED=1 go test -race ./...
) else (
  set CGO_ENABLED=1
  call :run agent go test -race ./... || set FAILED=1
  set CGO_ENABLED=
)

popd
echo.
if "%FAILED%"=="1" (
  echo === FAILED ===
  exit /b 1
)
echo === all checks passed ===
exit /b 0

REM ---------------------------------------------------------------------------
REM :run <subdir> <command...> - run a command inside <subdir>, report failures
REM without aborting the rest of the guard.
REM ---------------------------------------------------------------------------
:run
set "SUBDIR=%~1"
set "CMD=%~2 %~3 %~4 %~5"
pushd "%SUBDIR%" || (
  echo   FAILED: no such directory "%SUBDIR%"
  exit /b 1
)
echo + %CMD% ^(in %SUBDIR%^)
call %CMD%
set RC=%ERRORLEVEL%
popd
if not "%RC%"=="0" (
  echo   ^^ FAILED ^(exit %RC%^)
)
exit /b %RC%