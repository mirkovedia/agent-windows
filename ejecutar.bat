@echo off
REM Lanzador del agente forense.
REM Se puede ejecutar con clic derecho -> Ejecutar como administrador.
REM A diferencia del .exe suelto, esta ventana NO se cierra al terminar:
REM el "pause" del final te deja leer el resultado.

setlocal
cd /d "%~dp0"

echo ============================================
echo   Agente forense - escaneo local
echo ============================================
echo.

REM 1. Verificar privilegios de administrador.
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: falta ejecutar como administrador.
    echo.
    echo Cerra esta ventana, hace clic derecho sobre ejecutar.bat
    echo y elegi "Ejecutar como administrador".
    echo.
    pause
    exit /b 1
)

REM 2. Ubicar el binario (el nombre cambia segun la version compilada).
set AGENTE=
if exist "mirkkkov.exe" set AGENTE=mirkkkov.exe
if not defined AGENTE if exist "agent.exe" set AGENTE=agent.exe

if not defined AGENTE (
    echo ERROR: no encuentro el ejecutable en esta carpeta.
    echo Esperaba mirkkkov.exe o agent.exe en:
    echo   %CD%
    echo.
    echo Compilalo con:
    echo   go build -trimpath -o mirkkkov.exe ./cmd/agent
    echo.
    pause
    exit /b 1
)

echo Ejecutable: %AGENTE%
echo Reporte:    %CD%\reporte.json
echo.
echo El agente te va a pedir consentimiento explicito antes de escanear.
echo.

REM 3. Correr el escaneo en modo local (sin servidor de verificacion).
"%AGENTE%" -out reporte.json -timeout 10m
set CODIGO=%errorlevel%

echo.
echo ============================================
if %CODIGO% equ 0 (
    echo   Escaneo terminado. Codigo: %CODIGO%
    echo   Reporte guardado en reporte.json
) else (
    echo   El agente termino con error. Codigo: %CODIGO%
    echo   Revisa el mensaje de arriba.
)
echo ============================================
echo.
pause
