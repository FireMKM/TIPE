@echo off
set "GP_PATH=C:\Program Files\Java"
set "PROJECT_PATH=C:\Users\capie\IdeaProjects\javacard_tipe"
set "CAP_PATH=%PROJECT_PATH%\out\production\javacard_tipe\fr\tipe\javacard"
set "SDK_PATH=C:\Program Files\Java\java_card_devkit_tools-bin-v25.1-b_611-26-OCT-2025"
set "KEYS=--key-ver 01"


:menu_start
cls

ECHO.
ECHO ===========================================
ECHO  MENU PRINCIPAL - Gestion Applet
ECHO ===========================================
ECHO.
ECHO Choisissez une option :
ECHO.
ECHO   0 - Compiler l'applet
ECHO   1 - Installer l'applet
ECHO   2 - Lister le contenu de la carte
ECHO   3 - Supprimer l'applet
ECHO   4 - Commande custom
ECHO   5 - APDU en SM
ECHO   6 - Help
ECHO.
ECHO   Q - Quitter le programme
ECHO.

set /p input="Votre choix : "

if /I "%input%"=="0" goto action0
if /I "%input%"=="1" goto action1
if /I "%input%"=="2" goto action2
if /I "%input%"=="3" goto action3
if /I "%input%"=="4" goto action4
if /I "%input%"=="5" goto action5
if /I "%input%"=="6" goto action6
if /I "%input%"=="q" goto quit

echo.
echo [ERREUR] Choix invalide.
echo.
pause
goto menu_start

:action0
cls
echo --- ACTION 0 : Compilation de l'applet ---
echo.
CALL "%SDK_PATH%\bin\converter.bat" -config "%PROJECT_PATH%\cap_config\tipe.cap.cfg" -target 3.1.0
echo.
echo Action 0 terminee.
echo.
pause
goto menu_start

:action1
cls
echo --- ACTION 1 : Installation de l'applet ---
echo.
CALL java -jar "%GP_PATH%\gp.jar" -d -v --load "%CAP_PATH%\tipe.cap" %KEYS%
echo.
echo.
echo.
CALL java -jar "%GP_PATH%\gp.jar" -d -v --package FF53566F78FF2210 --applet FF53566F78FF221202 --create FF53566F78FF221202 %KEYS%
echo.
CALL java -jar "%GP_PATH%\gp.jar" -d -v --package FF53566F78FF2210 --applet FF53566F78FF221101 --create FF53566F78FF221101 %KEYS%
echo.
echo Action 1 terminee.
echo.
pause
goto menu_start

:action2
cls
echo --- ACTION 2 : Lister le contenu de la carte ---
echo.
CALL java -jar "%GP_PATH%\gp.jar" -l %KEYS%
echo.
echo Action 2 terminee.
echo.
pause
goto menu_start

:action3
cls
echo --- ACTION 3 : Suppression de l'applet ---
echo.
CALL java -jar "%GP_PATH%\gp.jar" -d -v --delete FF53566F78FF221101 %KEYS%
CALL java -jar "%GP_PATH%\gp.jar" -d -v --delete FF53566F78FF221202 %KEYS%
CALL java -jar "%GP_PATH%\gp.jar" -d -v --delete FF53566F78FF2210 %KEYS%
echo.
echo Action 3 terminee.
echo.
pause
goto menu_start

:action4
cls
echo --- ACTION 4 : Commande custom ---
echo.
set /p cmd="Votre commande : "
CALL java -jar "%GP_PATH%\gp.jar" %KEYS% %cmd%
echo.
echo Action 4 terminee.
echo.
pause
goto menu_start

:action5
cls
echo --- ACTION 5 : APDU en SM ---
echo.
set /p apdu="Votre apdu : "
CALL java -jar "%GP_PATH%\gp.jar" %KEYS% -d -v -s %apdu%
echo.
echo Action 5 terminee.
echo.
pause
goto menu_start

:action6
cls
echo --- ACTION 6 : Menu d'aide ---
echo.
CALL java -jar "%GP_PATH%\gp.jar" -h
echo.
echo Action 6 terminee.
echo.
pause
goto menu_start

:quit
echo Au revoir !
exit /b