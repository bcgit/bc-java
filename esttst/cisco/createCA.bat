:: ############################################################################
:: Program: createCA.bat
::
:: Direct port of ESTcommon.sh & createCA.sh
::
:: Note: There is a small difference between .sh & .bat programs:
::   .sh expects a user response of any character to continue.
::   .bat expects a user response of a <CR> to continue.
::
:: ############################################################################

:: ############################################################################
:: ESTcommon.sh port (All function calls are in Functions section below)
:: ############################################################################
::
:: Max Pritikin
:: Copyright 2011, Cisco Systems, Inc
:: 
:: Sets variables and config for the ESTServer callout (think CGI) script 
:: Provides common helper functions
::

:: for detailed debugging
@echo off
set EST_SCRIPTNAME=%0
set EST_LOGGING=estserver.scripts.log
set RETURN_CODE=0

:: Base variables for CA's used. These are global. :(
:: also note that these must match the equivalent settings
:: within each associated config file
set EST_OPENSSL_EXTCACNF=extExampleCA.cnf
set EST_OPENSSL_EXTCADIR=extCA
set EST_OPENSSL_EXTCACERT=%EST_OPENSSL_EXTCADIR%\cacert.crt
set EST_OPENSSL_EXTCAPRIVDIR=%EST_OPENSSL_EXTCADIR%\private
set EST_OPENSSL_EXTCANEWCERTSDIR=%EST_OPENSSL_EXTCADIR%\newcerts
set EST_OPENSSL_EXTCADATABASE=%EST_OPENSSL_EXTCADIR%\index.txt
set EST_OPENSSL_EXTCASERIAL=%EST_OPENSSL_EXTCADIR%\serial
set EST_OPENSSL_EXTCAPRIVKEY=%EST_OPENSSL_EXTCAPRIVDIR%\cakey.pem
set EST_OPENSSL_EXTCAPRIVKEYPARAM=%EST_OPENSSL_EXTCAPRIVDIR%\cakeyparam.pem
set EST_OPENSSL_EXTCASUBJ="/CN=estEXTERNALCA"

set EST_OPENSSLCMD_EXTCAECPARAMSFILE=%EST_OPENSSL_EXTCADIR%\prime256v1.pem
:: if you want to use EC certificates set the ..._NEWKEY_PARAM like this:
set EST_OPENSSLCMD_EXTCANEWKEY_PARAM="-newkey ec:%EST_OPENSSLCMD_EXTCAECPARAMSFILE%"
::set EST_OPENSSLCMD_EXTCANEWKEY_PARAM=

set EST_OPENSSL_CACNF=estExampleCA.cnf
set EST_OPENSSL_CADIR=estCA
set EST_OPENSSL_CACERT=%EST_OPENSSL_CADIR%\cacert.crt
set EST_OPENSSL_CAPRIVDIR=%EST_OPENSSL_CADIR%\private
set EST_OPENSSL_CANEWCERTSDIR=%EST_OPENSSL_CADIR%\newcerts
set EST_OPENSSL_CADATABASE=%EST_OPENSSL_CADIR%\index.txt
set EST_OPENSSL_CASERIAL=%EST_OPENSSL_CADIR%\serial
set EST_OPENSSL_CAPRIVKEY=%EST_OPENSSL_CAPRIVDIR%\cakey.pem
set EST_OPENSSL_CAPRIVKEYPARAM=%EST_OPENSSL_CAPRIVDIR%\cakeyparam.pem
set EST_OPENSSL_CASUBJ="/CN=estExampleCA"

set EST_OPENSSLCMD_CAECPARAMSFILE=%EST_OPENSSL_CADIR%\prime256v1.pem
:: if you want to use EC certificates set the ..._NEWKEY_PARAM like this:
set EST_OPENSSLCMD_CANEWKEY_PARAM="-newkey ec:%EST_OPENSSLCMD_CAECPARAMSFILE%"
::set EST_OPENSSLCMD_CANEWKEY_PARAM=

:: to enable verbose debugging of curl exchanges set this
set CURLCMD_VERBOSE=" "
::set CURLCMD_VERBOSE="--verbose --trace -"
::set CURLCMD_VERBOSE="--verbose --trace-ascii -"

:: TODO: URGENT: why doesn't this work!? 
:: Openssl needs to know where to put the RANDFILE
set RANDFILE=%HOMEPATH%\.rnd

:: NOTE: est itself allows the CN= to be different than the FQDN but
:: curl is used from the demo client and curl mandates the HTTPS 
:: RFC2818 section 3.1 Server Identity limitations. Thus we use 
:: 127.0.0.1 here for the CN. If a real deployment were to use a 
:: curl script there would be an assumption of DNS (and proper FQDN
:: in the issued est server certificate)
:: curl error looks like:
::   * SSL: certificate subject name 'estExampleServer' does not match target host name '127.0.0.1'
::set EST_SERVER_SUBJ=/CN=estExampleServer
set EST_SERVER_SUBJ=/CN=127.0.0.1
set EST_SERVER_CERTREQ=%EST_OPENSSL_CADIR%\estserver.req
set EST_SERVER_CERT=%EST_OPENSSL_CADIR%\estserver.crt
set EST_SERVER_PRIVKEY=%EST_OPENSSL_CAPRIVDIR%\estserver.pem
set EST_SERVER_CERTANDKEY=%EST_OPENSSL_CAPRIVDIR%\estservercertandkey.pem

set EST_SERVER_CCAUTHZDB=ccAuthz.db

:: TODO: check to see if cmd path's have been overridden by a local settings file

:: which openssl to use (Not depending on the path because openssl has many
:: versions with various functionalities. Many OS distributions have an 
:: older version. These scripts were intially tested against OpenSSL 0.9.8r
::set OPENSSLCMD=~/src/openssl-fecc2/apps/openssl
::set OPENSSLCMD=~/src/openssl-1.0.1c/apps/openssl
set OPENSSLCMD=openssl

:: which version of curl to use (also not depending on the path)
set CURLCMD=curl

:: demoClient variables
set EST_DEMOCLIENT_DIR=demoClient
set EST_DEMOCLIENT_CACERT=%EST_DEMOCLIENT_DIR%\cacert.pem
set EST_DEMOCLIENT_CACERTUPDATED=%EST_DEMOCLIENT_DIR%\cacert_updated.pem


:: ############################################################################
:: createCA.sh port (createCA function is in the Function section below)
:: ############################################################################

:: completely clean out and re-create demoCA database directories (DESTRUCTIVE!!)
echo #################################################################
echo SECURITY CONSIDERATIONS - NOTE WELL
echo The sample scripts used to handle EST operations are NOT
echo intended to provide a secure implementation. They have not
echo been evaluated for security, they have not had a Thread Model
echo reviewed, they are not particularly good about cleaning up after
echo themselves and they assume the data exchanged is well formed
echo if the cryptographic checks pass.
echo.
echo In short: They are not to be trusted. They provide a functional
echo implementation only.
echo.
echo Continuing will completely erase/destroy/nuke the existing estCA
set /p DUMMY="Press return..."
echo.
echo Nuking from orbit!
echo #################################################################
rmdir /s /q %EST_OPENSSL_CADIR%
rmdir /s /q %EST_OPENSSL_EXTCADIR%


:: Create a 3rd party (existing) CA certificate
:: Think of this like a common web CA as one might purchase certificates from
echo #################################################################
echo ####(Re)creating an initial EXTERNAL 'web root CA' certificate
echo #################################################################
:: Batch scripts only allow 9 arguments to be passed in, manually setup #10
set ARG10=%EST_OPENSSLCMD_EXTCAECPARAMSFILE%
call :createCA %EST_OPENSSL_EXTCASUBJ%^
 %EST_OPENSSL_EXTCADIR%^
 %EST_OPENSSL_EXTCACERT%^
 %EST_OPENSSL_EXTCAPRIVDIR%^
 %EST_OPENSSL_EXTCASERIAL%^
 %EST_OPENSSL_EXTCADATABASE%^
 %EST_OPENSSL_EXTCANEWCERTSDIR%^
 %EST_OPENSSL_EXTCAPRIVKEY%^
 %EST_OPENSSLCMD_EXTCANEWKEY_PARAM%
if %RETURN_CODE% neq 0 (
    goto :script_complete
)

:: Create our CA certificate
echo #################################################################
echo ####(Re)creating an initial root CA certificate
echo #################################################################
:: Batch scripts only allow 9 arguments to be passed in, manually setup #10
set ARG10=%EST_OPENSSLCMD_CAECPARAMSFILE%
call :createCA %EST_OPENSSL_CASUBJ%^
 %EST_OPENSSL_CADIR%^
 %EST_OPENSSL_CACERT%^
 %EST_OPENSSL_CAPRIVDIR%^
 %EST_OPENSSL_CASERIAL%^
 %EST_OPENSSL_CADATABASE%^
 %EST_OPENSSL_CANEWCERTSDIR%^
 %EST_OPENSSL_CAPRIVKEY%^
 %EST_OPENSSLCMD_CANEWKEY_PARAM%
if %RETURN_CODE% neq 0 (
    goto :script_complete
)

:: Create a certificate for our est server
:: TODO: add extension for est server
echo #################################################################
echo ####(Re)creating an initial peer certificate for our estServer to use
echo #################################################################

:: re-using the same NEWKEY_PARAM as is used for our CA
call :removequotes %EST_OPENSSLCMD_CANEWKEY_PARAM%
set EST_OPENSSLCMD_CANEWKEY_PARAM=%RETURN_VALUE%
call %OPENSSLCMD% req -new -sha256 -nodes -out %EST_SERVER_CERTREQ%^
 %EST_OPENSSLCMD_CANEWKEY_PARAM% -keyout %EST_SERVER_PRIVKEY%^
 -subj %EST_SERVER_SUBJ% -config %EST_OPENSSL_CACNF%
if %ERRORLEVEL% neq 0 (
    call :logerror "Unable to create est server CSR" 1
    goto :script_complete
)

call %OPENSSLCMD% ca -md sha256 -out %EST_SERVER_CERT% -batch^
 -config %EST_OPENSSL_CACNF%^ -extfile .\ext.cnf -infiles %EST_SERVER_CERTREQ%
if %ERRORLEVEL% neq 0 (
    call :logerror "Unable to create est server certificate" 1
    goto :script_complete
)

call %OPENSSLCMD% x509 -sha256 -in %EST_SERVER_CERT% -text

:: the mongoose https server wants to recieve the server certificate in
:: a combined file:
call :combinefiles %EST_SERVER_CERT% %EST_SERVER_PRIVKEY% %EST_SERVER_CERTANDKEY%

echo #################################################################
echo ####Creating combined trusted cert file
call :combinefiles estCA\cacert.crt extCA\cacert.crt trustedcerts.crt

echo #################################################################
echo ####Setting up and launching the estServer

:: destructive creating user of "estuser" w/ password "estpwd"
:: mongoose uses the same format as apache (see htpasswd)
echo Resetting the est server password file
echo estuser:estrealm:36807fa200741bb0e8fb04fcf08e2de6 > %EST_OPENSSL_CADIR%\estpwdfile

:: merging the two ca certs into one file so that the est server can be configured
:: to use both when validating client certificates
call :combinefiles extCA\cacert.crt estCA\cacert.crt estCA\multicacerts.crt

:: Go to the end of the script
goto :script_complete

:: #############################################################################
:: Functions
:: #############################################################################

:: Return the value without its quote wrapper
:removequotes
    set RETURN_VALUE=%~1
    exit /b


:: Combine 2 files into 1 output file
:combinefiles
    if exist %3 (
        del /f /q %3
    )
    type %1 > %3
    type %2 >> %3
    exit /b


:: NOT used in createCA.sh, just ported to keep the programs in sync
:dumpheadersandcontent
    echo Headers:      >> %EST_LOGGING%
    type %1            >> %EST_LOGGING%
    echo /Headers      >> %EST_LOGGING%
    IF [%2] != [] (
        echo Content:  >> %EST_LOGGING%
        if exist %2 (
            type %2    >> %EST_LOGGING%
        )
        echo /Content  >> %EST_LOGGING%
    )
    exit /b


:: NOT used in createCA.sh, just ported to keep the programs in sync
:: <name> header-to-search-for file-to-look-in msg-to-log additional-file-to-log
:iferrorheaderslog
    findstr %1 %2  > NUL
    if %ERRORLEVEL% neq 0 (
        call :dumpheadersandcontent %2 %4
        call :logerror "Header ERROR: %3" 1
    )
    exit /b


:: NOT used in createdCA.sh, just ported to key the programs in sync
:: TODO: support multiple certificates in pkcs7 responses (e.g. ca chains)
:: puts a (single) certificate into a degenerate pkcs7
:cert2pkcs72stdout
    echo Content-Type: application/pkcs7-mime
    echo.
    call %OPENSSLCMD% crl2pkcs7 -certfile $1 -nocrl
    exit /b


:: given a base directory name this sets up a full CA for use
:createCA
    :: inputs (only 9 arguments can be passed in windows batch mode)
    ::        (%ARG10% is assigned before calling this function)
    set CREATECA_CASUBJ=%1
    set CREATECA_CADIR=%2
    set CREATECA_CACERT=%3
    set CREATECA_CAPRIVDIR=%4
    set CREATECA_CASERIAL=%5
    set CREATECA_CADATABASE=%6
    set CREATECA_CANEWCERTSDIR=%7
    set CREATECA_CAPRIVKEY=%8
    set CREATECA_NEWKEY_PARAM=%~9
    set CREATECA_ECPARAMSFILE=%ARG10%

    echo #################################################################
    echo ####(Re)creating the directory structure and initial files 
    echo ####for the CA: %CREATECA_CASUBJ%
    echo #################################################################
    mkdir %CREATECA_CADIR%
    mkdir %CREATECA_CAPRIVDIR%
    mkdir %CREATECA_CANEWCERTSDIR%
    echo 01 > %CREATECA_CASERIAL%
    type NUL > %CREATECA_CADATABASE%
    
    :: This is only needed for EC mode
    call %OPENSSLCMD% ecparam -name prime256v1 -out %CREATECA_ECPARAMSFILE%
    if %ERRORLEVEL% neq 0 (
        call :logerror "Unable to build ECPARAMS file" 1
        exit /b
    )

    call %OPENSSLCMD% req -new -x509 -sha256 -extensions v3_ca %CREATECA_NEWKEY_PARAM%^
      -keyout %CREATECA_CAPRIVKEY% -out %CREATECA_CACERT% -days 365 -nodes^
      -subj %CREATECA_CASUBJ% -config %EST_OPENSSL_CACNF%
    if %ERRORLEVEL% neq 0 (
        call :logerror "Unable to create \"%CREATECA_CASUBJ%\" CA cert" 1
        exit /b
    )

    call %OPENSSLCMD% x509 -sha256 -in %CREATECA_CACERT%
    exit /b

:: Record the error into the log file and set the script return code
:logerror
    :: %1 = Function Name
    :: %2 = Exit Status
    set RETURN_CODE=%2
    echo ###########..EXIT..##########         >> %EST_LOGGING%
    echo SCRIPT %EST_SCRIPTNAME% EXIT: %1 (%2) >> %EST_LOGGING%
    echo ###########^^^^EXIT^^^^##########     >> %EST_LOGGING%
    echo.                                      >> %EST_LOGGING%
    echo ###########..EXIT..##########
    echo SCRIPT %EST_SCRIPTNAME% EXIT: %1 (%2)
    echo ###########^^^^EXIT^^^^##########
    echo.
    exit /b


:: End of Script
:script_complete
exit /b %RETURN_CODE%
