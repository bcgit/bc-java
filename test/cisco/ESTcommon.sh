#!/bin/bash

#
# Max Pritikin
# Copyright 2011, Cisco Systems, Inc
#
#
# Sets variables and config for the ESTServer callout (think CGI) script 
# Provides common helper functions
#

# for detailed debugging
EST_SCRIPTNAME=$0
EST_LOGGING=estserver.scripts.log

# make bash exit if an uninitialized variable is used
set -u

# Base variables for CA's used. These are global. :(
# also note that these must match the equivalent settings
# within each associated config file
export EST_OPENSSL_EXTCACNF=extExampleCA.cnf
EST_OPENSSL_EXTCADIR=extCA
export EST_OPENSSL_EXTCACERT=$EST_OPENSSL_EXTCADIR/cacert.crt
EST_OPENSSL_EXTCAPRIVDIR=$EST_OPENSSL_EXTCADIR/private
EST_OPENSSL_EXTCANEWCERTSDIR=$EST_OPENSSL_EXTCADIR/newcerts
EST_OPENSSL_EXTCADATABASE=$EST_OPENSSL_EXTCADIR/index.txt
EST_OPENSSL_EXTCASERIAL=$EST_OPENSSL_EXTCADIR/serial
EST_OPENSSL_EXTCAPRIVKEY=$EST_OPENSSL_EXTCAPRIVDIR/cakey.pem
EST_OPENSSL_EXTCAPRIVKEY_PKCS8=$EST_OPENSSL_EXTCAPRIVDIR/cakey.pkcs8.der
EST_OPENSSL_EXTCAPRIVKEYPARAM=$EST_OPENSSL_EXTCAPRIVDIR/cakeyparam.pem
EST_OPENSSL_EXTCASUBJ="/CN=estEXTERNALCA"

EST_OPENSSLCMD_EXTCAECPARAMSFILE=$EST_OPENSSL_EXTCADIR/prime256v1.pem
# if you want to use EC certificates set the ..._NEWKEY_PARAM like this:
EST_OPENSSLCMD_EXTCANEWKEY_PARAM="-newkey ec:$EST_OPENSSLCMD_EXTCAECPARAMSFILE"
#EST_OPENSSLCMD_EXTCANEWKEY_PARAM=" "

export EST_OPENSSL_CACNF=estExampleCA.cnf
EST_OPENSSL_CADIR=estCA
export EST_OPENSSL_CACERT=$EST_OPENSSL_CADIR/cacert.crt
EST_OPENSSL_CAPRIVDIR=$EST_OPENSSL_CADIR/private
EST_OPENSSL_CANEWCERTSDIR=$EST_OPENSSL_CADIR/newcerts
EST_OPENSSL_CADATABASE=$EST_OPENSSL_CADIR/index.txt
EST_OPENSSL_CASERIAL=$EST_OPENSSL_CADIR/serial
EST_OPENSSL_CAPRIVKEY=$EST_OPENSSL_CAPRIVDIR/cakey.pem
EST_OPENSSL_CAPRIVKEYPARAM=$EST_OPENSSL_CAPRIVDIR/cakeyparam.pem
EST_OPENSSL_CASUBJ="/CN=estExampleCA"

EST_OPENSSLCMD_CAECPARAMSFILE=$EST_OPENSSL_CADIR/prime256v1.pem
# if you want to use EC certificates set the ..._NEWKEY_PARAM like this:
EST_OPENSSLCMD_CANEWKEY_PARAM="-newkey ec:$EST_OPENSSLCMD_CAECPARAMSFILE"
#EST_OPENSSLCMD_CANEWKEY_PARAM=" "

# to enable verbose debugging of curl exchanges set this
# remember that "set -u" means we'll always need something like " " set
CURLCMD_VERBOSE=" "
#CURLCMD_VERBOSE="--verbose --trace -"
#CURLCMD_VERBOSE="--verbose --trace-ascii -"

# TODO: URGENT: why doesn't this work!? Openssl needs to know where to put the RANDFILE
RANDFILE="~/.rnd"

# NOTE: est itself allows the CN= to be different than the FQDN but
# curl is used from the demo client and curl mandates the HTTPS 
# RFC2818 section 3.1 Server Identity limitations. Thus we use 
# 127.0.0.1 here for the CN. If a real deployment were to use a 
# curl script there would be an assumption of DNS (and proper FQDN
# in the issued est server certificate)
# curl error looks like: * SSL: certificate subject name 'estExampleServer' does not match target host name '127.0.0.1'
# EST_SERVER_SUBJ="/CN=estExampleServer"
EST_SERVER_SUBJ="/CN=127.0.0.1"
EST_SERVER_CERTREQ=$EST_OPENSSL_CADIR/estserver.req
EST_SERVER_CERT=$EST_OPENSSL_CADIR/estserver.crt
EST_SERVER_PRIVKEY=$EST_OPENSSL_CAPRIVDIR/estserver.pem
EST_SERVER_CERTANDKEY=$EST_OPENSSL_CAPRIVDIR/estservercertandkey.pem

EST_SERVER_CCAUTHZDB=ccAuthz.db


#
# CLIENT certificate.
#

EST_CLIENT_SUBJ="/CN=estTestClient"
EST_CLIENT_CERTREQ=$EST_OPENSSL_CADIR/estclient.req
EST_CLIENT_CERT=$EST_OPENSSL_CADIR/estclient.crt
EST_CLIENT_PRIVKEY=$EST_OPENSSL_CAPRIVDIR/estclient.pem
EST_CLIENT_CERTANDKEY=$EST_OPENSSL_CAPRIVDIR/estclient.pem




# TODO: check to see if cmd path's have been overridden by a local settings file

# which openssl to use (Not depending on the path because openssl has many
# versions with various functionalities. Many OS distributions have an 
# older version. These scripts were intially tested against OpenSSL 0.9.8r
#OPENSSLCMD=~/src/openssl-fecc2/apps/openssl
#OPENSSLCMD=~/src/openssl-1.0.1c/apps/openssl
OPENSSLCMD=openssl

# which version of curl to use (also not depending on the path)
#CURLCMD=~/src/curl-7.24.0/src/curl
CURLCMD=curl

# demoClient variables
EST_DEMOCLIENT_DIR=demoClient
EST_DEMOCLIENT_CACERT=$EST_DEMOCLIENT_DIR/cacert.pem
EST_DEMOCLIENT_CACERTUPDATED=$EST_DEMOCLIENT_DIR/cacert_updated.pem

function logandexit ()
{
    echo "###########..EXIT..##########"           >> $EST_LOGGING
    echo "SCRIPT $EST_SCRIPTNAME EXIT: $1 ($2)"    >> $EST_LOGGING
    echo "###########^^EXIT^^##########"           >> $EST_LOGGING
    echo " "                                       >> $EST_LOGGING
    exit $2
}

function iferrorlogandexit ()
{
    if [ $? -ne 0 ] ; then
       logandexit "$1" "$2" 
    fi
}

function dumpheadersandcontent ()
{
    echo "Headers:"                  >> $EST_LOGGING
    cat "$1"                         >> $EST_LOGGING
    echo "/Headers"                  >> $EST_LOGGING
    if [ -n "$2" ] ; then 
        echo "Content:"              >> $EST_LOGGING
        if [ -e $2 ] ; then 
            cat "$2"                 >> $EST_LOGGING
        fi
        echo "/Content"              >> $EST_LOGGING
    fi
}

# <name> header-to-search-for file-to-look-in msg-to-log additional-file-to-log
function iferrorheaderslogandexit ()
{
    grep "$1" "$2" > /dev/null
    if [ $? -ne 0 ] 
    then
        dumpheadersandcontent $2 $4
        logandexit "Header ERROR: $3" 1
    fi 
}

# TODO: support multiple certificates in pkcs7 responses (e.g. ca chains)
# puts a (single) certificate into a degenerate pkcs7
function cert2pkcs72stdout ()
{
    echo "Content-Type: application/pkcs7-mime"
    echo ""
    $OPENSSLCMD crl2pkcs7 -certfile $1 -nocrl
}

###############################################################
##### Function: Combine files
###############################################################
function combinefiles ()
{
    cat $1 > $3
    cat $2 >> $3
}

