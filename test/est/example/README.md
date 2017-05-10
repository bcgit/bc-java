
# EST client examples

## Before running

The examples below use utility scripts, these scripts will try to ensure the dependencies are met to run the examples.

To do this ahead of time run the following:

```
cd <bc-java>/test/est/example
./ensurejar.sh
```

This script will download the provider from the betas page and it will then endeavour to build, using gradle the 
Bouncycastle distribution. You will need to have installed gradle and have it on the PATH for this to run.

When it is done building it will then copy the jars into the ```<bc-java>/test/est/example/jars/``` directory.

If you need to refresh these jars delete the jars directory or use ```./ensurejar.sh force```

## Using Java 7 ('org.bouncycastle.est.ESTException: Connection reset')
The Cisco EST server will reject TLS version 1 'TLSv1' handshakes. 

This is the default in Java 7, however Java 8 defaults to TLSv1.2 which the Cisco test EST server will accept.

When using Java 7 you will need to supply the argument: ```--tls TLSv1.2```


## Not in a unix environment
The examples need a provider, the pkix jar, and the test jar.

If you have openjdk installed you can simply use gradle to compile bc-java and the libraries will be in
```
cd <bc-java>

gradle -x test clean jar

# Libraries will be in:
# test/build/libs
# prov/build/libs
# pkix/build/libs
#
```
NB: The above was built disabling the tests.


OpenJDK does not enforce provider signing which can be advantageous in testing. If you are using a JVM that does
enforce provider signing then you will need to download the provider from the betas page.

If you are familiar with .BAT files you will be able to examine each .sh file to see how to invoke the examples.


## The code:
The code can be found in
```
/src/main/java/org/bouncycastle/test/est/examples
```

## Utility Scripts:
The utility scripts to run each example can be found in same folder as this file.


### Fetching CA Certs

The Bouncycastle EST client makes no assumptions about trust anchors, it assumes that the caller either can supply
trust anchors or it cannot, if you don't supply trust anchors the only interaction you may perform is to request CA
certificates from an EST server using the Bootstrapping procedure defined in RFC 7030.

#### Arguments

```
-t <file>                         Trust anchor file. (PEM)
-u <url>                          Server Hostname
--printTLS <url>                  Print TLS certificates as PEM format
--tls <version>                   Use this TLS version when creating socket factory, Eg TLSv1.2
--tlsProvider <provider> <class>  The JSSE Provider.
--to <milliseconds>               Timeout in milliseconds.
--no-name-verifier                No hostname verifier.
--label <ca label>                CA Label.


```



#### Bootstrapping
If bootstrapping is used, the user will be asked to manually validate the certificates, you will be presented with the
peer certificates from the TLS connection first, then you will be presented with the CA certificate second.
You will need to confirm by typing 'y [enter]' for each certificate:

```
#
# Run the following to get ca certs with bootstrapping.
#
./cacerts.sh -u testrfc7030.com:8443


Subject: CN=testrfc7030.cisco.com, O="Cisco Systems, Inc.", L=San Jose, ST=CA, C=US
Issuer: CN=HydrantID SSL ICA G2, O=HydrantID (Avalanche Cloud Corporation), C=US
Serial Number: 14501330919915432666369885490604141760160130548
Not Before: Tue Oct 11 01:02:35 AEDT 2016
Not After: Thu Oct 11 01:02:29 AEDT 2018
Signature Algorithm: SHA256withRSA

Subject: CN=HydrantID SSL ICA G2, O=HydrantID (Avalanche Cloud Corporation), C=US
Issuer: CN=QuoVadis Root CA 2, O=QuoVadis Limited, C=BM
Serial Number: 668466794465057825139349354921536757627739689900
Not Before: Wed Dec 18 01:25:10 AEDT 2013
Not After: Mon Dec 18 01:25:10 AEDT 2023
Signature Algorithm: SHA256withRSA

As part of the TLS handshake, the server tendered to us these certificates.

Do you accept these certificates (y,n) ? 
y


The untrusted server tendered to us these certificates as CA certs
Subject: CN=estExampleCA
Issuer: CN=estExampleCA
Serial Number: 13965287907438568554
Not Before: Thu Sep 08 03:19:39 AEST 2016
Not After: Fri Sep 08 03:19:39 AEST 2017
Signature Algorithm: org.bouncycastle.asn1.x509.AlgorithmIdentifier@ca7a8819


Do you accept these certificates (y,n) ? 
y

Fetched CA Certs:


-----BEGIN CERTIFICATE-----
MIIBUjCB+aADAgECAgkAwc6rXEzvJGowCQYHKoZIzj0EATAXMRUwEwYDVQQDEwxl
c3RFeGFtcGxlQ0EwHhcNMTYwOTA3MTcxOTM5WhcNMTcwOTA3MTcxOTM5WjAXMRUw
EwYDVQQDEwxlc3RFeGFtcGxlQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQs
JmLuU8faAKwGQs6A0WpYlwdwR/C0U6kvIIMjcLdPX+OBtYtHo2B8WMDOU5AkGgZ+
Bmy9ZdaZj2BTqGqsiNSioy8wLTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBTSse7P
EyPT3DkGbsMutPbRjWpKdDAJBgcqhkjOPQQBA0kAMEYCIQDtdmXQD7TQo/mLMsce
Hw+Xzwb+1WhQoG8ra1PkEugcygIhAPOZ/L5cnpw/1S8rpVfxSVXUOQpatrgIo50y
WmAvxibh
-----END CERTIFICATE-----
```

As we are using the Cisco Test Server: 
```
http://testrfc7030.com/
```

In order to proceed you will need copy the last TLS certificate and use that as a trust anchor for the remaining examples:

```
./cacerts.sh -u testrfc7030.com:8443 --printTLS

```
Answer the prompts as usual and at the very the TLS peer certificates will be printed PEM encoded.
Take the last one of those and use it as a trust anchor, so cut and paste that into a file.
Or try this one, but be aware it may not be current.

Copy the certificate to the file: ```server.ta.pem```

```
-----BEGIN CERTIFICATE-----
MIIGxDCCBKygAwIBAgIUdRcWd4PQQ361VsNXlG5FY7jr06wwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxGzAZ
BgNVBAMTElF1b1ZhZGlzIFJvb3QgQ0EgMjAeFw0xMzEyMTcxNDI1MTBaFw0yMzEy
MTcxNDI1MTBaMF4xCzAJBgNVBAYTAlVTMTAwLgYDVQQKEydIeWRyYW50SUQgKEF2
YWxhbmNoZSBDbG91ZCBDb3Jwb3JhdGlvbikxHTAbBgNVBAMTFEh5ZHJhbnRJRCBT
U0wgSUNBIEcyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9p1ZOA9+
H+tgdln+STF7bdOxvnOERYyjo8ZbKumzigNePSwbQYVWuso76GI843yjaX2rhn0+
Jt0NVJM41jVctf9qwacVduR7CEi0qJgpAUJyZUuB9IpFWF1Kz14O3Leh6URuRZ43
RzHaRmNtzkxttGBuOtAg+ilOuwiGAo9VQLgdONlqQFcrbp97/fO8ZIqiPrbhLxCZ
fXkYi3mktZVRFKXG62FHAuH1sLDXCKba3avDcUR7ykG4ZXcmp6kl14UKa8JHOHPE
NYyr0R6oHELOGZMox1nQcFwuYMX9sJdAUU/9SQVXyA6u6YtxlpZiC8qhXM1IE00T
Q9+q5ppffSUDMC4V/5If5A6snKVP78M8qd/RMVswcjMUMEnov+wykwCbDLD+IReM
A57XX+HojN+8XFTL9Jwge3z3ZlMwL7E54W3cI7f6cxO5DVwoKxkdk2jRIg37oqSl
SU3z/bA9UXjHcTl/6BoLho2p9rWm6oljANPeQuLHyGJ3hc19N8nDo2IATp70klGP
kd1qhIgrdkki7gBpanMOK98hKMpdQgs+NY4DkaMJqfrHzWR/CYkdyUCivFaepaFS
K78+jVu1oCMOFOnucPXL2fQa3VQn+69+7mA324frjwZj9NzrHjd0a5UP7waPpd9W
2jZoj4b+g+l+XU1SQ+9DWiuZtvfDW++k0BMCAwEAAaOCAZEwggGNMBIGA1UdEwEB
/wQIMAYBAf8CAQAweAYDVR0gBHEwbzAIBgZngQwBAgEwCAYGZ4EMAQICMA4GDCsG
AQQBvlgAAmQBAjBJBgwrBgEEAb5YAAOHBAAwOTA3BggrBgEFBQcCARYraHR0cDov
L3d3dy5oeWRyYW50aWQuY29tL3N1cHBvcnQvcmVwb3NpdG9yeTByBggrBgEFBQcB
AQRmMGQwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3NwLnF1b3ZhZGlzZ2xvYmFsLmNv
bTA2BggrBgEFBQcwAoYqaHR0cDovL3RydXN0LnF1b3ZhZGlzZ2xvYmFsLmNvbS9x
dnJjYTIuY3J0MA4GA1UdDwEB/wQEAwIBBjAfBgNVHSMEGDAWgBQahGK8SEwzJQTU
7tD2A8QZRtGUazA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vY3JsLnF1b3ZhZGlz
Z2xvYmFsLmNvbS9xdnJjYTIuY3JsMB0GA1UdDgQWBBSYarYtLr+nqp/299YJr9WL
V/mKtzANBgkqhkiG9w0BAQsFAAOCAgEAlraik8EDDUkpAnIOajO9/r4dpj/Zry76
6SH1oYPo7eTGzpDanPMeGMuSmwdjUkFUPALuWwkaDERfz9xdyFL3N8CRg9mQhdtT
3aWQUv/iyXULXT87EgL3b8zzf8fhTS7r654m9WM2W7pFqfimx9qAlFe9XcVlZrUu
9hph+/MfWMrUju+VPL5U7hZvUpg66mS3BaN15rsXv2+Vw6kQsQC/82iJLHvtYVL/
LwbNio18CsinDeyRE0J9wlYDqzcg5rhD0rtX4JEmBzq8yBRvHIB/023o/vIO5oxh
83Hic/2Xgwksf1DKS3/z5nTzhsUIpCpwkN6nHp6gmA8JBXoUlKQz4eYHJCq/ZyC+
BuY2vHpNx6101J5dmy7ps7J7d6mZXzguP3DQN84hjtfwJPqdf+/9RgLriXeFTqwe
snxbk2FsPhwxhiNOH98GSZVvG02v10uHLVaf9B+puYpoUiEqgm1WG5mWW1PxHstu
Ew9jBMcJ6wjQc8He9rSUmrhBr0HyhckdC99RgEvpcZpV2XL4nPPrTI2ki/c9xQb9
kmhVGonSXy5aP+hDC+Ht+bxmc4wN5x+vB02hak8Hh8jIUStRxOsRfJozU0R9ysyP
EZAHFZ3Zivg2BaD4tOISO8/T2FDjG7PNUv0tgPAOKw2t94B+1evrSUhqJDU0Wf9c
9vkaKoPvX4w=
-----END CERTIFICATE-----
```

#### Non bootstrap fetching of CA certs

If you have a trust anchor then fetching CA certs will simply
return the CA cert, if the server cannot be validated with
the trust anchor it will fail.

```
./cacerts.sh -u testrfc7030.com:8443 -t server.ta.pem 

Fetched CA Certs:

-----BEGIN CERTIFICATE-----
MIIBUjCB+aADAgECAgkAwc6rXEzvJGowCQYHKoZIzj0EATAXMRUwEwYDVQQDEwxl
c3RFeGFtcGxlQ0EwHhcNMTYwOTA3MTcxOTM5WhcNMTcwOTA3MTcxOTM5WjAXMRUw
EwYDVQQDEwxlc3RFeGFtcGxlQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQs
JmLuU8faAKwGQs6A0WpYlwdwR/C0U6kvIIMjcLdPX+OBtYtHo2B8WMDOU5AkGgZ+
Bmy9ZdaZj2BTqGqsiNSioy8wLTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBTSse7P
EyPT3DkGbsMutPbRjWpKdDAJBgcqhkjOPQQBA0kAMEYCIQDtdmXQD7TQo/mLMsce
Hw+Xzwb+1WhQoG8ra1PkEugcygIhAPOZ/L5cnpw/1S8rpVfxSVXUOQpatrgIo50y
WmAvxibh
-----END CERTIFICATE-----

```

___

Unit Tests for CA cert fetching can be found in:

```<bc-java>/test/src/test/java/org/bouncycastle/test/est/TestCACertsFetch.java```

___


### Enrollment
To perform enrollment the user must have a trust anchor to verify the EST server, the enrollment example
can accept an optional keystore without a trust anchor for client side authentication.

The enroll example has a number of options:
```
./enroll.sh

--r                                     Re-enroll
 -t <file>                              Trust anchor file
 -u <url>                               EST hostname url.
 -c <common name>                       EST CN.
 --keyStore <file>                      Optional Key Store.
 --keyStorePass <password>              Optional Key Store password.
 --keyStoreType <JKS>                   Optional Key Store type, defaults to JKS
 --auth <realm:user:password>           Auth credentials, if real is not
 --tls <version>                        Use this TLS version when creating socket factory, Eg TLSv1.2
 --tlsProvider <provider> <class>       The JSSE Provider.
 --pop                                  Turn on PoP
 --to <milliseconds>                    Timeout in milliseconds.
 --no-name-verifier                     No hostname verifier.
 --label <ca label>                     CA Label.
 --save <path to file>                  Save generated public and private key to file, (PEM)
 --load <path to file>                  Load generated public and private key from a file, (PEM)

```


This following enrollment example will generate CSR internally but you an specify the common name, when enrollment is complete
it will return a summary of the returned certificate.
```
./enroll.sh -t server.ta.pem -u testrfc7030.com:8443 --auth estuser:estpwd -c BARRY


Subject: CN=BARRY
Issuer: CN=estExampleCA
Serial Number: 8727
Not Before: Tue Feb 07 16:00:25 AEDT 2017
Not After: Wed Feb 07 16:00:25 AEDT 2018
Signature Algorithm: org.bouncycastle.asn1.x509.AlgorithmIdentifier@ca7a8819

```


#### Enrollment with PoP
The Enrollment client defaults to use BCJSSE for its TLS provider as it supports the extraction of the TLS unique value required for PoP. At the time of writing, extraction of the TLS unique value is not supported by the default JSSE provider.

---
Unit Tests for Enrollment can be found in:

```test/src/test/java/org/bouncycastle/test/est/TestEnroll.java```

And for reenrollment:
```<bc-java>/test/src/test/java/org/bouncycastle/test/est/TestReEnroll.java```

---

#### Loading and saving key pairs.

Use the ```--load <file>``` and ```--save <file>``` to load and save the generated keys used with the CSR for enrollment.



### Fetching CSR Attributes
The EST server may require that CSRs have a certain set of attributes. 
These attributes can be fetched from the server and you will need a trust
anchor for the server to make this call.

#### Arguments
```
-t <file>                         Trust anchor file. (PEM)
-u <url>                          Server Hostname
--tls <version>                   Use this TLS version when creating socket factory, Eg TLSv1.2
--tlsProvider <provider> <class>  The JSSE Provider.
--to <milliseconds>               Timeout in milliseconds.
--no-name-verifier                No hostname verifier.
--label <ca label>                CA Label.

```


To fetch the attributes:

```
./csrattrs.sh -t server.ta.pem -u testrfc7030.com:8443

1.2.840.113549.1.9.1
1.3.132.0.34
2.16.840.1.101.3.4.2.2
1.3.6.1.1.1.1.22

```

---
Unit tests for fetching csr attributes can be found in:
```<bc-java>/test/src/test/java/org/bouncycastle/test/est/TestGetCSRAttrs.java```
---
