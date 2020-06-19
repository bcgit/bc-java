package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.Hashtable;
import java.util.Set;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class CertTest
    implements Test
{
    //
    // server.crt
    //
    byte[]  cert1 = Base64.decode(
           "MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
         + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
         + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
         + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
         + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2"
         + "MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
         + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
         + "dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l"
         + "Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv"
         + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re"
         + "Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO"
         + "Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE"
         + "7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy"
         + "QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0"
         + "ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw"
         + "DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL"
         + "iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4"
         + "yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF"
         + "5/8=");

    //
    // ca.crt
    //
    byte[]  cert2 = Base64.decode(
           "MIIDbDCCAtWgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
         + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
         + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
         + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
         + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU1MzNaFw0wMTA2"
         + "MDIwNzU1MzNaMIG3MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
         + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
         + "dGQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEVMBMGA1UEAxMMQ29u"
         + "bmVjdCA0IENBMSgwJgYJKoZIhvcNAQkBFhl3ZWJtYXN0ZXJAY29ubmVjdDQuY29t"
         + "LmF1MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgs5ptNG6Qv1ZpCDuUNGmv"
         + "rhjqMDPd3ri8JzZNRiiFlBA4e6/ReaO1U8ASewDeQMH6i9R6degFdQRLngbuJP0s"
         + "xcEE+SksEWNvygfzLwV9J/q+TQDyJYK52utb++lS0b48A1KPLwEsyL6kOAgelbur"
         + "ukwxowprKUIV7Knf1ajetQIDAQABo4GFMIGCMCQGA1UdEQQdMBuBGXdlYm1hc3Rl"
         + "ckBjb25uZWN0NC5jb20uYXUwDwYDVR0TBAgwBgEB/wIBADA2BglghkgBhvhCAQ0E"
         + "KRYnbW9kX3NzbCBnZW5lcmF0ZWQgY3VzdG9tIENBIGNlcnRpZmljYXRlMBEGCWCG"
         + "SAGG+EIBAQQEAwICBDANBgkqhkiG9w0BAQQFAAOBgQCsGvfdghH8pPhlwm1r3pQk"
         + "msnLAVIBb01EhbXm2861iXZfWqGQjrGAaA0ZpXNk9oo110yxoqEoSJSzniZa7Xtz"
         + "soTwNUpE0SLHvWf/SlKdFWlzXA+vOZbzEv4UmjeelekTm7lc01EEa5QRVzOxHFtQ"
         + "DhkaJ8VqOMajkQFma2r9iA==");

    //
    // testx509.pem
    //
    byte[]  cert3 = Base64.decode(
           "MIIBWzCCAQYCARgwDQYJKoZIhvcNAQEEBQAwODELMAkGA1UEBhMCQVUxDDAKBgNV"
         + "BAgTA1FMRDEbMBkGA1UEAxMSU1NMZWF5L3JzYSB0ZXN0IENBMB4XDTk1MDYxOTIz"
         + "MzMxMloXDTk1MDcxNzIzMzMxMlowOjELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA1FM"
         + "RDEdMBsGA1UEAxMUU1NMZWF5L3JzYSB0ZXN0IGNlcnQwXDANBgkqhkiG9w0BAQEF"
         + "AANLADBIAkEAqtt6qS5GTxVxGZYWa0/4u+IwHf7p2LNZbcPBp9/OfIcYAXBQn8hO"
         + "/Re1uwLKXdCjIoaGs4DLdG88rkzfyK5dPQIDAQABMAwGCCqGSIb3DQIFBQADQQAE"
         + "Wc7EcF8po2/ZO6kNCwK/ICH6DobgLekA5lSLr5EvuioZniZp5lFzAw4+YzPQ7XKJ"
         + "zl9HYIMxATFyqSiD9jsx");

    //
    // v3-cert1.pem
    //
    byte[]  cert4 = Base64.decode(
           "MIICjTCCAfigAwIBAgIEMaYgRzALBgkqhkiG9w0BAQQwRTELMAkGA1UEBhMCVVMx"
         + "NjA0BgNVBAoTLU5hdGlvbmFsIEFlcm9uYXV0aWNzIGFuZCBTcGFjZSBBZG1pbmlz"
         + "dHJhdGlvbjAmFxE5NjA1MjgxMzQ5MDUrMDgwMBcROTgwNTI4MTM0OTA1KzA4MDAw"
         + "ZzELMAkGA1UEBhMCVVMxNjA0BgNVBAoTLU5hdGlvbmFsIEFlcm9uYXV0aWNzIGFu"
         + "ZCBTcGFjZSBBZG1pbmlzdHJhdGlvbjEgMAkGA1UEBRMCMTYwEwYDVQQDEwxTdGV2"
         + "ZSBTY2hvY2gwWDALBgkqhkiG9w0BAQEDSQAwRgJBALrAwyYdgxmzNP/ts0Uyf6Bp"
         + "miJYktU/w4NG67ULaN4B5CnEz7k57s9o3YY3LecETgQ5iQHmkwlYDTL2fTgVfw0C"
         + "AQOjgaswgagwZAYDVR0ZAQH/BFowWDBWMFQxCzAJBgNVBAYTAlVTMTYwNAYDVQQK"
         + "Ey1OYXRpb25hbCBBZXJvbmF1dGljcyBhbmQgU3BhY2UgQWRtaW5pc3RyYXRpb24x"
         + "DTALBgNVBAMTBENSTDEwFwYDVR0BAQH/BA0wC4AJODMyOTcwODEwMBgGA1UdAgQR"
         + "MA8ECTgzMjk3MDgyM4ACBSAwDQYDVR0KBAYwBAMCBkAwCwYJKoZIhvcNAQEEA4GB"
         + "AH2y1VCEw/A4zaXzSYZJTTUi3uawbbFiS2yxHvgf28+8Js0OHXk1H1w2d6qOHH21"
         + "X82tZXd/0JtG0g1T9usFFBDvYK8O0ebgz/P5ELJnBL2+atObEuJy1ZZ0pBDWINR3"
         + "WkDNLCGiTkCKp0F5EWIrVDwh54NNevkCQRZita+z4IBO");

    //
    // v3-cert2.pem
    //
    byte[]  cert5 = Base64.decode(
           "MIICiTCCAfKgAwIBAgIEMeZfHzANBgkqhkiG9w0BAQQFADB9MQswCQYDVQQGEwJD"
         + "YTEPMA0GA1UEBxMGTmVwZWFuMR4wHAYDVQQLExVObyBMaWFiaWxpdHkgQWNjZXB0"
         + "ZWQxHzAdBgNVBAoTFkZvciBEZW1vIFB1cnBvc2VzIE9ubHkxHDAaBgNVBAMTE0Vu"
         + "dHJ1c3QgRGVtbyBXZWIgQ0EwHhcNOTYwNzEyMTQyMDE1WhcNOTYxMDEyMTQyMDE1"
         + "WjB0MSQwIgYJKoZIhvcNAQkBExVjb29rZUBpc3NsLmF0bC5ocC5jb20xCzAJBgNV"
         + "BAYTAlVTMScwJQYDVQQLEx5IZXdsZXR0IFBhY2thcmQgQ29tcGFueSAoSVNTTCkx"
         + "FjAUBgNVBAMTDVBhdWwgQS4gQ29va2UwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA"
         + "6ceSq9a9AU6g+zBwaL/yVmW1/9EE8s5you1mgjHnj0wAILuoB3L6rm6jmFRy7QZT"
         + "G43IhVZdDua4e+5/n1ZslwIDAQABo2MwYTARBglghkgBhvhCAQEEBAMCB4AwTAYJ"
         + "YIZIAYb4QgENBD8WPVRoaXMgY2VydGlmaWNhdGUgaXMgb25seSBpbnRlbmRlZCBm"
         + "b3IgZGVtb25zdHJhdGlvbiBwdXJwb3Nlcy4wDQYJKoZIhvcNAQEEBQADgYEAi8qc"
         + "F3zfFqy1sV8NhjwLVwOKuSfhR/Z8mbIEUeSTlnH3QbYt3HWZQ+vXI8mvtZoBc2Fz"
         + "lexKeIkAZXCesqGbs6z6nCt16P6tmdfbZF3I3AWzLquPcOXjPf4HgstkyvVBn0Ap"
         + "jAFN418KF/Cx4qyHB4cjdvLrRjjQLnb2+ibo7QU=");

    //
    // pem encoded pkcs7
    //
    byte[]  cert6 = Base64.decode(
          "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAQAAoIIJbzCCAj0w"
        + "ggGmAhEAzbp/VvDf5LxU/iKss3KqVTANBgkqhkiG9w0BAQIFADBfMQswCQYDVQQGEwJVUzEXMBUG"
        + "A1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDEgUHVibGljIFByaW1hcnkgQ2Vy"
        + "dGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNOTYwMTI5MDAwMDAwWhcNMjgwODAxMjM1OTU5WjBfMQsw"
        + "CQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDEgUHVi"
        + "bGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEBBQADgY0A"
        + "MIGJAoGBAOUZv22jVmEtmUhx9mfeuY3rt56GgAqRDvo4Ja9GiILlc6igmyRdDR/MZW4MsNBWhBiH"
        + "mgabEKFz37RYOWtuwfYV1aioP6oSBo0xrH+wNNePNGeICc0UEeJORVZpH3gCgNrcR5EpuzbJY1zF"
        + "4Ncth3uhtzKwezC6Ki8xqu6jZ9rbAgMBAAEwDQYJKoZIhvcNAQECBQADgYEATD+4i8Zo3+5DMw5d"
        + "6abLB4RNejP/khv0Nq3YlSI2aBFsfELM85wuxAc/FLAPT/+Qknb54rxK6Y/NoIAK98Up8YIiXbix"
        + "3YEjo3slFUYweRb46gVLlH8dwhzI47f0EEA8E8NfH1PoSOSGtHuhNbB7Jbq4046rPzidADQAmPPR"
        + "cZQwggMuMIICl6ADAgECAhEA0nYujRQMPX2yqCVdr+4NdTANBgkqhkiG9w0BAQIFADBfMQswCQYD"
        + "VQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDEgUHVibGlj"
        + "IFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNOTgwNTEyMDAwMDAwWhcNMDgwNTEy"
        + "MjM1OTU5WjCBzDEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRy"
        + "dXN0IE5ldHdvcmsxRjBEBgNVBAsTPXd3dy52ZXJpc2lnbi5jb20vcmVwb3NpdG9yeS9SUEEgSW5j"
        + "b3JwLiBCeSBSZWYuLExJQUIuTFREKGMpOTgxSDBGBgNVBAMTP1ZlcmlTaWduIENsYXNzIDEgQ0Eg"
        + "SW5kaXZpZHVhbCBTdWJzY3JpYmVyLVBlcnNvbmEgTm90IFZhbGlkYXRlZDCBnzANBgkqhkiG9w0B"
        + "AQEFAAOBjQAwgYkCgYEAu1pEigQWu1X9A3qKLZRPFXg2uA1Ksm+cVL+86HcqnbnwaLuV2TFBcHqB"
        + "S7lIE1YtxwjhhEKrwKKSq0RcqkLwgg4C6S/7wju7vsknCl22sDZCM7VuVIhPh0q/Gdr5FegPh7Yc"
        + "48zGmo5/aiSS4/zgZbqnsX7vyds3ashKyAkG5JkCAwEAAaN8MHowEQYJYIZIAYb4QgEBBAQDAgEG"
        + "MEcGA1UdIARAMD4wPAYLYIZIAYb4RQEHAQEwLTArBggrBgEFBQcCARYfd3d3LnZlcmlzaWduLmNv"
        + "bS9yZXBvc2l0b3J5L1JQQTAPBgNVHRMECDAGAQH/AgEAMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0B"
        + "AQIFAAOBgQCIuDc73dqUNwCtqp/hgQFxHpJqbS/28Z3TymQ43BuYDAeGW4UVag+5SYWklfEXfWe0"
        + "fy0s3ZpCnsM+tI6q5QsG3vJWKvozx74Z11NMw73I4xe1pElCY+zCphcPXVgaSTyQXFWjZSAA/Rgg"
        + "5V+CprGoksVYasGNAzzrw80FopCubjCCA/gwggNhoAMCAQICEBbbn/1G1zppD6KsP01bwywwDQYJ"
        + "KoZIhvcNAQEEBQAwgcwxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2ln"
        + "biBUcnVzdCBOZXR3b3JrMUYwRAYDVQQLEz13d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvUlBB"
        + "IEluY29ycC4gQnkgUmVmLixMSUFCLkxURChjKTk4MUgwRgYDVQQDEz9WZXJpU2lnbiBDbGFzcyAx"
        + "IENBIEluZGl2aWR1YWwgU3Vic2NyaWJlci1QZXJzb25hIE5vdCBWYWxpZGF0ZWQwHhcNMDAxMDAy"
        + "MDAwMDAwWhcNMDAxMjAxMjM1OTU5WjCCAQcxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYD"
        + "VQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMUYwRAYDVQQLEz13d3cudmVyaXNpZ24uY29tL3Jl"
        + "cG9zaXRvcnkvUlBBIEluY29ycC4gYnkgUmVmLixMSUFCLkxURChjKTk4MR4wHAYDVQQLExVQZXJz"
        + "b25hIE5vdCBWYWxpZGF0ZWQxJzAlBgNVBAsTHkRpZ2l0YWwgSUQgQ2xhc3MgMSAtIE1pY3Jvc29m"
        + "dDETMBEGA1UEAxQKRGF2aWQgUnlhbjElMCMGCSqGSIb3DQEJARYWZGF2aWRAbGl2ZW1lZGlhLmNv"
        + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqxBsdeNmSvFqhMNwhQgNzM8mdjX9eSXb"
        + "DawpHtQHjmh0AKJSa3IwUY0VIsyZHuXWktO/CgaMBVPt6OVf/n0R2sQigMP6Y+PhEiS0vCJBL9aK"
        + "0+pOo2qXrjVBmq+XuCyPTnc+BOSrU26tJsX0P9BYorwySiEGxGanBNATdVL4NdUCAwEAAaOBnDCB"
        + "mTAJBgNVHRMEAjAAMEQGA1UdIAQ9MDswOQYLYIZIAYb4RQEHAQgwKjAoBggrBgEFBQcCARYcaHR0"
        + "cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYTARBglghkgBhvhCAQEEBAMCB4AwMwYDVR0fBCwwKjAo"
        + "oCagJIYiaHR0cDovL2NybC52ZXJpc2lnbi5jb20vY2xhc3MxLmNybDANBgkqhkiG9w0BAQQFAAOB"
        + "gQBC8yIIdVGpFTf8/YiL14cMzcmL0nIRm4kGR3U59z7UtcXlfNXXJ8MyaeI/BnXwG/gD5OKYqW6R"
        + "yca9vZOxf1uoTBl82gInk865ED3Tej6msCqFzZffnSUQvOIeqLxxDlqYRQ6PmW2nAnZeyjcnbI5Y"
        + "syQSM2fmo7n6qJFP+GbFezGCAkUwggJBAgEBMIHhMIHMMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5j"
        + "LjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazFGMEQGA1UECxM9d3d3LnZlcmlzaWdu"
        + "LmNvbS9yZXBvc2l0b3J5L1JQQSBJbmNvcnAuIEJ5IFJlZi4sTElBQi5MVEQoYyk5ODFIMEYGA1UE"
        + "AxM/VmVyaVNpZ24gQ2xhc3MgMSBDQSBJbmRpdmlkdWFsIFN1YnNjcmliZXItUGVyc29uYSBOb3Qg"
        + "VmFsaWRhdGVkAhAW25/9Rtc6aQ+irD9NW8MsMAkGBSsOAwIaBQCggbowGAYJKoZIhvcNAQkDMQsG"
        + "CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMDAxMDAyMTczNTE4WjAjBgkqhkiG9w0BCQQxFgQU"
        + "gZjSaBEY2oxGvlQUIMnxSXhivK8wWwYJKoZIhvcNAQkPMU4wTDAKBggqhkiG9w0DBzAOBggqhkiG"
        + "9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4DAgcwDQYIKoZIhvcNAwICASgwBwYFKw4DAh0w"
        + "DQYJKoZIhvcNAQEBBQAEgYAzk+PU91/ZFfoiuKOECjxEh9fDYE2jfDCheBIgh5gdcCo+sS1WQs8O"
        + "HreQ9Nop/JdJv1DQMBK6weNBBDoP0EEkRm1XCC144XhXZC82jBZohYmi2WvDbbC//YN58kRMYMyy"
        + "srrfn4Z9I+6kTriGXkrpGk9Q0LSGjmG2BIsqiF0dvwAAAAAAAA==");

    //
    // dsaWithSHA1 cert
    //
    byte[]  cert7 = Base64.decode(
          "MIIEXAYJKoZIhvcNAQcCoIIETTCCBEkCAQExCzAJBgUrDgMCGgUAMAsGCSqG"
        + "SIb3DQEHAaCCAsMwggK/MIIB4AIBADCBpwYFKw4DAhswgZ0CQQEkJRHP+mN7"
        + "d8miwTMN55CUSmo3TO8WGCxgY61TX5k+7NU4XPf1TULjw3GobwaJX13kquPh"
        + "fVXk+gVy46n4Iw3hAhUBSe/QF4BUj+pJOF9ROBM4u+FEWA8CQQD4mSJbrABj"
        + "TUWrlnAte8pS22Tq4/FPO7jHSqjijUHfXKTrHL1OEqV3SVWcFy5j/cqBgX/z"
        + "m8Q12PFp/PjOhh+nMA4xDDAKBgNVBAMTA0lEMzAeFw05NzEwMDEwMDAwMDBa"
        + "Fw0zODAxMDEwMDAwMDBaMA4xDDAKBgNVBAMTA0lEMzCB8DCBpwYFKw4DAhsw"
        + "gZ0CQQEkJRHP+mN7d8miwTMN55CUSmo3TO8WGCxgY61TX5k+7NU4XPf1TULj"
        + "w3GobwaJX13kquPhfVXk+gVy46n4Iw3hAhUBSe/QF4BUj+pJOF9ROBM4u+FE"
        + "WA8CQQD4mSJbrABjTUWrlnAte8pS22Tq4/FPO7jHSqjijUHfXKTrHL1OEqV3"
        + "SVWcFy5j/cqBgX/zm8Q12PFp/PjOhh+nA0QAAkEAkYkXLYMtGVGWj9OnzjPn"
        + "sB9sefSRPrVegZJCZbpW+Iv0/1RP1u04pHG9vtRpIQLjzUiWvLMU9EKQTThc"
        + "eNMmWDCBpwYFKw4DAhswgZ0CQQEkJRHP+mN7d8miwTMN55CUSmo3TO8WGCxg"
        + "Y61TX5k+7NU4XPf1TULjw3GobwaJX13kquPhfVXk+gVy46n4Iw3hAhUBSe/Q"
        + "F4BUj+pJOF9ROBM4u+FEWA8CQQD4mSJbrABjTUWrlnAte8pS22Tq4/FPO7jH"
        + "SqjijUHfXKTrHL1OEqV3SVWcFy5j/cqBgX/zm8Q12PFp/PjOhh+nAy8AMCwC"
        + "FBY3dBSdeprGcqpr6wr3xbG+6WW+AhRMm/facKJNxkT3iKgJbp7R8Xd3QTGC"
        + "AWEwggFdAgEBMBMwDjEMMAoGA1UEAxMDSUQzAgEAMAkGBSsOAwIaBQCgXTAY"
        + "BgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0wMjA1"
        + "MjQyMzEzMDdaMCMGCSqGSIb3DQEJBDEWBBS4WMsoJhf7CVbZYCFcjoTRzPkJ"
        + "xjCBpwYFKw4DAhswgZ0CQQEkJRHP+mN7d8miwTMN55CUSmo3TO8WGCxgY61T"
        + "X5k+7NU4XPf1TULjw3GobwaJX13kquPhfVXk+gVy46n4Iw3hAhUBSe/QF4BU"
        + "j+pJOF9ROBM4u+FEWA8CQQD4mSJbrABjTUWrlnAte8pS22Tq4/FPO7jHSqji"
        + "jUHfXKTrHL1OEqV3SVWcFy5j/cqBgX/zm8Q12PFp/PjOhh+nBC8wLQIVALID"
        + "dt+MHwawrDrwsO1Z6sXBaaJsAhRaKssrpevmLkbygKPV07XiAKBG02Zvb2Jh"
        + "cg==");

    //
    // testcrl.pem
    //
    byte[]  crl1 = Base64.decode(
        "MIICjTCCAfowDQYJKoZIhvcNAQECBQAwXzELMAkGA1UEBhMCVVMxIDAeBgNVBAoT"
        + "F1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2VydmVy"
        + "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05NTA1MDIwMjEyMjZaFw05NTA2MDEw"
        + "MDAxNDlaMIIBaDAWAgUCQQAABBcNOTUwMjAxMTcyNDI2WjAWAgUCQQAACRcNOTUw"
        + "MjEwMDIxNjM5WjAWAgUCQQAADxcNOTUwMjI0MDAxMjQ5WjAWAgUCQQAADBcNOTUw"
        + "MjI1MDA0NjQ0WjAWAgUCQQAAGxcNOTUwMzEzMTg0MDQ5WjAWAgUCQQAAFhcNOTUw"
        + "MzE1MTkxNjU0WjAWAgUCQQAAGhcNOTUwMzE1MTk0MDQxWjAWAgUCQQAAHxcNOTUw"
        + "MzI0MTk0NDMzWjAWAgUCcgAABRcNOTUwMzI5MjAwNzExWjAWAgUCcgAAERcNOTUw"
        + "MzMwMDIzNDI2WjAWAgUCQQAAIBcNOTUwNDA3MDExMzIxWjAWAgUCcgAAHhcNOTUw"
        + "NDA4MDAwMjU5WjAWAgUCcgAAQRcNOTUwNDI4MTcxNzI0WjAWAgUCcgAAOBcNOTUw"
        + "NDI4MTcyNzIxWjAWAgUCcgAATBcNOTUwNTAyMDIxMjI2WjANBgkqhkiG9w0BAQIF"
        + "AAN+AHqOEJXSDejYy0UwxxrH/9+N2z5xu/if0J6qQmK92W0hW158wpJg+ovV3+wQ"
        + "wvIEPRL2rocL0tKfAsVq1IawSJzSNgxG0lrcla3MrJBnZ4GaZDu4FutZh72MR3Gt"
        + "JaAL3iTJHJD55kK2D/VoyY1djlsPuNh6AEgdVwFAyp0v");

    //
    // ecdsa cert with extra octet string.
    //
    byte[]  oldEcdsa = Base64.decode(
          "MIICljCCAkCgAwIBAgIBATALBgcqhkjOPQQBBQAwgY8xCzAJBgNVBAYTAkFVMSgwJ"
        + "gYDVQQKEx9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHEw"
        + "lNZWxib3VybmUxETAPBgNVBAgTCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWV"
        + "kYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzAeFw0wMTEyMDcwMTAwMDRaFw0w"
        + "MTEyMDcwMTAxNDRaMIGPMQswCQYDVQQGEwJBVTEoMCYGA1UEChMfVGhlIExlZ2lvb"
        + "iBvZiB0aGUgQm91bmN5IENhc3RsZTESMBAGA1UEBxMJTWVsYm91cm5lMREwDwYDVQ"
        + "QIEwhWaWN0b3JpYTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5"
        + "jeWNhc3RsZS5vcmcwgeQwgb0GByqGSM49AgEwgbECAQEwKQYHKoZIzj0BAQIef///"
        + "////////////f///////gAAAAAAAf///////MEAEHn///////////////3///////"
        + "4AAAAAAAH///////AQeawFsO9zxiUHQ1lSSFHXKcanbL7J9HTd5YYXClCwKBB8CD/"
        + "qWPNyogWzMM7hkK+35BcPTWFc9Pyf7vTs8uaqvAh5///////////////9///+eXpq"
        + "fXZBx+9FSJoiQnQsDIgAEHwJbbcU7xholSP+w9nFHLebJUhqdLSU05lq/y9X+DHAw"
        + "CwYHKoZIzj0EAQUAA0MAMEACHnz6t4UNoVROp74ma4XNDjjGcjaqiIWPZLK8Bdw3G"
        + "QIeLZ4j3a6ividZl344UH+UPUE7xJxlYGuy7ejTsqRR");

    byte[]  uncompressedPtEC = Base64.decode(
          "MIIDKzCCAsGgAwIBAgICA+kwCwYHKoZIzj0EAQUAMGYxCzAJBgNVBAYTAkpQ"
        + "MRUwEwYDVQQKEwxuaXRlY2guYWMuanAxDjAMBgNVBAsTBWFpbGFiMQ8wDQYD"
        + "VQQDEwZ0ZXN0Y2ExHzAdBgkqhkiG9w0BCQEWEHRlc3RjYUBsb2NhbGhvc3Qw"
        + "HhcNMDExMDEzMTE1MzE3WhcNMjAxMjEyMTE1MzE3WjBmMQswCQYDVQQGEwJK"
        + "UDEVMBMGA1UEChMMbml0ZWNoLmFjLmpwMQ4wDAYDVQQLEwVhaWxhYjEPMA0G"
        + "A1UEAxMGdGVzdGNhMR8wHQYJKoZIhvcNAQkBFhB0ZXN0Y2FAbG9jYWxob3N0"
        + "MIIBczCCARsGByqGSM49AgEwggEOAgEBMDMGByqGSM49AQECKEdYWnajFmnZ"
        + "tzrukK2XWdle2v+GsD9l1ZiR6g7ozQDbhFH/bBiMDQcwVAQoJ5EQKrI54/CT"
        + "xOQ2pMsd/fsXD+EX8YREd8bKHWiLz8lIVdD5cBNeVwQoMKSc6HfI7vKZp8Q2"
        + "zWgIFOarx1GQoWJbMcSt188xsl30ncJuJT2OoARRBAqJ4fD+q6hbqgNSjTQ7"
        + "htle1KO3eiaZgcJ8rrnyN8P+5A8+5K+H9aQ/NbBR4Gs7yto5PXIUZEUgodHA"
        + "TZMSAcSq5ZYt4KbnSYaLY0TtH9CqAigEwZ+hglbT21B7ZTzYX2xj0x+qooJD"
        + "hVTLtIPaYJK2HrMPxTw6/zfrAgEPA1IABAnvfFcFDgD/JicwBGn6vR3N8MIn"
        + "mptZf/mnJ1y649uCF60zOgdwIyI7pVSxBFsJ7ohqXEHW0x7LrGVkdSEiipiH"
        + "LYslqh3xrqbAgPbl93GUo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB"
        + "/wQEAwIBxjAdBgNVHQ4EFgQUAEo62Xm9H6DcsE0zUDTza4BRG90wCwYHKoZI"
        + "zj0EAQUAA1cAMFQCKAQsCHHSNOqfJXLgt3bg5+k49hIBGVr/bfG0B9JU3rNt"
        + "Ycl9Y2zfRPUCKAK2ccOQXByAWfsasDu8zKHxkZv7LVDTFjAIffz3HaCQeVhD"
        + "z+fauEg=");

    byte[]  keyUsage = Base64.decode(
          "MIIE7TCCBFagAwIBAgIEOAOR7jANBgkqhkiG9w0BAQQFADCByTELMAkGA1UE"
        + "BhMCVVMxFDASBgNVBAoTC0VudHJ1c3QubmV0MUgwRgYDVQQLFD93d3cuZW50"
        + "cnVzdC5uZXQvQ2xpZW50X0NBX0luZm8vQ1BTIGluY29ycC4gYnkgcmVmLiBs"
        + "aW1pdHMgbGlhYi4xJTAjBgNVBAsTHChjKSAxOTk5IEVudHJ1c3QubmV0IExp"
        + "bWl0ZWQxMzAxBgNVBAMTKkVudHJ1c3QubmV0IENsaWVudCBDZXJ0aWZpY2F0"
        + "aW9uIEF1dGhvcml0eTAeFw05OTEwMTIxOTI0MzBaFw0xOTEwMTIxOTU0MzBa"
        + "MIHJMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLRW50cnVzdC5uZXQxSDBGBgNV"
        + "BAsUP3d3dy5lbnRydXN0Lm5ldC9DbGllbnRfQ0FfSW5mby9DUFMgaW5jb3Jw"
        + "LiBieSByZWYuIGxpbWl0cyBsaWFiLjElMCMGA1UECxMcKGMpIDE5OTkgRW50"
        + "cnVzdC5uZXQgTGltaXRlZDEzMDEGA1UEAxMqRW50cnVzdC5uZXQgQ2xpZW50"
        + "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGdMA0GCSqGSIb3DQEBAQUAA4GL"
        + "ADCBhwKBgQDIOpleMRffrCdvkHvkGf9FozTC28GoT/Bo6oT9n3V5z8GKUZSv"
        + "x1cDR2SerYIbWtp/N3hHuzeYEpbOxhN979IMMFGpOZ5V+Pux5zDeg7K6PvHV"
        + "iTs7hbqqdCz+PzFur5GVbgbUB01LLFZHGARS2g4Qk79jkJvh34zmAqTmT173"
        + "iwIBA6OCAeAwggHcMBEGCWCGSAGG+EIBAQQEAwIABzCCASIGA1UdHwSCARkw"
        + "ggEVMIHkoIHhoIHepIHbMIHYMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLRW50"
        + "cnVzdC5uZXQxSDBGBgNVBAsUP3d3dy5lbnRydXN0Lm5ldC9DbGllbnRfQ0Ff"
        + "SW5mby9DUFMgaW5jb3JwLiBieSByZWYuIGxpbWl0cyBsaWFiLjElMCMGA1UE"
        + "CxMcKGMpIDE5OTkgRW50cnVzdC5uZXQgTGltaXRlZDEzMDEGA1UEAxMqRW50"
        + "cnVzdC5uZXQgQ2xpZW50IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MQ0wCwYD"
        + "VQQDEwRDUkwxMCygKqAohiZodHRwOi8vd3d3LmVudHJ1c3QubmV0L0NSTC9D"
        + "bGllbnQxLmNybDArBgNVHRAEJDAigA8xOTk5MTAxMjE5MjQzMFqBDzIwMTkx"
        + "MDEyMTkyNDMwWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUxPucKXuXzUyW"
        + "/O5bs8qZdIuV6kwwHQYDVR0OBBYEFMT7nCl7l81MlvzuW7PKmXSLlepMMAwG"
        + "A1UdEwQFMAMBAf8wGQYJKoZIhvZ9B0EABAwwChsEVjQuMAMCBJAwDQYJKoZI"
        + "hvcNAQEEBQADgYEAP66K8ddmAwWePvrqHEa7pFuPeJoSSJn59DXeDDYHAmsQ"
        + "OokUgZwxpnyyQbJq5wcBoUv5nyU7lsqZwz6hURzzwy5E97BnRqqS5TvaHBkU"
        + "ODDV4qIxJS7x7EU47fgGWANzYrAQMY9Av2TgXD7FTx/aEkP/TOYGJqibGapE"
        + "PHayXOw=");

        byte[] nameCert = Base64.decode(
            "MIIEFjCCA3+gAwIBAgIEdS8BozANBgkqhkiG9w0BAQUFADBKMQswCQYDVQQGEwJE" +
            "RTERMA8GA1UEChQIREFURVYgZUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRQ0Eg" +
            "REFURVYgRDAzIDE6UE4wIhgPMjAwMTA1MTAxMDIyNDhaGA8yMDA0MDUwOTEwMjI0" +
            "OFowgYQxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIFAZCYXllcm4xEjAQBgNVBAcUCU7I" +
            "dXJuYmVyZzERMA8GA1UEChQIREFURVYgZUcxHTAbBgNVBAUTFDAwMDAwMDAwMDA4" +
            "OTU3NDM2MDAxMR4wHAYDVQQDFBVEaWV0bWFyIFNlbmdlbmxlaXRuZXIwgaEwDQYJ" +
            "KoZIhvcNAQEBBQADgY8AMIGLAoGBAJLI/LJLKaHoMk8fBECW/od8u5erZi6jI8Ug" +
            "C0a/LZyQUO/R20vWJs6GrClQtXB+AtfiBSnyZOSYzOdfDI8yEKPEv8qSuUPpOHps" +
            "uNCFdLZF1vavVYGEEWs2+y+uuPmg8q1oPRyRmUZ+x9HrDvCXJraaDfTEd9olmB/Z" +
            "AuC/PqpjAgUAwAAAAaOCAcYwggHCMAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/BAUD" +
            "AwdAADAxBgNVHSAEKjAoMCYGBSskCAEBMB0wGwYIKwYBBQUHAgEWD3d3dy56cy5k" +
            "YXRldi5kZTApBgNVHREEIjAggR5kaWV0bWFyLnNlbmdlbmxlaXRuZXJAZGF0ZXYu" +
            "ZGUwgYQGA1UdIwR9MHuhc6RxMG8xCzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1" +
            "bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0" +
            "MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjVSLUNBIDE6UE6CBACm8LkwDgYHAoIG" +
            "AQoMAAQDAQEAMEcGA1UdHwRAMD4wPKAUoBKGEHd3dy5jcmwuZGF0ZXYuZGWiJKQi" +
            "MCAxCzAJBgNVBAYTAkRFMREwDwYDVQQKFAhEQVRFViBlRzAWBgUrJAgDBAQNMAsT" +
            "A0VVUgIBBQIBATAdBgNVHQ4EFgQUfv6xFP0xk7027folhy+ziZvBJiwwLAYIKwYB" +
            "BQUHAQEEIDAeMBwGCCsGAQUFBzABhhB3d3cuZGlyLmRhdGV2LmRlMA0GCSqGSIb3" +
            "DQEBBQUAA4GBAEOVX6uQxbgtKzdgbTi6YLffMftFr2mmNwch7qzpM5gxcynzgVkg" +
            "pnQcDNlm5AIbS6pO8jTCLfCd5TZ5biQksBErqmesIl3QD+VqtB+RNghxectZ3VEs" +
            "nCUtcE7tJ8O14qwCb3TxS9dvIUFiVi4DjbxX46TdcTbTaK8/qr6AIf+l");

        byte[] probSelfSignedCert = Base64.decode(
               "MIICxTCCAi6gAwIBAgIQAQAAAAAAAAAAAAAAAAAAATANBgkqhkiG9w0BAQUFADBF"
             + "MScwJQYDVQQKEx4gRElSRUNUSU9OIEdFTkVSQUxFIERFUyBJTVBPVFMxGjAYBgNV"
             + "BAMTESBBQyBNSU5FRkkgQiBURVNUMB4XDTA0MDUwNzEyMDAwMFoXDTE0MDUwNzEy"
             + "MDAwMFowRTEnMCUGA1UEChMeIERJUkVDVElPTiBHRU5FUkFMRSBERVMgSU1QT1RT"
             + "MRowGAYDVQQDExEgQUMgTUlORUZJIEIgVEVTVDCBnzANBgkqhkiG9w0BAQEFAAOB"
             + "jQAwgYkCgYEAveoCUOAukZdcFCs2qJk76vSqEX0ZFzHqQ6faBPZWjwkgUNwZ6m6m"
             + "qWvvyq1cuxhoDvpfC6NXILETawYc6MNwwxsOtVVIjuXlcF17NMejljJafbPximEt"
             + "DQ4LcQeSp4K7FyFlIAMLyt3BQ77emGzU5fjFTvHSUNb3jblx0sV28c0CAwEAAaOB"
             + "tTCBsjAfBgNVHSMEGDAWgBSEJ4bLbvEQY8cYMAFKPFD1/fFXlzAdBgNVHQ4EFgQU"
             + "hCeGy27xEGPHGDABSjxQ9f3xV5cwDgYDVR0PAQH/BAQDAgEGMBEGCWCGSAGG+EIB"
             + "AQQEAwIBBjA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vYWRvbmlzLnBrNy5jZXJ0"
             + "cGx1cy5uZXQvZGdpLXRlc3QuY3JsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN"
             + "AQEFBQADgYEAmToHJWjd3+4zknfsP09H6uMbolHNGG0zTS2lrLKpzcmkQfjhQpT9"
             + "LUTBvfs1jdjo9fGmQLvOG+Sm51Rbjglb8bcikVI5gLbclOlvqLkm77otjl4U4Z2/"
             + "Y0vP14Aov3Sn3k+17EfReYUZI4liuB95ncobC4e8ZM++LjQcIM0s+Vs=");
        
        byte[] gost34102001base = Base64.decode(
                "MIIB1DCCAYECEEjpVKXP6Wn1yVz3VeeDQa8wCgYGKoUDAgIDBQAwbTEfMB0G"
                + "A1UEAwwWR29zdFIzNDEwLTIwMDEgZXhhbXBsZTESMBAGA1UECgwJQ3J5cHRv"
                + "UHJvMQswCQYDVQQGEwJSVTEpMCcGCSqGSIb3DQEJARYaR29zdFIzNDEwLTIw"
                + "MDFAZXhhbXBsZS5jb20wHhcNMDUwMjAzMTUxNjQ2WhcNMTUwMjAzMTUxNjQ2"
                + "WjBtMR8wHQYDVQQDDBZHb3N0UjM0MTAtMjAwMSBleGFtcGxlMRIwEAYDVQQK"
                + "DAlDcnlwdG9Qcm8xCzAJBgNVBAYTAlJVMSkwJwYJKoZIhvcNAQkBFhpHb3N0"
                + "UjM0MTAtMjAwMUBleGFtcGxlLmNvbTBjMBwGBiqFAwICEzASBgcqhQMCAiQA"
                + "BgcqhQMCAh4BA0MABECElWh1YAIaQHUIzROMMYks/eUFA3pDXPRtKw/nTzJ+"
                + "V4/rzBa5lYgD0Jp8ha4P5I3qprt+VsfLsN8PZrzK6hpgMAoGBiqFAwICAwUA"
                + "A0EAHw5dw/aw/OiNvHyOE65kvyo4Hp0sfz3csM6UUkp10VO247ofNJK3tsLb"
                + "HOLjUaqzefrlGb11WpHYrvWFg+FcLA==");
        
        byte[] gost341094base = Base64.decode(
                "MIICDzCCAbwCEBcxKsIb0ghYvAQeUjfQdFAwCgYGKoUDAgIEBQAwaTEdMBsG"
                + "A1UEAwwUR29zdFIzNDEwLTk0IGV4YW1wbGUxEjAQBgNVBAoMCUNyeXB0b1By"
                + "bzELMAkGA1UEBhMCUlUxJzAlBgkqhkiG9w0BCQEWGEdvc3RSMzQxMC05NEBl"
                + "eGFtcGxlLmNvbTAeFw0wNTAyMDMxNTE2NTFaFw0xNTAyMDMxNTE2NTFaMGkx"
                + "HTAbBgNVBAMMFEdvc3RSMzQxMC05NCBleGFtcGxlMRIwEAYDVQQKDAlDcnlw"
                + "dG9Qcm8xCzAJBgNVBAYTAlJVMScwJQYJKoZIhvcNAQkBFhhHb3N0UjM0MTAt"
                + "OTRAZXhhbXBsZS5jb20wgaUwHAYGKoUDAgIUMBIGByqFAwICIAIGByqFAwIC"
                + "HgEDgYQABIGAu4Rm4XmeWzTYLIB/E6gZZnFX/oxUJSFHbzALJ3dGmMb7R1W+"
                + "t7Lzk2w5tUI3JoTiDRCKJA4fDEJNKzsRK6i/ZjkyXJSLwaj+G2MS9gklh8x1"
                + "G/TliYoJgmjTXHemD7aQEBON4z58nJHWrA0ILD54wbXCtrcaqCqLRYGTMjJ2"
                + "+nswCgYGKoUDAgIEBQADQQBxKNhOmjgz/i5CEgLOyKyz9pFGkDcaymsWYQWV"
                + "v7CZ0pTM8IzMzkUBW3GHsUjCFpanFZDfg2zuN+3kT+694n9B");
        
        byte[] gost341094A = Base64.decode(
                "MIICSDCCAfWgAwIBAgIBATAKBgYqhQMCAgQFADCBgTEXMBUGA1UEAxMOZGVmYXVsdDM0MTAtOTQx"
                + "DTALBgNVBAoTBERpZ3QxDzANBgNVBAsTBkNyeXB0bzEOMAwGA1UEBxMFWS1vbGExDDAKBgNVBAgT"
                + "A01FTDELMAkGA1UEBhMCcnUxGzAZBgkqhkiG9w0BCQEWDHRlc3RAdGVzdC5ydTAeFw0wNTAzMjkx"
                + "MzExNTdaFw0wNjAzMjkxMzExNTdaMIGBMRcwFQYDVQQDEw5kZWZhdWx0MzQxMC05NDENMAsGA1UE"
                + "ChMERGlndDEPMA0GA1UECxMGQ3J5cHRvMQ4wDAYDVQQHEwVZLW9sYTEMMAoGA1UECBMDTUVMMQsw"
                + "CQYDVQQGEwJydTEbMBkGCSqGSIb3DQEJARYMdGVzdEB0ZXN0LnJ1MIGlMBwGBiqFAwICFDASBgcq"
                + "hQMCAiACBgcqhQMCAh4BA4GEAASBgIQACDLEuxSdRDGgdZxHmy30g/DUYkRxO9Mi/uSHX5NjvZ31"
                + "b7JMEMFqBtyhql1HC5xZfUwZ0aT3UnEFDfFjLP+Bf54gA+LPkQXw4SNNGOj+klnqgKlPvoqMGlwa"
                + "+hLPKbS561WpvB2XSTgbV+pqqXR3j6j30STmybelEV3RdS2Now8wDTALBgNVHQ8EBAMCB4AwCgYG"
                + "KoUDAgIEBQADQQBCFy7xWRXtNVXflKvDs0pBdBuPzjCMeZAXVxK8vUxsxxKu76d9CsvhgIFknFRi"
                + "wWTPiZenvNoJ4R1uzeX+vREm");
        
        byte[] gost341094B = Base64.decode(
                "MIICSDCCAfWgAwIBAgIBATAKBgYqhQMCAgQFADCBgTEXMBUGA1UEAxMOcGFyYW0xLTM0MTAtOTQx"
                +  "DTALBgNVBAoTBERpZ3QxDzANBgNVBAsTBkNyeXB0bzEOMAwGA1UEBxMFWS1PbGExDDAKBgNVBAgT"
                +  "A01lbDELMAkGA1UEBhMCcnUxGzAZBgkqhkiG9w0BCQEWDHRlc3RAdGVzdC5ydTAeFw0wNTAzMjkx"
                +  "MzEzNTZaFw0wNjAzMjkxMzEzNTZaMIGBMRcwFQYDVQQDEw5wYXJhbTEtMzQxMC05NDENMAsGA1UE"
                +  "ChMERGlndDEPMA0GA1UECxMGQ3J5cHRvMQ4wDAYDVQQHEwVZLU9sYTEMMAoGA1UECBMDTWVsMQsw"
                +  "CQYDVQQGEwJydTEbMBkGCSqGSIb3DQEJARYMdGVzdEB0ZXN0LnJ1MIGlMBwGBiqFAwICFDASBgcq"
                +  "hQMCAiADBgcqhQMCAh4BA4GEAASBgEa+AAcZmijWs1M9x5Pn9efE8D9ztG1NMoIt0/hNZNqln3+j"
                +  "lMZjyqPt+kTLIjtmvz9BRDmIDk6FZz+4LhG2OTL7yGpWfrMxMRr56nxomTN9aLWRqbyWmn3brz9Y"
                +  "AUD3ifnwjjIuW7UM84JNlDTOdxx0XRUfLQIPMCXe9cO02Xskow8wDTALBgNVHQ8EBAMCB4AwCgYG"
                +  "KoUDAgIEBQADQQBzFcnuYc/639OTW+L5Ecjw9KxGr+dwex7lsS9S1BUgKa3m1d5c+cqI0B2XUFi5"
                +  "4iaHHJG0dCyjtQYLJr0OZjRw");
        
        byte[] gost34102001A = Base64.decode(
                "MIICCzCCAbigAwIBAgIBATAKBgYqhQMCAgMFADCBhDEaMBgGA1UEAxMRZGVmYXVsdC0zNDEwLTIw"
                + "MDExDTALBgNVBAoTBERpZ3QxDzANBgNVBAsTBkNyeXB0bzEOMAwGA1UEBxMFWS1PbGExDDAKBgNV"
                + "BAgTA01lbDELMAkGA1UEBhMCcnUxGzAZBgkqhkiG9w0BCQEWDHRlc3RAdGVzdC5ydTAeFw0wNTAz"
                + "MjkxMzE4MzFaFw0wNjAzMjkxMzE4MzFaMIGEMRowGAYDVQQDExFkZWZhdWx0LTM0MTAtMjAwMTEN"
                + "MAsGA1UEChMERGlndDEPMA0GA1UECxMGQ3J5cHRvMQ4wDAYDVQQHEwVZLU9sYTEMMAoGA1UECBMD"
                + "TWVsMQswCQYDVQQGEwJydTEbMBkGCSqGSIb3DQEJARYMdGVzdEB0ZXN0LnJ1MGMwHAYGKoUDAgIT"
                + "MBIGByqFAwICIwEGByqFAwICHgEDQwAEQG/4c+ZWb10IpeHfmR+vKcbpmSOClJioYmCVgnojw0Xn"
                + "ned0KTg7TJreRUc+VX7vca4hLQaZ1o/TxVtfEApK/O6jDzANMAsGA1UdDwQEAwIHgDAKBgYqhQMC"
                + "AgMFAANBAN8y2b6HuIdkD3aWujpfQbS1VIA/7hro4vLgDhjgVmev/PLzFB8oTh3gKhExpDo82IEs"
                + "ZftGNsbbyp1NFg7zda0=");
        
        byte[] gostCA1 = Base64.decode(
                "MIIDNDCCAuGgAwIBAgIQZLcKDcWcQopF+jp4p9jylDAKBgYqhQMCAgQFADBm"
                + "MQswCQYDVQQGEwJSVTEPMA0GA1UEBxMGTW9zY293MRcwFQYDVQQKEw5PT08g"
                + "Q3J5cHRvLVBybzEUMBIGA1UECxMLRGV2ZWxvcG1lbnQxFzAVBgNVBAMTDkNQ"
                + "IENTUCBUZXN0IENBMB4XDTAyMDYwOTE1NTIyM1oXDTA5MDYwOTE1NTkyOVow"
                + "ZjELMAkGA1UEBhMCUlUxDzANBgNVBAcTBk1vc2NvdzEXMBUGA1UEChMOT09P"
                + "IENyeXB0by1Qcm8xFDASBgNVBAsTC0RldmVsb3BtZW50MRcwFQYDVQQDEw5D"
                + "UCBDU1AgVGVzdCBDQTCBpTAcBgYqhQMCAhQwEgYHKoUDAgIgAgYHKoUDAgIe"
                + "AQOBhAAEgYAYglywKuz1nMc9UiBYOaulKy53jXnrqxZKbCCBSVaJ+aCKbsQm"
                + "glhRFrw6Mwu8Cdeabo/ojmea7UDMZd0U2xhZFRti5EQ7OP6YpqD0alllo7za"
                + "4dZNXdX+/ag6fOORSLFdMpVx5ganU0wHMPk67j+audnCPUj/plbeyccgcdcd"
                + "WaOCASIwggEeMAsGA1UdDwQEAwIBxjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud"
                + "DgQWBBTe840gTo4zt2twHilw3PD9wJaX0TCBygYDVR0fBIHCMIG/MDygOqA4"
                + "hjYtaHR0cDovL2ZpZXdhbGwvQ2VydEVucm9sbC9DUCUyMENTUCUyMFRlc3Ql"
                + "MjBDQSgzKS5jcmwwRKBCoECGPmh0dHA6Ly93d3cuY3J5cHRvcHJvLnJ1L0Nl"
                + "cnRFbnJvbGwvQ1AlMjBDU1AlMjBUZXN0JTIwQ0EoMykuY3JsMDmgN6A1hjMt"
                + "ZmlsZTovL1xcZmlld2FsbFxDZXJ0RW5yb2xsXENQIENTUCBUZXN0IENBKDMp"
                + "LmNybC8wEgYJKwYBBAGCNxUBBAUCAwMAAzAKBgYqhQMCAgQFAANBAIJi7ni7"
                + "9rwMR5rRGTFftt2k70GbqyUEfkZYOzrgdOoKiB4IIsIstyBX0/ne6GsL9Xan"
                + "G2IN96RB7KrowEHeW+k=");
        
        byte[] gostCA2 = Base64.decode(
                "MIIC2DCCAoWgAwIBAgIQe9ZCugm42pRKNcHD8466zTAKBgYqhQMCAgMFADB+"
                + "MRowGAYJKoZIhvcNAQkBFgtzYmFAZGlndC5ydTELMAkGA1UEBhMCUlUxDDAK"
                + "BgNVBAgTA01FTDEUMBIGA1UEBxMLWW9zaGthci1PbGExDTALBgNVBAoTBERp"
                + "Z3QxDzANBgNVBAsTBkNyeXB0bzEPMA0GA1UEAxMGc2JhLUNBMB4XDTA0MDgw"
                + "MzEzMzE1OVoXDTE0MDgwMzEzNDAxMVowfjEaMBgGCSqGSIb3DQEJARYLc2Jh"
                + "QGRpZ3QucnUxCzAJBgNVBAYTAlJVMQwwCgYDVQQIEwNNRUwxFDASBgNVBAcT"
                + "C1lvc2hrYXItT2xhMQ0wCwYDVQQKEwREaWd0MQ8wDQYDVQQLEwZDcnlwdG8x"
                + "DzANBgNVBAMTBnNiYS1DQTBjMBwGBiqFAwICEzASBgcqhQMCAiMBBgcqhQMC"
                + "Ah4BA0MABEDMSy10CuOH+i8QKG2UWA4XmCt6+BFrNTZQtS6bOalyDY8Lz+G7"
                + "HybyipE3PqdTB4OIKAAPsEEeZOCZd2UXGQm5o4HaMIHXMBMGCSsGAQQBgjcU"
                + "AgQGHgQAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud"
                + "DgQWBBRJJl3LcNMxkZI818STfoi3ng1xoDBxBgNVHR8EajBoMDGgL6Athito"
                + "dHRwOi8vc2JhLmRpZ3QubG9jYWwvQ2VydEVucm9sbC9zYmEtQ0EuY3JsMDOg"
                + "MaAvhi1maWxlOi8vXFxzYmEuZGlndC5sb2NhbFxDZXJ0RW5yb2xsXHNiYS1D"
                + "QS5jcmwwEAYJKwYBBAGCNxUBBAMCAQAwCgYGKoUDAgIDBQADQQA+BRJHbc/p"
                + "q8EYl6iJqXCuR+ozRmH7hPAP3c4KqYSC38TClCgBloLapx/3/WdatctFJW/L"
                + "mcTovpq088927shE");

    public String getName()
    {
        return "CertTest";
    }

    public TestResult checkCertificate(
        int     id,
        byte[]  bytes)
    {
        ByteArrayInputStream    bIn;
        String                  dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory  fact = CertificateFactory.getInstance("X.509", "BC");

            Certificate cert = fact.generateCertificate(bIn);

            PublicKey    k = cert.getPublicKey();
            // System.out.println(cert);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

        return new SimpleTestResult(true, getName() + ": " + id + " Okay");
    }

    public TestResult checkNameCertificate(
        int     id,
        byte[]  bytes)
    {
        ByteArrayInputStream    bIn;
        String                  dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory  fact = CertificateFactory.getInstance("X.509", "BC");

            X509Certificate cert = (X509Certificate)fact.generateCertificate(bIn);

            PublicKey    k = cert.getPublicKey();
            if (!cert.getIssuerDN().toString().equals("C=DE,O=DATEV eG,0.2.262.1.10.7.20=1+CN=CA DATEV D03 1:PN"))
            {
                return new SimpleTestResult(false, getName() + ": " + id + " failed - name test.");
            }
            // System.out.println(cert);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

        return new SimpleTestResult(true, getName() + ": " + id + " Okay");
    }

    public TestResult checkKeyUsage(
        int     id,
        byte[]  bytes)
    {
        ByteArrayInputStream    bIn;
        String                  dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory  fact = CertificateFactory.getInstance("X.509", "BC");

            X509Certificate cert = (X509Certificate)fact.generateCertificate(bIn);

            PublicKey    k = cert.getPublicKey();

            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage == null || keyUsage.length <= 7 || keyUsage[7])
            {
                return new SimpleTestResult(false, getName() + ": error generating cert - key usage wrong.");
            }

            // System.out.println(cert);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

        return new SimpleTestResult(true, getName() + ": " + id + " Okay");
    }


    public TestResult checkSelfSignedCertificate(
        int     id,
        byte[]  bytes)
    {
        ByteArrayInputStream    bIn;
        String                  dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory  fact = CertificateFactory.getInstance("X.509", "BC");

            Certificate cert = fact.generateCertificate(bIn);

            PublicKey    k = cert.getPublicKey();

            cert.verify(k);
            // System.out.println(cert);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

        return new SimpleTestResult(true, getName() + ": " + id + " Okay");
    }

    /**
     * we generate a self signed certificate for the sake of testing - RSA
     */
    public TestResult checkCreation1()
    {
        //
        // a sample key pair.
        //
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

        //
        // set up the keys
        //
        SecureRandom        rand = new SecureRandom();
        PrivateKey          privKey;
        PublicKey           pubKey;

        try
        {
            KeyFactory  fact = KeyFactory.getInstance("RSA", "BC");

            privKey = fact.generatePrivate(privKeySpec);
            pubKey = fact.generatePublic(pubKeySpec);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting up keys - " + e.toString());
        }

        //
        // distinguished name table.
        //
        Hashtable                   attrs = new Hashtable();

        attrs.put(X509Principal.C, "AU");
        attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Principal.L, "Melbourne");
        attrs.put(X509Principal.ST, "Victoria");
        attrs.put(X509Principal.E, "feedback-crypto@bouncycastle.org");

        Vector                      ord = new Vector();
        Vector                      values = new Vector();

        ord.addElement(X509Principal.C);
        ord.addElement(X509Principal.O);
        ord.addElement(X509Principal.L);
        ord.addElement(X509Principal.ST);
        ord.addElement(X509Principal.E);

        values.addElement("AU");
        values.addElement("The Legion of the Bouncy Castle");
        values.addElement("Melbourne");
        values.addElement("Victoria");
        values.addElement("feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3 - without extensions
        //
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal(attrs));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal(attrs));
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        try
        {
            X509Certificate cert = certGen.generateX509Certificate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            Set dummySet = cert.getNonCriticalExtensionOIDs();
            dummySet = cert.getNonCriticalExtensionOIDs();
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting generating cert - " + e.toString());
        }

        //
        // create the certificate - version 3 - with extensions
        //
        certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal(attrs));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal(attrs));
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("MD5WithRSAEncryption");
        certGen.addExtension("2.5.29.15", true,
            new X509KeyUsage(X509KeyUsage.encipherOnly));
        certGen.addExtension("2.5.29.37", true,
            new DERSequence(KeyPurposeId.anyExtendedKeyUsage));
        certGen.addExtension("2.5.29.17", true,
            new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        try
        {
            X509Certificate cert = certGen.generateX509Certificate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream   sbIn = new ByteArrayInputStream(cert.getEncoded());
            ASN1InputStream        sdIn = new ASN1InputStream(sbIn);
            ByteArrayInputStream   bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory     fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage == null || keyUsage.length <= 7 || !keyUsage[7])
            {
                return new SimpleTestResult(false, getName() + ": error generating cert - key usage wrong.");
            }

            // System.out.println(cert);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting generating cert - " + e.toString(), e);
        }

        //
        // create the certificate - version 1
        //
        X509V1CertificateGenerator  certGen1 = new X509V1CertificateGenerator();

        certGen1.setSerialNumber(BigInteger.valueOf(1));
        certGen1.setIssuerDN(new X509Principal(ord, attrs));
        certGen1.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen1.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen1.setSubjectDN(new X509Principal(ord, values));
        certGen1.setPublicKey(pubKey);
        certGen1.setSignatureAlgorithm("MD5WithRSAEncryption");

        try
        {
            X509Certificate cert = certGen1.generateX509Certificate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            // System.out.println(cert);
            if (!cert.getIssuerDN().equals(cert.getSubjectDN()))
            {
                return new SimpleTestResult(false, getName() + ": name comparison fails");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting generating cert - " + e.toString());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    /**
     * we generate a self signed certificate for the sake of testing - DSA
     */
    public TestResult checkCreation2()
    {
        //
        // set up the keys
        //
        PrivateKey          privKey;
        PublicKey           pubKey;

        try
        {
            KeyPairGenerator    g = KeyPairGenerator.getInstance("DSA", "SUN");

            g.initialize(512, new SecureRandom());

            KeyPair p = g.generateKeyPair();

            privKey = p.getPrivate();
            pubKey = p.getPublic();
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting up keys - " + e.toString());
        }

        //
        // distinguished name table.
        //
        Hashtable                   attrs = new Hashtable();

        attrs.put(X509Principal.C, "AU");
        attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Principal.L, "Melbourne");
        attrs.put(X509Principal.ST, "Victoria");
        attrs.put(X509Principal.E, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3
        //
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal(attrs));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal(attrs));
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("SHA1withDSA");

        try
        {
            X509Certificate cert = certGen.generateX509Certificate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            // System.out.println(cert);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting generating cert - " + e.toString());
        }

        //
        // create the certificate - version 1
        //
        X509V1CertificateGenerator  certGen1 = new X509V1CertificateGenerator();

        certGen1.setSerialNumber(BigInteger.valueOf(1));
        certGen1.setIssuerDN(new X509Principal(attrs));
        certGen1.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen1.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen1.setSubjectDN(new X509Principal(attrs));
        certGen1.setPublicKey(pubKey);
        certGen1.setSignatureAlgorithm("SHA1withDSA");

        try
        {
            X509Certificate cert = certGen1.generateX509Certificate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            //System.out.println(cert);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting generating cert - " + e.toString());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    /**
     * we generate a self signed certificate for the sake of testing - ECDSA
     */
    public TestResult checkCreation3()
    {
        ECCurve curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECParameterSpec spec = new ECParameterSpec(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
        

        ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(
            new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
            spec);

        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
            curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
            spec);

        //
        // set up the keys
        //
        PrivateKey          privKey;
        PublicKey           pubKey;

        try
        {
            KeyFactory     fact = KeyFactory.getInstance("ECDSA", "BC");

            privKey = fact.generatePrivate(privKeySpec);
            pubKey = fact.generatePublic(pubKeySpec);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting up keys - " + e.toString());
        }

        //
        // distinguished name table.
        //
        Hashtable                   attrs = new Hashtable();
        Vector                      order = new Vector();

        attrs.put(X509Principal.C, "AU");
        attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Principal.L, "Melbourne");
        attrs.put(X509Principal.ST, "Victoria");
        attrs.put(X509Principal.E, "feedback-crypto@bouncycastle.org");

        order.addElement(X509Principal.C);
        order.addElement(X509Principal.O);
        order.addElement(X509Principal.L);
        order.addElement(X509Principal.ST);
        order.addElement(X509Principal.E);


        //
        // toString test
        //
        X509Principal p = new X509Principal(order, attrs);
        String  s = p.toString();

        if (!s.equals("C=AU,O=The Legion of the Bouncy Castle,L=Melbourne,ST=Victoria,E=feedback-crypto@bouncycastle.org"))
        {
            return new SimpleTestResult(false, getName() + ": ordered X509Principal test failed - s = " + s + ".");
        }

        p = new X509Principal(attrs);
        s = p.toString();

        //
        // we need two of these as the hash code for strings changed...
        //
        if (!s.equals("O=The Legion of the Bouncy Castle,E=feedback-crypto@bouncycastle.org,ST=Victoria,L=Melbourne,C=AU") && !s.equals("ST=Victoria,L=Melbourne,C=AU,E=feedback-crypto@bouncycastle.org,O=The Legion of the Bouncy Castle"))
        {
            return new SimpleTestResult(false, getName() + ": unordered X509Principal test failed.");
        }

        //
        // create the certificate - version 3
        //
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal(order, attrs));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal(order, attrs));
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("ECDSAwithSHA1");

        try
        {
            X509Certificate cert = certGen.generateX509Certificate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            //
            // try with point compression turned off
            //
            ((ECPointEncoder)pubKey).setPointFormat("UNCOMPRESSED");
            
            certGen.setPublicKey(pubKey);
            
            cert = certGen.generateX509Certificate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            bIn = new ByteArrayInputStream(cert.getEncoded());
            fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);
            // System.out.println(cert);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting generating cert - " + e.toString());
        }

        X509Principal pr = new X509Principal("O=\"The Bouncy Castle, The Legion of\",E=feedback-crypto@bouncycastle.org,ST=Victoria,L=Melbourne,C=AU");

        if (!pr.toString().equals("O=The Bouncy Castle\\, The Legion of,E=feedback-crypto@bouncycastle.org,ST=Victoria,L=Melbourne,C=AU"))
        {
            return new SimpleTestResult(false, getName() + ": string based X509Principal test failed.");
        }

        pr = new X509Principal("O=The Bouncy Castle\\, The Legion of,E=feedback-crypto@bouncycastle.org,ST=Victoria,L=Melbourne,C=AU");

        if (!pr.toString().equals("O=The Bouncy Castle\\, The Legion of,E=feedback-crypto@bouncycastle.org,ST=Victoria,L=Melbourne,C=AU"))
        {
            return new SimpleTestResult(false, getName() + ": string based X509Principal test failed.");
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public TestResult checkCRL(
        int     id,
        byte[]  bytes)
    {
        ByteArrayInputStream    bIn;
        String                  dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory  fact = CertificateFactory.getInstance("X.509", "BC");

            CRL cert = fact.generateCRL(bIn);

            // System.out.println(cert);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

        return new SimpleTestResult(true, getName() + ": " + id + " Okay");
    }

//    /**
//     * we generate a self signed certificate for the sake of testing - GOST3410
//     */
//    public TestResult checkCreation4()
//    {
//        //
//        // set up the keys
//        //
//        PrivateKey          privKey;
//        PublicKey           pubKey;
//
//        try
//        {
//            KeyPairGenerator    g = KeyPairGenerator.getInstance("GOST3410", "BC");
//            GOST3410ParameterSpec gost3410P = new GOST3410ParameterSpec("GostR3410-94-CryptoPro-A");
//
//            g.initialize(gost3410P, new SecureRandom());
//
//            KeyPair p = g.generateKeyPair();
//
//            privKey = p.getPrivate();
//            pubKey = p.getPublic();
//        }
//        catch (Exception e)
//        {
//            return new SimpleTestResult(false, getName() + ": error setting up keys - " + e.toString());
//        }
//
//        //
//        // distinguished name table.
//        //
//        Hashtable                   attrs = new Hashtable();
//
//        attrs.put(X509Principal.C, "AU");
//        attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
//        attrs.put(X509Principal.L, "Melbourne");
//        attrs.put(X509Principal.ST, "Victoria");
//        attrs.put(X509Principal.E, "feedback-crypto@bouncycastle.org");
//
//        //
//        // extensions
//        //
//
//        //
//        // create the certificate - version 3
//        //
//        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();
//
//        certGen.setSerialNumber(BigInteger.valueOf(1));
//        certGen.setIssuerDN(new X509Principal(attrs));
//        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
//        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
//        certGen.setSubjectDN(new X509Principal(attrs));
//        certGen.setPublicKey(pubKey);
//        certGen.setSignatureAlgorithm("GOST3411withGOST3410");
//
//        try
//        {
//            X509Certificate cert = certGen.generateX509Certificate(privKey);
//
//            cert.checkValidity(new Date());
//
//            //
//            // check verifies in general
//            //
//            cert.verify(pubKey);
//
//            //
//            // check verifies with contained key
//            //
//            cert.verify(cert.getPublicKey());
//            
//            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
//            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");
//
//            cert = (X509Certificate)fact.generateCertificate(bIn);
//
//            //System.out.println(cert);
//
//            //check getEncoded()
//            byte[]  bytesch = cert.getEncoded();
//        }
//        catch (Exception e)
//        {
//            return new SimpleTestResult(false, getName() + ": error setting generating cert - " + e.toString(), e);
//        }
//
//        return new SimpleTestResult(true, getName() + ": Okay");
//    }
    
    public TestResult perform()
    {
        TestResult  res;

        res = checkCertificate(1, cert1);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkCertificate(2, cert2);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkCertificate(4, cert4);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkCertificate(5, cert5);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkCertificate(6, oldEcdsa);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkCertificate(7, cert7);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkKeyUsage(8, keyUsage);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkSelfSignedCertificate(9, uncompressedPtEC);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkNameCertificate(10, nameCert);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkSelfSignedCertificate(11, probSelfSignedCert);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkSelfSignedCertificate(12, gostCA1);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkSelfSignedCertificate(13, gostCA2);
        if (!res.isSuccessful())
        {
            return res;
        }
        
        res = checkSelfSignedCertificate(14, gost341094base);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkSelfSignedCertificate(15, gost34102001base);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkSelfSignedCertificate(16, gost341094A);
        if (!res.isSuccessful())
        {
            return res;
        }
        
        res = checkSelfSignedCertificate(17, gost341094B);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkSelfSignedCertificate(17, gost34102001A);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkCRL(1, crl1);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkCreation1();
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkCreation2();
        if (!res.isSuccessful())
        {
            return res;
        }

        res = checkCreation3();
        if (!res.isSuccessful())
        {
            return res;
        }

//        res = checkCreation4();
//        if (!res.isSuccessful())
//        {
//            return res;
//        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test    test = new CertTest();

        TestResult  result = test.perform();

        System.out.println(result);
    }
}
