package org.bouncycastle.jce.provider.test;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestFailedException;

public class CertTest
    extends SimpleTest
{
    //
    // server.crt
    //
    byte[] cert1 = Base64.decode(
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
    byte[] cert2 = Base64.decode(
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
    byte[] cert3 = Base64.decode(
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
    byte[] cert4 = Base64.decode(
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
    byte[] cert5 = Base64.decode(
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
    byte[] cert6 = Base64.decode(
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
    byte[] cert7 = Base64.decode(
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
    byte[] crl1 = Base64.decode(
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
    byte[] oldEcdsa = Base64.decode(
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

    byte[] uncompressedPtEC = Base64.decode(
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

    byte[] keyUsage = Base64.decode(
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
            + "DTALBgNVBAoTBERpZ3QxDzANBgNVBAsTBkNyeXB0bzEOMAwGA1UEBxMFWS1PbGExDDAKBgNVBAgT"
            + "A01lbDELMAkGA1UEBhMCcnUxGzAZBgkqhkiG9w0BCQEWDHRlc3RAdGVzdC5ydTAeFw0wNTAzMjkx"
            + "MzEzNTZaFw0wNjAzMjkxMzEzNTZaMIGBMRcwFQYDVQQDEw5wYXJhbTEtMzQxMC05NDENMAsGA1UE"
            + "ChMERGlndDEPMA0GA1UECxMGQ3J5cHRvMQ4wDAYDVQQHEwVZLU9sYTEMMAoGA1UECBMDTWVsMQsw"
            + "CQYDVQQGEwJydTEbMBkGCSqGSIb3DQEJARYMdGVzdEB0ZXN0LnJ1MIGlMBwGBiqFAwICFDASBgcq"
            + "hQMCAiADBgcqhQMCAh4BA4GEAASBgEa+AAcZmijWs1M9x5Pn9efE8D9ztG1NMoIt0/hNZNqln3+j"
            + "lMZjyqPt+kTLIjtmvz9BRDmIDk6FZz+4LhG2OTL7yGpWfrMxMRr56nxomTN9aLWRqbyWmn3brz9Y"
            + "AUD3ifnwjjIuW7UM84JNlDTOdxx0XRUfLQIPMCXe9cO02Xskow8wDTALBgNVHQ8EBAMCB4AwCgYG"
            + "KoUDAgIEBQADQQBzFcnuYc/639OTW+L5Ecjw9KxGr+dwex7lsS9S1BUgKa3m1d5c+cqI0B2XUFi5"
            + "4iaHHJG0dCyjtQYLJr0OZjRw");

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

    private final byte[] pkcs7CrlProblem = Base64.decode(
        "MIIwSAYJKoZIhvcNAQcCoIIwOTCCMDUCAQExCzAJBgUrDgMCGgUAMAsGCSqG"
            + "SIb3DQEHAaCCEsAwggP4MIIC4KADAgECAgF1MA0GCSqGSIb3DQEBBQUAMEUx"
            + "CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMR4wHAYDVQQD"
            + "ExVHZW9UcnVzdCBDQSBmb3IgQWRvYmUwHhcNMDQxMjAyMjEyNTM5WhcNMDYx"
            + "MjMwMjEyNTM5WjBMMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMR2VvVHJ1c3Qg"
            + "SW5jMSYwJAYDVQQDEx1HZW9UcnVzdCBBZG9iZSBPQ1NQIFJlc3BvbmRlcjCB"
            + "nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA4gnNYhtw7U6QeVXZODnGhHMj"
            + "+OgZ0DB393rEk6a2q9kq129IA2e03yKBTfJfQR9aWKc2Qj90dsSqPjvTDHFG"
            + "Qsagm2FQuhnA3fb1UWhPzeEIdm6bxDsnQ8nWqKqxnWZzELZbdp3I9bBLizIq"
            + "obZovzt60LNMghn/unvvuhpeVSsCAwEAAaOCAW4wggFqMA4GA1UdDwEB/wQE"
            + "AwIE8DCB5QYDVR0gAQH/BIHaMIHXMIHUBgkqhkiG9y8BAgEwgcYwgZAGCCsG"
            + "AQUFBwICMIGDGoGAVGhpcyBjZXJ0aWZpY2F0ZSBoYXMgYmVlbiBpc3N1ZWQg"
            + "aW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBBY3JvYmF0IENyZWRlbnRpYWxzIENQ"
            + "UyBsb2NhdGVkIGF0IGh0dHA6Ly93d3cuZ2VvdHJ1c3QuY29tL3Jlc291cmNl"
            + "cy9jcHMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2VvdHJ1c3QuY29tL3Jl"
            + "c291cmNlcy9jcHMwEwYDVR0lBAwwCgYIKwYBBQUHAwkwOgYDVR0fBDMwMTAv"
            + "oC2gK4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9hZG9iZWNhMS5j"
            + "cmwwHwYDVR0jBBgwFoAUq4BZw2WDbR19E70Zw+wajw1HaqMwDQYJKoZIhvcN"
            + "AQEFBQADggEBAENJf1BD7PX5ivuaawt90q1OGzXpIQL/ClzEeFVmOIxqPc1E"
            + "TFRq92YuxG5b6+R+k+tGkmCwPLcY8ipg6ZcbJ/AirQhohzjlFuT6YAXsTfEj"
            + "CqEZfWM2sS7crK2EYxCMmKE3xDfPclYtrAoz7qZvxfQj0TuxHSstHZv39wu2"
            + "ZiG1BWiEcyDQyTgqTOXBoZmfJtshuAcXmTpgkrYSrS37zNlPTGh+pMYQ0yWD"
            + "c8OQRJR4OY5ZXfdna01mjtJTOmj6/6XPoLPYTq2gQrc2BCeNJ4bEhLb7sFVB"
            + "PbwPrpzTE/HRbQHDrzj0YimDxeOUV/UXctgvYwHNtEkcBLsOm/uytMYwggSh"
            + "MIIDiaADAgECAgQ+HL0oMA0GCSqGSIb3DQEBBQUAMGkxCzAJBgNVBAYTAlVT"
            + "MSMwIQYDVQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UE"
            + "CxMUQWRvYmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3Qg"
            + "Q0EwHhcNMDMwMTA4MjMzNzIzWhcNMjMwMTA5MDAwNzIzWjBpMQswCQYDVQQG"
            + "EwJVUzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJbmNvcnBvcmF0ZWQxHTAb"
            + "BgNVBAsTFEFkb2JlIFRydXN0IFNlcnZpY2VzMRYwFAYDVQQDEw1BZG9iZSBS"
            + "b290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzE9UhPen"
            + "ouczU38/nBKIayyZR2d+Dx65rRSI+cMQ2B3w8NWfaQovWTWwzGypTJwVoJ/O"
            + "IL+gz1Ti4CBmRT85hjh+nMSOByLGJPYBErA131XqaZCw24U3HuJOB7JCoWoT"
            + "aaBm6oCREVkqmwh5WiBELcm9cziLPC/gQxtdswvwrzUaKf7vppLdgUydPVmO"
            + "rTE8QH6bkTYG/OJcjdGNJtVcRc+vZT+xqtJilvSoOOq6YEL09BxKNRXO+E4i"
            + "Vg+VGMX4lp+f+7C3eCXpgGu91grwxnSUnfMPUNuad85LcIMjjaDKeCBEXDxU"
            + "ZPHqojAZn+pMBk0GeEtekt8i0slns3rSAQIDAQABo4IBTzCCAUswEQYJYIZI"
            + "AYb4QgEBBAQDAgAHMIGOBgNVHR8EgYYwgYMwgYCgfqB8pHoweDELMAkGA1UE"
            + "BhMCVVMxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMgSW5jb3Jwb3JhdGVkMR0w"
            + "GwYDVQQLExRBZG9iZSBUcnVzdCBTZXJ2aWNlczEWMBQGA1UEAxMNQWRvYmUg"
            + "Um9vdCBDQTENMAsGA1UEAxMEQ1JMMTArBgNVHRAEJDAigA8yMDAzMDEwODIz"
            + "MzcyM1qBDzIwMjMwMTA5MDAwNzIzWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgw"
            + "FoAUgrc4SpOqmxDvgLvZVOLxD/uAnN4wHQYDVR0OBBYEFIK3OEqTqpsQ74C7"
            + "2VTi8Q/7gJzeMAwGA1UdEwQFMAMBAf8wHQYJKoZIhvZ9B0EABBAwDhsIVjYu"
            + "MDo0LjADAgSQMA0GCSqGSIb3DQEBBQUAA4IBAQAy2p9DdcH6b8lv26sdNjc+"
            + "vGEZNrcCPB0jWZhsnu5NhedUyCAfp9S74r8Ad30ka3AvXME6dkm10+AjhCpx"
            + "aiLzwScpmBX2NZDkBEzDjbyfYRzn/SSM0URDjBa6m02l1DUvvBHOvfdRN42f"
            + "kOQU8Rg/vulZEjX5M5LznuDVa5pxm5lLyHHD4bFhCcTl+pHwQjo3fTT5cujN"
            + "qmIcIenV9IIQ43sFti1oVgt+fpIsb01yggztVnSynbmrLSsdEF/bJ3Vwj/0d"
            + "1+ICoHnlHOX/r2RAUS2em0fbQqV8H8KmSLDXvpJpTaT2KVfFeBEY3IdRyhOy"
            + "Yp1PKzK9MaXB+lKrBYjIMIIEyzCCA7OgAwIBAgIEPhy9tTANBgkqhkiG9w0B"
            + "AQUFADBpMQswCQYDVQQGEwJVUzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJ"
            + "bmNvcnBvcmF0ZWQxHTAbBgNVBAsTFEFkb2JlIFRydXN0IFNlcnZpY2VzMRYw"
            + "FAYDVQQDEw1BZG9iZSBSb290IENBMB4XDTA0MDExNzAwMDMzOVoXDTE1MDEx"
            + "NTA4MDAwMFowRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUdlb1RydXN0IElu"
            + "Yy4xHjAcBgNVBAMTFUdlb1RydXN0IENBIGZvciBBZG9iZTCCASIwDQYJKoZI"
            + "hvcNAQEBBQADggEPADCCAQoCggEBAKfld+BkeFrnOYW8r9L1WygTDlTdSfrO"
            + "YvWS/Z6Ye5/l+HrBbOHqQCXBcSeCpz7kB2WdKMh1FOE4e9JlmICsHerBLdWk"
            + "emU+/PDb69zh8E0cLoDfxukF6oVPXj6WSThdSG7H9aXFzRr6S3XGCuvgl+Qw"
            + "DTLiLYW+ONF6DXwt3TQQtKReJjOJZk46ZZ0BvMStKyBaeB6DKZsmiIo89qso"
            + "13VDZINH2w1KvXg0ygDizoNtbvgAPFymwnsINS1klfQlcvn0x0RJm9bYQXK3"
            + "5GNZAgL3M7Lqrld0jMfIUaWvuHCLyivytRuzq1dJ7E8rmidjDEk/G+27pf13"
            + "fNZ7vR7M+IkCAwEAAaOCAZ0wggGZMBIGA1UdEwEB/wQIMAYBAf8CAQEwUAYD"
            + "VR0gBEkwRzBFBgkqhkiG9y8BAgEwODA2BggrBgEFBQcCARYqaHR0cHM6Ly93"
            + "d3cuYWRvYmUuY29tL21pc2MvcGtpL2Nkc19jcC5odG1sMBQGA1UdJQQNMAsG"
            + "CSqGSIb3LwEBBTCBsgYDVR0fBIGqMIGnMCKgIKAehhxodHRwOi8vY3JsLmFk"
            + "b2JlLmNvbS9jZHMuY3JsMIGAoH6gfKR6MHgxCzAJBgNVBAYTAlVTMSMwIQYD"
            + "VQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UECxMUQWRv"
            + "YmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3QgQ0ExDTAL"
            + "BgNVBAMTBENSTDEwCwYDVR0PBAQDAgEGMB8GA1UdIwQYMBaAFIK3OEqTqpsQ"
            + "74C72VTi8Q/7gJzeMB0GA1UdDgQWBBSrgFnDZYNtHX0TvRnD7BqPDUdqozAZ"
            + "BgkqhkiG9n0HQQAEDDAKGwRWNi4wAwIEkDANBgkqhkiG9w0BAQUFAAOCAQEA"
            + "PzlZLqIAjrFeEWEs0uC29YyJhkXOE9mf3YSaFGsITF+Gl1j0pajTjyH4R35Q"
            + "r3floW2q3HfNzTeZ90Jnr1DhVERD6zEMgJpCtJqVuk0sixuXJHghS/KicKf4"
            + "YXJJPx9epuIRF1siBRnznnF90svmOJMXApc0jGnYn3nQfk4kaShSnDaYaeYR"
            + "DJKcsiWhl6S5zfwS7Gg8hDeyckhMQKKWnlG1CQrwlSFisKCduoodwRtWgft8"
            + "kx13iyKK3sbalm6vnVc+5nufS4vI+TwMXoV63NqYaSroafBWk0nL53zGXPEy"
            + "+A69QhzEViJKn2Wgqt5gt++jMMNImbRObIqgfgF1VjCCBUwwggQ0oAMCAQIC"
            + "AgGDMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1H"
            + "ZW9UcnVzdCBJbmMuMR4wHAYDVQQDExVHZW9UcnVzdCBDQSBmb3IgQWRvYmUw"
            + "HhcNMDYwMzI0MTU0MjI5WhcNMDkwNDA2MTQ0MjI5WjBzMQswCQYDVQQGEwJV"
            + "UzELMAkGA1UECBMCTUExETAPBgNVBAoTCEdlb1RydXN0MR0wGwYDVQQDExRN"
            + "YXJrZXRpbmcgRGVwYXJ0bWVudDElMCMGCSqGSIb3DQEJARYWbWFya2V0aW5n"
            + "QGdlb3RydXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB"
            + "ANmvajTO4XJvAU2nVcLmXeCnAQX7RZt+7+ML3InmqQ3LCGo1weop09zV069/"
            + "1x/Nmieol7laEzeXxd2ghjGzwfXafqQEqHn6+vBCvqdNPoSi63fSWhnuDVWp"
            + "KVDOYgxOonrXl+Cc43lu4zRSq+Pi5phhrjDWcH74a3/rdljUt4c4GFezFXfa"
            + "w2oTzWkxj2cTSn0Szhpr17+p66UNt8uknlhmu4q44Speqql2HwmCEnpLYJrK"
            + "W3fOq5D4qdsvsLR2EABLhrBezamLI3iGV8cRHOUTsbTMhWhv/lKfHAyf4XjA"
            + "z9orzvPN5jthhIfICOFq/nStTgakyL4Ln+nFAB/SMPkCAwEAAaOCAhYwggIS"
            + "MA4GA1UdDwEB/wQEAwIF4DCB5QYDVR0gAQH/BIHaMIHXMIHUBgkqhkiG9y8B"
            + "AgEwgcYwgZAGCCsGAQUFBwICMIGDGoGAVGhpcyBjZXJ0aWZpY2F0ZSBoYXMg"
            + "YmVlbiBpc3N1ZWQgaW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBBY3JvYmF0IENy"
            + "ZWRlbnRpYWxzIENQUyBsb2NhdGVkIGF0IGh0dHA6Ly93d3cuZ2VvdHJ1c3Qu"
            + "Y29tL3Jlc291cmNlcy9jcHMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2Vv"
            + "dHJ1c3QuY29tL3Jlc291cmNlcy9jcHMwOgYDVR0fBDMwMTAvoC2gK4YpaHR0"
            + "cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9hZG9iZWNhMS5jcmwwHwYDVR0j"
            + "BBgwFoAUq4BZw2WDbR19E70Zw+wajw1HaqMwRAYIKwYBBQUHAQEEODA2MDQG"
            + "CCsGAQUFBzABhihodHRwOi8vYWRvYmUtb2NzcC5nZW90cnVzdC5jb20vcmVz"
            + "cG9uZGVyMBQGA1UdJQQNMAsGCSqGSIb3LwEBBTA8BgoqhkiG9y8BAQkBBC4w"
            + "LAIBAYYnaHR0cDovL2Fkb2JlLXRpbWVzdGFtcC5nZW90cnVzdC5jb20vdHNh"
            + "MBMGCiqGSIb3LwEBCQIEBTADAgEBMAwGA1UdEwQFMAMCAQAwDQYJKoZIhvcN"
            + "AQEFBQADggEBAAOhy6QxOo+i3h877fvDvTa0plGD2bIqK7wMdNqbMDoSWied"
            + "FIcgcBOIm2wLxOjZBAVj/3lDq59q2rnVeNnfXM0/N0MHI9TumHRjU7WNk9e4"
            + "+JfJ4M+c3anrWOG3NE5cICDVgles+UHjXetHWql/LlP04+K2ZOLb6LE2xGnI"
            + "YyLW9REzCYNAVF+/WkYdmyceHtaBZdbyVAJq0NAJPsfgY1pWcBo31Mr1fpX9"
            + "WrXNTYDCqMyxMImJTmN3iI68tkXlNrhweQoArKFqBysiBkXzG/sGKYY6tWKU"
            + "pzjLc3vIp/LrXC5zilROes8BSvwu1w9qQrJNcGwo7O4uijoNtyYil1Exgh1Q"
            + "MIIdTAIBATBLMEUxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJ"
            + "bmMuMR4wHAYDVQQDExVHZW9UcnVzdCBDQSBmb3IgQWRvYmUCAgGDMAkGBSsO"
            + "AwIaBQCgggxMMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwIwYJKoZIhvcN"
            + "AQkEMRYEFP4R6qIdpQJzWyzrqO8X1ZfJOgChMIIMCQYJKoZIhvcvAQEIMYIL"
            + "+jCCC/agggZ5MIIGdTCCA6gwggKQMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV"
            + "BAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMR4wHAYDVQQDExVHZW9U"
            + "cnVzdCBDQSBmb3IgQWRvYmUXDTA2MDQwNDE3NDAxMFoXDTA2MDQwNTE3NDAx"
            + "MFowggIYMBMCAgC5Fw0wNTEwMTEyMDM2MzJaMBICAVsXDTA0MTEwNDE1MDk0"
            + "MVowEwICALgXDTA1MTIxMjIyMzgzOFowEgIBWhcNMDQxMTA0MTUwOTMzWjAT"
            + "AgIA5hcNMDUwODI3MDQwOTM4WjATAgIAtxcNMDYwMTE2MTc1NTEzWjATAgIA"
            + "hhcNMDUxMjEyMjIzODU1WjATAgIAtRcNMDUwNzA2MTgzODQwWjATAgIA4BcN"
            + "MDYwMzIwMDc0ODM0WjATAgIAgRcNMDUwODAyMjIzMTE1WjATAgIA3xcNMDUx"
            + "MjEyMjIzNjUwWjASAgFKFw0wNDExMDQxNTA5MTZaMBICAUQXDTA0MTEwNDE1"
            + "MDg1M1owEgIBQxcNMDQxMDAzMDEwMDQwWjASAgFsFw0wNDEyMDYxOTQ0MzFa"
            + "MBMCAgEoFw0wNjAzMDkxMjA3MTJaMBMCAgEkFw0wNjAxMTYxNzU1MzRaMBIC"
            + "AWcXDTA1MDMxODE3NTYxNFowEwICAVEXDTA2MDEzMTExMjcxMVowEgIBZBcN"
            + "MDQxMTExMjI0ODQxWjATAgIA8RcNMDUwOTE2MTg0ODAxWjATAgIBThcNMDYw"
            + "MjIxMjAxMDM2WjATAgIAwRcNMDUxMjEyMjIzODE2WjASAgFiFw0wNTAxMTAx"
            + "NjE5MzRaMBICAWAXDTA1MDExMDE5MDAwNFowEwICAL4XDTA1MDUxNzE0NTYx"
            + "MFowDQYJKoZIhvcNAQEFBQADggEBAEKhRMS3wVho1U3EvEQJZC8+JlUngmZQ"
            + "A78KQbHPWNZWFlNvPuf/b0s7Lu16GfNHXh1QAW6Y5Hi1YtYZ3YOPyMd4Xugt"
            + "gCdumbB6xtKsDyN5RvTht6ByXj+CYlYqsL7RX0izJZ6mJn4fjMkqzPKNOjb8"
            + "kSn5T6rn93BjlATtCE8tPVOM8dnqGccRE0OV59+nDBXc90UMt5LdEbwaUOap"
            + "snVB0oLcNm8d/HnlVH6RY5LnDjrT4vwfe/FApZtTecEWsllVUXDjSpwfcfD/"
            + "476/lpGySB2otALqzImlA9R8Ok3hJ8dnF6hhQ5Oe6OJMnGYgdhkKbxsKkdib"
            + "tTVl3qmH5QAwggLFMIIBrQIBATANBgkqhkiG9w0BAQUFADBpMQswCQYDVQQG"
            + "EwJVUzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJbmNvcnBvcmF0ZWQxHTAb"
            + "BgNVBAsTFEFkb2JlIFRydXN0IFNlcnZpY2VzMRYwFAYDVQQDEw1BZG9iZSBS"
            + "b290IENBFw0wNjAxMjcxODMzMzFaFw0wNzAxMjcwMDAwMDBaMIHeMCMCBD4c"
            + "vUAXDTAzMDEyMTIzNDY1NlowDDAKBgNVHRUEAwoBBDAjAgQ+HL1BFw0wMzAx"
            + "MjEyMzQ3MjJaMAwwCgYDVR0VBAMKAQQwIwIEPhy9YhcNMDMwMTIxMjM0NzQy"
            + "WjAMMAoGA1UdFQQDCgEEMCMCBD4cvWEXDTA0MDExNzAxMDg0OFowDDAKBgNV"
            + "HRUEAwoBBDAjAgQ+HL2qFw0wNDAxMTcwMTA5MDVaMAwwCgYDVR0VBAMKAQQw"
            + "IwIEPhy9qBcNMDQwMTE3MDEzOTI5WjAMMAoGA1UdFQQDCgEEoC8wLTAKBgNV"
            + "HRQEAwIBDzAfBgNVHSMEGDAWgBSCtzhKk6qbEO+Au9lU4vEP+4Cc3jANBgkq"
            + "hkiG9w0BAQUFAAOCAQEAwtXF9042wG39icUlsotn5tpE3oCusLb/hBpEONhx"
            + "OdfEQOq0w5hf/vqaxkcf71etA+KpbEUeSVaHMHRPhx/CmPrO9odE139dJdbt"
            + "9iqbrC9iZokFK3h/es5kg73xujLKd7C/u5ngJ4mwBtvhMLjFjF2vJhPKHL4C"
            + "IgMwdaUAhrcNzy16v+mw/VGJy3Fvc6oCESW1K9tvFW58qZSNXrMlsuidgunM"
            + "hPKG+z0SXVyCqL7pnqKiaGddcgujYGOSY4S938oVcfZeZQEODtSYGlzldojX"
            + "C1U1hCK5+tHAH0Ox/WqRBIol5VCZQwJftf44oG8oviYq52aaqSejXwmfT6zb"
            + "76GCBXUwggVxMIIFbQoBAKCCBWYwggViBgkrBgEFBQcwAQEEggVTMIIFTzCB"
            + "taIWBBS+8EpykfXdl4h3z7m/NZfdkAQQERgPMjAwNjA0MDQyMDIwMTVaMGUw"
            + "YzA7MAkGBSsOAwIaBQAEFEb4BuZYkbjBjOjT6VeA/00fBvQaBBT3fTSQniOp"
            + "BbHBSkz4xridlX0bsAICAYOAABgPMjAwNjA0MDQyMDIwMTVaoBEYDzIwMDYw"
            + "NDA1MDgyMDE1WqEjMCEwHwYJKwYBBQUHMAECBBIEEFqooq/R2WltD7TposkT"
            + "BhMwDQYJKoZIhvcNAQEFBQADgYEAMig6lty4b0JDsT/oanfQG5x6jVKPACpp"
            + "1UA9SJ0apJJa7LeIdDFmu5C2S/CYiKZm4A4P9cAu0YzgLHxE4r6Op+HfVlAG"
            + "6bzUe1P/hi1KCJ8r8wxOZAktQFPSzs85RAZwkHMfB0lP2e/h666Oye+Zf8VH"
            + "RaE+/xZ7aswE89HXoumgggQAMIID/DCCA/gwggLgoAMCAQICAXUwDQYJKoZI"
            + "hvcNAQEFBQAwRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUdlb1RydXN0IElu"
            + "Yy4xHjAcBgNVBAMTFUdlb1RydXN0IENBIGZvciBBZG9iZTAeFw0wNDEyMDIy"
            + "MTI1MzlaFw0wNjEyMzAyMTI1MzlaMEwxCzAJBgNVBAYTAlVTMRUwEwYDVQQK"
            + "EwxHZW9UcnVzdCBJbmMxJjAkBgNVBAMTHUdlb1RydXN0IEFkb2JlIE9DU1Ag"
            + "UmVzcG9uZGVyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDiCc1iG3Dt"
            + "TpB5Vdk4OcaEcyP46BnQMHf3esSTprar2SrXb0gDZ7TfIoFN8l9BH1pYpzZC"
            + "P3R2xKo+O9MMcUZCxqCbYVC6GcDd9vVRaE/N4Qh2bpvEOydDydaoqrGdZnMQ"
            + "tlt2ncj1sEuLMiqhtmi/O3rQs0yCGf+6e++6Gl5VKwIDAQABo4IBbjCCAWow"
            + "DgYDVR0PAQH/BAQDAgTwMIHlBgNVHSABAf8EgdowgdcwgdQGCSqGSIb3LwEC"
            + "ATCBxjCBkAYIKwYBBQUHAgIwgYMagYBUaGlzIGNlcnRpZmljYXRlIGhhcyBi"
            + "ZWVuIGlzc3VlZCBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIEFjcm9iYXQgQ3Jl"
            + "ZGVudGlhbHMgQ1BTIGxvY2F0ZWQgYXQgaHR0cDovL3d3dy5nZW90cnVzdC5j"
            + "b20vcmVzb3VyY2VzL2NwczAxBggrBgEFBQcCARYlaHR0cDovL3d3dy5nZW90"
            + "cnVzdC5jb20vcmVzb3VyY2VzL2NwczATBgNVHSUEDDAKBggrBgEFBQcDCTA6"
            + "BgNVHR8EMzAxMC+gLaArhilodHRwOi8vY3JsLmdlb3RydXN0LmNvbS9jcmxz"
            + "L2Fkb2JlY2ExLmNybDAfBgNVHSMEGDAWgBSrgFnDZYNtHX0TvRnD7BqPDUdq"
            + "ozANBgkqhkiG9w0BAQUFAAOCAQEAQ0l/UEPs9fmK+5prC33SrU4bNekhAv8K"
            + "XMR4VWY4jGo9zURMVGr3Zi7Eblvr5H6T60aSYLA8txjyKmDplxsn8CKtCGiH"
            + "OOUW5PpgBexN8SMKoRl9YzaxLtysrYRjEIyYoTfEN89yVi2sCjPupm/F9CPR"
            + "O7EdKy0dm/f3C7ZmIbUFaIRzINDJOCpM5cGhmZ8m2yG4BxeZOmCSthKtLfvM"
            + "2U9MaH6kxhDTJYNzw5BElHg5jlld92drTWaO0lM6aPr/pc+gs9hOraBCtzYE"
            + "J40nhsSEtvuwVUE9vA+unNMT8dFtAcOvOPRiKYPF45RX9Rdy2C9jAc20SRwE"
            + "uw6b+7K0xjANBgkqhkiG9w0BAQEFAASCAQC7a4yICFGCEMPlJbydK5qLG3rV"
            + "sip7Ojjz9TB4nLhC2DgsIHds8jjdq2zguInluH2nLaBCVS+qxDVlTjgbI2cB"
            + "TaWS8nglC7nNjzkKAsa8vThA8FZUVXTW0pb74jNJJU2AA27bb4g+4WgunCrj"
            + "fpYp+QjDyMmdrJVqRmt5eQN+dpVxMS9oq+NrhOSEhyIb4/rejgNg9wnVK1ms"
            + "l5PxQ4x7kpm7+Ua41//owkJVWykRo4T1jo4eHEz1DolPykAaKie2VKH/sMqR"
            + "Spjh4E5biKJLOV9fKivZWKAXByXfwUbbMsJvz4v/2yVHFy9xP+tqB5ZbRoDK"
            + "k8PzUyCprozn+/22oYIPijCCD4YGCyqGSIb3DQEJEAIOMYIPdTCCD3EGCSqG"
            + "SIb3DQEHAqCCD2Iwgg9eAgEDMQswCQYFKw4DAhoFADCB+gYLKoZIhvcNAQkQ"
            + "AQSggeoEgecwgeQCAQEGAikCMCEwCQYFKw4DAhoFAAQUoT97qeCv3FXYaEcS"
            + "gY8patCaCA8CAiMHGA8yMDA2MDQwNDIwMjA1N1owAwIBPAEB/wIIO0yRre3L"
            + "8/6ggZCkgY0wgYoxCzAJBgNVBAYTAlVTMRYwFAYDVQQIEw1NYXNzYWNodXNl"
            + "dHRzMRAwDgYDVQQHEwdOZWVkaGFtMRUwEwYDVQQKEwxHZW9UcnVzdCBJbmMx"
            + "EzARBgNVBAsTClByb2R1Y3Rpb24xJTAjBgNVBAMTHGFkb2JlLXRpbWVzdGFt"
            + "cC5nZW90cnVzdC5jb22gggzJMIIDUTCCAjmgAwIBAgICAI8wDQYJKoZIhvcN"
            + "AQEFBQAwRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUdlb1RydXN0IEluYy4x"
            + "HjAcBgNVBAMTFUdlb1RydXN0IENBIGZvciBBZG9iZTAeFw0wNTAxMTAwMTI5"
            + "MTBaFw0xNTAxMTUwODAwMDBaMIGKMQswCQYDVQQGEwJVUzEWMBQGA1UECBMN"
            + "TWFzc2FjaHVzZXR0czEQMA4GA1UEBxMHTmVlZGhhbTEVMBMGA1UEChMMR2Vv"
            + "VHJ1c3QgSW5jMRMwEQYDVQQLEwpQcm9kdWN0aW9uMSUwIwYDVQQDExxhZG9i"
            + "ZS10aW1lc3RhbXAuZ2VvdHJ1c3QuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GN"
            + "ADCBiQKBgQDRbxJotLFPWQuuEDhKtOMaBUJepGxIvWxeahMbq1DVmqnk88+j"
            + "w/5lfPICPzQZ1oHrcTLSAFM7Mrz3pyyQKQKMqUyiemzuG/77ESUNfBNSUfAF"
            + "PdtHuDMU8Is8ABVnFk63L+wdlvvDIlKkE08+VTKCRdjmuBVltMpQ6QcLFQzm"
            + "AQIDAQABo4GIMIGFMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwuZ2Vv"
            + "dHJ1c3QuY29tL2NybHMvYWRvYmVjYTEuY3JsMB8GA1UdIwQYMBaAFKuAWcNl"
            + "g20dfRO9GcPsGo8NR2qjMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAK"
            + "BggrBgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAQEAmnyXjdtX+F79Nf0KggTd"
            + "6YC2MQD9s09IeXTd8TP3rBmizfM+7f3icggeCGakNfPRmIUMLoa0VM5Kt37T"
            + "2X0TqzBWusfbKx7HnX4v1t/G8NJJlT4SShSHv+8bjjU4lUoCmW2oEcC5vXwP"
            + "R5JfjCyois16npgcO05ZBT+LLDXyeBijE6qWmwLDfEpLyILzVRmyU4IE7jvm"
            + "rgb3GXwDUvd3yQXGRRHbPCh3nj9hBGbuzyt7GnlqnEie3wzIyMG2ET/wvTX5"
            + "4BFXKNe7lDLvZj/MXvd3V7gMTSVW0kAszKao56LfrVTgp1VX3UBQYwmQqaoA"
            + "UwFezih+jEvjW6cYJo/ErDCCBKEwggOJoAMCAQICBD4cvSgwDQYJKoZIhvcN"
            + "AQEFBQAwaTELMAkGA1UEBhMCVVMxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMg"
            + "SW5jb3Jwb3JhdGVkMR0wGwYDVQQLExRBZG9iZSBUcnVzdCBTZXJ2aWNlczEW"
            + "MBQGA1UEAxMNQWRvYmUgUm9vdCBDQTAeFw0wMzAxMDgyMzM3MjNaFw0yMzAx"
            + "MDkwMDA3MjNaMGkxCzAJBgNVBAYTAlVTMSMwIQYDVQQKExpBZG9iZSBTeXN0"
            + "ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UECxMUQWRvYmUgVHJ1c3QgU2Vydmlj"
            + "ZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUA"
            + "A4IBDwAwggEKAoIBAQDMT1SE96ei5zNTfz+cEohrLJlHZ34PHrmtFIj5wxDY"
            + "HfDw1Z9pCi9ZNbDMbKlMnBWgn84gv6DPVOLgIGZFPzmGOH6cxI4HIsYk9gES"
            + "sDXfVeppkLDbhTce4k4HskKhahNpoGbqgJERWSqbCHlaIEQtyb1zOIs8L+BD"
            + "G12zC/CvNRop/u+mkt2BTJ09WY6tMTxAfpuRNgb84lyN0Y0m1VxFz69lP7Gq"
            + "0mKW9Kg46rpgQvT0HEo1Fc74TiJWD5UYxfiWn5/7sLd4JemAa73WCvDGdJSd"
            + "8w9Q25p3zktwgyONoMp4IERcPFRk8eqiMBmf6kwGTQZ4S16S3yLSyWezetIB"
            + "AgMBAAGjggFPMIIBSzARBglghkgBhvhCAQEEBAMCAAcwgY4GA1UdHwSBhjCB"
            + "gzCBgKB+oHykejB4MQswCQYDVQQGEwJVUzEjMCEGA1UEChMaQWRvYmUgU3lz"
            + "dGVtcyBJbmNvcnBvcmF0ZWQxHTAbBgNVBAsTFEFkb2JlIFRydXN0IFNlcnZp"
            + "Y2VzMRYwFAYDVQQDEw1BZG9iZSBSb290IENBMQ0wCwYDVQQDEwRDUkwxMCsG"
            + "A1UdEAQkMCKADzIwMDMwMTA4MjMzNzIzWoEPMjAyMzAxMDkwMDA3MjNaMAsG"
            + "A1UdDwQEAwIBBjAfBgNVHSMEGDAWgBSCtzhKk6qbEO+Au9lU4vEP+4Cc3jAd"
            + "BgNVHQ4EFgQUgrc4SpOqmxDvgLvZVOLxD/uAnN4wDAYDVR0TBAUwAwEB/zAd"
            + "BgkqhkiG9n0HQQAEEDAOGwhWNi4wOjQuMAMCBJAwDQYJKoZIhvcNAQEFBQAD"
            + "ggEBADLan0N1wfpvyW/bqx02Nz68YRk2twI8HSNZmGye7k2F51TIIB+n1Lvi"
            + "vwB3fSRrcC9cwTp2SbXT4COEKnFqIvPBJymYFfY1kOQETMONvJ9hHOf9JIzR"
            + "REOMFrqbTaXUNS+8Ec6991E3jZ+Q5BTxGD++6VkSNfkzkvOe4NVrmnGbmUvI"
            + "ccPhsWEJxOX6kfBCOjd9NPly6M2qYhwh6dX0ghDjewW2LWhWC35+kixvTXKC"
            + "DO1WdLKduastKx0QX9sndXCP/R3X4gKgeeUc5f+vZEBRLZ6bR9tCpXwfwqZI"
            + "sNe+kmlNpPYpV8V4ERjch1HKE7JinU8rMr0xpcH6UqsFiMgwggTLMIIDs6AD"
            + "AgECAgQ+HL21MA0GCSqGSIb3DQEBBQUAMGkxCzAJBgNVBAYTAlVTMSMwIQYD"
            + "VQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UECxMUQWRv"
            + "YmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3QgQ0EwHhcN"
            + "MDQwMTE3MDAwMzM5WhcNMTUwMTE1MDgwMDAwWjBFMQswCQYDVQQGEwJVUzEW"
            + "MBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEeMBwGA1UEAxMVR2VvVHJ1c3QgQ0Eg"
            + "Zm9yIEFkb2JlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp+V3"
            + "4GR4Wuc5hbyv0vVbKBMOVN1J+s5i9ZL9nph7n+X4esFs4epAJcFxJ4KnPuQH"
            + "ZZ0oyHUU4Th70mWYgKwd6sEt1aR6ZT788Nvr3OHwTRwugN/G6QXqhU9ePpZJ"
            + "OF1Ibsf1pcXNGvpLdcYK6+CX5DANMuIthb440XoNfC3dNBC0pF4mM4lmTjpl"
            + "nQG8xK0rIFp4HoMpmyaIijz2qyjXdUNkg0fbDUq9eDTKAOLOg21u+AA8XKbC"
            + "ewg1LWSV9CVy+fTHREmb1thBcrfkY1kCAvczsuquV3SMx8hRpa+4cIvKK/K1"
            + "G7OrV0nsTyuaJ2MMST8b7bul/Xd81nu9Hsz4iQIDAQABo4IBnTCCAZkwEgYD"
            + "VR0TAQH/BAgwBgEB/wIBATBQBgNVHSAESTBHMEUGCSqGSIb3LwECATA4MDYG"
            + "CCsGAQUFBwIBFipodHRwczovL3d3dy5hZG9iZS5jb20vbWlzYy9wa2kvY2Rz"
            + "X2NwLmh0bWwwFAYDVR0lBA0wCwYJKoZIhvcvAQEFMIGyBgNVHR8Egaowgacw"
            + "IqAgoB6GHGh0dHA6Ly9jcmwuYWRvYmUuY29tL2Nkcy5jcmwwgYCgfqB8pHow"
            + "eDELMAkGA1UEBhMCVVMxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMgSW5jb3Jw"
            + "b3JhdGVkMR0wGwYDVQQLExRBZG9iZSBUcnVzdCBTZXJ2aWNlczEWMBQGA1UE"
            + "AxMNQWRvYmUgUm9vdCBDQTENMAsGA1UEAxMEQ1JMMTALBgNVHQ8EBAMCAQYw"
            + "HwYDVR0jBBgwFoAUgrc4SpOqmxDvgLvZVOLxD/uAnN4wHQYDVR0OBBYEFKuA"
            + "WcNlg20dfRO9GcPsGo8NR2qjMBkGCSqGSIb2fQdBAAQMMAobBFY2LjADAgSQ"
            + "MA0GCSqGSIb3DQEBBQUAA4IBAQA/OVkuogCOsV4RYSzS4Lb1jImGRc4T2Z/d"
            + "hJoUawhMX4aXWPSlqNOPIfhHflCvd+Whbarcd83NN5n3QmevUOFUREPrMQyA"
            + "mkK0mpW6TSyLG5ckeCFL8qJwp/hhckk/H16m4hEXWyIFGfOecX3Sy+Y4kxcC"
            + "lzSMadifedB+TiRpKFKcNphp5hEMkpyyJaGXpLnN/BLsaDyEN7JySExAopae"
            + "UbUJCvCVIWKwoJ26ih3BG1aB+3yTHXeLIorextqWbq+dVz7me59Li8j5PAxe"
            + "hXrc2phpKuhp8FaTScvnfMZc8TL4Dr1CHMRWIkqfZaCq3mC376Mww0iZtE5s"
            + "iqB+AXVWMYIBgDCCAXwCAQEwSzBFMQswCQYDVQQGEwJVUzEWMBQGA1UEChMN"
            + "R2VvVHJ1c3QgSW5jLjEeMBwGA1UEAxMVR2VvVHJ1c3QgQ0EgZm9yIEFkb2Jl"
            + "AgIAjzAJBgUrDgMCGgUAoIGMMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB"
            + "BDAcBgkqhkiG9w0BCQUxDxcNMDYwNDA0MjAyMDU3WjAjBgkqhkiG9w0BCQQx"
            + "FgQUp7AnXBqoNcarvO7fMJut1og2U5AwKwYLKoZIhvcNAQkQAgwxHDAaMBgw"
            + "FgQU1dH4eZTNhgxdiSABrat6zsPdth0wDQYJKoZIhvcNAQEBBQAEgYCinr/F"
            + "rMiQz/MRm9ZD5YGcC0Qo2dRTPd0Aop8mZ4g1xAhKFLnp7lLsjCbkSDpVLDBh"
            + "cnCk7CV+3FT5hlvt8OqZlR0CnkSnCswLFhrppiWle6cpxlwGqyAteC8uKtQu"
            + "wjE5GtBKLcCOAzQYyyuNZZeB6oCZ+3mPhZ62FxrvvEGJCgAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");

    private final byte[] emptyDNCert = Base64.decode(
        "MIICfTCCAeagAwIBAgIBajANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJVUzEMMAoGA1UEChMD"
            + "Q0RXMQkwBwYDVQQLEwAxCTAHBgNVBAcTADEJMAcGA1UECBMAMRowGAYDVQQDExFUZW1wbGFyIFRl"
            + "c3QgMTAyNDEiMCAGCSqGSIb3DQEJARYTdGVtcGxhcnRlc3RAY2R3LmNvbTAeFw0wNjA1MjIwNTAw"
            + "MDBaFw0xMDA1MjIwNTAwMDBaMHwxCzAJBgNVBAYTAlVTMQwwCgYDVQQKEwNDRFcxCTAHBgNVBAsT"
            + "ADEJMAcGA1UEBxMAMQkwBwYDVQQIEwAxGjAYBgNVBAMTEVRlbXBsYXIgVGVzdCAxMDI0MSIwIAYJ"
            + "KoZIhvcNAQkBFhN0ZW1wbGFydGVzdEBjZHcuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
            + "gQDH3aJpJBfM+A3d84j5YcU6zEQaQ76u5xO9NSBmHjZykKS2kCcUqPpvVOPDA5WgV22dtKPh+lYV"
            + "iUp7wyCVwAKibq8HIbihHceFqMKzjwC639rMoDJ7bi/yzQWz1Zg+075a4FGPlUKn7Yfu89wKkjdW"
            + "wDpRPXc/agqBnrx5pJTXzQIDAQABow8wDTALBgNVHQ8EBAMCALEwDQYJKoZIhvcNAQEEBQADgYEA"
            + "RRsRsjse3i2/KClFVd6YLZ+7K1BE0WxFyY2bbytkwQJSxvv3vLSuweFUbhNxutb68wl/yW4GLy4b"
            + "1QdyswNxrNDXTuu5ILKhRDDuWeocz83aG2KGtr3JlFyr3biWGEyn5WUOE6tbONoQDJ0oPYgI6CAc"
            + "EHdUp0lioOCt6UOw7Cs=");

    private final byte[] gostRFC4491_94 = Base64.decode(
        "MIICCzCCAboCECMO42BGlSTOxwvklBgufuswCAYGKoUDAgIEMGkxHTAbBgNVBAMM" +
            "FEdvc3RSMzQxMC05NCBleGFtcGxlMRIwEAYDVQQKDAlDcnlwdG9Qcm8xCzAJBgNV" +
            "BAYTAlJVMScwJQYJKoZIhvcNAQkBFhhHb3N0UjM0MTAtOTRAZXhhbXBsZS5jb20w" +
            "HhcNMDUwODE2MTIzMjUwWhcNMTUwODE2MTIzMjUwWjBpMR0wGwYDVQQDDBRHb3N0" +
            "UjM0MTAtOTQgZXhhbXBsZTESMBAGA1UECgwJQ3J5cHRvUHJvMQswCQYDVQQGEwJS" +
            "VTEnMCUGCSqGSIb3DQEJARYYR29zdFIzNDEwLTk0QGV4YW1wbGUuY29tMIGlMBwG" +
            "BiqFAwICFDASBgcqhQMCAiACBgcqhQMCAh4BA4GEAASBgLuEZuF5nls02CyAfxOo" +
            "GWZxV/6MVCUhR28wCyd3RpjG+0dVvrey85NsObVCNyaE4g0QiiQOHwxCTSs7ESuo" +
            "v2Y5MlyUi8Go/htjEvYJJYfMdRv05YmKCYJo01x3pg+2kBATjeM+fJyR1qwNCCw+" +
            "eMG1wra3Gqgqi0WBkzIydvp7MAgGBiqFAwICBANBABHHCH4S3ALxAiMpR3aPRyqB" +
            "g1DjB8zy5DEjiULIc+HeIveF81W9lOxGkZxnrFjXBSqnjLeFKgF1hffXOAP7zUM=");

    private final byte[] gostRFC4491_2001 = Base64.decode(
        "MIIB0DCCAX8CECv1xh7CEb0Xx9zUYma0LiEwCAYGKoUDAgIDMG0xHzAdBgNVBAMM" +
            "Fkdvc3RSMzQxMC0yMDAxIGV4YW1wbGUxEjAQBgNVBAoMCUNyeXB0b1BybzELMAkG" +
            "A1UEBhMCUlUxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDAxQGV4YW1wbGUu" +
            "Y29tMB4XDTA1MDgxNjE0MTgyMFoXDTE1MDgxNjE0MTgyMFowbTEfMB0GA1UEAwwW" +
            "R29zdFIzNDEwLTIwMDEgZXhhbXBsZTESMBAGA1UECgwJQ3J5cHRvUHJvMQswCQYD" +
            "VQQGEwJSVTEpMCcGCSqGSIb3DQEJARYaR29zdFIzNDEwLTIwMDFAZXhhbXBsZS5j" +
            "b20wYzAcBgYqhQMCAhMwEgYHKoUDAgIkAAYHKoUDAgIeAQNDAARAhJVodWACGkB1" +
            "CM0TjDGJLP3lBQN6Q1z0bSsP508yfleP68wWuZWIA9CafIWuD+SN6qa7flbHy7Df" +
            "D2a8yuoaYDAIBgYqhQMCAgMDQQA8L8kJRLcnqeyn1en7U23Sw6pkfEQu3u0xFkVP" +
            "vFQ/3cHeF26NG+xxtZPz3TaTVXdoiYkXYiD02rEx1bUcM97i");

    private final byte[] uaczo1 = Base64.decode(
        "MIIFWzCCBNegAwIBAgIUMAR1He8seK4BAAAAAQAAAAEAAAAwDQYLKoYkAgEBAQED" +
            "AQEwgfoxPzA9BgNVBAoMNtCc0ZbQvdGW0YHRgtC10YDRgdGC0LLQviDRjtGB0YLQ" +
            "uNGG0ZbRlyDQo9C60YDQsNGX0L3QuDExMC8GA1UECwwo0JDQtNC80ZbQvdGW0YHR" +
            "gtGA0LDRgtC+0YAg0IbQotChINCm0JfQnjFJMEcGA1UEAwxA0KbQtdC90YLRgNCw" +
            "0LvRjNC90LjQuSDQt9Cw0YHQstGW0LTRh9GD0LLQsNC70YzQvdC40Lkg0L7RgNCz" +
            "0LDQvTEZMBcGA1UEBQwQVUEtMDAwMTU2MjItMjAxMjELMAkGA1UEBhMCVUExETAP" +
            "BgNVBAcMCNCa0LjRl9CyMB4XDTEyMDkyODE5NTMwMFoXDTIyMDkyODE5NTMwMFow" +
            "gfoxPzA9BgNVBAoMNtCc0ZbQvdGW0YHRgtC10YDRgdGC0LLQviDRjtGB0YLQuNGG" +
            "0ZbRlyDQo9C60YDQsNGX0L3QuDExMC8GA1UECwwo0JDQtNC80ZbQvdGW0YHRgtGA" +
            "0LDRgtC+0YAg0IbQotChINCm0JfQnjFJMEcGA1UEAwxA0KbQtdC90YLRgNCw0LvR" +
            "jNC90LjQuSDQt9Cw0YHQstGW0LTRh9GD0LLQsNC70YzQvdC40Lkg0L7RgNCz0LDQ" +
            "vTEZMBcGA1UEBQwQVUEtMDAwMTU2MjItMjAxMjELMAkGA1UEBhMCVUExETAPBgNV" +
            "BAcMCNCa0LjRl9CyMIIBUTCCARIGCyqGJAIBAQEBAwEBMIIBATCBvDAPAgIBrzAJ" +
            "AgEBAgEDAgEFAgEBBDbzykDGaaTaFzFJyhLDLa4Ya1Osa8Y2WZferq6K0tiI+b/V" +
            "NAFpTvnEJz2M/m3Cj3BqD0kQzgMCNj//////////////////////////////////" +
            "/7oxdUWACajApyTwL4Gqih/Lr4DZDHqVEQUEzwQ2fIV8lMVDO/2ZHhfCJoQGWFCp" +
            "oknte8JJrlpOh4aJ+HLvetUkCC7DA46a7ee6a6Ezgdl5umIaBECp1utF8TxwgoDE" +
            "lnsjH16t9ljrpMA3KR042WvwJcpOF/jpcg3GFbQ6KJdfC8Heo2Q4tWTqLBef0BI+" +
            "bbj6xXkEAzkABDa2G/m9S2LKqyw5UPXFHV+oDXB+AHtSW3BnZ9zlzRuvbido2tDG" +
            "qE/CL5kFHZE0NfTrHrGa1USjggE6MIIBNjApBgNVHQ4EIgQgMAR1He8seK4VC6vv" +
            "vv8Nq9v4LOVonutO0xCl+xM4+wowKwYDVR0jBCQwIoAgMAR1He8seK4VC6vvvv8N" +
            "q9v4LOVonutO0xCl+xM4+wowDgYDVR0PAQH/BAQDAgEGMBkGA1UdIAEB/wQPMA0w" +
            "CwYJKoYkAgEBAQICMBIGA1UdEwEB/wQIMAYBAf8CAQIwHgYIKwYBBQUHAQMBAf8E" +
            "DzANMAsGCSqGJAIBAQECATA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3pvLmdv" +
            "di51YS9kb3dubG9hZC9jcmxzL0NaTy1GdWxsLmNybDA+BgNVHS4ENzA1MDOgMaAv" +
            "hi1odHRwOi8vY3pvLmdvdi51YS9kb3dubG9hZC9jcmxzL0NaTy1EZWx0YS5jcmww" +
            "DQYLKoYkAgEBAQEDAQEDbwAEbPF4bx7drDxzzYABhB33Y0MQ+/N5FuPl7faVx/es" +
            "V5n5DXg5TzZovzZeICB5JHPLcbdeCq6aGwvXsgybt34zqf7LKmfq0rFNYfXJVWFH" +
            "4Tg5sPA+fCQ+T0O35VN873BLgTGz7bnHH9o8bnjwMA==");

    private final byte[] uaczo2 = Base64.decode(
        "MIIEvTCCBDmgAwIBAgIDAYhwMA0GCyqGJAIBAQEBAwEBMIIBHjELMAkGA1UEBhMC" +
            "VUExKDAmBgNVBAgMH9Ca0LjRl9Cy0YHRjNC60LAg0L7QsdC70LDRgdGC0YwxETAP" +
            "BgNVBAcMCNCa0LjRl9CyMUkwRwYDVQQKDEDQptC10L3RgtGA0LDQu9GM0L3QuNC5" +
            "INC30LDRgdCy0ZbQtNGH0YPQstCw0LvRjNC90LjQuSDQvtGA0LPQsNC9MTUwMwYD" +
            "VQQLDCzQotC10YXQvdC+0LvQvtCz0ZbRh9C90LjQuSDRhtC10L3RgtGAINCm0JfQ" +
            "njE1MDMGA1UEAwws0KPQutGA0LDRl9C90LAsINCm0JfQniAvIFVrcmFpbmUsIENl" +
            "bnRyYWwgQ0ExGTAXBgNVBAUTEFVBLTM3MjAwMzAzLTIwMTAwHhcNMDYxMjI1MDc0" +
            "MDU4WhcNMTExMjI0MDc0MDU4WjCCAR4xCzAJBgNVBAYTAlVBMSgwJgYDVQQIDB/Q" +
            "mtC40ZfQstGB0YzQutCwINC+0LHQu9Cw0YHRgtGMMREwDwYDVQQHDAjQmtC40ZfQ" +
            "sjFJMEcGA1UECgxA0KbQtdC90YLRgNCw0LvRjNC90LjQuSDQt9Cw0YHQstGW0LTR" +
            "h9GD0LLQsNC70YzQvdC40Lkg0L7RgNCz0LDQvTE1MDMGA1UECwws0KLQtdGF0L3Q" +
            "vtC70L7Qs9GW0YfQvdC40Lkg0YbQtdC90YLRgCDQptCX0J4xNTAzBgNVBAMMLNCj" +
            "0LrRgNCw0ZfQvdCwLCDQptCX0J4gLyBVa3JhaW5lLCBDZW50cmFsIENBMRkwFwYD" +
            "VQQFExBVQS0zNzIwMDMwMy0yMDEwMIGdMGAGCyqGJAIBAQEBAwEBMFEGDSqGJAIB" +
            "AQEBAwEBAgkEQKnW60XxPHCCgMSWeyMfXq32WOukwDcpHTjZa/Alyk4X+OlyDcYV" +
            "tDool18Lwd6jZDi1ZOosF5/QEj5tuPrFeQQDOQAENlMfji/H5gxxL5TKtLMFv2X3" +
            "0EJrj3orwGV0zEz+EgSChr+I8bsOrnfkr5UwMQIjGJOg1G/nYKOCARgwggEUMA8G" +
            "A1UdEwEB/wQFMAMBAf8weQYDVR0gAQH/BG8wbTBeBgkqhiQCAQEBAgEwUTBPBggr" +
            "BgEFBQcCARZDaHR0cDovL2N6by5nb3YudWEvY29udGVudC9ub3JtYXRpdmVfZG9j" +
            "dW1lbnQvZ2VuZXJhbF9kb2MvcmVnQ1pPLnppcDALBgkqhiQCAQEBAgIwHgYIKwYB" +
            "BQUHAQMBAf8EDzANMAsGCSqGJAIBAQECATAOBgNVHQ8BAf8EBAMCAcYwKQYDVR0O" +
            "BCIEIPqbNt55OgWdLCn8hfuY9HJE3d3+DTTBlTJBN0nxog+mMCsGA1UdIwQkMCKA" +
            "IPqbNt55OgWdLCn8hfuY9HJE3d3+DTTBlTJBN0nxog+mMA0GCyqGJAIBAQEBAwEB" +
            "A28ABGx8QNaWcy0admsBt6iB0Vi+kAargzsQuoc/BThskYdxGNftLvYDPYxkEM2N" +
            "GQ+9f1RJgCSNVRj3NhWoHhkqcL5R3gxAHie+a+zMqsX0258hGdT3MXkm0Syn/cNo" +
            "sga4XzzvnVaas9vsPKMrZTQ=");

    private final byte[] uaczo3 = Base64.decode(
        "MIIEtTCCBDGgAwIBAgIDAYisMA0GCyqGJAIBAQEBAwEBMIIBGjELMAkGA1UEBhMC" +
            "VUExKDAmBgNVBAgMH9Ca0LjRl9Cy0YHRjNC60LAg0L7QsdC70LDRgdGC0YwxETAP" +
            "BgNVBAcMCNCa0LjRl9CyMUkwRwYDVQQKDEDQptC10L3RgtGA0LDQu9GM0L3QuNC5" +
            "INC30LDRgdCy0ZbQtNGH0YPQstCw0LvRjNC90LjQuSDQvtGA0LPQsNC9MTEwLwYD" +
            "VQQLDCjQkNC00LzRltC90ZbRgdGC0YDQsNGC0L7RgCDQhtCi0KEg0KbQl9CeMTUw" +
            "MwYDVQQDDCzQo9C60YDQsNGX0L3QsCwg0KbQl9CeIC8gVWtyYWluZSwgQ2VudHJh" +
            "bCBDQTEZMBcGA1UEBRMQVUEtMDAwMTU2MjItMjAxMTAeFw0wNzEyMjAxMDAwMDBa" +
            "Fw0xMjEyMTgxMDAwMDBaMIIBGjELMAkGA1UEBhMCVUExKDAmBgNVBAgMH9Ca0LjR" +
            "l9Cy0YHRjNC60LAg0L7QsdC70LDRgdGC0YwxETAPBgNVBAcMCNCa0LjRl9CyMUkw" +
            "RwYDVQQKDEDQptC10L3RgtGA0LDQu9GM0L3QuNC5INC30LDRgdCy0ZbQtNGH0YPQ" +
            "stCw0LvRjNC90LjQuSDQvtGA0LPQsNC9MTEwLwYDVQQLDCjQkNC00LzRltC90ZbR" +
            "gdGC0YDQsNGC0L7RgCDQhtCi0KEg0KbQl9CeMTUwMwYDVQQDDCzQo9C60YDQsNGX" +
            "0L3QsCwg0KbQl9CeIC8gVWtyYWluZSwgQ2VudHJhbCBDQTEZMBcGA1UEBRMQVUEt" +
            "MDAwMTU2MjItMjAxMTCBnTBgBgsqhiQCAQEBAQMBATBRBg0qhiQCAQEBAQMBAQIJ" +
            "BECp1utF8TxwgoDElnsjH16t9ljrpMA3KR042WvwJcpOF/jpcg3GFbQ6KJdfC8He" +
            "o2Q4tWTqLBef0BI+bbj6xXkEAzkABDajkfNBomH27xjY1N7wklRvY5E0ZFaU53Fh" +
            "y4jUY+G4AUhEHHCkTvUja8CUxPqtb9KyfuZELVOjggEYMIIBFDAPBgNVHRMBAf8E" +
            "BTADAQH/MHkGA1UdIAEB/wRvMG0wXgYJKoYkAgEBAQIBMFEwTwYIKwYBBQUHAgEW" +
            "Q2h0dHA6Ly9jem8uZ292LnVhL2NvbnRlbnQvbm9ybWF0aXZlX2RvY3VtZW50L2dl" +
            "bmVyYWxfZG9jL3JlZ0NaTy56aXAwCwYJKoYkAgEBAQICMB4GCCsGAQUFBwEDAQH/" +
            "BA8wDTALBgkqhiQCAQEBAgEwDgYDVR0PAQH/BAQDAgHGMCkGA1UdDgQiBCC+e+cA" +
            "bIdAgQkh6q3dUAZjPrNhwDDGrVnLNP6telmoCjArBgNVHSMEJDAigCC+e+cAbIdA" +
            "gQkh6q3dUAZjPrNhwDDGrVnLNP6telmoCjANBgsqhiQCAQEBAQMBAQNvAARsyq9i" +
            "ajEgdBh5mPUZefcLY56AIRWqmsJsWuZuUbCa5oQXRH5iCRa4PSvs8v6zHAKKlMgK" +
            "gaoY6jywqmwiMlylbSgo/A0HKdCFnUUl7S8yjE4054MSSIjb2R0c2pmqmwtU25JB" +
            "/MkNbe77Uzka");

    private final byte[] uaczo4 = Base64.decode(
        "MIIEKzCCA6egAwIBAgIBATANBgsqhiQCAQEBAQMBATCBzDFJMEcGA1UECwxA0KbQ" +
            "tdC90YLRgNCw0LvRjNC90LjQuSDQt9Cw0YHQstGW0LTRh9GD0LLQsNC70YzQvdC4" +
            "0Lkg0L7RgNCz0LDQvTE1MDMGA1UEAwws0KPQutGA0LDRl9C90LAsINCm0JfQniAv" +
            "IFVrcmFpbmUsIENlbnRyYWwgQ0ExCzAJBgNVBAYTAlVBMREwDwYDVQQHDAjQmtC4" +
            "0ZfQsjEoMCYGA1UECAwf0JrQuNGX0LLRgdGM0LrQsCDQvtCx0LvQsNGB0YLRjDAe" +
            "Fw0wNTEyMjMyMzAxMDFaFw0xMDEyMjMyMzAxMDFaMIHMMUkwRwYDVQQLDEDQptC1" +
            "0L3RgtGA0LDQu9GM0L3QuNC5INC30LDRgdCy0ZbQtNGH0YPQstCw0LvRjNC90LjQ" +
            "uSDQvtGA0LPQsNC9MTUwMwYDVQQDDCzQo9C60YDQsNGX0L3QsCwg0KbQl9CeIC8g" +
            "VWtyYWluZSwgQ2VudHJhbCBDQTELMAkGA1UEBhMCVUExETAPBgNVBAcMCNCa0LjR" +
            "l9CyMSgwJgYDVQQIDB/QmtC40ZfQstGB0YzQutCwINC+0LHQu9Cw0YHRgtGMMIIB" +
            "UTCCARIGCyqGJAIBAQEBAwEBMIIBATCBvDAPAgIBrzAJAgEBAgEDAgEFAgEBBDbz" +
            "ykDGaaTaFzFJyhLDLa4Ya1Osa8Y2WZferq6K0tiI+b/VNAFpTvnEJz2M/m3Cj3Bq" +
            "D0kQzgMCNj///////////////////////////////////7oxdUWACajApyTwL4Gq" +
            "ih/Lr4DZDHqVEQUEzwQ2lqAgR9+skUI33jGNgj2Qsh9+3x7so5koelwr4fy89k/x" +
            "5eqNSvFZ/1fPHfXz+iz7PmFIhr15BECLwhftNllK8B904j3LmmBY/teFIBSrw2lL" +
            "CKc1nWIez+h/01q0GSxgeuwU0oOw9WmwlkGuj13DJ8cSmm70jTULAzkABDa6vb3U" +
            "VIxZr2cXcVSvKkPM65Ii2+8biqyoH8i9e0NKJu+IhjDvUrvzlr8U+ywuf5bpSj4N" +
            "fEmjezB5MA4GA1UdDwEB/wQEAwIBxjAPBgNVHRMBAf8EBTADAQH/MCsGA1UdIwQk" +
            "MCKAIOPEn/xcXE6VGFNB8vbfXS1XMYYzAa4ML8opsOslTHJNMCkGA1UdDgQiBCDj" +
            "xJ/8XFxOlRhTQfL2310tVzGGMwGuDC/KKbDrJUxyTTANBgsqhiQCAQEBAQMBAQNv" +
            "AARsh0unjBfQoINx2rXAJggrBdoRsCouw8lN771DhcuUrlQUuEEQHTaZrQoYbECu" +
            "AGfsxfTyldQDEOVzD/Uq8Xh4gIHuSqki9mRSjMR19MQtTKRmI9TRHIeTdIZ6l3P7" +
            "jFfGJvTP0E9NYSolx+kM");

    private final byte[] sha3Cert = Base64.decode(
        "MIID8jCCAqagAwIBAgIICfBykpzUT+IwQQYJKoZIhvcNAQEKMDSgDzANBglg"
            + "hkgBZQMEAggFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAggFAKIDAgEg"
            + "MCwxCzAJBgNVBAYTAkRFMQ4wDAYDVQQKDAV4aXBraTENMAsGA1UEAwwEUkNB"
            + "MTAeFw0xNjEwMTgxODQzMjhaFw0yNjEwMTgxODQzMjdaMCwxCzAJBgNVBAYT"
            + "AkRFMQ4wDAYDVQQKDAV4aXBraTENMAsGA1UEAwwEUkNBMTCCASIwDQYJKoZI"
            + "hvcNAQEBBQADggEPADCCAQoCggEBAK/pzm1RASDYDg3WBXyW3AnAESRF/+li"
            + "qh0X8Y89m+JFJeOi1u89bOSPjsFfo5SbRSElyRXedh/d37KrONg39NEKIcC6"
            + "iSuiNfXu0D6nlSzhrQzmvHIyfLnm8N2JtHDr/hZIprOcFO+lZTJIjjrOVe9y"
            + "lFGgGDd/uQCEJk1Cmi5Ivi9odeiN3z8lVlGNeN9/Q5n47ijuYWr73z/FyyAK"
            + "gAG3B5nhAYWs4ft0O3JWBc0QJZzShqsRjm3SNhAqMDnRoTq04PFgbDYizV8T"
            + "ydz2kCne79TDwsY4MckYYaGoNcPoQXVS+9YjQjI72ktSlxiJxodL9WMFl+ED"
            + "5ZLBRIRsDJECAwEAAaOBrzCBrDAPBgNVHRMBAf8EBTADAQH/MGoGCCsGAQUF"
            + "BwEBBF4wXDAnBggrBgEFBQcwAoYbaHR0cDovL2V4YW1wbGUub3JnL1JDQTEu"
            + "ZGVyMDEGCCsGAQUFBzABhiVodHRwOi8vbG9jYWxob3N0OjgwODAvb2NzcC9y"
            + "ZXNwb25kZXIxMB0GA1UdDgQWBBRTXKdJI3P1kveLlRxPvzUfDnC8JjAOBgNV"
            + "HQ8BAf8EBAMCAQYwQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAggFAKEc"
            + "MBoGCSqGSIb3DQEBCDANBglghkgBZQMEAggFAKIDAgEgA4IBAQCpSVaqOMKz"
            + "6NT0+mivEhig9cKsglFhnWStKUtdhrG4HqOf6Qjny9Xvq1nE7x8e2xAoaZLd"
            + "GMsNAWFCbwzoJrDL7Ct6itQ5ymxi2haN+Urc5UWJd/8C0R74OdP1uPCiljZ9"
            + "DdjbNk/hS36UPYi+FT5r6Jr/1X/EqgL1MOUsSTEXdYlZH662zjbV4D9QSBzx"
            + "ul9bYyWrqSZFKvKef4UQwUy8yXtChwiwp50mfJQBdVcIqPBYCgmLYclamjQx"
            + "hlkk5VbZb4D/Cv4HxrdxpJfy/ewUZR7uHlzDx0/m4qjzNzWgq+sh3ZbveDrV"
            + "wd/FDMFOxSIno9qgHtdfgXRwZJ+l07fF");

    private final String ecPemCert =
        "-----BEGIN CERTIFICATE-----\n" +
            "MIIB/jCCAYWgAwIBAgIIdJclisc/elQwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMC\n" +
            "VVMxFDASBgNVBAoMC0FmZmlybVRydXN0MSAwHgYDVQQDDBdBZmZpcm1UcnVzdCBQ\n" +
            "cmVtaXVtIEVDQzAeFw0xMDAxMjkxNDIwMjRaFw00MDEyMzExNDIwMjRaMEUxCzAJ\n" +
            "BgNVBAYTAlVTMRQwEgYDVQQKDAtBZmZpcm1UcnVzdDEgMB4GA1UEAwwXQWZmaXJt\n" +
            "VHJ1c3QgUHJlbWl1bSBFQ0MwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQNMF4bFZ0D\n" +
            "0KF5Nbc6PJJ6yhUczWLznCZcBz3lVPqj1swS6vQUX+iOGasvLkjmrBhDeKzQN8O9\n" +
            "ss0s5kfiGuZjuD0uL3jET9v0D6RoTFVya5UdThhClXjMNzyR4ptlKymjQjBAMB0G\n" +
            "A1UdDgQWBBSaryl6wBE1NSZRMADDav5A1a7WPDAPBgNVHRMBAf8EBTADAQH/MA4G\n" +
            "A1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNnADBkAjAXCfOHiFBar8jAQr9HX/Vs\n" +
            "aobgxCd05DhT1wV/GzTjxi+zygk8N53X57hG8f2h4nECMEJZh0PUUd+60wkyWs6I\n" +
            "flc9nF9Ca/UHLbXwgpP5WW+uZPpY5Yse42O+tYHNbwKMeQ==\n" +
            "-----END CERTIFICATE-----";

    private final String pemPKCS7 =
        "-----BEGIN PKCS7-----\n" +
            "MIIJDAYJKoZIhvcNAQcCoIII/TCCCPkCAQExADALBgkqhkiG9w0BBwGgggjfMIIF\n" +
            "wTCCBKmgAwIBAgIJ+pQ4odKc8AABMA0GCSqGSIb3DQEBBQUAMGAxCzAJBgNVBAYT\n" +
            "AlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTYW4gTWF0ZW8xFzAV\n" +
            "BgNVBAoTDkdlbml1cy5jb20gSW5jMQ8wDQYDVQQLEwZOZXRPcHMwHhcNMTQwMTI4\n" +
            "MjE0MjE0WhcNMjQwMTI2MjE0MjE0WjBgMQswCQYDVQQGEwJVUzETMBEGA1UECBMK\n" +
            "Q2FsaWZvcm5pYTESMBAGA1UEBxMJU2FuIE1hdGVvMRcwFQYDVQQKEw5HZW5pdXMu\n" +
            "Y29tIEluYzEPMA0GA1UECxMGTmV0T3BzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
            "MIIBCgKCAQEArfmkkDffJP6ODl13KnTaB8cwvB4anWw8+bGa8y9N7wPx7RWZWFMr\n" +
            "fOac01p2fhq+oUIw3/uxRcDAQBQx0ZFLx3OFMuQkTpFbzHeSctsXi1Kk28pn4K3B\n" +
            "K2CModRh8ir/qdhu0PG4SsXdyN8uT8H6bitmH4vpLaAMMi6aa1M6Ygio8a37UCQQ\n" +
            "7fw2P7YVR61BsyqwsM/eYtgd2LqrObLwkkOvxTwpZPWDftHI4ucz1rgNnD9q0H3g\n" +
            "kyGyGq9NBkBHJ25+CkMe+1q/eh4Xt2kt2ML4q5YZmQEwHm1eIR3/uGlb1+bueRMd\n" +
            "hrueth/FsUiKPJ0gzmsxzQefgcLnctIx3wIDAQABo4ICfDCCAngwCQYDVR0TBAIw\n" +
            "ADALBgNVHQ8EBAMCBeAwHQYDVR0OBBYEFJ/uU/wudzNDSI/SWkNNTXNLq2EIMIGS\n" +
            "BgNVHSMEgYowgYeAFJ/uU/wudzNDSI/SWkNNTXNLq2EIoWSkYjBgMQswCQYDVQQG\n" +
            "EwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU2FuIE1hdGVvMRcw\n" +
            "FQYDVQQKEw5HZW5pdXMuY29tIEluYzEPMA0GA1UECxMGTmV0T3Bzggn6lDih0pzw\n" +
            "AAEwHgYJYIZIAYb4QgENBBEWD1guNTA5IFVuaXQgVGVzdDCBwwYDVR0RBIG7MIG4\n" +
            "oA4GAyoDBKAHDAV0ZXN0MYEQeDUwOUBleGFtcGxlLmNvbYIQeDUwOS5leGFtcGxl\n" +
            "LmNvbaRQME4xCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1Bd2Vzb21lIER1ZGVzMRcw\n" +
            "FQYDVQQLFA7DnGJlciBGcsOuZW5kczEOMAwGA1UEAxQF4oiGxpKGJWh0dHA6Ly93\n" +
            "d3cuZXhhbXBsZS5jb20vP3E9YXdlc29tZW5lc3OHBMCoAAGIAyoDBDCBwwYDVR0S\n" +
            "BIG7MIG4oA4GAyoDBKAHDAV0ZXN0MYEQeDUwOUBleGFtcGxlLmNvbYIQeDUwOS5l\n" +
            "eGFtcGxlLmNvbaRQME4xCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1Bd2Vzb21lIER1\n" +
            "ZGVzMRcwFQYDVQQLFA7DnGJlciBGcsOuZW5kczEOMAwGA1UEAxQF4oiGxpKGJWh0\n" +
            "dHA6Ly93d3cuZXhhbXBsZS5jb20vP3E9YXdlc29tZW5lc3OHBMCoAAGIAyoDBDAN\n" +
            "BgkqhkiG9w0BAQUFAAOCAQEAQK5jBzTq2lX1GpVD9RHxtTHJn/WkYOpMJYJruw8j\n" +
            "HGfQwAkhlL9AqWgodTruoTnXgZbA7F3S8hx9gmUbHVjVeBvxZnGEJ8g7So1erFKv\n" +
            "yQD1Ajtn7+uGXw6s0Dvde2ZVzV05pRk9ybg7kxKNXvVbKS3kyd6XoA27H5CSmzDu\n" +
            "8cwHQkN4mJlwAiNCwMarpN4m4X0rQ+g1Ncfq+4sRjFLd8VVCbCpzD8UMBOVTpxxj\n" +
            "kSyRPJZ7Db8SY0H2vcTUj2Yyog1RQ+RA/xp7Fgw+leEiveIE23Dq62hCHq6rU5Vj\n" +
            "6L/LlLiKZ17lZT4z0fJ0lukPUpmVTynALKsKNm57+fOfnzCCAxYwggLWoAMCAQIC\n" +
            "CQDcaK5WyhbztjAJBgcqhkjOOAQDMGAxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpD\n" +
            "YWxpZm9ybmlhMRIwEAYDVQQHEwlTYW4gTWF0ZW8xFzAVBgNVBAoTDkdlbml1cy5j\n" +
            "b20gSW5jMQ8wDQYDVQQLEwZOZXRPcHMwHhcNMTQwMTI4MjE0MjE1WhcNMTQwMjI3\n" +
            "MjE0MjE1WjBgMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAG\n" +
            "A1UEBxMJU2FuIE1hdGVvMRcwFQYDVQQKEw5HZW5pdXMuY29tIEluYzEPMA0GA1UE\n" +
            "CxMGTmV0T3BzMIIBtzCCASsGByqGSM44BAEwggEeAoGBAIiv42coWuyVXpYoyEwf\n" +
            "7uevd4ILhylFuvKH5tRWRcZENuxPOmXfr3L43PCdbnJhXMg3RkkWgjaE7lBk5evx\n" +
            "LKH6rU2a1GnGmoY34OIvVvGL3xi96uYTTvLIX3+6NXaAlNppIBSHXcYx8cMdtYIn\n" +
            "3J6JGSHEPo36ay4rDZbfS1frAhUAxF6k+/9T00QMolE41R+6ytzrawkCgYA4soyt\n" +
            "rrIrQq6gwm2HanT8coIChr3/Et8rMamj7gS1yT9kH8HNGf217XtE3f/LUZZWUkBq\n" +
            "3PNOuxhprNmvSAdQ7ZzhWfRvOFHKaH/DtKvLeEC5I00DfYSI64/V869Jy7lnyY7M\n" +
            "h7ShLIwOlwnBDIL5oluircfXTr20a/Jv9pS1AAOBhQACgYEAhg6lELBZAIHVkjm7\n" +
            "bwVJ5G/ka+KCjXxWXo+BCbqo0LqfrKQoQwUcwDzuKdqWxYbyUd0cl5/9fX59/RT/\n" +
            "9ULklGy+dTyUSc/hj85PCXLYly3G6WECiN29TK0QLhEMZfi+iSm3YxNX3rxvmrHb\n" +
            "bfO2SMef4r6ujv9KscDg0zQ4AgajGjAYMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgA3\n" +
            "MAkGByqGSM44BAMDLwAwLAIUVcYZ1LNv22fDBiajZ99FpTn05SMCFCgMXzUGLdPy\n" +
            "gY460q7tGpuydry+oQAxAA==\n" +
            "-----END PKCS7-----\n";

    private static byte[] sm_root = Base64.decode(
        "MIICDTCCAbGgAwIBAgIEHPP3OTAMBggqgRzPVQGDdQUAMFoxCzAJBgNVBAYTAkNO"
            + "MTAwLgYDVQQKDCdDaGluYSBGaW5hbmNpYWwgQ2VydGlmaWNhdGlvbiBBdXRob3Jp"
            + "dHkxGTAXBgNVBAMMEENGQ0EgRVYgU00yIFJPT1QwHhcNMTIwODA4MDMwNjMwWhcN"
            + "MjkxMjMxMDMwNjMwWjBaMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmlu"
            + "YW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRkwFwYDVQQDDBBDRkNBIEVW"
            + "IFNNMiBST09UMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE/9xokvYPq1PPsvqh"
            + "wzc1OvhRJyqfm+FeefW522OMUJeSqmaYRcwAaEC1IH03etyYEOD4R4HQG+ovJr4z"
            + "PLZzUqNjMGEwHwYDVR0jBBgwFoAUXxyJKUK15hS66W6X7kBqaMo9lLgwDwYDVR0T"
            + "AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFF8ciSlCteYUuulu"
            + "l+5AamjKPZS4MAwGCCqBHM9VAYN1BQADSAAwRQIgbE/XnzWMMQItSfz/LH6CyNz1"
            + "OxFwvI6WcgcqGGUdCiMCIQDRFwF7M4Cvo7KqGMNuSiByFNUX9PJYXByjxqPart9U"
            + "tw==");

    private static byte[] sm_sign = Base64.decode(
        "MIICzTCCAnKgAwIBAgIGAIgmba9KMAwGCCqBHM9VAYN1BQAwWjELMAkGA1UEBhMC"
            + "Q04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFuY2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhv"
            + "cml0eTEZMBcGA1UEAwwQQ0ZDQSBFViBTTTIgUk9PVDAeFw0xMjA4MDgwNTU2Mjda"
            + "Fw0yOTEyMjkwNTU2MjdaMFkxCzAJBgNVBAYTAkNOMTAwLgYDVQQKDCdDaGluYSBG"
            + "aW5hbmNpYWwgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxGDAWBgNVBAMMD0NGQ0Eg"
            + "RVYgU00yIE9DQTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABG6sjKVpVukkQpY1"
            + "nokr6wmp44hwkVnzmdXvuBbq/VtwB/8V+awkIfpz4THaSjPGzSGh+hwFcka0NCFK"
            + "TQ7y8rqjggEhMIIBHTA4BggrBgEFBQcBAQQsMCowKAYIKwYBBQUHMAGGHGh0dHA6"
            + "Ly9vY3NwLmNmY2EuY29tLmNuL29jc3AwHwYDVR0jBBgwFoAUXxyJKUK15hS66W6X"
            + "7kBqaMo9lLgwDwYDVR0TAQH/BAUwAwEB/zBEBgNVHSAEPTA7MDkGBFUdIAAwMTAv"
            + "BggrBgEFBQcCARYjaHR0cDovL3d3dy5jZmNhLmNvbS5jbi91cy91cy0xMi5odG0w"
            + "OgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybC5jZmNhLmNvbS5jbi9ldnJjYS9T"
            + "TTIvY3JsMS5jcmwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTDJFfnVXuTdN3s"
            + "yIha7AIm0b8vWTAMBggqgRzPVQGDdQUAA0cAMEQCIBgrKO75mE5lfONElZZzkAWh"
            + "eb0R0ai6/J7nj7SCZ3jJAiAE2dKJIv9ROkN17bhZpXsVrOtyYULW7YzQePqnNN58"
            + "MA==");

    private static byte[] sm_root1 = Base64.decode(
        "MIICwzCCAmmgAwIBAgIIIBQGIgAAAAMwCgYIKoEcz1UBg3UwgdgxCzAJBgNVBAYT" +
            "AkNOMRIwEAYDVQQIDAnmsZ/oi4/nnIExEjAQBgNVBAcMCeWNl+S6rOW4gjE8MDoG" +
            "A1UECgwz5rGf6IuP55yB55S15a2Q5ZWG5Yqh5pyN5Yqh5Lit5b+D5pyJ6ZmQ6LSj" +
            "5Lu75YWs5Y+4MUswSQYDVQQLDELmsZ/oi4/nnIHnlLXlrZDllYbliqHmnI3liqHk" +
            "uK3lv4PmnInpmZDotKPku7vlhazlj7jlronlhajkuovkuJrpg6gxFjAUBgNVBAMM" +
            "DUpTQ0FfUk9PVF9TTTIwHhcNMTQwNjIyMDQ1MzAyWhcNMzQwNjIyMDQ1MzAyWjCB" +
            "1jELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeaxn+iLj+ecgTESMBAGA1UEBwwJ5Y2X" +
            "5Lqs5biCMTwwOgYDVQQKDDPmsZ/oi4/nnIHnlLXlrZDllYbliqHmnI3liqHkuK3l" +
            "v4PmnInpmZDotKPku7vlhazlj7gxSzBJBgNVBAsMQuaxn+iLj+ecgeeUteWtkOWV" +
            "huWKoeacjeWKoeS4reW/g+aciemZkOi0o+S7u+WFrOWPuOWuieWFqOS6i+S4mumD" +
            "qDEUMBIGA1UEAwwLSlNDQV9DQV9TTTIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNC" +
            "AAS/gvW90+LvyXPgpR7L0pwlVoZQdan7V5YQMEpxt47tzer31/8WJIfldx9NL/1A" +
            "swkk6ItveCVW5k0u+IIk6crLox0wGzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIB" +
            "BjAKBggqgRzPVQGDdQNIADBFAiEAy9NkogihHCj9Jx0ZiHdkMyCHF0wHWX58KZco" +
            "CW5mjbgCIC9cAyuVV91ygLWk14PDuIAPFWKm6rJPXbiZL6KzwHQA");

    private static byte[] sm_ca1 = Base64.decode(
         "MIIC/TCCAqKgAwIBAgIIIBYDKQETeGQwCgYIKoEcz1UBg3UwgccxCzAJBgNVBAYT" +
             "AkNOMRIwEAYDVQQIDAnmsZ/oi4/nnIExEjAQBgNVBAcMCeWNl+S6rOW4gjE8MDoG" +
             "A1UECgwz5rGf6IuP55yB55S15a2Q5ZWG5Yqh5pyN5Yqh5Lit5b+D5pyJ6ZmQ6LSj" +
             "5Lu75YWs5Y+4MTwwOgYDVQQLDDPmsZ/oi4/nnIHnlLXlrZDllYbliqHmnI3liqHk" +
             "uK3lv4PmnInpmZDotKPku7vlhazlj7gxFDASBgNVBAMMC0pTQ0FfQ0FfU00yMB4X" +
             "DTE2MDMyOTA3MzQxOVoXDTIxMDMyOTA3MzQxOVowejENMAsGA1UEAxMEaG9zdDEL" +
             "MAkGA1UECxMCMTExETAPBgNVBAoTCEFCQyBsdGQuMQswCQYDVQQHEwJOSjELMAkG" +
             "A1UECBMCSlMxIjAgBgRVBC0RExhEOURGQThBN0NFMDg5QTg0Q0Q4Q0RCQjYxCzAJ" +
             "BgNVBAYTAkNOMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEaTG1mpejjdsNRr2q" +
             "p3ZC0pPXuBO19sNhIJEG6cMSi/kE1hNDosCBRhpr2gOqKP9bXHrIhVGe41Z9Ci8L" +
             "jf/hpaOBwzCBwDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIEsDAdBgNVHSUEFjAUBggr" +
             "BgEFBQcDAgYIKwYBBQUHAwQwHwYDVR0jBBgwFoAU/9NocgiO5XrE+eYsU0VOkaSx" +
             "egMwRwYIKwYBBQUHAQEEOzA5MDcGCCsGAQUFBzAChitodHRwOi8vMTAuMTA4LjUu" +
             "Mjo4ODgwL2Rvd25sb2FkL0pTQ0FfQ0EuY2VyMB0GA1UdDgQWBBQQ80pId+SJS9uP" +
             "aZaItbNdEE2C0zAKBggqgRzPVQGDdQNJADBGAiEAogpBxL3Cc4P4v+FvQsnCgCZs" +
             "oSdFZLZDB4uDlOIqU9wCIQDXmE1iiCsWi1RmdoY+/ics2ZlY8vyHWBJnZ+XFy1Jb" +
             "fA==");

    private static byte[] sm_sign1 = Base64.decode(
        "MIID9zCCA5ygAwIBAgIIIBcEJwKSCCMwCgYIKoEcz1UBg3UwgccxCzAJBgNVBAYT" +
        "AkNOMRIwEAYDVQQIDAnmsZ/oi4/nnIExEjAQBgNVBAcMCeWNl+S6rOW4gjE8MDoG" +
        "A1UECgwz5rGf6IuP55yB55S15a2Q5ZWG5Yqh5pyN5Yqh5Lit5b+D5pyJ6ZmQ6LSj" +
        "5Lu75YWs5Y+4MTwwOgYDVQQLDDPmsZ/oi4/nnIHnlLXlrZDllYbliqHmnI3liqHk" +
        "uK3lv4PmnInpmZDotKPku7vlhazlj7gxFDASBgNVBAMMC0pTQ0FfQ0FfU00yMB4X" +
        "DTE3MDQyNzAwMzkwNVoXDTE4MDQyNzAwMzkwNVowggEdMQ4wDAYDVQRYDAUwMDAw" +
        "MTESMBAGA1UEGgwJ5biC6L6W5Yy6MRswGQYDVQQBDBIzMjAxMTIxOTgxMDUxMTAw" +
        "MTQxDTALBgRVBIhYDAM0NTYxDTALBgRVBIhXDAMxMjMxEjAQBgNVBC0MCXVzZXJD" +
        "ZXJ0MjELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeaxn+iLj+ecgTESMBAGA1UEBwwJ" +
        "5Y2X5Lqs5biCMQwwCgYDVQQLDAMwMDgxHzAdBgkqhkiG9w0BCQEWEDMyNzMyMTU2" +
        "OEBxcS5jb20xITAfBgNVBCoMGOa1i+ivlee9keWFs1NNMueul+azlTEyMzEhMB8G" +
        "A1UEAwwY5rWL6K+V572R5YWzU00y566X5rOVMTIzMFkwEwYHKoZIzj0CAQYIKoEc" +
        "z1UBgi0DQgAEdbrBzy2y8Gz4grOF23iaDipPhRPQRApAMIAP0cAuL1tATFjFuWJs" +
        "pBc1cnCZmsOJnVpV4W7VF8hNOaqv3Tq4NqOCARcwggETMAkGA1UdEwQCMAAwCwYD" +
        "VR0PBAQDAgbAMB0GA1UdDgQWBBRsWSOQDniy75t7UEvTXugwfq0HpzAfBgNVHSME" +
        "GDAWgBT/02hyCI7lesT55ixTRU6RpLF6AzAxBgNVHSUEKjAoBggrBgEFBQcDAgYI" +
        "KwYBBQUHAwgGCCsGAQUFBwMEBggrBgEFBQcDCDA9BgNVHR8ENjA0MDKgMKAuhixo" +
        "dHRwOi8vY3JsLmpzY2EuY29tLmNuL2NybC9TTTJDUkxfRU5USVRZLmNybDBHBggr" +
        "BgEFBQcBAQQ7MDkwNwYIKwYBBQUHMAKBK2h0dHA6Ly8xMC4xMDguNS4yOjg4ODAv" +
        "ZG93bmxvYWQvSlNDQV9DQS5jZXIwCgYIKoEcz1UBg3UDSQAwRgIhALFoMoA1+uO4" +
        "tXfmoyePz1pmv0CWPBgEP1EfDeS6FPitAiEAjHJYq7ryHKULqpRg6ph9r+xUDoWd" +
        "0TPMOQ9jj4XJPO4=");

    private byte[] x25519Cert = Base64.decode(
        "MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX" +
            "N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD" +
            "DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj" +
            "ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg" +
            "BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v" +
            "/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg" +
            "w1AH9efZBw=="
    );

    private PublicKey dudPublicKey = new PublicKey()
    {
        public String getAlgorithm()
        {
            return null;
        }

        public String getFormat()
        {
            return null;
        }

        public byte[] getEncoded()
        {
            return null;
        }

    };

    public String getName()
    {
        return "CertTest";
    }

    public void checkCertificate(
        int id,
        byte[] bytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            Certificate cert = fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();

//            System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    public void checkCertificate(
        int id,
        byte[] bytes,
        PublicKey pubKey)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            Certificate cert = fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();

            cert.verify(pubKey);
            //            System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    public void checkNameCertificate(
        int id,
        byte[] bytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            X509Certificate cert = (X509Certificate)fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();
            if (!cert.getIssuerDN().toString().equals("C=DE,O=DATEV eG,0.2.262.1.10.7.20=1+CN=CA DATEV D03 1:PN"))
            {
                fail(id + " failed - name test.");
            }
            // System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    public void checkKeyUsage(
        int id,
        byte[] bytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            X509Certificate cert = (X509Certificate)fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();

            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage == null || keyUsage.length <= 7 || keyUsage[7])
            {
                fail("error generating cert - key usage wrong.");
            }

            // System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    public void checkSelfSignedCertificate(
        int id,
        byte[] bytes,
        String sigAlgName)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            Certificate cert = fact.generateCertificate(bIn);

            PublicKey k = cert.getPublicKey();

            cert.verify(k);
            if (sigAlgName != null && !sigAlgName.equals(((X509Certificate)cert).getSigAlgName()))
            {
                fail("sigAlgName not matched on certificate: " + sigAlgName);
            }

            // System.out.println(cert);
        }
        catch (TestFailedException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    public void checkCertificateSignedBy(
        int id,
        byte[] certBytes,
        byte[] signingCertBytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(certBytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            Certificate cert = fact.generateCertificate(bIn);

            bIn = new ByteArrayInputStream(signingCertBytes);

            PublicKey k = fact.generateCertificate(bIn).getPublicKey();

            cert.verify(k);

            // System.out.println(cert);
        }
        catch (TestFailedException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    private void checkCRL(
        int id,
        byte[] bytes)
    {
        ByteArrayInputStream bIn;
        String dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            CRL cert = fact.generateCRL(bIn);

            // System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": " + id + " failed - exception " + e.toString(), e);
        }

    }

    private void testForgedSignature()
        throws Exception
    {
        String cert = "MIIBsDCCAVoCAQYwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCQVUxEzARBgNV"
            + "BAgTClF1ZWVuc2xhbmQxGjAYBgNVBAoTEUNyeXB0U29mdCBQdHkgTHRkMSMwIQYD"
            + "VQQDExpTZXJ2ZXIgdGVzdCBjZXJ0ICg1MTIgYml0KTAeFw0wNjA5MTEyMzU4NTVa"
            + "Fw0wNjEwMTEyMzU4NTVaMGMxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpRdWVlbnNs"
            + "YW5kMRowGAYDVQQKExFDcnlwdFNvZnQgUHR5IEx0ZDEjMCEGA1UEAxMaU2VydmVy"
            + "IHRlc3QgY2VydCAoNTEyIGJpdCkwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAn7PD"
            + "hCeV/xIxUg8V70YRxK2A5jZbD92A12GN4PxyRQk0/lVmRUNMaJdq/qigpd9feP/u"
            + "12S4PwTLb/8q/v657QIDAQABMA0GCSqGSIb3DQEBBQUAA0EAbynCRIlUQgaqyNgU"
            + "DF6P14yRKUtX8akOP2TwStaSiVf/akYqfLFm3UGka5XbPj4rifrZ0/sOoZEEBvHQ"
            + "e20sRA==";

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate x509 = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(Base64.decode(cert)));
        try
        {
            x509.verify(x509.getPublicKey());

            fail("forged RSA signature passed");
        }
        catch (Exception e)
        {
            // expected
        }
    }


    private void pemTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        Certificate cert = readPEMCert(cf, PEMData.CERTIFICATE_1);
        if (cert == null)
        {
            fail("PEM cert not read");
        }
        cert = readPEMCert(cf, "-----BEGIN CERTIFICATE-----" + PEMData.CERTIFICATE_2);
        if (cert == null)
        {
            fail("PEM cert with extraneous header not read");
        }
        CRL crl = cf.generateCRL(new ByteArrayInputStream(PEMData.CRL_1.getBytes("US-ASCII")));
        if (crl == null)
        {
            fail("PEM crl not read");
        }
        Collection col = cf.generateCertificates(new ByteArrayInputStream(PEMData.CERTIFICATE_2.getBytes("US-ASCII")));
        if (col.size() != 1 || !col.contains(cert))
        {
            fail("PEM cert collection not right");
        }
        col = cf.generateCRLs(new ByteArrayInputStream(PEMData.CRL_2.getBytes("US-ASCII")));
        if (col.size() != 1 || !col.contains(crl))
        {
            fail("PEM crl collection not right");
        }

        cert = readPEMCert(cf, ecPemCert);

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(cert.getPublicKey().getEncoded());

        AlgorithmParameters ecParams = AlgorithmParameters.getInstance("EC", "BC");

        ecParams.init(pubInfo.getAlgorithm().getParameters().toASN1Primitive().getEncoded());

        if (!new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
            .equals(((ECPublicKey)cert.getPublicKey()).getParameters().getN()))
        {
            fail("N incorrect");
        }
    }

    private static Certificate readPEMCert(CertificateFactory cf, String pemData)
        throws CertificateException, UnsupportedEncodingException
    {
        return cf.generateCertificate(new ByteArrayInputStream(pemData.getBytes("US-ASCII")));
    }

    private void pkcs7Test()
        throws Exception
    {
        ASN1EncodableVector certs = new ASN1EncodableVector();

        certs.add(new ASN1InputStream(CertPathTest.rootCertBin).readObject());
        certs.add(new DERTaggedObject(false, 2, new ASN1InputStream(AttrCertData.attrCert).readObject()));

        ASN1EncodableVector crls = new ASN1EncodableVector();

        crls.add(new ASN1InputStream(CertPathTest.rootCrlBin).readObject());
        SignedData sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null), new DERSet(certs), new DERSet(crls), new DERSet());

        ContentInfo info = new ContentInfo(CMSObjectIdentifiers.signedData, sigData);

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(info.getEncoded()));
        if (cert == null || !areEqual(cert.getEncoded(), certs.get(0).toASN1Primitive().getEncoded()))
        {
            fail("PKCS7 cert not read");
        }
        X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(info.getEncoded()));
        if (crl == null || !areEqual(crl.getEncoded(), crls.get(0).toASN1Primitive().getEncoded()))
        {
            fail("PKCS7 crl not read");
        }

        if (!"SHA256WITHRSA".equals(crl.getSigAlgName()))
        {
            fail("signature ID not matched in CRL: " + crl.getSigAlgName());
        }

        Collection col = cf.generateCertificates(new ByteArrayInputStream(info.getEncoded()));
        if (col.size() != 1 || !col.contains(cert))
        {
            fail("PKCS7 cert collection not right");
        }
        col = cf.generateCRLs(new ByteArrayInputStream(info.getEncoded()));
        if (col.size() != 1 || !col.contains(crl))
        {
            fail("PKCS7 crl collection not right");
        }

        // data with no certificates or CRLs

        sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null), new DERSet(), new DERSet(), new DERSet());

        info = new ContentInfo(CMSObjectIdentifiers.signedData, sigData);

        cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(info.getEncoded()));
        if (cert != null)
        {
            fail("PKCS7 cert present");
        }
        crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(info.getEncoded()));
        if (crl != null)
        {
            fail("PKCS7 crl present");
        }

        // data with absent certificates and CRLS

        sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers.data, null), null, null, new DERSet());

        info = new ContentInfo(CMSObjectIdentifiers.signedData, sigData);

        cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(info.getEncoded()));
        if (cert != null)
        {
            fail("PKCS7 cert present");
        }
        crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(info.getEncoded()));
        if (crl != null)
        {
            fail("PKCS7 crl present");
        }

        //
        // sample message
        //
        InputStream in = new ByteArrayInputStream(pkcs7CrlProblem);
        Collection certCol = cf.generateCertificates(in);

        in.reset();
        Collection crlCol = cf.generateCRLs(in);

        if (crlCol.size() != 0)
        {
            fail("wrong number of CRLs: " + crlCol.size());
        }

        if (certCol.size() != 4)
        {
            fail("wrong number of Certs: " + certCol.size());
        }

        in = new ByteArrayInputStream(pemPKCS7.getBytes("US-ASCII"));
        certCol = cf.generateCertificates(in);

        in.reset();
        crlCol = cf.generateCRLs(in);

        if (crlCol.size() != 0)
        {
            fail("wrong number of CRLs: " + crlCol.size());
        }

        if (certCol.size() != 2)
        {
            fail("wrong number of Certs: " + certCol.size());
        }
    }

    private KeyPair generateLongFixedKeys()
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137", 16),
            new BigInteger("010001", 16));

        RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137", 16),
            new BigInteger("010001", 16),
            new BigInteger("33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325", 16),
            new BigInteger("e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443", 16),
            new BigInteger("b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd", 16),
            new BigInteger("28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979", 16),
            new BigInteger("1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729", 16),
            new BigInteger("27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d", 16));

        KeyFactory fact = KeyFactory.getInstance("RSA", "BC");

        return new KeyPair(fact.generatePublic(pubKeySpec), fact.generatePrivate(privKeySpec));
    }

    private void rfc4491Test()
        throws Exception
    {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate x509 = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gostRFC4491_94));

        x509.verify(x509.getPublicKey(), "BC");

        x509 = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gostRFC4491_2001));

        x509.verify(x509.getPublicKey(), "BC");
    }

    private void testCertificateSerialization()
        throws Exception
    {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        X509Certificate x509 = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(gostRFC4491_2001));

        oOut.writeObject(x509);
        
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        x509 = (X509Certificate)oIn.readObject();

        x509.verify(x509.getPublicKey(), "BC");
    }

    private void checkComparison(byte[] encCert)
        throws NoSuchProviderException, CertificateException
    {
        CertificateFactory bcFact = CertificateFactory.getInstance("X.509", "BC");
        CertificateFactory sunFact = CertificateFactory.getInstance("X.509", "SUN");

        X509Certificate bcCert = (X509Certificate)bcFact.generateCertificate(new ByteArrayInputStream(encCert));
        X509Certificate sunCert = (X509Certificate)sunFact.generateCertificate(new ByteArrayInputStream(encCert));

        if (!bcCert.equals(sunCert) || !sunCert.equals(bcCert))
        {
            fail("BC/Sun equals test failed");
        }

        // Yes, they actually changed hashCode() on a certificate in JDK 1.8...
//        if (bcCert.hashCode() != sunCert.hashCode())
//        {
//            fail("BC/Sun hashCode test failed");
//        }
    }

    private void testV1CRL()
        throws Exception
    {
        byte[] certData = Streams.readAll(this.getClass().getResourceAsStream("ThawteSGCCA.cer"));
        byte[] crlData = Streams.readAll(this.getClass().getResourceAsStream("ThawteSGCCA.crl"));

        // verify CRL with default (JCE) provider
        CertificateFactory jceFac = CertificateFactory.getInstance("X.509");

        X509Certificate jceIssuer = (X509Certificate)
            jceFac.generateCertificate(new ByteArrayInputStream(certData));

        X509CRL jceCRL = (X509CRL)jceFac.generateCRL(new ByteArrayInputStream(crlData));

        jceCRL.verify(jceIssuer.getPublicKey());

        // verify CRL with BC provider
        CertificateFactory bcFac = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate bcIssuer = (X509Certificate)
            bcFac.generateCertificate(new ByteArrayInputStream(certData));

        X509CRL bcCRL = (X509CRL)bcFac.generateCRL(new ByteArrayInputStream(crlData));

        jceCRL.verify(bcIssuer.getPublicKey());

        bcCRL.verify(bcIssuer.getPublicKey());

        if (!"SHA1WITHRSA".equals(bcCRL.getSigAlgName()))
        {
            fail("signature ID not matched in CRL");
        }

        if (!"SHA1WITHRSA".equals(bcIssuer.getSigAlgName()))
        {
            fail("signature ID not matched in certificate");
        }
    }

    private void testCertPathEncAvailableTest()
        throws Exception
    {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");

        Iterator it = certFact.getCertPathEncodings();

        if (!"PkiPath".equals(it.next()))
        {
            fail("available enc 1 wrong");
        }
        if (!"PEM".equals(it.next()))
        {
            fail("available enc 2 wrong");
        }
        if (!"PKCS7".equals(it.next()))
        {
            fail("available enc 3 wrong");
        }

        if (it.hasNext())
        {
            fail("wrong number of encodings");
        }
    }

    private void pemFileTest()
        throws Exception
    {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");

        Collection<Certificate> certs1 = (Collection<Certificate>)certFact.generateCertificates(this.getClass().getResourceAsStream("cert_chain.txt"));

        isTrue("certs wrong <cr><nl>", 2 == certs1.size());

        BufferedInputStream in = new BufferedInputStream(this.getClass().getResourceAsStream("cert_chain.txt"));

        Set certs2 = new HashSet();
        while ((in.available() > 0))
        {
            Certificate c = certFact.generateCertificate(in);

            // this isn't strictly correct with the way it's defined in the Java JavaDoc - need it for backward
            // compatibility.
            if (c != null)
            {
                certs2.add(c);
            }
        }

        isTrue("certs size <cr><nl>", certs1.size() == certs2.size());

        for (Iterator it = certs1.iterator(); it.hasNext(); )
        {
            certs2.remove(it.next());
        }

        isTrue("collection not empty", certs2.isEmpty());
    }

    private void invalidCRLs()
        throws Exception
    {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");

        try
        {
            certFact.generateCRLs(this.getClass().getResourceAsStream("cert_chain.txt"));
            fail("multi crl - no exception");
        }
        catch (CRLException e)
        {
            // ignore
        }
        try
        {
            certFact.generateCRL(this.getClass().getResourceAsStream("cert_chain.txt"));
            fail("single crl - no exception");
        }
        catch (CRLException e)
        {
            // ignore
        }
    }

    private void pemFileTestWithNl()
        throws Exception
    {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");

        Collection<Certificate> certs1 = (Collection<Certificate>)certFact.generateCertificates(this.getClass().getResourceAsStream("cert_chain_nl.txt"));

        isTrue("certs wrong <nl>", 2 == certs1.size());

        BufferedInputStream in = new BufferedInputStream(this.getClass().getResourceAsStream("cert_chain_nl.txt"));

        Set certs2 = new HashSet();
        while ((in.available() > 0))
        {
            Certificate c = certFact.generateCertificate(in);

            // this isn't strictly correct with the way it's defined in the Java JavaDoc - need it for backward
            // compatibility.
            if (c != null)
            {
                certs2.add(c);
            }
        }

        isTrue("certs size <nl>", certs1.size() == certs2.size());

        for (Iterator it = certs1.iterator(); it.hasNext(); )
        {
            certs2.remove(it.next());
        }

        isTrue("collection not empty", certs2.isEmpty());
    }

    public void performTest()
        throws Exception
    {
        testV1CRL();

        checkCertificate(1, cert1);
        checkCertificate(2, cert2);
        checkCertificate(3, cert3);
        checkCertificate(4, cert4);
        checkCertificate(5, cert5);
        checkCertificate(6, oldEcdsa);
        checkCertificate(7, cert7);
        checkCertificate(8, sm_sign);

        System.setProperty("org.bouncycastle.x509.allow_non-der_tbscert", "true");

        checkCertificate(9, x25519Cert,
            KeyFactory.getInstance("EdDSA").generatePublic(new X509EncodedKeySpec(Base64.decode("MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE="))));

        System.setProperty("org.bouncycastle.x509.allow_non-der_tbscert", "false");

        try
        {
            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            Certificate cert = fact.generateCertificate(new ByteArrayInputStream(x25519Cert));

            cert.verify(KeyFactory.getInstance("EdDSA").generatePublic(new X509EncodedKeySpec(Base64.decode("MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE="))));

            fail("no exception");
        }
        catch (SignatureException e)
        {
            isEquals("certificate does not verify with supplied key", e.getMessage());
        }
        
        checkComparison(cert1);

        checkKeyUsage(8, keyUsage);
        checkSelfSignedCertificate(9, uncompressedPtEC, "ECDSA");
        checkNameCertificate(10, nameCert);

        checkSelfSignedCertificate(11, probSelfSignedCert, "SHA1WITHRSA");
        checkSelfSignedCertificate(12, gostCA1, "GOST3410");
        checkSelfSignedCertificate(13, gostCA2, "GOST3411WITHECGOST3410");
        checkSelfSignedCertificate(14, gost341094base, "GOST3410");
        checkSelfSignedCertificate(15, gost34102001base, "GOST3411WITHECGOST3410");
        checkSelfSignedCertificate(16, gost341094A, "GOST3410");
        checkSelfSignedCertificate(17, gost341094B, "GOST3410");
        checkSelfSignedCertificate(18, gost34102001A, "GOST3411WITHECGOST3410");

        try
        {
            checkSelfSignedCertificate(19, uaczo1, "GOST3411WITHDSTU4145LE");
            checkSelfSignedCertificate(20, uaczo2, "GOST3411WITHDSTU4145LE");
            checkSelfSignedCertificate(21, uaczo3, "GOST3411WITHDSTU4145LE");
            checkSelfSignedCertificate(22, uaczo4, "GOST3411WITHDSTU4145LE");
        }
        catch (Exception e)
        {
            if (e instanceof NoSuchAlgorithmException)
            {
                // ignore - only valid for jdk1.5+
            }
        }

        checkSelfSignedCertificate(23, sha3Cert, "SHA3-256withRSAandMGF1");
        checkSelfSignedCertificate(24, sm_root, "SM3WITHSM2");

        checkCertificateSignedBy(1, sm_sign, sm_root);
        checkCertificateSignedBy(2, sm_ca1, sm_root1);
        checkCertificateSignedBy(3, sm_sign1, sm_root1);
        
        checkCRL(1, crl1);

        pemTest();
        pemFileTest();
        pemFileTestWithNl();
        pkcs7Test();
        rfc4491Test();

        invalidCRLs();

        testForgedSignature();
        testCertificateSerialization();

        checkCertificate(18, emptyDNCert);

        testCertPathEncAvailableTest();
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertTest());
    }
}
