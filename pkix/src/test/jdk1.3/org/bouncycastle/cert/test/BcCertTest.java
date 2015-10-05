package org.bouncycastle.cert.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CRL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509v1CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.cert.test.PEMData;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

public class BcCertTest
    extends TestCase
{
    DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
    DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

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
            "MIIEFjCCA3+gAwIBAgIEdS8BozANBgkqhkiG9w0BAQUFADBKMQswCQYDVQQGEwJE"+
            "RTERMA8GA1UEChQIREFURVYgZUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRQ0Eg"+
            "REFURVYgRDAzIDE6UE4wIhgPMjAwMTA1MTAxMDIyNDhaGA8yMDA0MDUwOTEwMjI0"+
            "OFowgYQxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIFAZCYXllcm4xEjAQBgNVBAcUCU7I"+
            "dXJuYmVyZzERMA8GA1UEChQIREFURVYgZUcxHTAbBgNVBAUTFDAwMDAwMDAwMDA4"+
            "OTU3NDM2MDAxMR4wHAYDVQQDFBVEaWV0bWFyIFNlbmdlbmxlaXRuZXIwgaEwDQYJ"+
            "KoZIhvcNAQEBBQADgY8AMIGLAoGBAJLI/LJLKaHoMk8fBECW/od8u5erZi6jI8Ug"+
            "C0a/LZyQUO/R20vWJs6GrClQtXB+AtfiBSnyZOSYzOdfDI8yEKPEv8qSuUPpOHps"+
            "uNCFdLZF1vavVYGEEWs2+y+uuPmg8q1oPRyRmUZ+x9HrDvCXJraaDfTEd9olmB/Z"+
            "AuC/PqpjAgUAwAAAAaOCAcYwggHCMAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/BAUD"+
            "AwdAADAxBgNVHSAEKjAoMCYGBSskCAEBMB0wGwYIKwYBBQUHAgEWD3d3dy56cy5k"+
            "YXRldi5kZTApBgNVHREEIjAggR5kaWV0bWFyLnNlbmdlbmxlaXRuZXJAZGF0ZXYu"+
            "ZGUwgYQGA1UdIwR9MHuhc6RxMG8xCzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1"+
            "bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0"+
            "MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjVSLUNBIDE6UE6CBACm8LkwDgYHAoIG"+
            "AQoMAAQDAQEAMEcGA1UdHwRAMD4wPKAUoBKGEHd3dy5jcmwuZGF0ZXYuZGWiJKQi"+
            "MCAxCzAJBgNVBAYTAkRFMREwDwYDVQQKFAhEQVRFViBlRzAWBgUrJAgDBAQNMAsT"+
            "A0VVUgIBBQIBATAdBgNVHQ4EFgQUfv6xFP0xk7027folhy+ziZvBJiwwLAYIKwYB"+
            "BQUHAQEEIDAeMBwGCCsGAQUFBzABhhB3d3cuZGlyLmRhdGV2LmRlMA0GCSqGSIb3"+
            "DQEBBQUAA4GBAEOVX6uQxbgtKzdgbTi6YLffMftFr2mmNwch7qzpM5gxcynzgVkg"+
            "pnQcDNlm5AIbS6pO8jTCLfCd5TZ5biQksBErqmesIl3QD+VqtB+RNghxectZ3VEs"+
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

    private AsymmetricKeyParameter dudPublicKey = new AsymmetricKeyParameter(true)
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
        int     id,
        byte[]  bytes)
    {
        try
        {
            X509CertificateHolder certHldr = new X509CertificateHolder(bytes);

            SubjectPublicKeyInfo k = certHldr.getSubjectPublicKeyInfo();
            // System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(e.toString());
        }
    }
            /*
    public void checkNameCertificate(
        int     id,
        byte[]  bytes)
    {
        ByteArrayInputStream    bIn;
        String                  dump = "";

        try
        {
            bIn = new ByteArrayInputStream(bytes);

            CertificateFactory  fact = CertificateFactory.getInstance("X.509", "LKBX-BC");

            X509Certificate cert = (X509Certificate)fact.generateCertificate(bIn);

            AsymmetricKeyParameter    k = cert.getAsymmetricKeyParameter();
            if (!cert.getIssuerDN().toString().equals("C=DE,O=DATEV eG,0.2.262.1.10.7.20=1+CN=CA DATEV D03 1:PN"))
            {
                fail(id + " failed - name test.");
            }
            // System.out.println(cert);
        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": "+ id + " failed - exception " + e.toString(), e);
        }

    }
     */
    public void checkKeyUsage(
        int     id,
        byte[]  bytes)
        throws IOException
    {

            X509CertificateHolder certHld = new X509CertificateHolder(bytes);

            if ((DERBitString.getInstance(certHld.getExtension(Extension.keyUsage).getParsedValue()).getBytes()[0] & 0x01) != 0)
            {
                fail("error generating cert - key usage wrong.");
            }


    }


    public void checkSelfSignedCertificate(
        int     id,
        byte[]  bytes)
        throws OperatorCreationException, IOException, CertException
    {

            X509CertificateHolder certHolder = new X509CertificateHolder(bytes);

            assertTrue(certHolder.isSignatureValid(new BcRSAContentVerifierProviderBuilder(digAlgFinder).build(certHolder)));


    }

    /**
     * we generate a self signed certificate for the sake of testing - RSA
     */
    public void checkCreation1()
        throws Exception
    {
        //
        // a sample key pair.
        //
        AsymmetricKeyParameter pubKey = new RSAKeyParameters(
            false,
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        AsymmetricKeyParameter privKey = new RSAPrivateCrtKeyParameters(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

        //
        // distinguished name table.
        //
        X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);

        builder.addRDN(RFC4519Style.c, "AU");
        builder.addRDN(RFC4519Style.o, "The Legion of the Bouncy Castle");
        builder.addRDN(RFC4519Style.l, "Melbourne");
        builder.addRDN(RFC4519Style.st, "Victoria");
        builder.addRDN(PKCSObjectIdentifiers.pkcs_9_at_emailAddress, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3 - without extensions
        //
        AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA256WithRSAEncryption");
        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlg, digAlgFinder.find(sigAlg)).build(privKey);
        X509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000),builder.build(), pubKey);

        X509CertificateHolder certH = certGen.build(sigGen);

        assertTrue(certH.isValidOn(new Date()));

        ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(pubKey);

        assertTrue(certH.isSignatureValid(contentVerifierProvider));

        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certH);
        Set dummySet = cert.getNonCriticalExtensionOIDs();
        if (dummySet != null)
        {
            fail("non-critical oid set should be null");
        }
        dummySet = cert.getCriticalExtensionOIDs();
        if (dummySet != null)
        {
            fail("critical oid set should be null");
        }

        //
        // create the certificate - version 3 - with extensions
        //
        sigGen = new BcRSAContentSignerBuilder(sigAlgFinder.find("MD5WithRSA"), digAlgFinder.find(sigAlgFinder.find("MD5withRSA"))).build(privKey);
        certGen = new BcX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1)
            , new Date(System.currentTimeMillis() - 50000)
            , new Date(System.currentTimeMillis() + 50000)
            , builder.build()
            , pubKey)
            .addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new KeyUsage(KeyUsage.encipherOnly))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        X509CertificateHolder certHolder = certGen.build(sigGen);

        assertTrue(certHolder.isValidOn(new Date()));

        contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(digAlgFinder).build(pubKey);
        if (!certHolder.isSignatureValid(contentVerifierProvider))
        {
            fail("signature test failed");
        }

        ByteArrayInputStream   bIn = new ByteArrayInputStream(certHolder.getEncoded());
        CertificateFactory     certFact = CertificateFactory.getInstance("X.509");

        cert = (X509Certificate)certFact.generateCertificate(bIn);

        if (!cert.getKeyUsage()[7])
        {
            fail("error generating cert - key usage wrong.");
        }

        // System.out.println(cert);

        //
        // create the certificate - version 1
        //
        sigGen = new BcRSAContentSignerBuilder(sigAlgFinder.find("MD5WithRSA"), digAlgFinder.find(sigAlgFinder.find("MD5withRSA"))).build(privKey);
        X509v1CertificateBuilder certGen1 = new BcX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000),new Date(System.currentTimeMillis() + 50000),builder.build(),pubKey);

        cert = new JcaX509CertificateConverter().getCertificate(certGen1.build(sigGen));

        assertTrue(certHolder.isValidOn(new Date()));

        contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(pubKey);

        assertTrue(certHolder.isSignatureValid(contentVerifierProvider));

        bIn = new ByteArrayInputStream(cert.getEncoded());
        certFact = CertificateFactory.getInstance("X.509");

        cert = (X509Certificate)certFact.generateCertificate(bIn);

        // System.out.println(cert);
        if (!cert.getIssuerDN().equals(cert.getSubjectDN()))
        {
            fail("name comparison fails");
        }

//
        // a lightweight key pair.
        //
        RSAKeyParameters lwPubKey = new RSAKeyParameters(
            false,
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        RSAPrivateCrtKeyParameters lwPrivKey = new RSAPrivateCrtKeyParameters(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

        //
        // distinguished name table.
        //
        builder = new X500NameBuilder(RFC4519Style.INSTANCE);

        builder.addRDN(RFC4519Style.c, "AU");
        builder.addRDN(RFC4519Style.o, "The Legion of the Bouncy Castle");
        builder.addRDN(RFC4519Style.l, "Melbourne");
        builder.addRDN(RFC4519Style.st, "Victoria");
        builder.addRDN(PKCSObjectIdentifiers.pkcs_9_at_emailAddress, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3 - without extensions
        //
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSAEncryption");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(lwPrivKey);
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(lwPubKey);
        certGen = new X509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubInfo);

        certHolder = certGen.build(sigGen);

        assertTrue(certHolder.isValidOn(new Date()));

        contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(lwPubKey);

        assertTrue(certHolder.isSignatureValid(contentVerifierProvider));

        if (!certHolder.isSignatureValid(contentVerifierProvider))
        {
            fail("lw sig verification failed");
        }
    }

    /**
     * we generate a self signed certificate for the sake of testing - DSA
     */
    public void checkCreation2()
        throws Exception
    {
        //
        // set up the keys
        //
        AsymmetricKeyParameter          privKey;
        AsymmetricKeyParameter          pubKey;

        AsymmetricCipherKeyPairGenerator kpg = new DSAKeyPairGenerator();
        BigInteger              r = new BigInteger("68076202252361894315274692543577577550894681403");
        BigInteger              s = new BigInteger("1089214853334067536215539335472893651470583479365");
        DSAParametersGenerator pGen = new DSAParametersGenerator();

        pGen.init(512, 80, new SecureRandom());

        DSAParameters params = pGen.generateParameters();
        DSAKeyGenerationParameters genParam = new DSAKeyGenerationParameters(new SecureRandom(), params);

        kpg.init(genParam);

        AsymmetricCipherKeyPair pair = kpg.generateKeyPair();

        privKey = (AsymmetricKeyParameter)pair.getPrivate();
        pubKey = (AsymmetricKeyParameter)pair.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // extensions
        //

        //
        // create the certificate - version 3
        //
        AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA1withDSA");
        AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);

        ContentSigner sigGen = new BcDSAContentSignerBuilder(sigAlgId, digAlgId).build(privKey);
        X509v3CertificateBuilder  certGen = new BcX509v3CertificateBuilder(builder.build(),BigInteger.valueOf(1),new Date(System.currentTimeMillis() - 50000),new Date(System.currentTimeMillis() + 50000),builder.build(),pubKey);


        X509CertificateHolder cert = certGen.build(sigGen);

        assertTrue(cert.isValidOn(new Date()));

        assertTrue(cert.isSignatureValid(new BcDSAContentVerifierProviderBuilder(digAlgFinder).build(pubKey)));


        //
        // create the certificate - version 1
        //
        sigAlgId = sigAlgFinder.find("SHA1withDSA");
        digAlgId = digAlgFinder.find(sigAlgId);

        sigGen = new BcDSAContentSignerBuilder(sigAlgId, digAlgId).build(privKey);
        X509v1CertificateBuilder  certGen1 = new BcX509v1CertificateBuilder(builder.build(),BigInteger.valueOf(1),new Date(System.currentTimeMillis() - 50000),new Date(System.currentTimeMillis() + 50000),builder.build(),pubKey);

        cert = certGen1.build(sigGen);

        assertTrue(cert.isValidOn(new Date()));

        assertTrue(cert.isSignatureValid(new BcDSAContentVerifierProviderBuilder(digAlgFinder).build(pubKey)));

        AsymmetricKeyParameter certPubKey = PublicKeyFactory.createKey(cert.getSubjectPublicKeyInfo());

        assertTrue(cert.isSignatureValid(new BcDSAContentVerifierProviderBuilder(digAlgFinder).build(certPubKey)));

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509");

        X509Certificate x509cert = (X509Certificate)fact.generateCertificate(bIn);

            //System.out.println(cert);
    }

    private X500NameBuilder createStdBuilder()
    {
        X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);

        builder.addRDN(RFC4519Style.c, "AU");
        builder.addRDN(RFC4519Style.o, "The Legion of the Bouncy Castle");
        builder.addRDN(RFC4519Style.l, "Melbourne");
        builder.addRDN(RFC4519Style.st, "Victoria");
        builder.addRDN(PKCSObjectIdentifiers.pkcs_9_at_emailAddress, "feedback-crypto@bouncycastle.org");

        return builder;
    }

    private void checkCRL(
        int     id,
        byte[]  bytes)
    {
        String                  dump = "";

        try
        {
            X509CRLHolder crlHolder = new X509CRLHolder(bytes);

        }
        catch (Exception e)
        {
            fail(dump + Strings.lineSeparator() + getName() + ": "+ id + " failed - exception " + e.toString());
        }

    }

    public void checkCRLCreation1()
        throws Exception
    {
        AsymmetricCipherKeyPairGenerator kpg = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters genParam = new RSAKeyGenerationParameters(
                                            BigInteger.valueOf(0x1001), new SecureRandom(), 1024, 25);

        kpg.init(genParam);

        AsymmetricCipherKeyPair pair = kpg.generateKeyPair();
        Date                 now = new Date();

        X509v2CRLBuilder     crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now);

        BcX509ExtensionUtils extFact = new BcX509ExtensionUtils(new SHA1DigestCalculator());

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        crlGen.addCRLEntry(BigInteger.ONE, now, CRLReason.privilegeWithdrawn);

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extFact.createAuthorityKeyIdentifier(pair.getPublic()));

        AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA256withRSAEncryption");
        AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);

        X509CRLHolder crl = crlGen.build(new BcRSAContentSignerBuilder(sigAlg, digAlg).build(pair.getPrivate()));

        if (!crl.getIssuer().equals(new X500Name("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        Extension authExt = crl.getExtension(Extension.authorityKeyIdentifier);

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(authExt.getParsedValue());

        X509CRLEntryHolder entry = crl.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        Extension ext = entry.getExtension(Extension.reasonCode);

        if (ext != null)
        {
            ASN1Enumerated reasonCode = ASN1Enumerated.getInstance(ext.getParsedValue());

            if (reasonCode.getValue().intValue() != CRLReason.privilegeWithdrawn)
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }
    }

    public void checkCRLCreation2()
        throws Exception
    {
        AsymmetricCipherKeyPairGenerator kpg = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters genParam = new RSAKeyGenerationParameters(
                                            BigInteger.valueOf(0x1001), new SecureRandom(), 1024, 25);

        kpg.init(genParam);

        AsymmetricCipherKeyPair pair = kpg.generateKeyPair();
        Date                 now = new Date();

        X509v2CRLBuilder     crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        extGen.addExtension(Extension.reasonCode, false, crlReason);

        BcX509ExtensionUtils extFact = new BcX509ExtensionUtils(new SHA1DigestCalculator());

        crlGen.addCRLEntry(BigInteger.ONE, now, extGen.generate());

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extFact.createAuthorityKeyIdentifier((AsymmetricKeyParameter)pair.getPublic()));

        AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA256withRSAEncryption");
        AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);

        X509CRLHolder crlHolder = crlGen.build(new BcRSAContentSignerBuilder(sigAlg, digAlg).build((AsymmetricKeyParameter)pair.getPrivate()));

        if (!crlHolder.getIssuer().equals(new X500Name("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        Extension authExt = crlHolder.getExtension(Extension.authorityKeyIdentifier);

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(authExt.getParsedValue());

        X509CRLEntryHolder entry = crlHolder.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        Extension ext = entry.getExtension(Extension.reasonCode);

        if (ext != null)
        {
            ASN1Enumerated   reasonCode = ASN1Enumerated.getInstance(ext.getParsedValue());

            if (reasonCode.getValue().intValue() != CRLReason.privilegeWithdrawn)
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }
    }

    public void checkCRLCreation3()
        throws Exception
    {
        AsymmetricCipherKeyPairGenerator kpg = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters genParam = new RSAKeyGenerationParameters(
                                            BigInteger.valueOf(0x1001), new SecureRandom(), 1024, 25);

        kpg.init(genParam);

        AsymmetricCipherKeyPair pair = kpg.generateKeyPair();
        Date                 now = new Date();
        X509v2CRLBuilder     crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        extGen.addExtension(Extension.reasonCode, false, crlReason);

        BcX509ExtensionUtils extFact = new BcX509ExtensionUtils(new SHA1DigestCalculator());

        Extensions entryExtensions = extGen.generate();

        crlGen.addCRLEntry(BigInteger.ONE, now, entryExtensions);

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extFact.createAuthorityKeyIdentifier((AsymmetricKeyParameter)pair.getPublic()));

        AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA256withRSAEncryption");
        AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);

        X509CRLHolder crlHolder = crlGen.build(new BcRSAContentSignerBuilder(sigAlg, digAlg).build((AsymmetricKeyParameter)pair.getPrivate()));

        if (!crlHolder.getIssuer().equals(new X500Name("CN=Test CA")))
        {
            fail("failed CRL issuer test");
        }

        Extension authExt = crlHolder.getExtension(Extension.authorityKeyIdentifier);

        if (authExt == null)
        {
            fail("failed to find CRL extension");
        }

        AuthorityKeyIdentifier authId = AuthorityKeyIdentifier.getInstance(authExt.getParsedValue());

        X509CRLEntryHolder entry = crlHolder.getRevokedCertificate(BigInteger.ONE);

        if (entry == null)
        {
            fail("failed to find CRL entry");
        }

        if (!entry.getSerialNumber().equals(BigInteger.ONE))
        {
            fail("CRL cert serial number does not match");
        }

        if (!entry.hasExtensions())
        {
            fail("CRL entry extension not found");
        }

        Extension  ext = entry.getExtension(Extension.reasonCode);

        if (ext != null)
        {
            ASN1Enumerated   reasonCode = ASN1Enumerated.getInstance(ext.getParsedValue());

            if (reasonCode.getValue().intValue() != CRLReason.privilegeWithdrawn)
            {
                fail("CRL entry reasonCode wrong");
            }
        }
        else
        {
            fail("CRL entry reasonCode not found");
        }

        //
        // check loading of existing CRL
        //
        now = new Date();
        crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now);

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        crlGen.addCRL(crlHolder);

        crlGen.addCRLEntry(BigInteger.valueOf(2), now, entryExtensions);

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extFact.createAuthorityKeyIdentifier(pair.getPublic()));

        crlHolder = crlGen.build(new BcRSAContentSignerBuilder(sigAlg, digAlg).build(pair.getPrivate()));

        int     count = 0;
        boolean oneFound = false;
        boolean twoFound = false;

        Iterator it = crlHolder.getRevokedCertificates().iterator();
        while (it.hasNext())
        {
            X509CRLEntryHolder crlEnt = (X509CRLEntryHolder)it.next();

            if (crlEnt.getSerialNumber().intValue() == 1)
            {
                oneFound = true;
                Extension extn = crlEnt.getExtension(Extension.reasonCode);

                if (extn != null)
                {
                    ASN1Enumerated reasonCode = ASN1Enumerated.getInstance(extn.getParsedValue());

                    if (reasonCode.getValue().intValue() != CRLReason.privilegeWithdrawn)
                    {
                        fail("CRL entry reasonCode wrong on recheck");
                    }
                }
                else
                {
                    fail("CRL entry reasonCode not found on recheck");
                }
            }
            else if (crlEnt.getSerialNumber().intValue() == 2)
            {
                twoFound = true;
            }

            count++;
        }

        if (count != 2)
        {
            fail("wrong number of CRLs found, got: " + count);
        }

        if (!oneFound || !twoFound)
        {
            fail("wrong CRLs found in copied list");
        }

        //
        // check factory read back
        //
        CertificateFactory cFact = CertificateFactory.getInstance("X.509");

        X509CRL readCrl = (X509CRL)cFact.generateCRL(new ByteArrayInputStream(crlHolder.getEncoded()));

        if (readCrl == null)
        {
            fail("crl not returned!");
        }

        Collection col = cFact.generateCRLs(new ByteArrayInputStream(crlHolder.getEncoded()));

        if (col.size() != 1)
        {
            fail("wrong number of CRLs found in collection");
        }
    }

    public void checkCreation5()
        throws Exception
    {
        //
        // a sample key pair.
        //
        AsymmetricKeyParameter pubKey = new RSAKeyParameters(
            false,
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        AsymmetricKeyParameter privKey = new RSAPrivateCrtKeyParameters(
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

        //
        // distinguished name table.
        //
        X500NameBuilder builder = createStdBuilder();

        //
        // create base certificate - version 3
        //
        AlgorithmIdentifier sigAlg = sigAlgFinder.find("MD5WithRSA");
        AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(privKey);
        ASN1ObjectIdentifier extOid = new ASN1ObjectIdentifier("2.5.29.37");
        X509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(builder.build(),BigInteger.valueOf(1),new Date(System.currentTimeMillis() - 50000),new Date(System.currentTimeMillis() + 50000),builder.build(),pubKey)
            .addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
            new KeyUsage(KeyUsage.encipherOnly))
            .addExtension(extOid, true,
            new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
            new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        X509CertificateHolder baseCert = certGen.build(sigGen);

        //
        // copy certificate
        //

        certGen = new BcX509v3CertificateBuilder(builder.build(),BigInteger.valueOf(1),new Date(System.currentTimeMillis() - 50000),new Date(System.currentTimeMillis() + 50000),builder.build(),pubKey)
            .copyAndAddExtension(new ASN1ObjectIdentifier("2.5.29.15"), true, baseCert)
            .copyAndAddExtension(extOid, false, baseCert);

        X509CertificateHolder cert = certGen.build(sigGen);

        assertTrue(cert.isValidOn(new Date()));

        assertTrue(cert.isSignatureValid(new BcRSAContentVerifierProviderBuilder(digAlgFinder).build(pubKey)));

        if (!baseCert.getExtension(new ASN1ObjectIdentifier("2.5.29.15")).equals(cert.getExtension(new ASN1ObjectIdentifier("2.5.29.15"))))
        {
            fail("2.5.29.15 differs");
        }

        assertTrue(baseCert.getExtension(extOid).getExtnId().equals(cert.getExtension(extOid).getExtnId()));
        assertFalse(baseCert.getExtension(extOid).isCritical() == cert.getExtension(extOid).isCritical());
        if (!baseCert.getExtension(extOid).getParsedValue().equals(cert.getExtension(extOid).getParsedValue()))
        {
            fail("2.5.29.37 differs");
        }

        //
        // exception test
        //

        try
        {
            certGen.copyAndAddExtension(new ASN1ObjectIdentifier("2.5.99.99"), true, baseCert);

            fail("exception not thrown on dud extension copy");
        }
        catch (NullPointerException e)
        {
            // expected
        }

//        try
//        {
//            certGen.setPublicKey(dudPublicKey);
//
//            certGen.generate(privKey, BC);
//
//            fail("key without encoding not detected in v3");
//        }
//        catch (IllegalArgumentException e)
//        {
//            // expected
//        }

    }

    public void testForgedSignature()
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

        X509CertificateHolder hldr = new X509CertificateHolder(Base64.decode(cert));

        assertFalse(hldr.isSignatureValid(new BcRSAContentVerifierProviderBuilder(digAlgFinder).build(hldr)));
    }

    private void pemTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate cert = readPEMCert(cf, PEMData.CERTIFICATE_1);
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
    }

    private static X509Certificate readPEMCert(CertificateFactory cf, String pemData)
        throws CertificateException, UnsupportedEncodingException
    {
        return (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(pemData.getBytes("US-ASCII")));
    }

    private void createPSSCert(String algorithm)
        throws Exception
    {
        AsymmetricCipherKeyPair pair = generateLongFixedKeys();

        AsymmetricKeyParameter privKey = (AsymmetricKeyParameter)pair.getPrivate();
        AsymmetricKeyParameter pubKey = (AsymmetricKeyParameter)pair.getPublic();

        //
        // distinguished name table.
        //

        X500NameBuilder builder = createStdBuilder();

        //
        // create base certificate - version 3
        //
        BcX509ExtensionUtils extFact = new BcX509ExtensionUtils(new SHA1DigestCalculator());

        AlgorithmIdentifier sigAlgId = sigAlgFinder.find(algorithm);
        AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privKey);
        BcX509v3CertificateBuilder  certGen = new BcX509v3CertificateBuilder(builder.build(),BigInteger.valueOf(1),
        new Date(System.currentTimeMillis() - 50000),new Date(System.currentTimeMillis() + 50000),builder.build(),pubKey);

        certGen.addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
            new KeyUsage(KeyUsage.encipherOnly));
        certGen.addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
            new DERSequence(KeyPurposeId.anyExtendedKeyUsage));
        certGen.addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
            new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        certGen.addExtension(Extension.authorityKeyIdentifier, true, extFact.createAuthorityKeyIdentifier(pubKey));

        X509CertificateHolder baseCert = certGen.build(sigGen);

        assertTrue(baseCert.isSignatureValid(new BcRSAContentVerifierProviderBuilder(digAlgFinder).build(pubKey)));
    }

    private AsymmetricCipherKeyPair generateLongFixedKeys()
    {
        RSAKeyParameters pubKeySpec = new RSAKeyParameters(
            false,
            new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",16),
            new BigInteger("010001",16));

        RSAKeyParameters privKeySpec = new RSAPrivateCrtKeyParameters(
            new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",16),
            new BigInteger("010001",16),
            new BigInteger("33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325",16),
            new BigInteger("e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443",16),
            new BigInteger("b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd",16),
            new BigInteger("28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979",16),
            new BigInteger("1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729",16),
            new BigInteger("27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d",16));

        return new AsymmetricCipherKeyPair(pubKeySpec, privKeySpec);
    }

    public void testNullDerNullCert()
        throws Exception
    {
        AsymmetricCipherKeyPair pair = generateLongFixedKeys();
        AsymmetricKeyParameter pubKey = (AsymmetricKeyParameter)pair.getPublic();
        AsymmetricKeyParameter privKey = (AsymmetricKeyParameter)pair.getPrivate();

        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

        AlgorithmIdentifier sigAlgId = sigAlgFinder.find("MD5withRSA");
        AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privKey);
        BcX509v3CertificateBuilder  certGen = new BcX509v3CertificateBuilder(new X500Name("CN=Test"),BigInteger.valueOf(1),new Date(System.currentTimeMillis() - 50000),new Date(System.currentTimeMillis() + 50000),new X500Name("CN=Test"),pubKey);
        X509CertificateHolder cert = certGen.build(sigGen);

        Certificate struct = Certificate.getInstance(cert.getEncoded());

        ASN1Object tbsCertificate = struct.getTBSCertificate();
        AlgorithmIdentifier sig = struct.getSignatureAlgorithm();

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCertificate);
        v.add(new AlgorithmIdentifier(sig.getAlgorithm()));
        v.add(struct.getSignature());

        // verify
        ByteArrayInputStream    bIn;
        String                  dump = "";

        bIn = new ByteArrayInputStream(new DERSequence(v).getEncoded());

        cert = new X509CertificateHolder(new DERSequence(v).getEncoded());

        assertTrue(cert.isSignatureValid(new BcRSAContentVerifierProviderBuilder(digAlgFinder).build(pubKey)));
    }

    public void testCertificates()
        throws Exception
    {
        checkCertificate(1, cert1);
        checkCertificate(2, cert2);
        checkCertificate(3, cert3);
        checkCertificate(4, cert4);
        checkCertificate(5, cert5);
        //checkCertificate(7, cert7);

        checkKeyUsage(8, keyUsage);

        checkSelfSignedCertificate(11, probSelfSignedCert);

        checkCRL(1, crl1);

        checkCreation1();
        checkCreation2();
        checkCreation5();

        createPSSCert("SHA1withRSAandMGF1");
        createPSSCert("SHA224withRSAandMGF1");
        createPSSCert("SHA256withRSAandMGF1");
        createPSSCert("SHA384withRSAandMGF1");

        checkCRLCreation1();
        checkCRLCreation2();
        checkCRLCreation3();

        pemTest();

        checkCertificate(18, emptyDNCert);
    }
}
