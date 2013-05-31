package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.X509CRLStoreSelector;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.bouncycastle.x509.X509Store;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

public class X509LDAPCertStoreTest extends SimpleTest
{
    private static final byte cert1[] = Base64
        .decode("MIIDyTCCAzKgAwIBAgIEL64+8zANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJE"
            + "RTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEoMAwGBwKCBgEKBxQTATEw"
            + "GAYDVQQDFBFUVEMgVGVzdCBDQSAxMTpQTjAeFw0wMzAzMjUxNDM1MzFaFw0wNjAz"
            + "MjUxNDM1MzFaMGIxCzAJBgNVBAYTAkRFMRswGQYDVQQKDBJHRlQgU29sdXRpb25z"
            + "IEdtYkgxEjAQBgNVBAsMCUhZUEFSQ0hJVjEWMBQGA1UEAwwNRGllZ2UsIFNpbW9u"
            + "ZTEKMAgGA1UEBRMBMTCBoDANBgkqhkiG9w0BAQEFAAOBjgAwgYoCgYEAiEYsFbs4"
            + "FesQpMjBkzJB92c0p8tJ02nbCNA5l17VVbbrv6/twnQHW4kgA+9lZlXfzI8iunT1"
            + "KuiwVupWObHgFaGPkelIN/qIbuwbQzh7T+IUKdKETE12Lc+xk9YvQ6mJVgosmwpr"
            + "nMMjezymh8DjPhe7MC7/H3AotrHVNM3mEJcCBEAAAIGjggGWMIIBkjAfBgNVHSME"
            + "GDAWgBTQc8wTeltcAM3iTE63fk/wTA+IJTAdBgNVHQ4EFgQUq6ChBvXPiqhMHLS3"
            + "kiKpSeGWDz4wDgYDVR0PAQH/BAQDAgQwMB8GA1UdEQQYMBaBFHNpbW9uZS5kaWVn"
            + "ZUBnZnQuY29tMIHoBgNVHR8EgeAwgd0wgdqgaqBohjVsZGFwOi8vcGtzbGRhcC50"
            + "dHRjLmRlOjM4OS9jPWRlLG89RGV1dHNjaGUgVGVsZWtvbSBBR4YvaHR0cDovL3d3"
            + "dy50dHRjLmRlL3RlbGVzZWMvc2VydmxldC9kb3dubG9hZF9jcmyibKRqMGgxCzAJ"
            + "BgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMTswDAYHAoIG"
            + "AQoHFBMBMTArBgNVBAMUJFRlbGVTZWMgRGlyZWN0b3J5IFNlcnZpY2UgU2lnRyAx"
            + "MDpQTjA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly93d3cudHR0"
            + "Yy5kZS9vY3NwcjANBgkqhkiG9w0BAQUFAAOBgQBCPudAtrP9Bx7GRhHQgYS6kaoN"
            + "vYb/yDss86pyn0uiFuwT+mT1popcAfxPo2yxL0jqqlsDNFBC2hJob5rjihsKPmqV"
            + "rSaW0VJu/zBihsX7hLKOVMf5gvUYMS5ulq/bp8jOj8a+5SmxVY+WWZVFghWjISse"
            + "T3WABdTS9S3zjnQiyg==");

    private static final byte[] directCRL = Base64
        .decode("MIIGXTCCBckCAQEwCgYGKyQDAwECBQAwdDELMAkGA1UEBhMCREUxHDAaBgNVBAoU"
            + "E0RldXRzY2hlIFRlbGVrb20gQUcxFzAVBgNVBAsUDlQtVGVsZVNlYyBUZXN0MS4w"
            + "DAYHAoIGAQoHFBMBMTAeBgNVBAMUF1QtVGVsZVNlYyBUZXN0IERJUiA4OlBOFw0w"
            + "NjA4MDQwODQ1MTRaFw0wNjA4MDQxNDQ1MTRaMIIElTAVAgQvrj/pFw0wMzA3MjIw"
            + "NTQxMjhaMBUCBC+uP+oXDTAzMDcyMjA1NDEyOFowFQIEL64/5xcNMDQwNDA1MTMx"
            + "ODE3WjAVAgQvrj/oFw0wNDA0MDUxMzE4MTdaMBUCBC+uP+UXDTAzMDExMzExMTgx"
            + "MVowFQIEL64/5hcNMDMwMTEzMTExODExWjAVAgQvrj/jFw0wMzAxMTMxMTI2NTZa"
            + "MBUCBC+uP+QXDTAzMDExMzExMjY1NlowFQIEL64/4hcNMDQwNzEzMDc1ODM4WjAV"
            + "AgQvrj/eFw0wMzAyMTcwNjMzMjVaMBUCBC+uP98XDTAzMDIxNzA2MzMyNVowFQIE"
            + "L64/0xcNMDMwMjE3MDYzMzI1WjAVAgQvrj/dFw0wMzAxMTMxMTI4MTRaMBUCBC+u"
            + "P9cXDTAzMDExMzExMjcwN1owFQIEL64/2BcNMDMwMTEzMTEyNzA3WjAVAgQvrj/V"
            + "Fw0wMzA0MzAxMjI3NTNaMBUCBC+uP9YXDTAzMDQzMDEyMjc1M1owFQIEL64/xhcN"
            + "MDMwMjEyMTM0NTQwWjAVAgQvrj/FFw0wMzAyMTIxMzQ1NDBaMBUCBC+uP8IXDTAz"
            + "MDIxMjEzMDkxNlowFQIEL64/wRcNMDMwMjEyMTMwODQwWjAVAgQvrj++Fw0wMzAy"
            + "MTcwNjM3MjVaMBUCBC+uP70XDTAzMDIxNzA2MzcyNVowFQIEL64/sBcNMDMwMjEy"
            + "MTMwODU5WjAVAgQvrj+vFw0wMzAyMTcwNjM3MjVaMBUCBC+uP5MXDTAzMDQxMDA1"
            + "MjYyOFowFQIEL64/khcNMDMwNDEwMDUyNjI4WjAVAgQvrj8/Fw0wMzAyMjYxMTA0"
            + "NDRaMBUCBC+uPz4XDTAzMDIyNjExMDQ0NFowFQIEL64+zRcNMDMwNTIwMDUyNzM2"
            + "WjAVAgQvrj7MFw0wMzA1MjAwNTI3MzZaMBUCBC+uPjwXDTAzMDYxNzEwMzQxNlow"
            + "FQIEL64+OxcNMDMwNjE3MTAzNDE2WjAVAgQvrj46Fw0wMzA2MTcxMDM0MTZaMBUC"
            + "BC+uPjkXDTAzMDYxNzEzMDEwMFowFQIEL64+OBcNMDMwNjE3MTMwMTAwWjAVAgQv"
            + "rj43Fw0wMzA2MTcxMzAxMDBaMBUCBC+uPjYXDTAzMDYxNzEzMDEwMFowFQIEL64+"
            + "MxcNMDMwNjE3MTAzNzQ5WjAVAgQvrj4xFw0wMzA2MTcxMDQyNThaMBUCBC+uPjAX"
            + "DTAzMDYxNzEwNDI1OFowFQIEL649qRcNMDMxMDIyMTEzMjI0WjAVAgQvrjyyFw0w"
            + "NTAzMTEwNjQ0MjRaMBUCBC+uPKsXDTA0MDQwMjA3NTQ1M1owFQIEL6466BcNMDUw"
            + "MTI3MTIwMzI0WjAVAgQvrjq+Fw0wNTAyMTYwNzU3MTZaMBUCBC+uOqcXDTA1MDMx"
            + "MDA1NTkzNVowFQIEL646PBcNMDUwNTExMTA0OTQ2WjAVAgQvrG3VFw0wNTExMTEx"
            + "MDAzMjFaMBUCBC+uLmgXDTA2MDEyMzEwMjU1NVowFQIEL64mxxcNMDYwODAxMDk0"
            + "ODQ0WqCBijCBhzALBgNVHRQEBAICEQwwHwYDVR0jBBgwFoAUA1vI26YMj3njkfCU"
            + "IXbo244kLjkwVwYDVR0SBFAwToZMbGRhcDovL3Brc2xkYXAudHR0Yy5kZS9vdT1U"
            + "LVRlbGVTZWMgVGVzdCBESVIgODpQTixvPURldXRzY2hlIFRlbGVrb20gQUcsYz1k"
            + "ZTAKBgYrJAMDAQIFAAOBgQArj4eMlbAwuA2aS5O4UUUHQMKKdK/dtZi60+LJMiMY"
            + "ojrMIf4+ZCkgm1Ca0Cd5T15MJxVHhh167Ehn/Hd48pdnAP6Dfz/6LeqkIHGWMHR+"
            + "z6TXpwWB+P4BdUec1ztz04LypsznrHcLRa91ixg9TZCb1MrOG+InNhleRs1ImXk8"
            + "MQ==");

    private static final String ldapURL1 = "ldap://pksldap.tttc.de:389";

    private static final X509LDAPCertStoreParameters params1 = new X509LDAPCertStoreParameters.Builder(
        ldapURL1, "o=Deutsche Telekom AG, c=DE").
        setAACertificateSubjectAttributeName("ou cn").
        setAttributeAuthorityRevocationListIssuerAttributeName("cn").
        setAttributeCertificateAttributeSubjectAttributeName("cn").
        setAttributeCertificateRevocationListIssuerAttributeName("cn").
        setAttributeDescriptorCertificateSubjectAttributeName("ou cn").
        setAuthorityRevocationListIssuerAttributeName("cn").
        setCACertificateSubjectAttributeName("ou cn").
        setCertificateRevocationListIssuerAttributeName("cn").
        setCrossCertificateSubjectAttributeName("cn").
        setDeltaRevocationListIssuerAttributeName("cn").
        setSearchForSerialNumberIn("cn")
        .build();

    private static final String ldapURL2 = "ldap://directory.d-trust.de:389";

    private static final X509LDAPCertStoreParameters params2 = new X509LDAPCertStoreParameters.Builder(
        ldapURL2, "o=D-Trust GmbH, c=DE").
        setAACertificateSubjectAttributeName("cn o").
        setAttributeAuthorityRevocationListIssuerAttributeName("cn").
        setAttributeCertificateAttributeSubjectAttributeName("cn").
        setAttributeCertificateRevocationListIssuerAttributeName("cn").
        setAttributeDescriptorCertificateSubjectAttributeName("cn o").
        setAuthorityRevocationListIssuerAttributeName("cn").
        setCACertificateSubjectAttributeName("cn o").
        setCertificateRevocationListIssuerAttributeName("cn").
        setCrossCertificateSubjectAttributeName("cn o").
        setDeltaRevocationListIssuerAttributeName("cn").
        setSearchForSerialNumberIn("uid")
        .build();

    private static final byte[] cert2 = Base64
        .decode("MIIEADCCAuigAwIBAgIDAJ/QMA0GCSqGSIb3DQEBBQUAMD8xCzAJBgNVBAYTAkRF"
            + "MRUwEwYDVQQKDAxELVRydXN0IEdtYkgxGTAXBgNVBAMMEEQtVFJVU1QgRGVtbyBD"
            + "QTEwHhcNMDYwMzAyMTYxNTU3WhcNMDgwMzEyMTYxNTU3WjB+MQswCQYDVQQGEwJE"
            + "RTEUMBIGA1UECgwLTXVzdGVyIEdtYkgxFzAVBgNVBAMMDk1heCBNdXN0ZXJtYW5u"
            + "MRMwEQYDVQQEDApNdXN0ZXJtYW5uMQwwCgYDVQQqDANNYXgxHTAbBgNVBAUTFERU"
            + "UldFMTQxMjk5NDU1MTgwMTIxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC"
            + "AQEAjLDFeviSZDEZgLzTdptU4biPgNV7SvLqsNholfqkyQm2r5WSghGZSjhKYIne"
            + "qKmZ08W59a51bGqDEsifYR7Tw9JC/AhH19fyK01+1ZAXHalgVthaRtLw31lcoTVJ"
            + "R7j9fvrnW0sMPVP4m5gePb3P5/pYHVmN1MjdPIm38us5aJOytOO5Li2IwQIG0t4M"
            + "bEC6/1horBR5TgRl7ACamrdaPHOvO1QVweOqYU7uVxLgDTK4mSV6heyrisFMfkbj"
            + "7jT/c44kXM7dtgNcmESINudu6bnqaB1CxOFTJ/Jzv81R5lf7pBX2LOG1Bu94Yw2x"
            + "cHUVROs2UWY8kQrNUozsBHzQ0QIDAKq5o4HFMIHCMBMGA1UdIwQMMAqACEITKrPL"
            + "WuYiMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZC10"
            + "cnVzdC5uZXQwEAYDVR0gBAkwBzAFBgMqAwQwEQYDVR0OBAoECEvE8bXFHkFLMA4G"
            + "A1UdDwEB/wQEAwIGQDAPBgUrJAgDCAQGDARUZXN0MB8GA1UdEQQYMBaBFG0ubXVz"
            + "dGVybWFubkB0ZXN0LmRlMA8GBSskCAMPBAYMBFRlc3QwDQYJKoZIhvcNAQEFBQAD"
            + "ggEBADD/X+UZZN30nCBDzJ7MtmgwvMBVDAU6HkPlzfyn9pxIKFrq3uR9wcY2pedM"
            + "yQQk0NpTDCIhAYIjAHysMue0ViQnW5qq8uUCFn0+fsgMqqTQNRmE4NIqUrnYO40g"
            + "WjcepCEApkTqGf3RFaDMf9zpRvj9qUx18De+V0GC22uD2vPKpqRcvS2dSw6pHBW2"
            + "NwEU+RgNhoPXrHt332PEYdwO0zOL7eSLBD9AmkpP2uDjpMQ02Lu9kXG6OOfanwfS"
            + "jHioCvDXyl5pwSHwrHNWQRb5dLF12Fg41LMapDwR7awAKE9h6qHBonvCMBPMvqrr"
            + "NktqQcoQkluR9MItONJI5XHADtU=");

    private static final String ldapURL3 = "ldap://dir.signtrust.de:389";

    private static final X509LDAPCertStoreParameters params3 = new X509LDAPCertStoreParameters.Builder(
        ldapURL3, "o=Deutsche Post AG, c=de").
        setAACertificateSubjectAttributeName("ou").
        setAttributeAuthorityRevocationListIssuerAttributeName("cn").
        setAttributeCertificateAttributeSubjectAttributeName("cn").
        setAttributeCertificateRevocationListIssuerAttributeName("o").
        setAttributeDescriptorCertificateSubjectAttributeName("ou").
        setAuthorityRevocationListIssuerAttributeName("o").
        setCACertificateSubjectAttributeName("ou").
        setCertificateRevocationListIssuerAttributeName("o").
        setCrossCertificateSubjectAttributeName("o").
        setDeltaRevocationListIssuerAttributeName("o").
        setSearchForSerialNumberIn("serialNumber")
        .build();

    private static final byte[] cert3 = Base64
        .decode("MIICwDCCAimgAwIBAgIBKzANBgkqhkiG9w0BAQUFADA6MRAwDgYDVQQDEwdQQ0Ex"
            + "OlBOMRkwFwYDVQQKExBEZXV0c2NoZSBQb3N0IEFHMQswCQYDVQQGEwJERTAeFw0w"
            + "MDA0MTkyMjAwMDBaFw0wMzA0MTkyMjAwMDBaMIGOMRAwDgYDVQQEFAdN5G5jaGVy"
            + "MQ4wDAYDVQQqEwVLbGF1czEWMBQGA1UEAxQNS2xhdXMgTeRuY2hlcjEVMBMGA1UE"
            + "CRMMV2llc2Vuc3RyLiAzMQ4wDAYDVQQREwU2MzMyOTESMBAGA1UEBxMJRWdlbHNi"
            + "YWNoMQswCQYDVQQGEwJERTEKMAgGA1UEBRMBMTCBnzANBgkqhkiG9w0BAQEFAAOB"
            + "jQAwgYkCgYEAn7z6Ba9wpv/mNBIaricY/d0KpxGpqGAXdqKlvqkk/seJEoBLvmL7"
            + "wZz88RPELQqzDhc4oXYohS2dh3NHus9FpSPMq0JzKAcE3ArrVDxwtXtlcwN2v7iS"
            + "TcHurgLOb9C/r8JdsMHNgwHMkkdp96cJk/sioyP5sLPYmgWxg1JH0vMCAwEAAaOB"
            + "gDB+MAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/BAUDAwfAADBKBgNVHSMEQzBBoTyk"
            + "OjEQMA4GA1UEAxMHUENBMTpQTjEZMBcGA1UEChMQRGV1dHNjaGUgUG9zdCBBRzEL"
            + "MAkGA1UEBhMCREWCAQEwEQYDVR0OBAoECEAeJ6R3USjxMA0GCSqGSIb3DQEBBQUA"
            + "A4GBADMRtdiQJF2fg7IcedTjnAW+QGl/wNSKy7A4oaBQeahcruo+hzH+ZU+DsiSu"
            + "TJZaf2X1eUUEPmV+5zZlopGa3HvFfgmIYIXBw9ZO3Qb/HWGsPNgW0yg5eXEGwNEt"
            + "vV85BTMGuMjiuDw841IuAZaMKqOKnVXHmd2pLJz7Wv0MLJhw");

    private static final byte[] caCert3 = Base64
        .decode("MIICUjCCAb6gAwIBAgIDD2ptMAoGBiskAwMBAgUAMG8xCzAJBgNVBAYTAkRFMT0w"
            + "OwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0"
            + "aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjRSLUNBIDE6UE4w"
            + "IhgPMjAwMDA0MTIwODIyMDNaGA8yMDA0MDQxMjA4MjIwM1owWzELMAkGA1UEBhMC"
            + "REUxGTAXBgNVBAoUEERldXRzY2hlIFBvc3QgQUcxMTAMBgcCggYBCgcUEwExMCEG"
            + "A1UEAxQaQ0EgREVSIERFVVRTQ0hFTiBQT1NUIDU6UE4wgZ8wDQYJKoZIhvcNAQEB"
            + "BQADgY0AMIGJAoGBAIH3c+gig1KkY5ceR6n/AMq+xz7hi3f0PMdpwIe2v2w6Hu5k"
            + "jipe++NvU3r6wakIY2royHl3gKWrExOisBico9aQmn8lMJnWZ7SUbB+WpRn0mAWN"
            + "ZM9YT+/U5hRCffeeuLWClzrbScaWnAeaaI0G+N/QKnSSjrV/l64jogyADWCTAgMB"
            + "AAGjEjAQMA4GA1UdDwEB/wQEAwIBBjAKBgYrJAMDAQIFAAOBgQAaV5WClEneXk9s"
            + "LO8zTQAsf4KvDaLd1BFcFeYM7kLLRHKeWQ0MAd0xkuAMme5NVwWNpNZP74B4HX7Q"
            + "/Q0h/wo/9LTgQaxw52lLs4Ml0HUyJbSFjoQ+sqgjg2fGNGw7aGkVNY5dQTAy8oSv"
            + "iG8mxTsQ7Fxaush3cIB0qDDwXar/hg==");

    private static final byte[] crossCert3 = Base64
        .decode("MIICVDCCAcCgAwIBAgIDDIOsMAoGBiskAwMBAgUAMG8xCzAJBgNVBAYTAkRFMT0w"
            + "OwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0"
            + "aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjRSLUNBIDE6UE4w"
            + "IhgPMjAwMDAzMjIwOTQzNTBaGA8yMDA0MDEyMTE2MDQ1M1owbzELMAkGA1UEBhMC"
            + "REUxPTA7BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbIdXIgVGVsZWtvbW11"
            + "bmlrYXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwExMBEGA1UEAxQKNVItQ0Eg"
            + "MTpQTjCBoTANBgkqhkiG9w0BAQEFAAOBjwAwgYsCgYEAih5BUycfBpqKhU8RDsaS"
            + "vV5AtzWeXQRColL9CH3t0DKnhjKAlJ8iccFtJNv+d3bh8bb9sh0maRSo647xP7hs"
            + "HTjKgTE4zM5BYNfXvST79OtcMgAzrnDiGjQIIWv8xbfV1MqxxdtZJygrwzRMb9jG"
            + "CAGoJEymoyzAMNG7tSdBWnUCBQDAAAABMAoGBiskAwMBAgUAA4GBAIBWrl6aEy4d"
            + "2d6U/924YK8Tv9oChmaKVhklkiTzcKv1N8dhLnLTibq4/stop03CY3rKU4X5aTfu"
            + "0J77FIV1Poy9jLT5Tm1NBpi71m4uO3AUoSeyhJXGQGsYFjAc3URqkznbTL/nr9re"
            + "IoBhf6u9cX+idnN6Uy1q+j/LOrcy3zgj");

    public void performTest() throws Exception
    {
        certStoretest();
        x509StoreTest();
    }

    private void certStoretest() throws Exception
    {
        CertStore cs = CertStore.getInstance("X509LDAP", params1, "BC");
        X509CertSelector sl = new X509CertSelector();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate xcert = (X509Certificate)cf
            .generateCertificate(new ByteArrayInputStream(cert1));
        sl.setCertificate(xcert);
        Collection coll = cs.getCertificates(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("certificate could not be picked from LDAP directory.");
        }

        // System.out.println(coll.toArray()[0]);

        sl.setCertificate(null);
        sl.setSubject(getSubject(xcert).getEncoded());
        coll = cs.getCertificates(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("certificate could not be picked from LDAP directory.");
        }
        X509CRLSelector sl2 = new X509CRLSelector();
        X509CRL crl = (X509CRL)cf.generateCRL(new
            ByteArrayInputStream(directCRL));
        sl2.addIssuerName(getCRLIssuer(crl).getEncoded());
        coll = cs.getCRLs(sl2);
        if (!coll.iterator().hasNext())
        {
            fail("CRL could not be picked from LDAP directory.");
        }
        // System.out.println(coll.toArray()[0]);

        cs = CertStore.getInstance("X509LDAP", params2, "BC");
        sl = new X509CertSelector();
        xcert = (X509Certificate)cf
            .generateCertificate(new ByteArrayInputStream(cert2));
        sl.setCertificate(xcert);
        coll = cs.getCertificates(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("Certificate could not be picked from LDAP directory.");
        }

        // System.out.println(coll.toArray()[0]);

        cs = CertStore.getInstance("X509LDAP", params3, "BC");
        sl = new X509CertSelector();
        xcert = (X509Certificate)cf
            .generateCertificate(new ByteArrayInputStream(cert3));
        sl.setCertificate(xcert);
        coll = cs.getCertificates(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("Certificate could not be picked from LDAP directory.");
        }

        // System.out.println(coll.toArray()[0]);

        xcert = (X509Certificate)cf
            .generateCertificate(new ByteArrayInputStream(caCert3));
        sl = new X509CertSelector();
        sl.setSubject(getSubject(xcert).getEncoded());
        coll = cs.getCertificates(sl);
        boolean found = false;
        if (coll.isEmpty())
        {
            fail("Certificate could not be picked from LDAP directory.");
        }

        for (Iterator it = coll.iterator(); it.hasNext();)
        {
            if (it.next().equals(xcert))
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            fail("Certificate could not be picked from LDAP directory.");
        }

        // System.out.println(coll.toArray()[0]);

        sl = new X509CertSelector();
        xcert = (X509Certificate)cf
            .generateCertificate(new ByteArrayInputStream(crossCert3));
        sl = new X509CertSelector();
        sl.setSubject(getSubject(xcert).getEncoded());
        coll = cs.getCertificates(sl);
        if (coll.isEmpty())
        {
            fail("Cross certificate pair could not be picked from LDAP directory.");
        }
        found = false;
        for (Iterator it = coll.iterator(); it.hasNext();)
        {
            if (it.next().equals(xcert))
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            fail("Cross certificate pair could not be picked from LDAP directory.");
        }

        // System.out.println(coll.toArray()[0]);
    }

    private void x509StoreTest() throws Exception
    {
        X509Store cs = X509Store.getInstance("CERTIFICATE/LDAP", params1, "BC");

        X509CertStoreSelector sl = new X509CertStoreSelector();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate xcert = (X509Certificate)cf
            .generateCertificate(new ByteArrayInputStream(cert1));
        sl.setCertificate(xcert);
        Collection coll = cs.getMatches(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("certificate could not be picked from LDAP directory.");
        }

        // System.out.println(coll.toArray()[0]);

        sl.setCertificate(null);
        sl.setSubject(getSubject(xcert).getEncoded());
        coll = cs.getMatches(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("certificate could not be picked from LDAP directory.");
        }
        X509CRLStoreSelector sl2 = new X509CRLStoreSelector();
        X509CRL crl = (X509CRL)cf.generateCRL(new
            ByteArrayInputStream(directCRL));
        sl2.setIssuers(Collections.singleton(crl.getIssuerX500Principal()));
        cs = X509Store.getInstance("CRL/LDAP", params1, "BC");
        coll = cs.getMatches(sl2);
        if (!coll.iterator().hasNext())
        {
            fail("CRL could not be picked from LDAP directory.");
        }
        // System.out.println(coll.toArray()[0]);

        cs = X509Store.getInstance("CERTIFICATE/LDAP", params2, "BC");
        sl = new X509CertStoreSelector();
        xcert = (X509Certificate)cf
            .generateCertificate(new ByteArrayInputStream(cert2));
        sl.setCertificate(xcert);
        coll = cs.getMatches(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("Certificate could not be picked from LDAP directory.");
        }

        // System.out.println(coll.toArray()[0]);

        cs = X509Store.getInstance("CERTIFICATE/LDAP", params3, "BC");
        sl = new X509CertStoreSelector();
        xcert = (X509Certificate)cf
            .generateCertificate(new ByteArrayInputStream(cert3));
        sl.setCertificate(xcert);
        coll = cs.getMatches(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("Certificate could not be picked from LDAP directory.");
        }

        // System.out.println(coll.toArray()[0]);

        xcert = (X509Certificate)cf
            .generateCertificate(new ByteArrayInputStream(caCert3));
        sl = new X509CertStoreSelector();
        sl.setSubject(getSubject(xcert).getEncoded());
        coll = cs.getMatches(sl);
        boolean found = false;
        if (coll.isEmpty())
        {
            fail("Certificate could not be picked from LDAP directory.");
        }

        for (Iterator it = coll.iterator(); it.hasNext();)
        {
            if (it.next().equals(xcert))
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            fail("Certificate could not be picked from LDAP directory.");
        }

        // System.out.println(coll.toArray()[0]);

        sl = new X509CertStoreSelector();
        xcert = (X509Certificate)cf
            .generateCertificate(new ByteArrayInputStream(crossCert3));
        sl.setSubject(getSubject(xcert).getEncoded());
        coll = cs.getMatches(sl);
        if (coll.isEmpty())
        {
            fail("Cross certificate pair could not be picked from LDAP directory.");
        }
        found = false;
        for (Iterator it = coll.iterator(); it.hasNext();)
        {
            if (it.next().equals(xcert))
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            fail("Cross certificate pair could not be picked from LDAP directory.");
        }

        // System.out.println(coll.toArray()[0]);

    }

    private X509Principal getSubject(X509Certificate cert)
        throws CertificateEncodingException
    {
        return PrincipalUtil.getSubjectX509Principal(cert);
    }

    private X509Principal getCRLIssuer(X509CRL crl)
        throws CRLException
    {
        return PrincipalUtil.getIssuerX509Principal(crl);
    }

    public String getName()
    {
        return "LDAPCertStoreTest";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new X509LDAPCertStoreTest());
    }
}
