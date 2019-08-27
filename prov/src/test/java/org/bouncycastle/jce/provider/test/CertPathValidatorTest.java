package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PolicyNode;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.misc.VerisignCzagExtension;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class CertPathValidatorTest
    extends SimpleTest
{
    private byte[] AC_PR = Base64.decode(
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlFU1RDQ0F6R2dBd0lC"
            + "QWdJQkJUQU5CZ2txaGtpRzl3MEJBUVVGQURDQnRERUxNQWtHQTFVRUJoTUNR"
            + "bEl4DQpFekFSQmdOVkJBb1RDa2xEVUMxQ2NtRnphV3d4UFRBN0JnTlZCQXNU"
            + "TkVsdWMzUnBkSFYwYnlCT1lXTnBiMjVoDQpiQ0JrWlNCVVpXTnViMnh2WjJs"
            + "aElHUmhJRWx1Wm05eWJXRmpZVzhnTFNCSlZFa3hFVEFQQmdOVkJBY1RDRUp5"
            + "DQpZWE5wYkdsaE1Rc3dDUVlEVlFRSUV3SkVSakV4TUM4R0ExVUVBeE1vUVhW"
            + "MGIzSnBaR0ZrWlNCRFpYSjBhV1pwDQpZMkZrYjNKaElGSmhhWG9nUW5KaGMy"
            + "bHNaV2x5WVRBZUZ3MHdNakEwTURReE9UTTVNREJhRncwd05UQTBNRFF5DQpN"
            + "elU1TURCYU1HRXhDekFKQmdOVkJBWVRBa0pTTVJNd0VRWURWUVFLRXdwSlEx"
            + "QXRRbkpoYzJsc01UMHdPd1lEDQpWUVFERXpSQmRYUnZjbWxrWVdSbElFTmxj"
            + "blJwWm1sallXUnZjbUVnWkdFZ1VISmxjMmxrWlc1amFXRWdaR0VnDQpVbVZ3"
            + "ZFdKc2FXTmhNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJD"
            + "Z0tDQVFFQXMwc0t5NGsrDQp6b016aldyMTQxeTVYQ045UGJMZERFQXN2cjZ4"
            + "Z0NCN1l5bEhIQ1NBYmpGR3dOQ0R5NlVxN1h0VjZ6UHdIMXpGDQpFWENlS3Jm"
            + "UUl5YXBXSEZ4V1VKajBMblFrY1RZM1FOR1huK0JuVk9EVTZDV3M1c3NoZktH"
            + "RXZyVlQ1Z214V1NmDQp4OFlsdDgzY1dwUE1QZzg3VDlCaHVIbHQzazh2M2Ev"
            + "NmRPbmF2dytOYTAyZExBaDBlNzZqcCtQUS9LK0pHZlBuDQphQjVVWURrZkd0"
            + "em5uTTNBV01tY3VJK0o0ek5OMDZaa3ZnbDFsdEo2UU1qcnZEUFlSak9ndDlT"
            + "cklpY1NmbEo4DQptVDdHWGRRaXJnQUNXc3g1QURBSklRK253TU1vNHlyTUtx"
            + "SlFhNFFDMHhhT0QvdkdVcG9SaDQzT0FTZFp3c3YvDQpPWFlybmVJeVAwVCs4"
            + "UUlEQVFBQm80RzNNSUcwTUQwR0ExVWRId1EyTURRd01xQXdvQzZHTEdoMGRI"
            + "QTZMeTloDQpZM0poYVhvdWFXTndZbkpoYzJsc0xtZHZkaTVpY2k5TVExSmhZ"
            + "M0poYVhvdVkzSnNNQklHQTFVZElBUUxNQWt3DQpCd1lGWUV3QkFRRXdIUVlE"
            + "VlIwT0JCWUVGREpUVFlKNE9TWVB5T09KZkVMZXhDaHppK2hiTUI4R0ExVWRJ"
            + "d1FZDQpNQmFBRklyNjhWZUVFUk0xa0VMNlYwbFVhUTJreFBBM01BNEdBMVVk"
            + "RHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CDQpBZjhFQlRBREFRSC9NQTBHQ1Nx"
            + "R1NJYjNEUUVCQlFVQUE0SUJBUUJRUFNoZ1lidnFjaWV2SDVVb3ZMeXhkbkYr"
            + "DQpFcjlOeXF1SWNkMnZ3Y0N1SnpKMkQ3WDBUcWhHQ0JmUEpVVkdBVWorS0NP"
            + "SDFCVkgva1l1OUhsVHB1MGtKWFBwDQpBQlZkb2hJUERqRHhkbjhXcFFSL0Yr"
            + "ejFDaWtVcldIMDR4eTd1N1p6UUpLSlBuR0loY1FpOElyRm1PYkllMEc3DQpY"
            + "WTZPTjdPRUZxY21KTFFHWWdtRzFXMklXcytQd1JwWTdENGhLVEFoVjFSNkVv"
            + "amE1L3BPcmVDL09kZXlQWmVxDQo1SUZTOUZZZk02U0Npd2hrK3l2Q1FHbVo0"
            + "YzE5SjM0ZjVFYkRrK1NQR2tEK25EQ0E3L3VMUWNUMlJURE14SzBaDQpuZlo2"
            + "Nm1Sc0ZjcXRGaWdScjVFcmtKZDdoUVV6eHNOV0VrNzJEVUFIcVgvNlNjeWtt"
            + "SkR2V0plSUpqZlcNCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCg==");

    private byte[] AC_RAIZ_ICPBRASIL = Base64.decode(
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlFdURDQ0E2Q2dBd0lC"
            + "QWdJQkJEQU5CZ2txaGtpRzl3MEJBUVVGQURDQnRERUxNQWtHQTFVRUJoTUNR"
            + "bEl4DQpFekFSQmdOVkJBb1RDa2xEVUMxQ2NtRnphV3d4UFRBN0JnTlZCQXNU"
            + "TkVsdWMzUnBkSFYwYnlCT1lXTnBiMjVoDQpiQ0JrWlNCVVpXTnViMnh2WjJs"
            + "aElHUmhJRWx1Wm05eWJXRmpZVzhnTFNCSlZFa3hFVEFQQmdOVkJBY1RDRUp5"
            + "DQpZWE5wYkdsaE1Rc3dDUVlEVlFRSUV3SkVSakV4TUM4R0ExVUVBeE1vUVhW"
            + "MGIzSnBaR0ZrWlNCRFpYSjBhV1pwDQpZMkZrYjNKaElGSmhhWG9nUW5KaGMy"
            + "bHNaV2x5WVRBZUZ3MHdNVEV4TXpBeE1qVTRNREJhRncweE1URXhNekF5DQpN"
            + "elU1TURCYU1JRzBNUXN3Q1FZRFZRUUdFd0pDVWpFVE1CRUdBMVVFQ2hNS1NV"
            + "TlFMVUp5WVhOcGJERTlNRHNHDQpBMVVFQ3hNMFNXNXpkR2wwZFhSdklFNWhZ"
            + "Mmx2Ym1Gc0lHUmxJRlJsWTI1dmJHOW5hV0VnWkdFZ1NXNW1iM0p0DQpZV05o"
            + "YnlBdElFbFVTVEVSTUE4R0ExVUVCeE1JUW5KaGMybHNhV0V4Q3pBSkJnTlZC"
            + "QWdUQWtSR01URXdMd1lEDQpWUVFERXloQmRYUnZjbWxrWVdSbElFTmxjblJw"
            + "Wm1sallXUnZjbUVnVW1GcGVpQkNjbUZ6YVd4bGFYSmhNSUlCDQpJakFOQmdr"
            + "cWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBd1BNdWR3WC9odm0r"
            + "VWgyYi9sUUFjSFZBDQppc2FtYUxrV2Rrd1A5L1MvdE9LSWdSckw2T3krWklH"
            + "bE9VZGQ2dVl0azlNYS8zcFVwZ2NmTkFqMHZZbTVnc3lqDQpRbzllbXNjK3g2"
            + "bTRWV3drOWlxTVpTQ0s1RVFrQXEvVXQ0bjdLdUxFMStnZGZ0d2RJZ3hmVXNQ"
            + "dDRDeU5yWTUwDQpRVjU3S00yVVQ4eDVycm16RWpyN1RJQ0dwU1VBbDJnVnFl"
            + "NnhhaWkrYm1ZUjFRcm1XYUJTQUc1OUxya3Jqcll0DQpiUmhGYm9VRGUxREsr"
            + "NlQ4czVMNms4Yzhva3BiSHBhOXZlTXp0RFZDOXNQSjYwTVdYaDZhblZLbzFV"
            + "Y0xjYlVSDQp5RWVOdlpuZVZSS0FBVTZvdXdkakR2d2xzYUt5ZEZLd2VkMFRv"
            + "UTQ3Ym1VS2djbSt3VjNlVFJrMzZVT25Ud0lEDQpBUUFCbzRIU01JSFBNRTRH"
            + "QTFVZElBUkhNRVV3UXdZRllFd0JBUUF3T2pBNEJnZ3JCZ0VGQlFjQ0FSWXNh"
            + "SFIwDQpjRG92TDJGamNtRnBlaTVwWTNCaWNtRnphV3d1WjI5MkxtSnlMMFJR"
            + "UTJGamNtRnBlaTV3WkdZd1BRWURWUjBmDQpCRFl3TkRBeW9EQ2dMb1lzYUhS"
            + "MGNEb3ZMMkZqY21GcGVpNXBZM0JpY21GemFXd3VaMjkyTG1KeUwweERVbUZq"
            + "DQpjbUZwZWk1amNtd3dIUVlEVlIwT0JCWUVGSXI2OFZlRUVSTTFrRUw2VjBs"
            + "VWFRMmt4UEEzTUE4R0ExVWRFd0VCDQovd1FGTUFNQkFmOHdEZ1lEVlIwUEFR"
            + "SC9CQVFEQWdFR01BMEdDU3FHU0liM0RRRUJCUVVBQTRJQkFRQVpBNWMxDQpV"
            + "L2hnSWg2T2NnTEFmaUpnRldwdm1EWldxbFYzMC9iSEZwajhpQm9iSlNtNXVE"
            + "cHQ3VGlyWWgxVXhlM2ZRYUdsDQpZakplKzl6ZCtpelBSYkJxWFBWUUEzNEVY"
            + "Y3drNHFwV3VmMWhIcmlXZmRyeDhBY3FTcXI2Q3VRRndTcjc1Rm9zDQpTemx3"
            + "REFEYTcwbVQ3d1pqQW1RaG5aeDJ4SjZ3ZldsVDlWUWZTLy9KWWVJYzdGdWUy"
            + "Sk5MZDAwVU9TTU1haUsvDQp0NzllbktOSEVBMmZ1cEgzdkVpZ2Y1RWg0YlZB"
            + "TjVWb2hyVG02TVk1M3g3WFFaWnIxTUU3YTU1bEZFblNlVDB1DQptbE9BalIy"
            + "bUFidlNNNVg1b1NaTnJtZXRkenlUajJmbENNOENDN01MYWIwa2tkbmdSSWxV"
            + "QkdIRjEvUzVubVBiDQpLKzlBNDZzZDMzb3FLOG44DQotLS0tLUVORCBDRVJU"
            + "SUZJQ0FURS0tLS0tDQo=");

    private byte[] schefer = Base64.decode(
        "MIIEnDCCBAWgAwIBAgICIPAwDQYJKoZIhvcNAQEEBQAwgcAxCzAJBgNVBAYT"
            + "AkRFMQ8wDQYDVQQIEwZIRVNTRU4xGDAWBgNVBAcTDzY1MDA4IFdpZXNiYWRl"
            + "bjEaMBgGA1UEChMRU0NIVUZBIEhPTERJTkcgQUcxGjAYBgNVBAsTEVNDSFVG"
            + "QSBIT0xESU5HIEFHMSIwIAYDVQQDExlJbnRlcm5ldCBCZW51dHplciBTZXJ2"
            + "aWNlMSowKAYJKoZIhvcNAQkBFht6ZXJ0aWZpa2F0QHNjaHVmYS1vbmxpbmUu"
            + "ZGUwHhcNMDQwMzMwMTEwODAzWhcNMDUwMzMwMTEwODAzWjCBnTELMAkGA1UE"
            + "BhMCREUxCjAIBgNVBAcTASAxIzAhBgNVBAoTGlNIUyBJbmZvcm1hdGlvbnNz"
            + "eXN0ZW1lIEFHMRwwGgYDVQQLExM2MDAvMDU5NDktNjAwLzA1OTQ5MRgwFgYD"
            + "VQQDEw9TY2hldHRlciBTdGVmYW4xJTAjBgkqhkiG9w0BCQEWFlN0ZWZhbi5T"
            + "Y2hldHRlckBzaHMuZGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJD0"
            + "95Bi76fkAMjJNTGPDiLPHmZXNsmakngDeS0juzKMeJA+TjXFouhYh6QyE4Bl"
            + "Nf18fT4mInlgLefwf4t6meIWbiseeTo7VQdM+YrbXERMx2uHsRcgZMsiMYHM"
            + "kVfYMK3SMJ4nhCmZxrBkoTRed4gXzVA1AA8YjjTqMyyjvt4TAgMBAAGjggHE"
            + "MIIBwDAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIEsDALBgNVHQ8EBAMC"
            + "BNAwOQYJYIZIAYb4QgENBCwWKlplcnRpZmlrYXQgbnVyIGZ1ZXIgU0NIVUZB"
            + "LU9ubGluZSBndWVsdGlnLjAdBgNVHQ4EFgQUXReirhBfg0Yhf6MsBWoo/nPa"
            + "hGwwge0GA1UdIwSB5TCB4oAUf2UyCaBV9JUeG9lS1Yo6OFBUdEKhgcakgcMw"
            + "gcAxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIEwZIRVNTRU4xGDAWBgNVBAcTDzY1"
            + "MDA4IFdpZXNiYWRlbjEaMBgGA1UEChMRU0NIVUZBIEhPTERJTkcgQUcxGjAY"
            + "BgNVBAsTEVNDSFVGQSBIT0xESU5HIEFHMSIwIAYDVQQDExlJbnRlcm5ldCBC"
            + "ZW51dHplciBTZXJ2aWNlMSowKAYJKoZIhvcNAQkBFht6ZXJ0aWZpa2F0QHNj"
            + "aHVmYS1vbmxpbmUuZGWCAQAwIQYDVR0RBBowGIEWU3RlZmFuLlNjaGV0dGVy"
            + "QHNocy5kZTAmBgNVHRIEHzAdgRt6ZXJ0aWZpa2F0QHNjaHVmYS1vbmxpbmUu"
            + "ZGUwDQYJKoZIhvcNAQEEBQADgYEAWzZtN9XQ9uyrFXqSy3hViYwV751+XZr0"
            + "YH5IFhIS+9ixNAu8orP3bxqTaMhpwoU7T/oSsyGGSkb3fhzclgUADbA2lrOI"
            + "GkeB/m+FArTwRbwpqhCNTwZywOp0eDosgPjCX1t53BB/m/2EYkRiYdDGsot0"
            + "kQPOVGSjQSQ4+/D+TM8=");

    // circular dependency certificates
    private static final byte[] circCA = Base64.decode(
        "MIIDTzCCAjegAwIBAgIDARAAMA0GCSqGSIb3DQEBBQUAMDkxCzAJBgNVBAYT"
            + "AkZSMRAwDgYDVQQKEwdHSVAtQ1BTMRgwFgYDVQQLEw9HSVAtQ1BTIEFOT05Z"
            + "TUUwHhcNMDQxMDExMDAwMDAxWhcNMTQxMjMxMjM1OTU5WjA5MQswCQYDVQQG"
            + "EwJGUjEQMA4GA1UEChMHR0lQLUNQUzEYMBYGA1UECxMPR0lQLUNQUyBBTk9O"
            + "WU1FMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3WyWDwcM58aU"
            + "hPX4ueI1mwETt3WdQtMfIdRiCXeBrjCkYCc7nIgCmGbnfTzXSplHRgKColWh"
            + "q/Z+1rHYayje1gjAEU2+4/r1P2pnBmPgquDuguktCIbDtCcGZu0ylyKeHh37"
            + "aeIKzkcmRSLRzvGf/eO3RdFksrvaPaSjqCVfGRXVDKK2uftE8rIFJE+bCqow"
            + "6+WiaAaDDiJaSJPuu5hC1NA5jw0/BFodlCuAvl1GJ8A+TICkYWcSpKS9bkSC"
            + "0i8xdGbSSk94shA1PdDvRdFMfFys8g4aupBXV8yqqEAUkBYmOtZSJckc3W4y"
            + "2Gx53y7vY07Xh63mcgtJs2T82WJICwIDAQABo2AwXjAdBgNVHQ4EFgQU8c/P"
            + "NNJaL0srd9SwHwgtvwPB/3cwDgYDVR0PAQH/BAQDAgIEMBkGA1UdIAQSMBAw"
            + "DgYMKoF6AUcDBwgAAAABMBIGA1UdEwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcN"
            + "AQEFBQADggEBAHRjYDPJKlfUzID0YzajZpgR/i2ngJrJqYeaWCmwzBgNUPad"
            + "uBKSGHmPVg21sfULMSnirnR+e90i/D0EVzLwQzcbjPDD/85rp9QDCeMxqqPe"
            + "9ZCHGs2BpE/HOQMP0QfQ3/Kpk7SvOH/ZcpIf6+uE6lLBQYAGs5cxvtTGOzZk"
            + "jCVFG+TrAnF4V5sNkn3maCWiYLmyqcnxtKEFSONy2bYqqudx/dBBlRrDbRfZ"
            + "9XsCBdiXAHY1hFHldbfDs8rslmkXJi3fJC028HZYB6oiBX/JE7BbMk7bRnUf"
            + "HSpP7Sjxeso2SY7Yit+hQDVAlqTDGmh6kLt/hQMpsOMry4vgBL6XHKw=");

    private static final byte[] circCRLCA = Base64.decode(
        "MIIDXDCCAkSgAwIBAgIDASAAMA0GCSqGSIb3DQEBBQUAMDkxCzAJBgNVBAYT"
            + "AkZSMRAwDgYDVQQKEwdHSVAtQ1BTMRgwFgYDVQQLEw9HSVAtQ1BTIEFOT05Z"
            + "TUUwHhcNMDQxMDExMDAwMDAxWhcNMTQxMjMxMjM1OTU5WjA5MQswCQYDVQQG"
            + "EwJGUjEQMA4GA1UEChMHR0lQLUNQUzEYMBYGA1UECxMPR0lQLUNQUyBBTk9O"
            + "WU1FMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwfEcFK0g7Kfo"
            + "o5f2IBF7VEd/AG+RVGSds0Yg+u2kNYu4k04HR/+tOdBQtJvyr4W5jrQKsC5X"
            + "skeFWMyWaFKzAjZDWB52HWp/kiMivGcxnYDuYf5piukSC+d2+vL8YaAphDzV"
            + "HPnxEKqoM/J66uUussDTqfcL3JC/Bc7kBwn4srrsZOsamMWTQQtEqVQxNN7A"
            + "ROSRsdiTt3hMOKditc9/NBNmjZWxgc7Twr/SaZ8CfN5wf2wuOl23knWL0QsJ"
            + "0lSMBSBTzTcfAke4/jIT7d4nVMp3t7dsna8rt56pFK4wpRFGuCt+1P5gi51x"
            + "xVSdI+JoNXv6zGO4o8YVaRpC5rQeGQIDAQABo20wazAfBgNVHSMEGDAWgBTx"
            + "z8800lovSyt31LAfCC2/A8H/dzAdBgNVHQ4EFgQUGa3SbBrJx/wa2MQwhWPl"
            + "dwLw1+IwDgYDVR0PAQH/BAQDAgECMBkGA1UdIAQSMBAwDgYMKoF6AUcDBwgA"
            + "AAABMA0GCSqGSIb3DQEBBQUAA4IBAQAPDpYe2WPYnXTLsXSIUREBNMLmg+/7"
            + "4Yhq9uOm5Hb5LVkDuHoEHGfmpXXEvucx5Ehu69hw+F4YSrd9wPjOiG8G6GXi"
            + "RcrK8nE8XDvvV+E1HpJ7NKN4fSAoSb+0gliiq3aF15bvXP8nfespdd/x1xWQ"
            + "mpYCx/mJeuqONQv2/D/7hfRKYoDBaAkWGodenPFPVs6FxwnEuH2R+KWCUdA9"
            + "L04v8JBeL3kZiALkU7+DCCm7A0imUAgeeArbAbfIPu6eDygm+XndZ9qi7o4O"
            + "AntPxrqbeXFIbDrQ4GV1kpxnW+XpSGDd96SWKe715gxkkDBppR5IKYJwRb6O"
            + "1TRQIf2F+muQ");

    private static final byte[] circCRL = Base64.decode(
        "MIIB1DCBvQIBATANBgkqhkiG9w0BAQUFADA5MQswCQYDVQQGEwJGUjEQMA4G"
            + "A1UEChMHR0lQLUNQUzEYMBYGA1UECxMPR0lQLUNQUyBBTk9OWU1FFw0xMDAx"
            + "MDcwMzAwMTVaFw0xMDAxMTMwMzAwMTVaMACgTjBMMB8GA1UdIwQYMBaAFBmt"
            + "0mwaycf8GtjEMIVj5XcC8NfiMAsGA1UdFAQEAgILgzAcBgNVHRIEFTATgRFh"
            + "Yy1naXBAZ2lwLWNwcy5mcjANBgkqhkiG9w0BAQUFAAOCAQEAtF1DdFl1MQvf"
            + "vNkbrCPuppNYcHen4+za/ZDepKuwHsH/OpKuaDJc4LndRgd5IwzfpCHkQGzt"
            + "shK50bakN8oaYJgthKIOIJzR+fn6NMjftfR2a27Hdk2o3eQXRHQ360qMbpSy"
            + "qPb3WfuBhxO2/DlLChJP+OxZIHtT/rNYgE0tlIv7swYi81Gq+DafzaZ9+A5t"
            + "I0L2Gp/NUDsp5dF6PllAGiXQzl27qkcu+r50w+u0gul3nobXgbwPcMSYuWUz"
            + "1lhA+uDn/EUWV4RSiJciCGSS10WCkFh1/YPo++mV15KDB0m+8chscrSu/bAl"
            + "B19LxL/pCX3qr5iLE9ss3olVImyFZg==");

    private void checkCircProcessing()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate caCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(circCA));
        X509Certificate crlCaCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(circCRLCA));
        X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(circCRL));

        List list = new ArrayList();

        list.add(caCert);
        list.add(crlCaCert);
        list.add(crl);

        CertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp);

        Date validDate = new Date(crl.getThisUpdate().getTime() + 60 * 60 * 1000);

        //validating path
        List certchain = new ArrayList();

        certchain.add(crlCaCert);
        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(caCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        //PKIXParameters param = new PKIXParameters(trust);

        PKIXBuilderParameters param = new PKIXBuilderParameters(trust, null);
        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setCertificate(crlCaCert);
        param.setTargetCertConstraints(certSelector);
        param.addCertStore(store);
        param.setRevocationEnabled(true);
        param.setDate(validDate);

        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)cpv.validate(cp, param);
    }

    private void checkPolicyProcessingAtDomainMatch()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate root = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("qvRooCa3.crt"));
        X509Certificate ca1 = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("suvaRoot1.crt"));
        X509Certificate ca2 = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("suvaEmail1.crt"));
        X509Certificate ee = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("suvaEE.crt"));

        List certchain = new ArrayList();
        certchain.add(ee);
        certchain.add(ca2);
        certchain.add(ca1);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);
        param.setDate(new Date(0x156445410b4L)); // around 1st August 2016

        CertPath cp = cf.generateCertPath(certchain);

        MyChecker checker = new MyChecker();
        param.addCertPathChecker(checker);

        PKIXCertPathValidatorResult result =
            (PKIXCertPathValidatorResult)cpv.validate(cp, param);
    }

    public void testEmptyPath()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.rootCertBin));

        List list = new ArrayList();
        list.add(rootCert);
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");

        List certchain = new ArrayList();
        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        MyChecker checker = new MyChecker();
        param.addCertPathChecker(checker);

        try
        {
            cpv.validate(cp, param);
        }
        catch (CertPathValidatorException e)
        {
            if (!"Certification path is empty.".equals(e.getMessage()))
            {
                fail("message mismatch");
            }
        }
    }


    private void constraintTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("CERT_CI_ECDSA_NIST.pem"));
        X509Certificate interCert = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("CERT_EUM_ECDSA_NIST.pem"));
        X509Certificate finalCert = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("CERT_EUICC_ECDSA_NIST.pem"));

        List list = new ArrayList();
        list.add(interCert);
        list.add(finalCert);

        CertPath certPath = cf.generateCertPath(list);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        cpv.validate(certPath, param);

    }

    public void performTest()
        throws Exception
    {
        constraintTest();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        // initialise CertStore
        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.rootCertBin));
        X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.interCertBin));
        X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.finalCertBin));
        X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.rootCrlBin));
        X509CRL interCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.interCrlBin));
        List list = new ArrayList();
        list.add(rootCert);
        list.add(interCert);
        list.add(finalCert);
        list.add(rootCrl);
        list.add(interCrl);
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
        Date validDate = new Date(rootCrl.getThisUpdate().getTime() + 60 * 60 * 1000);
        //validating path
        List certchain = new ArrayList();
        certchain.add(finalCert);
        certchain.add(interCert);
      
        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);
        MyChecker checker = new MyChecker();
        param.addCertPathChecker(checker);

        PKIXCertPathValidatorResult result =
            (PKIXCertPathValidatorResult)cpv.validate(cp, param);
        PolicyNode policyTree = result.getPolicyTree();
        PublicKey subjectPublicKey = result.getPublicKey();

        if (checker.getCount() != 2)
        {
            fail("checker not evaluated for each certificate");
        }

        if (!subjectPublicKey.equals(finalCert.getPublicKey()))
        {
            fail("wrong public key returned");
        }

        isTrue(result.getTrustAnchor().getTrustedCert().equals(rootCert));

        // try a path with trust anchor included.
        certchain.clear();
        certchain.add(finalCert);
        certchain.add(interCert);
        certchain.add(rootCert);

        cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);

        cpv = CertPathValidator.getInstance("PKIX", "BC");
        param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);

        result = (PKIXCertPathValidatorResult)cpv.validate(cp, param);

        isTrue(result.getTrustAnchor().getTrustedCert().equals(rootCert));
        
        //
        // invalid path containing a valid one test
        //
        try
        {
            // initialise CertStore
            rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(AC_RAIZ_ICPBRASIL));
            interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(AC_PR));
            finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(schefer));

            list = new ArrayList();
            list.add(rootCert);
            list.add(interCert);
            list.add(finalCert);

            ccsp = new CollectionCertStoreParameters(list);
            store = CertStore.getInstance("Collection", ccsp);
            validDate = new Date(finalCert.getNotBefore().getTime() + 60 * 60 * 1000);

            //validating path
            certchain = new ArrayList();
            certchain.add(finalCert);
            certchain.add(interCert);
     
            cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
            trust = new HashSet();
            trust.add(new TrustAnchor(rootCert, null));

            cpv = CertPathValidator.getInstance("PKIX", "BC");
            param = new PKIXParameters(trust);
            param.addCertStore(store);
            param.setRevocationEnabled(false);
            param.setDate(validDate);

            result = (PKIXCertPathValidatorResult)cpv.validate(cp, param);
            policyTree = result.getPolicyTree();
            subjectPublicKey = result.getPublicKey();

            fail("Invalid path validated");
        }
        catch (Exception e)
        {
            if (!(e instanceof CertPathValidatorException
                && e.getMessage().startsWith("Could not validate certificate signature.")))
            {
                fail("unexpected exception", e);
            }
        }

        checkCircProcessing();
        checkPolicyProcessingAtDomainMatch();
        validateWithExtendedKeyUsage();
        testEmptyPath();
        checkInvalidCertPath();
    }

    // extended key usage chain
    static byte[] extEE = Base64.decode("MIICtDCCAh2gAwIBAgIBAzANBgkqhkiG9w0BAQUFADCBkjELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxKDAmBgNVBAsMH0JvdW5jeSBJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUxLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTE1MDMyNDAzNTEwOVoXDTE1MDUyMzAzNTEwOVowgZYxCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxGDAWBgNVBAMMD0VyaWMgSC4gRWNoaWRuYTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwWjANBgkqhkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKyK+WLaipil5hBm+EocqS9umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBEaNaMFgwHQYDVR0OBBYEFNBs7G01g7xVEhsMyz7+1yamFmRoMB8GA1UdIwQYMBaAFJQIM28yQPeHN9rRIKrtLqduyckeMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBBQUAA4GBAICrsNswvaXFMreUHHRHrhU4QqPOds8XJe0INx3v/5TfyjPPDMihMEm8WtWbVpFgFAqUQoZscf8cE/SO5375unYFgxrK+p2/je9E82VLF4Xb0cWizjQoWvvTmvFYjt43cGGXgySFLTrW87ju9uNFr/l4W9xvI0hoLI96vEW7Ccho");
    static byte[] extCA = Base64.decode("MIIDIzCCAoygAwIBAgIBAjANBgkqhkiG9w0BAQUFADBcMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTEjMCEGA1UECwwaQm91bmN5IFByaW1hcnkgQ2VydGlmaWNhdGUwHhcNMTUwMzI0MDM1MTA5WhcNMTUwNTIzMDM1MTA5WjCBkjELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxKDAmBgNVBAsMH0JvdW5jeSBJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUxLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCN4NETxec2lpyNKwR6JD+P4Y7a1kzenoQtNmkjDKSG98/d4fjuxU0ZBf/wSsyF5hCT4YDK3GzqQH8ZPUS7DpRJuNu0l4TNnjYmDDngapRymZeMbtgwByTohxmM/t4g8/veZY+ivQeL6Uajkr00nytJxIbiDEBViOMGcGyQFzCOaQIDAP//o4G9MIG6MB0GA1UdDgQWBBSUCDNvMkD3hzfa0SCq7S6nbsnJHjCBhAYDVR0jBH0we4AUwDYZB63EiJeoXnJvawnr5ebxKVyhYKReMFwxCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMSMwIQYDVQQLDBpCb3VuY3kgUHJpbWFyeSBDZXJ0aWZpY2F0ZYIBATASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBBQUAA4GBAJqUlDjse7Og+7qkkFsiXHzQ8FxT82hzfcji8W7bPwZddCPBEluxCJiJBPYXWsLvwo6BEmCDzT9lLQZ+QZyL1fVbOVHiI24hAalbEBEIrEO4GXMD9spqRQ5yoTJ8CgZHTPo0rJkH/ebprp0YHtahVF440zBOvuLM0QTYpERgO2Oe");
    static byte[] extTrust = Base64.decode("MIICJTCCAY4CAQEwDQYJKoZIhvcNAQEFBQAwXDELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxIzAhBgNVBAsMGkJvdW5jeSBQcmltYXJ5IENlcnRpZmljYXRlMB4XDTE1MDMyNDAzNTEwOVoXDTE1MDUyMzAzNTEwOVowXDELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxIzAhBgNVBAsMGkJvdW5jeSBQcmltYXJ5IENlcnRpZmljYXRlMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCyWdLW5ienaMlL42Fkwtn8edl6q5JTFA5b8XdRGXcx1vdUDSUJ57n/7gpwpuJtVuktLt1/hauoVgC2kInzX2vb88KY4FhCU12fBk5rA5HLfTBuCi0gxN+057SalkC96ibBCtacPwUAfOJRPO5Ez+AZmOYrbDY30/wDkQebJu421QIBETANBgkqhkiG9w0BAQUFAAOBgQCDNfqQnQbbmnGzZTl7ccWIyw7SPzWnijpKsQpuRNGkoXfkCcuQLZudytEFZGEL0cycNBnierjJWAn78zGpCQtab01r1GwytRMYz8qO5IIrhsJ4XNafNypYZbi0WtPa07UCQp8tipMbfQNLzSkvkIAaD5IfhdaWKLrSQJwmGg7YAg==");

    private void validateWithExtendedKeyUsage()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(extTrust));
        X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(extCA));
        X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(extEE));

        List list = new ArrayList();
        list.add(rootCert);
        list.add(interCert);
        list.add(finalCert);

        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
        Date validDate = new Date(rootCert.getNotBefore().getTime() + 60 * 60 * 1000);
        //validating path
        List certchain = new ArrayList();
        certchain.add(finalCert);
        certchain.add(interCert);
        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);
        param.setRevocationEnabled(false);

        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)cpv.validate(cp, param);
    }

    // invalid EE certificate
    static byte[] extInvEE = Base64.decode("MIICJjCCAY+gAwIBAAIGAV3Y0TnDMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBktQMSBDQTAeFw0xNzA4MTIyMzM5MzJaFw0xNzA4MTMwMDA5MzdaMBExDzANBgNVBAMMBktQMSBFRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAuOcqkp2+HBCuwRDwfR7kkUYXMdhScDG8m6A3Af6hpG86nAimNoVIQe3REaQ6IO0XSdd13rjjRwIXsUFLsrQhQJczF5JeyWXcaYqZyNNbUwFuLeSqOsLS63ltjOJYqOJRxY03Cr//baGWvxGXcRvHoZkg1nEXPcMZhgsy/9JxVoUCAwEAAaOBiDCBhTBABgNVHSMEOTA3gBSPMqzNmTdyjQmr9W1TSDW1h0ZzFaEXpBUwEzERMA8GA1UEAwwIS1AxIFJPT1SCBgFd2NE5wjAdBgNVHQ4EFgQUC1rtYrQdQkA3CLTeV1kbVIdysKQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADgYEAGr841G7E84Ow9+fFGW1zzXeTRfxsafdT/bHXCS75bjF2YPitKLcRLkm92VPxANRXIpmt++3iU/oduWqkLsfXnfTGmCwtjj/XrCvkCBQ4GONwmegltJEThMud0XOEB1UN6tfTINfLYpbyfOdE/wLy4Rte0t43aOTTOBo+/SapYOE=");
    static byte[] extInvCA = Base64.decode("MIICKDCCAZGgAwIBAgIGAV3Y0TnCMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCEtQMSBST09UMB4XDTE3MDgxMjIzMzkzMloXDTE3MDgxMzAwMDkzN1owETEPMA0GA1UEAwwGS1AxIENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7Qd/cTP5S0GoPcomcZU5QlJcb1uWydvmQx3U6p4/KOZBhk6JXQeSzT8QZ/gd+9vfosA62SEX+dq7MvxxzeERxdIsVU0zZ1TrYNxlQjnYXiYRVXBczowsxseQ9oSGD94Y4buhrMAltmIHijdzGRVMY41FZmWqNXqsEwQXj6ULX+QIDAQABo4GIMIGFMEAGA1UdIwQ5MDeAFAbfd2S3aiwFww3/0ocLa6ULQjJMoRekFTATMREwDwYDVQQDDAhLUDEgUk9PVIIGAV3Y0TnBMB0GA1UdDgQWBBSPMqzNmTdyjQmr9W1TSDW1h0ZzFTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOBgQCnmxQYy6LnvRSMxkTsGIQa4LB51O8skbWc4KYVDfcvTYQuvn6rE/ZoYf82jKXJzXksffanfjn/b38l4l8hwAcBQ8we9yjCkjO8OVDUlYiSGYUhH2ZJrl2+K2Z6wpakZ9Lz3pZ/PSS1FIsVd4I1jkexAdAm1+uMlfWXVt/uTZx98w==");
    static byte[] extInvTrust = Base64.decode("MIIBmjCCAQMCBgFd2NE5wTANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhLUDEgUk9PVDAeFw0xNzA4MTIyMzM5MzJaFw0xNzA4MTMwMDA5MzdaMBMxETAPBgNVBAMMCEtQMSBST09UMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8U3p6Y9ah0yQ58wpI3H6vQPMdhN6Hh+zuiNzwX3AIpEspUFTfqXJ6EIhqh/EraDnLnoFBajzihwS1y6a+ZyXYKa5pxbFsslmzms+ozcTaJ4mSMiC+DHbGYdOAEzwx2nsEt7UKyrlnl5h2kQFusUPmnXXEorIxhpS2Lul+zEBo1wIDAQABMA0GCSqGSIb3DQEBCwUAA4GBABClwXaJ8S66GmeySf1thOPc1GxIHuubezIjcBbECLZQqn7iwuzp+eft1vtnqNP7BWM1xBZkSe+/2xUsArc1rb1ffZHF3k92+WLbpDh3+NsQIod/91HRWUuu/S2g9oMK4b7BH8JrmBgy3ewtpNZwOaKF613GPCeGv3ya5Z24vBu+");

    static byte[] extInvV2Trust = Base64.decode("MIIBmjCCAQMCBgFd2NhVgTANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhLUDEgUk9PVDAeFw0xNzA4MTIyMzQ3MThaFw0xNzA4MTMwMDE3MjNaMBMxETAPBgNVBAMMCEtQMSBST09UMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQaASWM5avAAJ57eHQ2zQ0k/mAiYSOkRKDLEzptDPYfzuQtTdAlBPn7tsYx+Ylge4YQwtx5bQZbc3apinBK9tn+c++go0kUF1cec2bacYyFokSP2r48j6ZhlY4MYGfrvfWHULrG2JL2BMeuZVP+wiqXktXCEKVG1fh1m6RY0TJPwIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAC9mXO2i2vltBZZa7RMkizvhzhsehDHbEqvJd2aoWE9JG4sDo2tiIVN5vbq9EWLZVga3ejFzmQ+FI1Ty0xX3fwDgvUyxsveGTs40xwA9TEgVk1KNTQQs+sLE9rRB7L0giKn2DDmHFsOPL1KwxdzqD7vYhJr5av3eAsJpMxF+Anyg");
    static byte[] extInvV2CA = Base64.decode("MIICKDCCAZGgAwIBAgIGAV3Y2FWCMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCEtQMSBST09UMB4XDTE3MDgxMjIzNDcxOFoXDTE3MDgxMzAwMTcyM1owETEPMA0GA1UEAwwGS1AxIENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgb8h3h9d/FzhIc+PMbF0vwdiDKw7N3dNyY6TrmzCMC1mYDXSKmxxDwNKZCKj6VSNfbTDqxYKlZMoGVT8Cl/iE/+XEhOKYLv73rzTqzdMizqcQTCvwps1enGxI5wPBYKGCMWrpJui5RWV9wH6hMvmzSSZq7bdWTvc/pIltCpIj8wIDAQABo4GIMIGFMEAGA1UdIwQ5MDeAFMOcs/uWpVOkGRQJrVIp6cN6tCJQoRekFTATMREwDwYDVQQDDAhLUDEgUk9PVIIGAV3Y2FWBMB0GA1UdDgQWBBTsZ2B5JbgKm9/up2hOcYVyOaM1SjASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOBgQBI8J1bKh/e+uEZtfngKMADS1PSHztAPFFKXgeIfYeJDRznnamtbheensdxrA+aoriJbJfHxmjecr4xA8+s0uN9GPtQ3+ad1K5Sg6mfzsXtNPf3xa9y0pIWOGZavr1s/QugoPLQxEiuHrvkHX5+sZlx47KoBQJ8LBRmJydeSvxz1g==");
    static byte[] extInvV2EE = Base64.decode("MIICJjCCAY+gAwIBAQIGAV3Y2FWDMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBktQMSBDQTAeFw0xNzA4MTIyMzQ3MThaFw0xNzA4MTMwMDE3MjNaMBExDzANBgNVBAMMBktQMSBFRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzWXxtMpnjz8Q1qTdwpB66W2D0vEHhqow2PTsvfQdENL4AFESE1C7Cj3lLBTei1vRHCnpM0jdNghBW8k/u2b2tqeeWLBqwul0tEGbjtUwkYV2WgtTGmiYZZFfMH35HIvqlZMwIIdZqz4lEdkPiAPEUOELvycpVDFnWjF0qah5LqsCAwEAAaOBiDCBhTBABgNVHSMEOTA3gBTsZ2B5JbgKm9/up2hOcYVyOaM1SqEXpBUwEzERMA8GA1UEAwwIS1AxIFJPT1SCBgFd2NhVgjAdBgNVHQ4EFgQUfeKdn63Gmlkub8m8bwjqJook5ywwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADgYEAco35KYLE683l53J6V1q2tcMV3EpM39tifkL7Kl38oX9d3SGiKkEO6YFeQekRyto0Z91mPq7Pe/oOfDrfsY3r9KX7oqnhOKBnnR/58atM9udVLvuLfCJpxiroAldSkhRKvHG5MrFwZyDcVkTZF4GDrP6bojp32wVfU5EYkfwcJN8=");

    static byte[] extInvVersionTrust = Base64.decode("MIIBmjCCAQMCBgFd2RZiPjANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhLUDEgUk9PVDAeFw0xNzA4MTMwMDU1MDRaFw0xNzA4MTMwMTI1MDlaMBMxETAPBgNVBAMMCEtQMSBST09UMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPn6zObnrjGPUb0ozc3MCOOcHwtQABZmUHtB1jxRXWwYXKo+iTms2wJjDS5fhz2UmUptsbdFwPdvT2t7K8cpaZBcovC3jLvEAMmjO+nU3FQrdopZ6MhBjpgIezAvJ9LUhrYctqUJzfViqtLl0dL+YRjaVdfCz5z0iZn4rv2VSf3QIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAHtS9RjMIRzeEpH9MKIaMLR7wVb55MYW7E2CVuIbsHmT+KyDBFsYbAylgc76cH1b8F53ECygS9jCpzfKtO61WVPPlUhsL13i2XbzCtj8DSPXaW5pgvpwClQZ+dpGFz8D/MYLSdjTdls8dbhJ5O08ckSKcrIGHcF90oeepVXOmiTw");
    static byte[] extInvVersionCA = Base64.decode(    "MIICKDCCAZGgAwIBAgIGAV3ZFmI/MA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCEtQMSBST09UMB4XDTE3MDgxMzAwNTUwNFoXDTE3MDgxMzAxMjUwOVowETEPMA0GA1UEAwwGS1AxIENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChlaZhX9/eHmtfravHzs/E0g6ZhWTmD9aNNvuuz/GCBF9AMS6QQCGVhEzxESn0gLzs1bM/9M/EaylHS3Ecvi6QYdkrTKRDj38FDzrDhiPlM3TxY0XuUQ3Py590k8yZDcuEeVEQeoUx83qOnO7o/cL+vECfMj9ImYFFgY5sMcKkVQIDAQABo4GIMIGFMEAGA1UdIwQ5MDeAFAfTyJtmNkinVjfd7/2Giy6krDTpoRekFTATMREwDwYDVQQDDAhLUDEgUk9PVIIGAV3ZFmI+MB0GA1UdDgQWBBQkMq+wajXvKQaJtSdpvDJn77bU9zASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOBgQAqmKtykmixemAvppo2tTmekLsL93+/DMR+oz1iK2rjhqYzEF1/pM9VUyG+Ni1924U8tzGbXv2lL3MiToRSyjO50HHfnE7PfOvNiTUj73PTn27tPl03eWO3CtsOTGxtE2vpNyXyFXm4SFZlSicOXE0o/kUrNGVYvnjs/jjcNlPiHQ==");
    static byte[] extInvVersionEE = Base64.decode(   "MIICJjCCAY+gAwIBBQIGAV3ZFmJAMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBktQMSBDQTAeFw0xNzA4MTMwMDU1MDRaFw0xNzA4MTMwMTI1MDlaMBExDzANBgNVBAMMBktQMSBFRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA6PXdCOvE33+mMcal/rC+I7zdJqcc6OBhn+Lyku29TRcYplMA5mkh7WkjLtRYBUAzHukN/GXb1Mo+dFkvCnKO/l4gLWyVuf23rL6iELt8X1KVJdJlrDElCmTgl6lA0Omq7QhNrsv5Vdk7mK2mbJzl0bj4fcu5dc23nQXEskmGrZsCAwEAAaOBiDCBhTBABgNVHSMEOTA3gBQkMq+wajXvKQaJtSdpvDJn77bU96EXpBUwEzERMA8GA1UEAwwIS1AxIFJPT1SCBgFd2RZiPzAdBgNVHQ4EFgQU3Nw/DFxNqK1fRhc/W8W4o3mkCHQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADgYEAjMTiKgLC2Kb5+elvfD/+CM8pNeLt5Y43sMSTpgIrebdWPA2hyvjvW/upsIYIquGrymOYBU/K0abQlkNUbBHpQCQMPQ6iPXuhTQj/P7rt7McLl6OXV/DQqgF+39y0xWAzoZbgMKrQaSr9oRmEVt6xzLM92JS67w8Xgbh39PGBfEg=");

    static byte[] extInvExtTrust = Base64.decode("MIIBmjCCAQMCBgFd2SFqKjANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhLUDEgUk9PVDAeFw0xNzA4MTMwMTA3MDdaFw0xNzA4MTMwMTM3MTJaMBMxETAPBgNVBAMMCEtQMSBST09UMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEY3toxiphhoeoTd79/Uznb1YyKjYgxtXkYVQLZ+Q76bJFQftVVcUHw25/A/2qgSc8XPflGRpn82Qn/B7s3fxEglgeY0ekdYjea5+jZSJj70p1QcC60yH1NKGxE0ASBuv/22IoHhdu5dOTmiWegikKUXblBD1wAxbbvOcXFs2x/wIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAJPG9wt9edpTaCc0z03xGNF/M6x5cLx5eLgZaBFt+FO3S1xWIVby+iU8Hw2mzHOc58Fghw1jEwLaslQYadx9667NedGu7dYyY318h+VhaDppQqkhJiQl5Q8aTvVNt60fDEVLjvB7E6Z+CafVGR1jNrXxLDe6zVf/BZJK7QrkTKh4");
    static byte[] extInvExtCA = Base64.decode("MIICKDCCAZGgAwIBAgIGAV3ZIWorMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCEtQMSBST09UMB4XDTE3MDgxMzAxMDcwN1oXDTE3MDgxMzAxMzcxMlowETEPMA0GA1UEAwwGS1AxIENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCJKySmanEENpLJdPwpM/v0I7H0bW9ZlIxRpiL+/Z4uvF3j0r0O42Tm+dW8Ub42DzHcQ8pK/n/k2Wb4Jf7cP8+TGTAne3bgC24USW131XUZxaunGt4tCqZ0RNWpmBQUcUM0lgntDSfcvyv3QFB+nwLc93GYij9l3FaeUcHkwFiKsQIDAQABo4GIMIGFMEAGA1UdIwQ5MDeAFLnC9UF+JqEqboFH84ab9dEAkwEBoRekFTATMREwDwYDVQQDDAhLUDEgUk9PVIIGAV3ZIWoqMB0GA1UdDgQWBBQkr/0UP1MKPGQH7bkRNctHMsVQsjASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOBgQCZxLwkAPif1H2P398MHK3NLf3mrmLsP41ZphdHnSLNROlY9PdO5I/dfhElzVXW2oxecIIKbOQsjZe0FOSGvZHEhLftQmOdfGc5QfGf5w9CSFCCBe5vHdMjglRLVhNB51jz6DB7Dp0MjFDgkQI4lBHaiMVkE+HUZjNLwBddHH58Sw==");
    static byte[] extInvExtEE = Base64.decode("MIICNjCCAZ+gAwIBAgIGAV3ZIWosMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBktQMSBDQTAeFw0xNzA4MTMwMTA3MDdaFw0xNzA4MTMwMTM3MTJaMBExDzANBgNVBAMMBktQMSBFRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAj6WOoo8xHLLo+CT0l288xZDK3OsF64lPfNVkFnrRI65Ywl89M19nNF5Q24hF1FS6getO5oU+BhvRqft1/De22SME9SzKqs3G6uMxACKrMqgni1QBEOC/DdZ5Uaxh2s4lEgxbN0PQZIarAgLtAIgzRM4CrvofxFMwQy/neUuWmeMCAwEAAaOBmDCBlTBABgNVHSMEOTA3gBQkr/0UP1MKPGQH7bkRNctHMsVQsqEXpBUwEzERMA8GA1UEAwwIS1AxIFJPT1SCBgFd2SFqKzAdBgNVHQ4EFgQU/yuQXlvqXJQsbqB6whCPu5bwFCAwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4GBABYUGar9s7wlM3Qlnja7uc7U8FqU+xH4e8/Jk64ku7DdwXelEbKo/FTFAzh464aiFP4eMDOH7YThXyTruPudEAvYyWY7eaEgRqA2MmL0uWHSrN+HR9aBeqrMCJK/E2e1egvk2whJHMimhDUFJ3cIPsFhazMvLTnVgWGMjOqQtuP+");

    private void checkInvalidCertPath()
        throws Exception
    {
        checkInvalidPath(extInvTrust, extInvCA, extInvEE, "version 1 certificate contains extra data");
        checkInvalidPath(extInvV2Trust, extInvV2CA, extInvV2EE, "version 2 certificate cannot contain extensions");
        checkInvalidPath(extInvVersionTrust, extInvVersionCA, extInvVersionEE, "version number not recognised");
        checkInvalidPath(extInvExtTrust, extInvExtCA, extInvExtEE, "repeated extension found: 2.5.29.15");
    }

    private void checkInvalidPath(byte[] root, byte[] inter, byte[] ee, String expected)
        throws Exception
    {
        X509Certificate rootCert = new X509CertificateObject(X509CertificateStructure.getInstance(root));
        X509Certificate interCert = new X509CertificateObject(X509CertificateStructure.getInstance(inter));
        X509Certificate finalCert = new X509CertificateObject(X509CertificateStructure.getInstance(ee));
        List list = new ArrayList();
        list.add(rootCert);
        list.add(interCert);
        list.add(finalCert);

        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
        Date validDate = new Date(rootCert.getNotBefore().getTime() + 60 * 1000);
        //validating path
        List certchain = new ArrayList();
        certchain.add(finalCert);
        certchain.add(interCert);
        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);
        param.setRevocationEnabled(false);

        try
        {
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)cpv.validate(cp, param);
            fail("valid path passed");
        }
        catch (CertPathValidatorException e)
        {
            isTrue(e.getMessage().equals(expected));
        }

        // check that our cert factory also rejects - the EE is always the invalid one
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        try
        {
            cf.generateCertificate(new ByteArrayInputStream(ee));
        }
        catch (CertificateException e)
        {
            isTrue(e.getMessage().equals("parsing issue: " + expected));
        }
    }

    public String getName()
    {
        return "CertPathValidator";
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertPathValidatorTest());
    }

    private static class MyChecker
        extends PKIXCertPathChecker
    {
        private static int count;

        public void init(boolean forward)
            throws CertPathValidatorException
        {
            //To change body of implemented methods use File | Settings | File Templates.
        }

        public boolean isForwardCheckingSupported()
        {
            return true;
        }

        public Set getSupportedExtensions()
        {
            return null;
        }

        public void check(Certificate cert, Collection unresolvedCritExts)
            throws CertPathValidatorException
        {
            count++;
        }

        public int getCount()
        {
            return count;
        }
    }

    public static class X509CertificateObject
        extends X509Certificate
    {
        static final String CERTIFICATE_POLICIES = Extension.certificatePolicies.getId();
        static final String POLICY_MAPPINGS = Extension.policyMappings.getId();
        static final String INHIBIT_ANY_POLICY = Extension.inhibitAnyPolicy.getId();
        static final String ISSUING_DISTRIBUTION_POINT = Extension.issuingDistributionPoint.getId();
        static final String FRESHEST_CRL = Extension.freshestCRL.getId();
        static final String DELTA_CRL_INDICATOR = Extension.deltaCRLIndicator.getId();
        static final String POLICY_CONSTRAINTS = Extension.policyConstraints.getId();
        static final String BASIC_CONSTRAINTS = Extension.basicConstraints.getId();
        static final String CRL_DISTRIBUTION_POINTS = Extension.cRLDistributionPoints.getId();
        static final String SUBJECT_ALTERNATIVE_NAME = Extension.subjectAlternativeName.getId();
        static final String NAME_CONSTRAINTS = Extension.nameConstraints.getId();
        static final String AUTHORITY_KEY_IDENTIFIER = Extension.authorityKeyIdentifier.getId();
        static final String KEY_USAGE = Extension.keyUsage.getId();
        static final String CRL_NUMBER = Extension.cRLNumber.getId();
        static final String ANY_POLICY = "2.5.29.32.0";

        private org.bouncycastle.asn1.x509.X509CertificateStructure c;
        private BasicConstraints basicConstraints;
        private boolean[] keyUsage;
        private boolean hashValueSet;
        private int hashValue;

        public X509CertificateObject(
            org.bouncycastle.asn1.x509.X509CertificateStructure c)
            throws CertificateParsingException
        {
            this.c = c;

            try
            {
                byte[] bytes = this.getExtensionBytes("2.5.29.19");

                if (bytes != null)
                {
                    basicConstraints = BasicConstraints.getInstance(ASN1Primitive.fromByteArray(bytes));
                }
            }
            catch (Exception e)
            {
                throw new CertificateParsingException("cannot construct BasicConstraints: " + e);
            }

            try
            {
                byte[] bytes = this.getExtensionBytes("2.5.29.15");
                if (bytes != null)
                {
                    ASN1BitString bits = DERBitString.getInstance(ASN1Primitive.fromByteArray(bytes));

                    bytes = bits.getBytes();
                    int length = (bytes.length * 8) - bits.getPadBits();

                    keyUsage = new boolean[(length < 9) ? 9 : length];

                    for (int i = 0; i != length; i++)
                    {
                        keyUsage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
                    }
                }
                else
                {
                    keyUsage = null;
                }
            }
            catch (Exception e)
            {
                throw new CertificateParsingException("cannot construct KeyUsage: " + e);
            }
        }

        public void checkValidity()
            throws CertificateExpiredException, CertificateNotYetValidException
        {
            this.checkValidity(new Date());
        }

        public void checkValidity(
            Date date)
            throws CertificateExpiredException, CertificateNotYetValidException
        {
            if (date.getTime() > this.getNotAfter().getTime())  // for other VM compatibility
            {
                throw new CertificateExpiredException("certificate expired on " + c.getEndDate().getTime());
            }

            if (date.getTime() < this.getNotBefore().getTime())
            {
                throw new CertificateNotYetValidException("certificate not valid till " + c.getStartDate().getTime());
            }
        }

        public int getVersion()
        {
            return c.getVersion();
        }

        public BigInteger getSerialNumber()
        {
            return c.getSerialNumber().getValue();
        }

        public Principal getIssuerDN()
        {
            try
            {
                return new X509Principal(X500Name.getInstance(c.getIssuer().getEncoded()));
            }
            catch (IOException e)
            {
                return null;
            }
        }

        public X500Principal getIssuerX500Principal()
        {
            try
            {
                return new X500Principal(c.getIssuer().getEncoded());
            }
            catch (IOException e)
            {
                throw new IllegalStateException("can't encode issuer DN");
            }
        }

        public Principal getSubjectDN()
        {
            return new X509Principal(X500Name.getInstance(c.getSubject().toASN1Primitive()));
        }

        public X500Principal getSubjectX500Principal()
        {
            try
            {
                return new X500Principal(c.getSubject().getEncoded());
            }
            catch (IOException e)
            {
                throw new IllegalStateException("can't encode issuer DN");
            }
        }

        public Date getNotBefore()
        {
            return c.getStartDate().getDate();
        }

        public Date getNotAfter()
        {
            return c.getEndDate().getDate();
        }

        public byte[] getTBSCertificate()
            throws CertificateEncodingException
        {
            try
            {
                return c.getTBSCertificate().getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new CertificateEncodingException(e.toString());
            }
        }

        public byte[] getSignature()
        {
            return c.getSignature().getOctets();
        }

        /**
         * return a more "meaningful" representation for the signature algorithm used in
         * the certficate.
         */
        public String getSigAlgName()
        {
            Provider prov = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

            if (prov != null)
            {
                String algName = prov.getProperty("Alg.Alias.Signature." + this.getSigAlgOID());

                if (algName != null)
                {
                    return algName;
                }
            }

            Provider[] provs = Security.getProviders();

            //
            // search every provider looking for a real algorithm
            //
            for (int i = 0; i != provs.length; i++)
            {
                String algName = provs[i].getProperty("Alg.Alias.Signature." + this.getSigAlgOID());
                if (algName != null)
                {
                    return algName;
                }
            }

            return this.getSigAlgOID();
        }

        /**
         * return the object identifier for the signature.
         */
        public String getSigAlgOID()
        {
            return c.getSignatureAlgorithm().getAlgorithm().getId();
        }

        /**
         * return the signature parameters, or null if there aren't any.
         */
        public byte[] getSigAlgParams()
        {
            if (c.getSignatureAlgorithm().getParameters() != null)
            {
                try
                {
                    return c.getSignatureAlgorithm().getParameters().toASN1Primitive().getEncoded(ASN1Encoding.DER);
                }
                catch (IOException e)
                {
                    return null;
                }
            }
            else
            {
                return null;
            }
        }

        public boolean[] getIssuerUniqueID()
        {
            DERBitString id = c.getTBSCertificate().getIssuerUniqueId();

            if (id != null)
            {
                byte[] bytes = id.getBytes();
                boolean[] boolId = new boolean[bytes.length * 8 - id.getPadBits()];

                for (int i = 0; i != boolId.length; i++)
                {
                    boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
                }

                return boolId;
            }

            return null;
        }

        public boolean[] getSubjectUniqueID()
        {
            DERBitString id = c.getTBSCertificate().getSubjectUniqueId();

            if (id != null)
            {
                byte[] bytes = id.getBytes();
                boolean[] boolId = new boolean[bytes.length * 8 - id.getPadBits()];

                for (int i = 0; i != boolId.length; i++)
                {
                    boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
                }

                return boolId;
            }

            return null;
        }

        public boolean[] getKeyUsage()
        {
            return keyUsage;
        }

        public List getExtendedKeyUsage()
            throws CertificateParsingException
        {
            byte[] bytes = this.getExtensionBytes("2.5.29.37");

            if (bytes != null)
            {
                try
                {
                    ASN1InputStream dIn = new ASN1InputStream(bytes);
                    ASN1Sequence seq = (ASN1Sequence)dIn.readObject();
                    List list = new ArrayList();

                    for (int i = 0; i != seq.size(); i++)
                    {
                        list.add(((ASN1ObjectIdentifier)seq.getObjectAt(i)).getId());
                    }

                    return Collections.unmodifiableList(list);
                }
                catch (Exception e)
                {
                    throw new CertificateParsingException("error processing extended key usage extension");
                }
            }

            return null;
        }

        public int getBasicConstraints()
        {
            if (basicConstraints != null)
            {
                if (basicConstraints.isCA())
                {
                    if (basicConstraints.getPathLenConstraint() == null)
                    {
                        return Integer.MAX_VALUE;
                    }
                    else
                    {
                        return basicConstraints.getPathLenConstraint().intValue();
                    }
                }
                else
                {
                    return -1;
                }
            }

            return -1;
        }

        public Collection getSubjectAlternativeNames()
            throws CertificateParsingException
        {
            return getAlternativeNames(getExtensionBytes(Extension.subjectAlternativeName.getId()));
        }

        public Collection getIssuerAlternativeNames()
            throws CertificateParsingException
        {
            return getAlternativeNames(getExtensionBytes(Extension.issuerAlternativeName.getId()));
        }

        public Set getCriticalExtensionOIDs()
        {
            if (this.getVersion() == 3)
            {
                Set set = new HashSet();
                X509Extensions extensions = c.getTBSCertificate().getExtensions();

                if (extensions != null)
                {
                    Enumeration e = extensions.oids();

                    while (e.hasMoreElements())
                    {
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                        X509Extension ext = extensions.getExtension(oid);

                        if (ext.isCritical())
                        {
                            set.add(oid.getId());
                        }
                    }

                    return set;
                }
            }

            return null;
        }

        private byte[] getExtensionBytes(String oid)
        {
            X509Extensions exts = c.getTBSCertificate().getExtensions();

            if (exts != null)
            {
                X509Extension ext = exts.getExtension(new ASN1ObjectIdentifier(oid));
                if (ext != null)
                {
                    return ext.getValue().getOctets();
                }
            }

            return null;
        }

        public byte[] getExtensionValue(String oid)
        {
            X509Extensions exts = c.getTBSCertificate().getExtensions();

            if (exts != null)
            {
                X509Extension ext = exts.getExtension(new ASN1ObjectIdentifier(oid));

                if (ext != null)
                {
                    try
                    {
                        return ext.getValue().getEncoded();
                    }
                    catch (Exception e)
                    {
                        throw new IllegalStateException("error parsing " + e.toString());
                    }
                }
            }

            return null;
        }

        public Set getNonCriticalExtensionOIDs()
        {
            if (this.getVersion() == 3)
            {
                Set set = new HashSet();
                X509Extensions extensions = c.getTBSCertificate().getExtensions();

                if (extensions != null)
                {
                    Enumeration e = extensions.oids();

                    while (e.hasMoreElements())
                    {
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                        X509Extension ext = extensions.getExtension(oid);

                        if (!ext.isCritical())
                        {
                            set.add(oid.getId());
                        }
                    }

                    return set;
                }
            }

            return null;
        }

        public boolean hasUnsupportedCriticalExtension()
        {
            if (this.getVersion() == 3)
            {
                X509Extensions extensions = c.getTBSCertificate().getExtensions();

                if (extensions != null)
                {
                    Enumeration e = extensions.oids();

                    while (e.hasMoreElements())
                    {
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                        String oidId = oid.getId();

                        if (oidId.equals(KEY_USAGE)
                            || oidId.equals(CERTIFICATE_POLICIES)
                            || oidId.equals(POLICY_MAPPINGS)
                            || oidId.equals(INHIBIT_ANY_POLICY)
                            || oidId.equals(CRL_DISTRIBUTION_POINTS)
                            || oidId.equals(ISSUING_DISTRIBUTION_POINT)
                            || oidId.equals(DELTA_CRL_INDICATOR)
                            || oidId.equals(POLICY_CONSTRAINTS)
                            || oidId.equals(BASIC_CONSTRAINTS)
                            || oidId.equals(SUBJECT_ALTERNATIVE_NAME)
                            || oidId.equals(NAME_CONSTRAINTS))
                        {
                            continue;
                        }

                        X509Extension ext = extensions.getExtension(oid);

                        if (ext.isCritical())
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        public PublicKey getPublicKey()
        {
            try
            {
                return BouncyCastleProvider.getPublicKey(c.getSubjectPublicKeyInfo());
            }
            catch (IOException e)
            {
                return null;   // should never happen...
            }
        }

        public byte[] getEncoded()
            throws CertificateEncodingException
        {
            try
            {
                return c.getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new CertificateEncodingException(e.toString());
            }
        }

        public boolean equals(
            Object o)
        {
            if (o == this)
            {
                return true;
            }

            if (!(o instanceof Certificate))
            {
                return false;
            }

            Certificate other = (Certificate)o;

            try
            {
                byte[] b1 = this.getEncoded();
                byte[] b2 = other.getEncoded();

                return Arrays.areEqual(b1, b2);
            }
            catch (CertificateEncodingException e)
            {
                return false;
            }
        }

        public synchronized int hashCode()
        {
            if (!hashValueSet)
            {
                hashValue = calculateHashCode();
                hashValueSet = true;
            }

            return hashValue;
        }

        private int calculateHashCode()
        {
            try
            {
                int hashCode = 0;
                byte[] certData = this.getEncoded();
                for (int i = 1; i < certData.length; i++)
                {
                    hashCode += certData[i] * i;
                }
                return hashCode;
            }
            catch (CertificateEncodingException e)
            {
                return 0;
            }
        }

        public String toString()
        {
            StringBuffer buf = new StringBuffer();
            String nl = Strings.lineSeparator();

            buf.append("  [0]         Version: ").append(this.getVersion()).append(nl);
            buf.append("         SerialNumber: ").append(this.getSerialNumber()).append(nl);
            buf.append("             IssuerDN: ").append(this.getIssuerDN()).append(nl);
            buf.append("           Start Date: ").append(this.getNotBefore()).append(nl);
            buf.append("           Final Date: ").append(this.getNotAfter()).append(nl);
            buf.append("            SubjectDN: ").append(this.getSubjectDN()).append(nl);
            buf.append("           Public Key: ").append(this.getPublicKey()).append(nl);
            buf.append("  Signature Algorithm: ").append(this.getSigAlgName()).append(nl);

            byte[] sig = this.getSignature();

            buf.append("            Signature: ").append(new String(Hex.encode(sig, 0, 20))).append(nl);
            for (int i = 20; i < sig.length; i += 20)
            {
                if (i < sig.length - 20)
                {
                    buf.append("                       ").append(new String(Hex.encode(sig, i, 20))).append(nl);
                }
                else
                {
                    buf.append("                       ").append(new String(Hex.encode(sig, i, sig.length - i))).append(nl);
                }
            }

            X509Extensions extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                Enumeration e = extensions.oids();

                if (e.hasMoreElements())
                {
                    buf.append("       Extensions: \n");
                }

                while (e.hasMoreElements())
                {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                    X509Extension ext = extensions.getExtension(oid);

                    if (ext.getValue() != null)
                    {
                        byte[] octs = ext.getValue().getOctets();
                        ASN1InputStream dIn = new ASN1InputStream(octs);
                        buf.append("                       critical(").append(ext.isCritical()).append(") ");
                        try
                        {
                            if (oid.equals(Extension.basicConstraints))
                            {
                                buf.append(BasicConstraints.getInstance(dIn.readObject())).append(nl);
                            }
                            else if (oid.equals(Extension.keyUsage))
                            {
                                buf.append(KeyUsage.getInstance(dIn.readObject())).append(nl);
                            }
                            else if (oid.equals(MiscObjectIdentifiers.netscapeCertType))
                            {
                                buf.append(new NetscapeCertType((DERBitString)dIn.readObject())).append(nl);
                            }
                            else if (oid.equals(MiscObjectIdentifiers.netscapeRevocationURL))
                            {
                                buf.append(new NetscapeRevocationURL((DERIA5String)dIn.readObject())).append(nl);
                            }
                            else if (oid.equals(MiscObjectIdentifiers.verisignCzagExtension))
                            {
                                buf.append(new VerisignCzagExtension((DERIA5String)dIn.readObject())).append(nl);
                            }
                            else
                            {
                                buf.append(oid.getId());
                                buf.append(" value = ").append(ASN1Dump.dumpAsString(dIn.readObject())).append(nl);
                                //buf.append(" value = ").append("*****").append(nl);
                            }
                        }
                        catch (Exception ex)
                        {
                            buf.append(oid.getId());
                            //     buf.append(" value = ").append(new String(Hex.encode(ext.getExtnValue().getOctets()))).append(nl);
                            buf.append(" value = ").append("*****").append(nl);
                        }
                    }
                    else
                    {
                        buf.append(nl);
                    }
                }
            }

            return buf.toString();
        }

        public final void verify(
            PublicKey key)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException
        {
            Signature signature;
            String sigName = "SHA256withRSA";

            try
            {
                signature = Signature.getInstance(sigName, BouncyCastleProvider.PROVIDER_NAME);
            }
            catch (Exception e)
            {
                signature = Signature.getInstance(sigName);
            }

            checkSignature(key, signature);
        }

        public final void verify(
            PublicKey key,
            String sigProvider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException
        {
            String sigName = "SHA256withRSA";
            Signature signature;

            if (sigProvider != null)
            {
                signature = Signature.getInstance(sigName, sigProvider);
            }
            else
            {
                signature = Signature.getInstance(sigName);
            }

            checkSignature(key, signature);
        }

        public final void verify(
            PublicKey key,
            Provider sigProvider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException
        {
            String sigName = "SHA256withRSA";
            Signature signature;

            if (sigProvider != null)
            {
                signature = Signature.getInstance(sigName, sigProvider);
            }
            else
            {
                signature = Signature.getInstance(sigName);
            }

            checkSignature(key, signature);
        }

        private void checkSignature(
            PublicKey key,
            Signature signature)
            throws CertificateException, NoSuchAlgorithmException,
            SignatureException, InvalidKeyException
        {
            if (!isAlgIdEqual(c.getSignatureAlgorithm(), c.getTBSCertificate().getSignature()))
            {
                throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
            }

            ASN1Encodable params = c.getSignatureAlgorithm().getParameters();

            signature.initVerify(key);

            signature.update(this.getTBSCertificate());

            if (!signature.verify(this.getSignature()))
            {
                throw new SignatureException("certificate does not verify with supplied key");
            }
        }

        private boolean isAlgIdEqual(AlgorithmIdentifier id1, AlgorithmIdentifier id2)
        {
            if (!id1.getAlgorithm().equals(id2.getAlgorithm()))
            {
                return false;
            }

            if (id1.getParameters() == null)
            {
                if (id2.getParameters() != null && !id2.getParameters().equals(DERNull.INSTANCE))
                {
                    return false;
                }

                return true;
            }

            if (id2.getParameters() == null)
            {
                if (id1.getParameters() != null && !id1.getParameters().equals(DERNull.INSTANCE))
                {
                    return false;
                }

                return true;
            }

            return id1.getParameters().equals(id2.getParameters());
        }

        private static Collection getAlternativeNames(byte[] extVal)
            throws CertificateParsingException
        {
            if (extVal == null)
            {
                return null;
            }
            try
            {
                Collection temp = new ArrayList();
                Enumeration it = ASN1Sequence.getInstance(extVal).getObjects();
                while (it.hasMoreElements())
                {
                    GeneralName genName = GeneralName.getInstance(it.nextElement());
                    List list = new ArrayList();
                    list.add(Integers.valueOf(genName.getTagNo()));
                    switch (genName.getTagNo())
                    {
                    case GeneralName.ediPartyName:
                    case GeneralName.x400Address:
                    case GeneralName.otherName:
                        list.add(genName.getEncoded());
                        break;
                    case GeneralName.directoryName:
                        list.add(X500Name.getInstance(RFC4519Style.INSTANCE, genName.getName()).toString());
                        break;
                    case GeneralName.dNSName:
                    case GeneralName.rfc822Name:
                    case GeneralName.uniformResourceIdentifier:
                        list.add(((ASN1String)genName.getName()).getString());
                        break;
                    case GeneralName.registeredID:
                        list.add(ASN1ObjectIdentifier.getInstance(genName.getName()).getId());
                        break;
                    case GeneralName.iPAddress:
                        byte[] addrBytes = DEROctetString.getInstance(genName.getName()).getOctets();
                        final String addr;
                        try
                        {
                            addr = InetAddress.getByAddress(addrBytes).getHostAddress();
                        }
                        catch (UnknownHostException e)
                        {
                            continue;
                        }
                        list.add(addr);
                        break;
                    default:
                        throw new IOException("Bad tag number: " + genName.getTagNo());
                    }

                    temp.add(Collections.unmodifiableList(list));
                }
                if (temp.size() == 0)
                {
                    return null;
                }
                return Collections.unmodifiableCollection(temp);
            }
            catch (Exception e)
            {
                throw new CertificateParsingException(e.getMessage());
            }
        }
    }
}

