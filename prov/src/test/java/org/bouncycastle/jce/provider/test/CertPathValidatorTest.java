package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
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
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
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
        CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(caCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
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

        X509Certificate   root = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("qvRooCa3.crt"));
        X509Certificate   ca1 = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("suvaRoot1.crt"));
        X509Certificate   ca2 = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("suvaEmail1.crt"));
        X509Certificate   ee = (X509Certificate)cf.generateCertificate(this.getClass().getResourceAsStream("suvaEE.crt"));

        List certchain = new ArrayList();
        certchain.add(ee);
        certchain.add(ca2);
        certchain.add(ca1);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);
        param.setDate(new Date(0x156445410b4L)); // around 1st August 2016

        CertPath cp = cf.generateCertPath(certchain);

        MyChecker checker = new MyChecker();
        param.addCertPathChecker(checker);

        PKIXCertPathValidatorResult result =
            (PKIXCertPathValidatorResult) cpv.validate(cp, param);
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
        CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
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

    public void performTest()
        throws Exception
    {
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
        CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);
        MyChecker checker = new MyChecker();
        param.addCertPathChecker(checker);

        PKIXCertPathValidatorResult result =
            (PKIXCertPathValidatorResult) cpv.validate(cp, param);
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
            cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);
            trust = new HashSet();
            trust.add(new TrustAnchor(rootCert, null));

            cpv = CertPathValidator.getInstance("PKIX","BC");
            param = new PKIXParameters(trust);
            param.addCertStore(store);
            param.setRevocationEnabled(false);
            param.setDate(validDate);

            result =(PKIXCertPathValidatorResult) cpv.validate(cp, param);
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
        CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);
        param.setRevocationEnabled(false);

        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, param);
    }

    public String getName()
    {
        return "CertPathValidator";
    }

    public static void main(
        String[]    args)
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
}

