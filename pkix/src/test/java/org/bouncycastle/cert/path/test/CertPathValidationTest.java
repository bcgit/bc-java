package org.bouncycastle.cert.path.test;

import java.security.Security;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.path.CertPath;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationResult;
import org.bouncycastle.cert.path.validations.BasicConstraintsValidation;
import org.bouncycastle.cert.path.validations.CRLValidation;
import org.bouncycastle.cert.path.validations.KeyUsageValidation;
import org.bouncycastle.cert.path.validations.ParentCertIssuedValidation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class CertPathValidationTest
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

//    private void checkCircProcessing()
//        throws Exception
//    {
//        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
//
//        X509Certificate caCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(circCA));
//        X509Certificate crlCaCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(circCRLCA));
//        X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(circCRL));
//
//        List list = new ArrayList();
//
//        list.add(caCert);
//        list.add(crlCaCert);
//        list.add(crl);
//
//        CertStoreParameters ccsp = new CollectionCertStoreParameters(list);
//        CertStore store = CertStore.getInstance("Collection", ccsp);
//
//        Calendar validDate = Calendar.getInstance();
//        validDate.set(2010,0,8,2,21,10);
//
//            //validating path
//        List certchain = new ArrayList();
//
//        certchain.add(crlCaCert);
//        CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);
//
//        Set trust = new HashSet();
//        trust.add(new TrustAnchor(caCert, null));
//
//        CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
//        //PKIXParameters param = new PKIXParameters(trust);
//
//        PKIXBuilderParameters param = new PKIXBuilderParameters(trust, null);
//        X509CertSelector certSelector = new X509CertSelector();
//        certSelector.setCertificate(crlCaCert);
//        param.setTargetCertConstraints(certSelector);
//        param.addCertStore(store);
//        param.setRevocationEnabled(true);
//        param.setDate(validDate.getTime());
//
//        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)cpv.validate(cp, param);
//    }

    private void basicConstraintsTest()
        throws Exception
    {
        byte[] cert = Base64.decode("MIIDRzCCAi+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3QgQW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowRTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFTATBgNVBAMTDFRydXN0IEFuY2hvcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALmZUYkRR+DNRbmEJ4ITAhbNRDmqrNsJw97iLE7bpFeflDUoNcJrZPZbC208bG+g5M0ATzV0vOqg88Ds1/FjFDK1oPItqsiDImJIq0xb/et5w72WNPxHVrcsr7Ap6DHfdwLpNMncqtzX92hU/iGVHLE/w/OCWwAIIbTHaxdrGMUG7DkJJ6iI7mzqpcyPvyAAo9O3SHjJr+uw5vSrHRretnV2un0bohvGslN64MY/UIiRnPFwd2gD76byDzoM1ioyLRCllfBJ5sRDz9xrUHNigTAUdlblb6yrnNtNJmkrROYvkh6sLETUh9EYh0Ar+94fZVXfGVi57Sw7x1jyANTlA40CAwEAAaNCMEAwHQYDVR0OBBYEFOR9X9FclYYILAWuvnW2ZafZXahmMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCYoa9uR55KJTkpwyPihIgXHq7/Z8dx3qZlCJQwE5qQBZXIsf5eC8Va/QjnTHOC4Gt4MwpnqqmoDqyqSW8pBVQgAUFAXqO91nLCQb4+/yfjiiNjzprpxQlcqIZYjJSVtckH1IDWFLFeuGW+OgPPEFgN4hjU5YFIsE2r1i4+ixkeuorxxsK1D/jYbVwQMXLqn1pjJttOPJwuA8+ho1f2c8FrKlqjHgOwxuHhsiGN6MKgs1baalpR/lnNFCIpq+/+3cnhufDjvxMy5lg+cwgMCiGzCxn4n4dBMw41C+4KhNF7ZtKuKSZ1eczztXD9NUkGUGw3LzpLDJazz3JhlZ/9pXzF");

        new BasicConstraintsValidation(true).validate(new CertPathValidationContext(new HashSet()), new X509CertificateHolder(cert));
    }

    public void performTest()
        throws Exception
    {
        basicConstraintsTest();

            // initialise CertStore
        X509CertificateHolder rootCert = new X509CertificateHolder(CertPathTest.rootCertBin);
        X509CertificateHolder interCert = new X509CertificateHolder(CertPathTest.interCertBin);
        X509CertificateHolder finalCert = new X509CertificateHolder(CertPathTest.finalCertBin);
        X509CRLHolder rootCrl = new X509CRLHolder(CertPathTest.rootCrlBin);
        X509CRLHolder interCrl =  new X509CRLHolder(CertPathTest.interCrlBin);

        CertPath path = new CertPath(new X509CertificateHolder[] { finalCert, interCert });
        X509ContentVerifierProviderBuilder verifier = new JcaX509ContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);

        CertPathValidationResult result = path.validate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier), new BasicConstraintsValidation(), new KeyUsageValidation()});

        if (!result.isValid())
        {
            fail("basic validation (1) not working");
        }

        result = path.evaluate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier), new BasicConstraintsValidation(), new KeyUsageValidation()});

        if (!result.isValid())
        {
            fail("basic evaluation (1) not working");
        }

        List crlList = new ArrayList();

        crlList.add(rootCrl);
        crlList.add(interCrl);

        Store crls = new CollectionStore(crlList);

        result = path.validate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier), new BasicConstraintsValidation(), new KeyUsageValidation(), new CRLValidation(rootCert.getSubject(), crls)});

        if (!result.isValid())
        {
            fail("basic validation (2) not working");
        }

        result = path.validate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier), new KeyUsageValidation(), new CRLValidation(rootCert.getSubject(), crls)});

        if (result.isValid() || result.getUnhandledCriticalExtensionOIDs().size() != 1
            || !result.getUnhandledCriticalExtensionOIDs().contains(Extension.basicConstraints))
        {
            fail("basic validation (3) not working");
        }

        result = path.validate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier), new CRLValidation(rootCert.getSubject(), crls)});

        if (result.isValid() || result.getUnhandledCriticalExtensionOIDs().size() != 2
            || !result.getUnhandledCriticalExtensionOIDs().contains(Extension.basicConstraints)
            || !result.getUnhandledCriticalExtensionOIDs().contains(Extension.keyUsage))
        {
            fail("basic validation (4) not working");
        }

        path = new CertPath(new X509CertificateHolder[] { interCert, finalCert });

        result = path.validate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier)});

        if (result.isValid())
        {
            fail("incorrect path validated!!");
        }

        result = path.evaluate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier)});

        if (result.isValid())
        {
            fail("incorrect path validated!!");
        }

        isTrue(result.isDetailed());
        
//        List list = new ArrayList();
//        list.add(rootCert);
//        list.add(interCert);
//        list.add(finalCert);
//        list.add(rootCrl);
//        list.add(interCrl);
//        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
//        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
//        Calendar validDate = Calendar.getInstance();
//        validDate.set(2008,8,4,14,49,10);
//            //validating path
//        List certchain = new ArrayList();
//        certchain.add(finalCert);
//        certchain.add(interCert);
//        CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);
//        Set trust = new HashSet();
//        trust.add(new TrustAnchor(rootCert, null));
//
//        CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
//        PKIXParameters param = new PKIXParameters(trust);
//        param.addCertStore(store);
//        param.setDate(validDate.getTime());
//        MyChecker checker = new MyChecker();
//        param.addCertPathChecker(checker);
//
//        PKIXCertPathValidatorResult result =
//            (PKIXCertPathValidatorResult) cpv.validate(cp, param);
//        PolicyNode policyTree = result.getPolicyTree();
//        PublicKey subjectPublicKey = result.getPublicKey();
//
//        if (checker.getCount() != 2)
//        {
//            fail("checker not evaluated for each certificate");
//        }
//
//        if (!subjectPublicKey.equals(finalCert.getPublicKey()))
//        {
//            fail("wrong public key returned");
//        }
//
//        //
//        // invalid path containing a valid one test
//        //
//        try
//        {
//                // initialise CertStore
//            rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(AC_RAIZ_ICPBRASIL));
//            interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(AC_PR));
//            finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(schefer));
//
//            list = new ArrayList();
//            list.add(rootCert);
//            list.add(interCert);
//            list.add(finalCert);
//
//            ccsp = new CollectionCertStoreParameters(list);
//            store = CertStore.getInstance("Collection", ccsp);
//            validDate = Calendar.getInstance();
//            validDate.set(2004,2,21,2,21,10);
//
//                //validating path
//            certchain = new ArrayList();
//            certchain.add(finalCert);
//            certchain.add(interCert);
//            cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);
//            trust = new HashSet();
//            trust.add(new TrustAnchor(rootCert, null));
//
//            cpv = CertPathValidator.getInstance("PKIX","BC");
//            param = new PKIXParameters(trust);
//            param.addCertStore(store);
//            param.setRevocationEnabled(false);
//            param.setDate(validDate.getTime());
//
//            result =(PKIXCertPathValidatorResult) cpv.validate(cp, param);
//            policyTree = result.getPolicyTree();
//            subjectPublicKey = result.getPublicKey();
//
//            fail("Invalid path validated");
//        }
//        catch (Exception e)
//        {
//            if (!(e instanceof CertPathValidatorException
//                && e.getMessage().startsWith("Could not validate certificate signature.")))
//            {
//                fail("unexpected exception", e);
//            }
//        }
//
//        checkCircProcessing();
    }

    public String getName()
    {
        return "CertPathValidator";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertPathValidationTest());
    }
}

