package org.bouncycastle.pkix.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PolicyNode;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkix.jcajce.X509RevocationChecker;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;

public class RevocationTest
    extends TestCase
{
    public static byte[] rootCertBin = Base64.decode(
        "MIIBqzCCARQCAQEwDQYJKoZIhvcNAQEFBQAwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTAeFw0wODA5MDQwNDQ1MDhaFw0wODA5MTEwNDQ1MDhaMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMRLUjhPe4YUdLo6EcjKcWUOG7CydFTH53Pr1lWjOkbmszYDpkhCTT9LOsI+disk18nkBxSl8DAHTqV+VxtuTPt64iyi10YxyDeep+DwZG/f8cVQv97U3hA9cLurZ2CofkMLGr6JpSGCMZ9FcstcTdHB4lbErIJ54YqfF4pNOs4/AgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAgyrTEFY7ALpeY59jL6xFOLpuPqoBOWrUWv6O+zy5BCU0qiX71r3BpigtxRj+DYcfLIM9FNERDoHu3TthD3nwYWUBtFX8N0QUJIdJabxqAMhLjSC744koiFpCYse5Ye3ZvEdFwDzgAQsJTp5eFGgTZPkPzcdhkFJ2p9+OWs+cb24=");


    static byte[] interCertBin = Base64.decode(
        "MIICSzCCAbSgAwIBAgIBATANBgkqhkiG9w0BAQUFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTA4MDkwNDA0NDUwOFoXDTA4MDkxMTA0NDUwOFowKDEmMCQGA1UEAxMdVGVzdCBJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAISS9OOZ2wxzdWny9aVvk4Joq+dwSJ+oqvHUxX3PflZyuiLiCBUOUE4q59dGKdtNX5fIfwyK3cpV0e73Y/0fwfM3m9rOWFrCKOhfeswNTes0w/2PqPVVDDsF/nj7NApuqXwioeQlgTL251RDF4sVoxXqAU7lRkcqwZt3mwqS4KTJAgMBAAGjgY4wgYswRgYDVR0jBD8wPYAUhv8BOT27EB9JaCccJD4YASPP5XWhIqQgMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGWCAQEwHQYDVR0OBBYEFL/IwAGOkHzaQyPZegy79CwM5oTFMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4GBAE4TRgUz4sUvZyVdZxqV+XyNRnqXAeLOOqFGYv2D96tQrS+zjd0elVlT6lFrtchZdOmmX7R6/H/tjMWMcTBICZyRYrvK8cCAmDOI+EIdq5p6lj2Oq6Pbw/wruojAqNrpaR6IkwNpWtdOSSupv4IJL+YU9q2YFTh4R1j3tOkPoFGr");

    static byte[] finalCertBin = Base64.decode(
        "MIICRjCCAa+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAoMSYwJAYDVQQDEx1UZXN0IEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZTAeFw0wODA5MDQwNDQ1MDhaFw0wODA5MTEwNDQ1MDhaMB8xHTAbBgNVBAMTFFRlc3QgRW5kIENlcnRpZmljYXRlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChpUeo0tPYywWKiLlbWKNJBcCpSaLSlaZ+4+yer1AxI5yJIVHP6SAlBghlbD5Qne5ImnN/15cz1xwYAiul6vGKJkVPlFEe2Mr+g/J/WJPQQPsjbZ1G+vxbAwXEDA4KaQrnpjRZFq+CdKHwOjuPLYS/MYQNgdIvDVEQcTbPQ8GaiQIDAQABo4GIMIGFMEYGA1UdIwQ/MD2AFL/IwAGOkHzaQyPZegy79CwM5oTFoSKkIDAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlggEBMB0GA1UdDgQWBBSVkw+VpqBf3zsLc/9GdkK9TzHPwDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0BAQUFAAOBgQBLv/0bVDjzTs/y1vN3FUiZNknEbzupIZduTuXJjqv/vBX+LDPjUfu/+iOCXOSKoRn6nlOWhwB1z6taG2usQkFG8InMkRcPREi2uVgFdhJ/1C3dAWhsdlubjdL926bftXvxnx/koDzyrePW5U96RlOQM2qLvbaky2Giz6hrc3Wl+w==");
    public static byte[] rootCrlBin = Base64.decode(
        "MIIBYjCBzAIBATANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlFw0wODA5MDQwNDQ1MDhaFw0wODA5MDQwNzMxNDhaMCIwIAIBAhcNMDgwOTA0MDQ0NTA4WjAMMAoGA1UdFQQDCgEJoFYwVDBGBgNVHSMEPzA9gBSG/wE5PbsQH0loJxwkPhgBI8/ldaEipCAwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZYIBATAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOBgQCAbaFCo0BNG4AktVf6jjBLeawP1u0ELYkOCEGvYZE0mBpQ+OvFg7subZ6r3lRIj030nUli28sPFtu5ZQMBNcpE4nS1ziF44RfT3Lp5UgHx9x17Krz781iEyV+7zU8YxYMY9wULD+DCuK294kGKIssVNbmTYXZatBNoXQN5CLIocA==");
    static byte[] interCrlBin = Base64.decode(
        "MIIBbDCB1gIBATANBgkqhkiG9w0BAQsFADAoMSYwJAYDVQQDEx1UZXN0IEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZRcNMDgwOTA0MDQ0NTA4WhcNMDgwOTA0MDczMTQ4WjAiMCACAQIXDTA4MDkwNDA0NDUwOFowDDAKBgNVHRUEAwoBCaBWMFQwRgYDVR0jBD8wPYAUv8jAAY6QfNpDI9l6DLv0LAzmhMWhIqQgMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGWCAQEwCgYDVR0UBAMCAQEwDQYJKoZIhvcNAQELBQADgYEAEVCr5TKs5yguGgLH+dBzmSPoeSIWJFLsgWwJEit/iUDJH3dgYmaczOcGxIDtbYYHLWIHM+P2YRyQz3MEkCXEgm/cx4y7leAmux5l+xQWgmxFPz+197vaphPeCZo+B7V1CWtm518gcq4mrs9ovfgNqgyFj7KGjcBpWdJE32KMt50=");

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
    private static final byte[] sampleTrust = Base64.decode(
        "MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT" +
            "MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i" +
            "YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG" +
            "EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg" +
            "R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9" +
            "9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq" +
            "fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv" +
            "iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU" +
            "1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+" +
            "bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW" +
            "MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA" +
            "ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l" +
            "uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn" +
            "Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS" +
            "tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF" +
            "PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un" +
            "hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV" +
            "5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==");

    private static final byte[] sampleCA = Base64.decode(
        "MIIETTCCAzWgAwIBAgIDAjpxMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT" +
            "MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i" +
            "YWwgQ0EwHhcNMTMxMjExMjM0NTUxWhcNMjIwNTIwMjM0NTUxWjBCMQswCQYDVQQG" +
            "EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSUmFwaWRTU0wg" +
            "U0hBMjU2IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1jBEgEu" +
            "l9h9GKrIwuWF4hdsYC7JjTEFORoGmFbdVNcRjFlbPbFUrkshhTIWX1SG5tmx2GCJ" +
            "a1i+ctqgAEJ2sSdZTM3jutRc2aZ/uyt11UZEvexAXFm33Vmf8Wr3BvzWLxmKlRK6" +
            "msrVMNI4/Bk7WxU7NtBDTdFlodSLwWBBs9ZwF8w5wJwMoD23ESJOztmpetIqYpyg" +
            "C04q18NhWoXdXBC5VD0tA/hJ8LySt7ecMcfpuKqCCwW5Mc0IW7siC/acjopVHHZD" +
            "dvDibvDfqCl158ikh4tq8bsIyTYYZe5QQ7hdctUoOeFTPiUs2itP3YqeUFDgb5rE" +
            "1RkmiQF1cwmbOwIDAQABo4IBSjCCAUYwHwYDVR0jBBgwFoAUwHqYaI2J+6sFZAwR" +
            "fap9ZbjKzE4wHQYDVR0OBBYEFJfCJ1CewsnsDIgyyHyt4qYBT9pvMBIGA1UdEwEB" +
            "/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMDYGA1UdHwQvMC0wK6ApoCeGJWh0" +
            "dHA6Ly9nMS5zeW1jYi5jb20vY3Jscy9ndGdsb2JhbC5jcmwwLwYIKwYBBQUHAQEE" +
            "IzAhMB8GCCsGAQUFBzABhhNodHRwOi8vZzIuc3ltY2IuY29tMEwGA1UdIARFMEMw" +
            "QQYKYIZIAYb4RQEHNjAzMDEGCCsGAQUFBwIBFiVodHRwOi8vd3d3Lmdlb3RydXN0" +
            "LmNvbS9yZXNvdXJjZXMvY3BzMCkGA1UdEQQiMCCkHjAcMRowGAYDVQQDExFTeW1h" +
            "bnRlY1BLSS0xLTU2OTANBgkqhkiG9w0BAQsFAAOCAQEANevhiyBWlLp6vXmp9uP+" +
            "bji0MsGj21hWID59xzqxZ2nVeRQb9vrsYPJ5zQoMYIp0TKOTKqDwUX/N6fmS/Zar" +
            "RfViPT9gRlATPSATGC6URq7VIf5Dockj/lPEvxrYrDrK3maXI67T30pNcx9vMaJR" +
            "BBZqAOv5jUOB8FChH6bKOvMoPF9RrNcKRXdLDlJiG9g4UaCSLT+Qbsh+QJ8gRhVd" +
            "4FB84XavXu0R0y8TubglpK9YCa81tGJUheNI3rzSkHp6pIQNo0LyUcDUrVNlXWz4" +
            "Px8G8k/Ll6BKWcZ40egDuYVtLLrhX7atKz4lecWLVtXjCYDqwSfC2Q7sRwrp0Mr8" +
            "2A==");

    // Tau Ceti Email Cert.
    private static final byte[] sampleEE = Base64.decode(
            "MIIF5DCCBMygAwIBAgIQXWymKNy5PxuC4PCrhdImEDANBgkqhkiG9w0BAQsFADBC" +
            "MQswCQYDVQQGEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMS" +
            "UmFwaWRTU0wgU0hBMjU2IENBMB4XDTE2MTEyODAwMDAwMFoXDTE5MDEyNzIzNTk1" +
            "OVowHjEcMBoGA1UEAwwTbWFpbC50YXVjZXRpLm9yZy5hdTCCASIwDQYJKoZIhvcN" +
            "AQEBBQADggEPADCCAQoCggEBAPK3JUkZfsxNIuZmLLgZuJCDmWbi3KVEi4YTjpSm" +
            "X3S+aZzO/QenA+den98fUFDIgch0X+S5mlvKRhdQuaJrtb5Y+W4QGieur9uQrind" +
            "8CP7/eu+lMD1UUbwcYosHX13eQ+zM6Z6TcjPXBgK79QWuKLIvOm1Xxqy4+c9EtFk" +
            "72555AOEjPS7PGZsOUBkoIWqp5p0Ryl+ZZ+DumZxNsggWgKBXL8eYL4uQVCAUvTY" +
            "I1sfNQvSYm/ACk4LvQHNIYPxD2eOycu9xttxfG6VBOLLwHrZUqmIgwu+XY0NcO+W" +
            "gowFtVD01R+jyVNMpnFxGovVbncym+0z71jP3cI93laO8TECAwEAAaOCAvgwggL0" +
            "MB4GA1UdEQQXMBWCE21haWwudGF1Y2V0aS5vcmcuYXUwCQYDVR0TBAIwADArBgNV" +
            "HR8EJDAiMCCgHqAchhpodHRwOi8vZ3Auc3ltY2IuY29tL2dwLmNybDBvBgNVHSAE" +
            "aDBmMGQGBmeBDAECATBaMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5yYXBpZHNz" +
            "bC5jb20vbGVnYWwwLAYIKwYBBQUHAgIwIAweaHR0cHM6Ly93d3cucmFwaWRzc2wu" +
            "Y29tL2xlZ2FsMB8GA1UdIwQYMBaAFJfCJ1CewsnsDIgyyHyt4qYBT9pvMA4GA1Ud" +
            "DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwVwYIKwYB" +
            "BQUHAQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8vZ3Auc3ltY2QuY29tMCYGCCsG" +
            "AQUFBzAChhpodHRwOi8vZ3Auc3ltY2IuY29tL2dwLmNydDCCAX4GCisGAQQB1nkC" +
            "BAIEggFuBIIBagFoAHYA3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvswA" +
            "AAFYqH/T8QAABAMARzBFAiEA06gAEejY34PZqiYmMsVR4UmD6cJg4j7l6NcbIfVi" +
            "aN0CICR9s94moCy9qgE63TZfsW+dHB3bcJL0Smxjo2+h4LCEAHYA7ku9t3XOYLrh" +
            "Qmkfq+GeZqMPfl+wctiDAMR7iXqo/csAAAFYqH/UOgAABAMARzBFAiEAu42gWW4w" +
            "9t+CSry8h8xXuveO/f0fdqo/fswaHa/L9ecCIGPueAD/ydOIkjskpnFkeNcHdXVa" +
            "a18AR8pzjW/IdMI+AHYAvHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKUA" +
            "AAFYqH/U7wAABAMARzBFAiEAiQrwaLoNvmFlNLapDYN18gA09iIAvtfAM0noB35a" +
            "wK8CIEjk9DPQthhMTtqDUA0LthHiLLeRIjlw9G7o3+4/a/A9MA0GCSqGSIb3DQEB" +
            "CwUAA4IBAQB1/JjAkaEFcQFeihxJvGc4DpbucdB0OfmQrkjH5HvSYi/5xlp+BOxM" +
            "es32KSI6CBiLhZviz3JVW05Zgz8tCEoV1D6kfmNQNQPXW958vO4QU88EPmbPo7fg" +
            "Hb38Xv1BesjNN7R7S/nS80hFFU1UsspsrfRJnEMshkD4Xrt8644g+5VqQGxeN0WZ" +
            "LkG40sYhBmVHwYBKIfefk8Erzxk58Fzfx4cIZZuIEqmVZVjuXGCmFzsW8StanBPP" +
            "8Vyr5e9TEEGbsEyjpibgzLqrphtSpBsN4OphPYWtFzQpgq09wqLkLkhEHp+EvwPN" +
            "gUt3Qm/EwLuDb+X5uVOqKWyP4PAlxmAr");

    static boolean initialized = false;

    static KeyPair trustKp;
    static KeyPair caKp;
    static KeyPair eeKp;

    // initialise CertStore
    static X509Certificate trustCert;
    static X509Certificate caCert;
    static X509Certificate eeCert;
    static X509Certificate eeCertWithDistPoint;

    static X509CRL trustCrl;
    static X509CRL caCrl;
    
    public void setUp()
        throws Exception
    {
        if(!initialized)
        {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

            kpGen.initialize(2048);

            trustKp = kpGen.generateKeyPair();
            caKp = kpGen.generateKeyPair();
            eeKp = kpGen.generateKeyPair();

            // initialise CertStore
            trustCert = TestUtil.makeTrustAnchor(trustKp, "CN=Trust Anchor");
            caCert = TestUtil.makeCaCertificate(trustCert, trustKp.getPrivate(), caKp.getPublic(), "CN=CA Cert");
            eeCert = TestUtil.makeEeCertificate(false, caCert, caKp.getPrivate(), eeKp.getPublic(), "CN=End Entity");
            eeCertWithDistPoint = TestUtil.makeEeCertificate(true, caCert, caKp.getPrivate(), eeKp.getPublic(), "CN=End Entity");
            trustCrl = TestUtil.makeCrl(trustCert, trustKp.getPrivate(), BigInteger.valueOf(100));
            caCrl = TestUtil.makeCrl(caCert, caKp.getPrivate(), BigInteger.valueOf(100));

            initialized = true;
        }
    }

    public void testValidPath()
        throws Exception
    {
        List list = new ArrayList();
        list.add(trustCert);
        list.add(caCert);
        list.add(eeCert);

        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
        Date validDate = new Date(trustCrl.getThisUpdate().getTime() + 60 * 60 * 1000);
        //validating path
        List certchain = new ArrayList();
        certchain.add(eeCert);
        certchain.add(caCert);

        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(trustCert, null));

        List<CRL> crls = new ArrayList<CRL>();
        crls.add(trustCrl);
        crls.add(caCrl);

        X509RevocationChecker revocationChecker = new X509RevocationChecker
            .Builder(new TrustAnchor(trustCert, null))
            .addCrls(new CollectionStore<CRL>(crls))
            .build();

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);
        param.setRevocationEnabled(false);

        param.addCertPathChecker(revocationChecker);

        PKIXCertPathValidatorResult result =
            (PKIXCertPathValidatorResult)cpv.validate(cp, param);
        PolicyNode policyTree = result.getPolicyTree();
        PublicKey subjectPublicKey = result.getPublicKey();

        if (!subjectPublicKey.equals(eeCert.getPublicKey()))
        {
            fail("wrong public key returned");
        }
    }

    public void testEndEntityOnly()
        throws Exception
    {
        List list = new ArrayList();
    
        list.add(caCert);
        list.add(eeCert);

        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
        Date validDate = new Date(trustCrl.getThisUpdate().getTime() + 60 * 60 * 1000);
        //validating path
        List certchain = new ArrayList();
        certchain.add(eeCert);
        certchain.add(caCert);

        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(trustCert, null));

        List<CRL> crls = new ArrayList<CRL>();
        crls.add(caCrl);

        X509RevocationChecker revocationChecker = new X509RevocationChecker
            .Builder(new TrustAnchor(trustCert, null))
            .setCheckEndEntityOnly(true)
            .addCrls(new CollectionStore<CRL>(crls))
            .build();

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);
        param.setRevocationEnabled(false);

        param.addCertPathChecker(revocationChecker);

        PKIXCertPathValidatorResult result =
            (PKIXCertPathValidatorResult)cpv.validate(cp, param);
        PolicyNode policyTree = result.getPolicyTree();
        PublicKey subjectPublicKey = result.getPublicKey();

        if (!subjectPublicKey.equals(eeCert.getPublicKey()))
        {
            fail("wrong public key returned");
        }
    }

    public void testRevokedEndEntityOnly()
        throws Exception
    {
        List list = new ArrayList();

        list.add(caCert);
        list.add(eeCert);

        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
        Date validDate = new Date(trustCrl.getThisUpdate().getTime() + 60 * 60 * 1000);
        //validating path
        List certchain = new ArrayList();
        certchain.add(eeCert);
        certchain.add(caCert);

        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(trustCert, null));

        List<CRL> crls = new ArrayList<CRL>();
        crls.add(TestUtil.makeCrl(caCert, caKp.getPrivate(), eeCert.getSerialNumber()));

        X509RevocationChecker revocationChecker = new X509RevocationChecker
            .Builder(new TrustAnchor(trustCert, null))
            .setCheckEndEntityOnly(true)
            .addCrls(new CollectionStore<CRL>(crls))
            .build();

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);
        param.setRevocationEnabled(false);

        param.addCertPathChecker(revocationChecker);

        try
        {
            PKIXCertPathValidatorResult result =
                (PKIXCertPathValidatorResult)cpv.validate(cp, param);
            fail("no exception");
        }
        catch (CertPathValidatorException e)
        {
            assertTrue(e.getMessage().startsWith("certificate [issuer=\"CN=CA Cert\",serialNumber=3,subject=\"CN=End Entity\"] revoked"));
            assertTrue(e.getMessage().endsWith(", reason: privilegeWithdrawn"));
        }
    }

    public void testRevokedEndEntityWithSoftFailure()
        throws Exception
    {
        List list = new ArrayList();

        list.add(caCert);
        list.add(eeCert);

        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
        Date validDate = new Date(trustCrl.getThisUpdate().getTime() + 60 * 60 * 1000);
        //validating path
        List certchain = new ArrayList();
        certchain.add(eeCertWithDistPoint);
        certchain.add(caCert);

        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(trustCert, null));

        List<CRL> crls = new ArrayList<CRL>();
        crls.add(TestUtil.makeCrl(caCert, caKp.getPrivate(), eeCert.getSerialNumber()));

        X509RevocationChecker revocationChecker = new X509RevocationChecker
            .Builder(new TrustAnchor(trustCert, null))
            .setCheckEndEntityOnly(true)
            .setSoftFailHardLimit(true, 0)
            .build();

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);
        param.setRevocationEnabled(false);

        param.addCertPathChecker(revocationChecker);

        PKIXCertPathValidatorResult result =
                (PKIXCertPathValidatorResult)cpv.validate(cp, param);

        // should fail on the second attempt.
        try
        {
            result =
                (PKIXCertPathValidatorResult)cpv.validate(cp, param);
            fail("no exception");
        }
        catch (CertPathValidatorException e)
        {
            assertTrue(e.getMessage().equals("No CRLs found for issuer \"cn=CA Cert\""));
        }
    }

    public void testRevokedWithCRLDistPointEndEntityOnly()
        throws Exception
    {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");
        List list = new ArrayList();

        X509Certificate trustCert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(sampleTrust));
        Certificate caCert = certFact.generateCertificate(new ByteArrayInputStream(sampleCA));
        Certificate eeCert = certFact.generateCertificate(new ByteArrayInputStream(sampleEE));

        list.add(caCert);
        list.add(eeCert);

        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
        Date validDate = new Date(trustCrl.getThisUpdate().getTime() + 60 * 60 * 1000);
        //validating path
        List certchain = new ArrayList();
        certchain.add(eeCert);
        certchain.add(caCert);

        CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
        Set trust = new HashSet();
        trust.add(new TrustAnchor(trustCert, null));

        List<CRL> crls = new ArrayList<CRL>();
       // crls.add(TestUtil.makeCrl(caCert, caKp.getPrivate(), eeCert.getSerialNumber()));

        X509RevocationChecker revocationChecker = new X509RevocationChecker
            .Builder(new TrustAnchor(trustCert, null))
            .setCheckEndEntityOnly(true)
            .addCrls(new CollectionStore<CRL>(crls))
            .usingProvider("BC")
            .build();

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setDate(validDate);
        param.setRevocationEnabled(false);

        param.addCertPathChecker(revocationChecker);

        try
        {
            PKIXCertPathValidatorResult result =
                (PKIXCertPathValidatorResult)cpv.validate(cp, param);

        }
        catch (CertPathValidatorException e)
        {
            fail(e.getMessage());
        }
    }
}
