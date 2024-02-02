package org.bouncycastle.cert.path.test;

import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.path.CertPath;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationResult;
import org.bouncycastle.cert.path.validations.BasicConstraintsValidation;
import org.bouncycastle.cert.path.validations.CRLValidation;
import org.bouncycastle.cert.path.validations.CertificatePoliciesValidation;
import org.bouncycastle.cert.path.validations.CertificatePoliciesValidationBuilder;
import org.bouncycastle.cert.path.validations.KeyUsageValidation;
import org.bouncycastle.cert.path.validations.ParentCertIssuedValidation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.test.GeneralTest;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

public class CertPathGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        CertPathGeneralTest test = new CertPathGeneralTest();
        test.setUp();
        test.testCertPathValidation();
        test.testPKITSBasicConstraints();
        test.testBasicConstraints();
        test.testPKITSBasicConstraints2();
    }

    private static final byte[] ROOT_CA = Base64.decode(
        "MIIDVzCCAj+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwOjELMAkGA1UEBhMCQkUxGTAXBgNVBAoM" +
            "EEJhZCBQcmFjdGljZSBJbmMxEDAOBgNVBAMMB1Jvb3QgQ0EwIhgPMjAwMDAxMDEwMDAwMDBaGA8y" +
            "NTAwMDEwMTAwMDAwMFowOjELMAkGA1UEBhMCQkUxGTAXBgNVBAoMEEJhZCBQcmFjdGljZSBJbmMx" +
            "EDAOBgNVBAMMB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2kPDLm90A" +
            "CXhVf3M7blnC/lNC42NSjukq67+JbBWDKXyxm4tjV+qR4GbqCDYLK00hxQ1if1Qle3eYUwnEB356" +
            "P/CoH3NDlNPhy7m01H6Z6q2BDILT3OHSLX4dTMnrqCw7AsqVLP9nIb2ZH0yTGF5wAo+TMvHf88G5" +
            "1d05r2S21UEiG8/FC/idMbwqCn4NHrJqK1w+v6wh7Hd3FxelcZsfKLlOY9xHTwpWqCiQ97EoJ1Rp" +
            "BbyOWfBTnOX777LR4fil72eIEb6zsmq2694Xi9/TXTnMTcoZg7kBFDOdpB8+ImfHOpMaxIXeYBRU" +
            "mOV23fKWnL1p8eQCI24RyoX2/lBrAgMBAAGjYzBhMB0GA1UdDgQWBBQoBOAp7AB+2f7NcYXlUgvF" +
            "IdBmEzAfBgNVHSMEGDAWgBQoBOAp7AB+2f7NcYXlUgvFIdBmEzAPBgNVHRMBAf8EBTADAQH/MA4G" +
            "A1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAZca2ZPVBRS5U6QOWNiis88N/T5dAHKFX" +
            "GHt4LxMXpzcL5G3B5eqIKgxzYCjPq7ssEoPQmnOdZbtwhPq2o9eoosTyt7iEjCpaRsF4YxWL+RaK" +
            "f1ZcY1G2gC0Q0RPbiK2h27jtYVNpElx/lDW396srRwYWTDRSTuWReCQCJ08jzwuANHbJreEnQReL" +
            "BMn/smwpBge270+9iVQ5Vvb1M0egDh/LOYHcD86XvBcPZ2Pzdg4Tz1CpzA/gyfLEZ9VQvVJgcHPG" +
            "BaV+Vb42Wl9CIo3iW8ppVVsqhqAu7JPKb9+zm6Bf6RlKMurjhBw8duEfAFJRqRDxW4d2GUuoy7Pz" +
            "km5lUA==");

    public static final byte[] INTERMEDIATE_WITH_PATHLEN_0 = Base64.decode(
        "MIIDXTCCAkWgAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwOjELMAkGA1UEBhMCQkUxGTAXBgNVBAoM" +
            "EEJhZCBQcmFjdGljZSBJbmMxEDAOBgNVBAMMB1Jvb3QgQ0EwIhgPMjAwMDAxMDEwMDAwMDBaGA8y" +
            "MTAwMDEwMTAwMDAwMFowPTELMAkGA1UEBhMCQkUxGTAXBgNVBAoMEEJhZCBQcmFjdGljZSBJbmMx" +
            "EzARBgNVBAMMCkxhenkgQWRtaW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLMxhj" +
            "Z34ybAIt8tRRbej7NYRP7cxA3GwTkl66zp+UoS4zyW11vi8xqpCEcvDXqZJba/39iwdZY1urtCGd" +
            "bWTvOkTNPUaYiw0swXaTDe4ypI2895RRJhD34I/jCrcRXvA3uS12qIIeRXeYf5avC/hZcKIb9n2T" +
            "KUqMvw91jylgxTnadgBAy/meGlmPS7GdLAdRu6Iy01X7yMMagWsICTmNm5EOwRIgCkihvYaI9xbZ" +
            "ddfMD2hlJcMrSbs71fgOGjgmFkVJk+12UUtN48fwy4d7PniH3lxaasMdVVdGIh9F9+FyTRgd/jWO" +
            "rSLAORJTsvdk2x0wOoqsZhU8YzNEhr+rAgMBAAGjZjBkMB0GA1UdDgQWBBQSn/hs/IrjHLu9DgFd" +
            "+BScdoLKVDAfBgNVHSMEGDAWgBQoBOAp7AB+2f7NcYXlUgvFIdBmEzASBgNVHRMBAf8ECDAGAQH/" +
            "AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAtUhPwgwEfE1/1+0ZdRt6Mi6Y" +
            "s9jkWy6xdvbxLJZIYs/D6w1qlAMxYxy/+UL6KFSmhszbXRwiUcGa7ogWtG++HYSwzvP6lZoW94d9" +
            "F3hEtcR4abccwLlzY/2Na2KL7oG+/EjK1HKBptuwfaCrY7dyta1ZZmQ/X1OFYmW6XwKyEb7OBArp" +
            "8cGfrAaEvAyZy9P07NwJ6rAcuBf0lOzGf30QiV1GMlqpDztvzWcu4QqogbQ7WvYyHTpdKBADq/aD" +
            "LhWkRMxZSXUBVWhXs5n+psVBUcpAI0Bd+2dOw7wEM98CxLCgBCCLQ/afTZ4t+JbTO0rFxp9iL6Ry" +
            "6dYpRKhzcu40hQ=="
    );

    private static final byte[] SECOND_INTERMEDIATE = Base64.decode(
        "MIIDaTCCAlGgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwPTELMAkGA1UEBhMCQkUxGTAXBgNVBAoM" +
            "EEJhZCBQcmFjdGljZSBJbmMxEzARBgNVBAMMCkxhenkgQWRtaW4wIhgPMjAwMDAxMDEwMDAwMDBa" +
            "GA8yMTAwMDEwMTAwMDAwMFowSTELMAkGA1UEBhMCQkUxGTAXBgNVBAoMEEJhZCBQcmFjdGljZSBJ" +
            "bmMxHzAdBgNVBAMMFlNoYWRvdyBJbnRlcm1lZGlhdGUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB" +
            "DwAwggEKAoIBAQC+mDkqD8PmUk2UFfGR5xrEXXR3ZbMc0lXGyu9CQ8xO407YTXaqC8Fq+aKfWi2j" +
            "G7ELe1/7z0PHmizuOYsliB6IuamBmudH4mgDwrJ/TGERM9K9XqpT7wsILiOnGFpAFKZd8HDHhWrK" +
            "4OqEq2NVfCk/AJnBeo0/8aubNIa7wZo0tSx5tktXm4Y3GEc1d29qQ5ssYvHBt0UolvTs3a1CYXka" +
            "f2eCdMtUHHHSmenp7TIicpF/2R8mG5BfSBk9lC5JDt+IEgU0+qrXfrnrBCF9vDv+H7f+2bPvFWoX" +
            "TJzVkp9TXDfiB9fxGar4Rjm/n404fyQ1w+NTEf9ZZfOdsnG3Hkf5AgMBAAGjYzBhMB0GA1UdDgQW" +
            "BBR71YnxSE32AVQLtqtkIrCTNcd/0jAfBgNVHSMEGDAWgBQSn/hs/IrjHLu9DgFd+BScdoLKVDAP" +
            "BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAh9YuQktc" +
            "51W7SFx9iBAjT4itBqb14ENPmg4irACNKP7XljYv+a4DIPfcTZ7TuznSeIeBzJ7SrvNM0PY0XJPB" +
            "UuvMiGWJ/r/8EcOuoPmJUdvDeB8C864PM/ukC0RIBPvK/A+dFaEOe+hxpTsrDY8x+UrEcwgoKbpK" +
            "FfH5ZWmt9p3IZWOdad+wSu1TbNC1iPkbNKQyIBb4K4eG0tb1Hn9MOV5oNN0BilN+O9eqMdswVpLS" +
            "vuTF3vTuzlsuH8K8rKeoB5r8QU2CDmgp9LxIILlxc0WZxwSRj2iYRJTsfx/Ipmlhd5CLhylh5pG8" +
            "r8/7K1TKLJv9tEi9KRbT1E8wUD674g=="
    );

    private static final byte[] LEAF = Base64.decode(
        "MIIDVzCCAj+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwSTELMAkGA1UEBhMCQkUxGTAXBgNVBAoM" +
            "EEJhZCBQcmFjdGljZSBJbmMxHzAdBgNVBAMMFlNoYWRvdyBJbnRlcm1lZGlhdGUgQ0EwIhgPMjAw" +
            "MDAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowPDELMAkGA1UEBhMCQkUxGTAXBgNVBAoMEEJh" +
            "ZCBQcmFjdGljZSBJbmMxEjAQBgNVBAMMCVNvbWUgRHVkZTCCASIwDQYJKoZIhvcNAQEBBQADggEP" +
            "ADCCAQoCggEBAMts+SnvA1CY+Yb16qulKPA/MnQY3+qLVHXsFoK8sAemFRls8PawxIE5hchYIGAg" +
            "LQRQIDE2EaW6UBBturG/ZRkIZV29PM0v+nWVSnF3yXiJ8UayUQ6scdGy0Jgf4JvtLkVZqudv1w3b" +
            "qpiGAzzk7nam49zkR+kGmKBCHddQs1DgMhTYfgB6xiqYJLBN3yK/o/GH0Wz5F/tzBfEWl6qmGgFM" +
            "HEbfOzTKumELsIp36qzMNhULVlGfJj97/jS2T6FGDloUPo/y8ghcZCGEGKGDF6W5m5XS/eDkf9d8" +
            "sRHBqx+KXIF96UQaoR4HgBQ+HepiChlU+EQ8u8fnkkqdQoYUK00CAwEAAaNSMFAwHQYDVR0OBBYE" +
            "FElgP4sTTZUauvPVJ4B9IxXN9G+jMB8GA1UdIwQYMBaAFHvVifFITfYBVAu2q2QisJM1x3/SMA4G" +
            "A1UdDwEB/wQEAwIGwDANBgkqhkiG9w0BAQsFAAOCAQEAKOvEO/leSCnh7yKk6gtOpC6oxnG54orC" +
            "grklHbePC86I6Mnx09UZ3L+SDWHdR+Nk1nEieyXyL7W9uv/f0J73O4dphigaVNDisWQFZB6h7wRo" +
            "YkrW3oRTGLHSjHnJzdHj/4l+1ApZbOi+zFppAUiuASwUMU1aA9lcrKDzB47kBm5tRDp17wfwA1oG" +
            "0z4RCkQYBNhBmUnnx23rhq+wwKjYD8d6ITpXp/LGKp08nJbdJJQ0HW5iJvu9j4R5Us/tQ74MW1Zl" +
            "vk0TWcJ+Ms2vlwm4kl8tUBFj04XkVRIM+wjuaORO34k4Fe4ICVfCg2r9IhFTIOIWo8IdJ9hzTuhl" +
            "aG9ooQ=="
    );

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

    public void testBasicConstraints()
        throws Exception
    {
        // Test dodgy chain with incorrect path lengths
        X509CertificateHolder root = new X509CertificateHolder(ROOT_CA);
        X509CertificateHolder interm1 = new X509CertificateHolder(INTERMEDIATE_WITH_PATHLEN_0);
        X509CertificateHolder interm2 = new X509CertificateHolder(SECOND_INTERMEDIATE);
        X509CertificateHolder leaf = new X509CertificateHolder(LEAF);

        CertPath path = new CertPath(new X509CertificateHolder[]{leaf, interm2, interm1, root});
        X509CertificateHolder[] certHolders = path.getCertificates();
        assertEquals(4, path.length());
        assertEquals(certHolders[0].hashCode(), leaf.hashCode());

        X509ContentVerifierProviderBuilder verifier = new JcaX509ContentVerifierProviderBuilder();
        CertPathValidation[] validations = new CertPathValidation[]{
            new ParentCertIssuedValidation(verifier),
            new BasicConstraintsValidation(),
            new KeyUsageValidation()
        };
        CertPathValidationResult cpvr = path.evaluate(validations);

        assertFalse(cpvr.isValid());
        assertTrue(cpvr.getCause().getMessage().contains("path length exceeded"));
        assertEquals(0, cpvr.getFailingCertIndex());
        assertEquals(1, cpvr.getFailingRuleIndex());
        assertTrue(cpvr.isDetailed());
        assertEquals(1, cpvr.getCauses().length);
        assertEquals(1, cpvr.getFailingCertIndexes().length);
        assertEquals(1, cpvr.getFailingRuleIndexes().length);
    }

    private static X509CertificateHolder readPKITSCert(String fileName)
        throws IOException
    {
        ASN1InputStream asn1In = new ASN1InputStream(TestResourceFinder.findTestResource(PKITSBasicConstraintsTest.PKITS_DATA_RESOURCE_PREFIX, fileName));
        return new X509CertificateHolder(Certificate.getInstance(asn1In.readObject()));
    }

    public void testPKITSBasicConstraints2()
        throws Exception
    {
        // PKITS 4.6.4
        String eeCertFile = "ValidbasicConstraintsNotCriticalTest4EE.crt";
        String[] intermCertFiles = new String[]{"basicConstraintsNotCriticalCACert.crt"};
        X509CertificateHolder[] certsInPath = new X509CertificateHolder[intermCertFiles.length + 2];
        certsInPath[certsInPath.length - 1] = readPKITSCert("TrustAnchorRootCertificate.crt");
        certsInPath[0] = readPKITSCert(eeCertFile);
        // order specified in PKITS is reversed from the one the validation API expects
        for (int i = 0; i < intermCertFiles.length; i++)
        {
            certsInPath[certsInPath.length - 2 - i] = readPKITSCert(intermCertFiles[i]);
        }
        CertPath path = new CertPath(certsInPath);

        X509ContentVerifierProviderBuilder verifier = new JcaX509ContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider());

        BasicConstraintsValidation bcv = new BasicConstraintsValidation();
        bcv.reset(new BasicConstraintsValidation().copy());
        KeyUsageValidation kuv = new KeyUsageValidation();
        kuv.reset(new KeyUsageValidation().copy());
        ParentCertIssuedValidation pciv = new ParentCertIssuedValidation(verifier);
        pciv.reset(new ParentCertIssuedValidation(verifier).copy());
        CertificatePoliciesValidationBuilder cpvb = new CertificatePoliciesValidationBuilder();
        cpvb.setAnyPolicyInhibited(true);
        cpvb.setExplicitPolicyRequired(true);
        cpvb.setPolicyMappingInhibited(true);
        CertificatePoliciesValidation cpv = cpvb.build(path);

        CertPathValidation[] validators = new CertPathValidation[]{bcv, kuv, pciv, cpv};
        CertPathValidationResult cpvr = path.validate(validators);
        assertTrue(cpvr.isValid());

        cpvb.setAnyPolicyInhibited(false);
        cpvb.setExplicitPolicyRequired(false);
        cpvb.setPolicyMappingInhibited(false);
        cpv.reset(cpvb.build(path).copy());
        validators = new CertPathValidation[]{bcv, kuv, pciv, cpv};
        cpvr = path.validate(validators);
        assertFalse(cpvr.isValid());

//        expectBCValidationFailure(
//            "InvalidMissingbasicConstraintsTest1EE.crt",
//            new String[]{"MissingbasicConstraintsCACert.crt"},
//            "Basic constraints violated: issuer is not a CA");
//
//        cpvr = checkPKITSPath(eeCertFile, intermCertFiles);
    }

    private static CertPath readPKITSPath(String eeCertFile, String[] intermCertFiles)
        throws IOException
    {
        X509CertificateHolder[] certsInPath = new X509CertificateHolder[intermCertFiles.length + 2];
        certsInPath[certsInPath.length - 1] = readPKITSCert("TrustAnchorRootCertificate.crt");
        certsInPath[0] = readPKITSCert(eeCertFile);
        // order specified in PKITS is reversed from the one the validation API expects
        for (int i = 0; i < intermCertFiles.length; i++)
        {
            certsInPath[certsInPath.length - 2 - i] = readPKITSCert(intermCertFiles[i]);
        }
        return new CertPath(certsInPath);
    }

    private static CertPathValidationResult checkPKITSPath(String eeCertFile, String[] intermCertFiles)
        throws IOException
    {
        CertPath path = readPKITSPath(eeCertFile, intermCertFiles);

        X509ContentVerifierProviderBuilder verifier = new JcaX509ContentVerifierProviderBuilder();
        CertificatePoliciesValidationBuilder cpvb = new CertificatePoliciesValidationBuilder();
        cpvb.setAnyPolicyInhibited(true);
        cpvb.setExplicitPolicyRequired(true);
        cpvb.setPolicyMappingInhibited(true);
        CertificatePoliciesValidation cpv = cpvb.build(path);
        CertPathValidation[] validators = new CertPathValidation[]
            {new BasicConstraintsValidation(), new KeyUsageValidation(), new ParentCertIssuedValidation(verifier), cpv};
        return path.validate(validators);
    }

    private void expectBCValidationSuccess(String eeCertFile, String[] intermCertFiles)
        throws IOException
    {
        CertPathValidationResult cpvr = checkPKITSPath(eeCertFile, intermCertFiles);
        assertTrue(cpvr.isValid());
    }

    private void expectBCValidationFailure(String eeCertFile, String[] intermCertFiles, String expectedMessage)
        throws IOException
    {
        CertPathValidationResult cpvr = checkPKITSPath(eeCertFile, intermCertFiles);
        assertFalse(cpvr.isValid());
        String reasonMessage = cpvr.getCause().getMessage();
        assertEquals(expectedMessage, reasonMessage);

    }

    public void testPKITSBasicConstraints()
        throws Exception
    {
        // PKITS 4.6.1
        expectBCValidationFailure(
            "InvalidMissingbasicConstraintsTest1EE.crt",
            new String[]{"MissingbasicConstraintsCACert.crt"},
            "Basic constraints violated: issuer is not a CA");

        // this test should pass with isMandatory=false
        CertPath invalidPath = readPKITSPath(
            "InvalidMissingbasicConstraintsTest1EE.crt",
            new String[]{"MissingbasicConstraintsCACert.crt"});

        CertPathValidation[] lenientValidators = new CertPathValidation[]
            {new BasicConstraintsValidation(false), new KeyUsageValidation(),
                new ParentCertIssuedValidation(new JcaX509ContentVerifierProviderBuilder())};
        assertTrue(invalidPath.validate(lenientValidators).isValid());

        // PKITS 4.6.2
        expectBCValidationFailure(
            "InvalidcAFalseTest2EE.crt",
            new String[]{"basicConstraintsCriticalcAFalseCACert.crt"},
            "Basic constraints violated: issuer is not a CA");

        // PKITS 4.6.3
        expectBCValidationFailure(
            "InvalidcAFalseTest3EE.crt",
            new String[]{"basicConstraintsNotCriticalcAFalseCACert.crt"},
            "Basic constraints violated: issuer is not a CA");

        // PKITS 4.6.4
        expectBCValidationSuccess(
            "ValidbasicConstraintsNotCriticalTest4EE.crt",
            new String[]{"basicConstraintsNotCriticalCACert.crt"});

        // PKITS 4.6.5
        expectBCValidationFailure("InvalidpathLenConstraintTest5EE.crt",
            new String[]{"pathLenConstraint0CACert.crt", "pathLenConstraint0subCACert.crt"},
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.6
        expectBCValidationFailure("InvalidpathLenConstraintTest6EE.crt",
            new String[]{"pathLenConstraint0CACert.crt", "pathLenConstraint0subCACert.crt"},
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.7
        expectBCValidationSuccess(
            "ValidpathLenConstraintTest7EE.crt",
            new String[]{"pathLenConstraint0CACert.crt"});

        // PKITS 4.6.8
        expectBCValidationSuccess(
            "ValidpathLenConstraintTest8EE.crt",
            new String[]{"pathLenConstraint0CACert.crt"});

        // PKITS 4.6.9
        expectBCValidationFailure("InvalidpathLenConstraintTest9EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA0Cert.crt",
                "pathLenConstraint6subsubCA00Cert.crt",
            },
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.10
        expectBCValidationFailure("InvalidpathLenConstraintTest10EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA0Cert.crt",
                "pathLenConstraint6subsubCA00Cert.crt",
            },
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.11
        expectBCValidationFailure("InvalidpathLenConstraintTest11EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA1Cert.crt",
                "pathLenConstraint6subsubCA11Cert.crt",
                "pathLenConstraint6subsubsubCA11XCert.crt",
            },
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.12
        expectBCValidationFailure("InvalidpathLenConstraintTest12EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA1Cert.crt",
                "pathLenConstraint6subsubCA11Cert.crt",
                "pathLenConstraint6subsubsubCA11XCert.crt",
            },
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.13
        expectBCValidationSuccess("ValidpathLenConstraintTest13EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA4Cert.crt",
                "pathLenConstraint6subsubCA41Cert.crt",
                "pathLenConstraint6subsubsubCA41XCert.crt",
            });

        // PKITS 4.6.14
        expectBCValidationSuccess("ValidpathLenConstraintTest14EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA4Cert.crt",
                "pathLenConstraint6subsubCA41Cert.crt",
                "pathLenConstraint6subsubsubCA41XCert.crt",
            });

        // PKITS 4.6.15
        expectBCValidationSuccess("ValidSelfIssuedpathLenConstraintTest15EE.crt",
            new String[]{
                "pathLenConstraint0CACert.crt",
                "pathLenConstraint0SelfIssuedCACert.crt",
            });

        // PKITS 4.6.16
        expectBCValidationFailure("InvalidSelfIssuedpathLenConstraintTest16EE.crt",
            new String[]{
                "pathLenConstraint0CACert.crt",
                "pathLenConstraint0SelfIssuedCACert.crt",
                "pathLenConstraint0subCA2Cert.crt",
            },
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.17
        expectBCValidationSuccess("ValidSelfIssuedpathLenConstraintTest17EE.crt",
            new String[]{
                "pathLenConstraint1CACert.crt",
                "pathLenConstraint1SelfIssuedCACert.crt",
                "pathLenConstraint1subCACert.crt",
                "pathLenConstraint1SelfIssuedsubCACert.crt",
            });
    }

    public void testCertPathValidation()
        throws IOException
    {
        X509CertificateHolder rootCert = new X509CertificateHolder(CertPathTest.rootCertBin);
        X509CertificateHolder interCert = new X509CertificateHolder(CertPathTest.interCertBin);
        X509CertificateHolder finalCert = new X509CertificateHolder(CertPathTest.finalCertBin);
        X509CRLHolder rootCrl = new X509CRLHolder(CertPathTest.rootCrlBin);
        X509CRLHolder interCrl = new X509CRLHolder(CertPathTest.interCrlBin);

        CertPath path = new CertPath(new X509CertificateHolder[]{finalCert, interCert});
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
        CRLValidation cv = new CRLValidation(interCert.getSubject(), crls);
        cv.reset(new CRLValidation(rootCert.getSubject(), crls));

        result = path.validate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier), new BasicConstraintsValidation(), new KeyUsageValidation(), (CertPathValidation)cv.copy()});

        if (!result.isValid())
        {
            fail("basic validation (2) not working");
        }

        result = path.validate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier), new KeyUsageValidation(), (CertPathValidation)cv.copy()});

        if (result.isValid() || result.getUnhandledCriticalExtensionOIDs().size() != 1
            || !result.getUnhandledCriticalExtensionOIDs().contains(Extension.basicConstraints))
        {
            fail("basic validation (3) not working");
        }

        result = path.validate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier), (CertPathValidation)cv.copy()});

        if (result.isValid() || result.getUnhandledCriticalExtensionOIDs().size() != 2
            || !result.getUnhandledCriticalExtensionOIDs().contains(Extension.basicConstraints)
            || !result.getUnhandledCriticalExtensionOIDs().contains(Extension.keyUsage))
        {
            fail("basic validation (4) not working");
        }

        path = new CertPath(new X509CertificateHolder[]{interCert, finalCert});

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

        assertTrue(result.isDetailed());

//        testException("Could not validate certificate signature.", "CertPathValidatorException", new TestExceptionOperation()
//        {
//            @Override
//            public void operation()
//                throws Exception
//            {
//                CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
//                // initialise CertStore
//                X509Certificate rootCert1 = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(AC_RAIZ_ICPBRASIL));
//                X509Certificate interCert1 = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(AC_PR));
//                X509Certificate finalCert1 = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(schefer));
//
//                List list = new ArrayList();
//                list.add(rootCert1);
//                list.add(interCert1);
//                list.add(finalCert1);
//
//                CertStoreParameters ccsp = new CollectionCertStoreParameters(list);
//                CertStore store = CertStore.getInstance("Collection", ccsp);
//                Calendar validDate = Calendar.getInstance();
//                validDate.set(2004, 2, 21, 2, 21, 10);
//
//                //validating path
//                List certchain = new ArrayList();
//                certchain.add(finalCert1);
//                certchain.add(interCert1);
//                java.security.cert.CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
//                Set trust = new HashSet();
//                trust.add(new TrustAnchor(rootCert1, null));
//
//                CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
//                PKIXParameters param = new PKIXParameters(trust);
//                param.addCertStore(store);
//                param.setRevocationEnabled(false);
//                param.setDate(validDate.getTime());
//
//                PKIXCertPathValidatorResult result1 = (PKIXCertPathValidatorResult)cpv.validate(cp, param);
//                PolicyNode policyTree = result1.getPolicyTree();
//                PublicKey subjectPublicKey = result1.getPublicKey();
//            }
//        });
    }
}
