package org.bouncycastle.cert.path.test;

import java.security.Security;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.path.CertPath;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationResult;
import org.bouncycastle.cert.path.validations.BasicConstraintsValidation;
import org.bouncycastle.cert.path.validations.KeyUsageValidation;
import org.bouncycastle.cert.path.validations.ParentCertIssuedValidation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class BasicConstraintsTest
    extends SimpleTest
{
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

    public String getName()
    {
        return "BasicConstraintsTest";
    }

    public void performTest()
        throws Exception
    {
        // Test dodgy chain with incorrect path lengths
        X509CertificateHolder root = new X509CertificateHolder(ROOT_CA);
        X509CertificateHolder interm1 = new X509CertificateHolder(INTERMEDIATE_WITH_PATHLEN_0);
        X509CertificateHolder interm2 = new X509CertificateHolder(SECOND_INTERMEDIATE);
        X509CertificateHolder leaf = new X509CertificateHolder(LEAF);

        CertPath path = new CertPath(new X509CertificateHolder[] {leaf, interm2, interm1, root});

        X509ContentVerifierProviderBuilder verifier = new JcaX509ContentVerifierProviderBuilder();
        CertPathValidation[] validations = new CertPathValidation[] {
                new ParentCertIssuedValidation(verifier),
                new BasicConstraintsValidation(),
                new KeyUsageValidation()
        };
        CertPathValidationResult cpvr = path.evaluate(validations);

        isTrue("Bad chain was accepted", !cpvr.isValid());
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BasicConstraintsTest());
    }
}