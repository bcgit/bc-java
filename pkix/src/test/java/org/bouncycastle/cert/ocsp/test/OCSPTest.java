package org.bouncycastle.cert.ocsp.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;
import java.util.Random;
import java.util.Set;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class OCSPTest
    extends SimpleTest
{
    byte[] testResp1 = Base64.decode(
        "MIIFnAoBAKCCBZUwggWRBgkrBgEFBQcwAQEEggWCMIIFfjCCARehgZ8wgZwx"
            + "CzAJBgNVBAYTAklOMRcwFQYDVQQIEw5BbmRocmEgcHJhZGVzaDESMBAGA1UE"
            + "BxMJSHlkZXJhYmFkMQwwCgYDVQQKEwNUQ1MxDDAKBgNVBAsTA0FUQzEeMBwG"
            + "A1UEAxMVVENTLUNBIE9DU1AgUmVzcG9uZGVyMSQwIgYJKoZIhvcNAQkBFhVv"
            + "Y3NwQHRjcy1jYS50Y3MuY28uaW4YDzIwMDMwNDAyMTIzNDU4WjBiMGAwOjAJ"
            + "BgUrDgMCGgUABBRs07IuoCWNmcEl1oHwIak1BPnX8QQUtGyl/iL9WJ1VxjxF"
            + "j0hAwJ/s1AcCAQKhERgPMjAwMjA4MjkwNzA5MjZaGA8yMDAzMDQwMjEyMzQ1"
            + "OFowDQYJKoZIhvcNAQEFBQADgYEAfbN0TCRFKdhsmvOdUoiJ+qvygGBzDxD/"
            + "VWhXYA+16AphHLIWNABR3CgHB3zWtdy2j7DJmQ/R7qKj7dUhWLSqclAiPgFt"
            + "QQ1YvSJAYfEIdyHkxv4NP0LSogxrumANcDyC9yt/W9yHjD2ICPBIqCsZLuLk"
            + "OHYi5DlwWe9Zm9VFwCGgggPMMIIDyDCCA8QwggKsoAMCAQICAQYwDQYJKoZI"
            + "hvcNAQEFBQAwgZQxFDASBgNVBAMTC1RDUy1DQSBPQ1NQMSYwJAYJKoZIhvcN"
            + "AQkBFhd0Y3MtY2FAdGNzLWNhLnRjcy5jby5pbjEMMAoGA1UEChMDVENTMQww"
            + "CgYDVQQLEwNBVEMxEjAQBgNVBAcTCUh5ZGVyYWJhZDEXMBUGA1UECBMOQW5k"
            + "aHJhIHByYWRlc2gxCzAJBgNVBAYTAklOMB4XDTAyMDgyOTA3MTE0M1oXDTAz"
            + "MDgyOTA3MTE0M1owgZwxCzAJBgNVBAYTAklOMRcwFQYDVQQIEw5BbmRocmEg"
            + "cHJhZGVzaDESMBAGA1UEBxMJSHlkZXJhYmFkMQwwCgYDVQQKEwNUQ1MxDDAK"
            + "BgNVBAsTA0FUQzEeMBwGA1UEAxMVVENTLUNBIE9DU1AgUmVzcG9uZGVyMSQw"
            + "IgYJKoZIhvcNAQkBFhVvY3NwQHRjcy1jYS50Y3MuY28uaW4wgZ8wDQYJKoZI"
            + "hvcNAQEBBQADgY0AMIGJAoGBAM+XWW4caMRv46D7L6Bv8iwtKgmQu0SAybmF"
            + "RJiz12qXzdvTLt8C75OdgmUomxp0+gW/4XlTPUqOMQWv463aZRv9Ust4f8MH"
            + "EJh4ekP/NS9+d8vEO3P40ntQkmSMcFmtA9E1koUtQ3MSJlcs441JjbgUaVnm"
            + "jDmmniQnZY4bU3tVAgMBAAGjgZowgZcwDAYDVR0TAQH/BAIwADALBgNVHQ8E"
            + "BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwkwNgYIKwYBBQUHAQEEKjAoMCYG"
            + "CCsGAQUFBzABhhpodHRwOi8vMTcyLjE5LjQwLjExMDo3NzAwLzAtBgNVHR8E"
            + "JjAkMCKgIKAehhxodHRwOi8vMTcyLjE5LjQwLjExMC9jcmwuY3JsMA0GCSqG"
            + "SIb3DQEBBQUAA4IBAQB6FovM3B4VDDZ15o12gnADZsIk9fTAczLlcrmXLNN4"
            + "PgmqgnwF0Ymj3bD5SavDOXxbA65AZJ7rBNAguLUo+xVkgxmoBH7R2sBxjTCc"
            + "r07NEadxM3HQkt0aX5XYEl8eRoifwqYAI9h0ziZfTNes8elNfb3DoPPjqq6V"
            + "mMg0f0iMS4W8LjNPorjRB+kIosa1deAGPhq0eJ8yr0/s2QR2/WFD5P4aXc8I"
            + "KWleklnIImS3zqiPrq6tl2Bm8DZj7vXlTOwmraSQxUwzCKwYob1yGvNOUQTq"
            + "pG6jxn7jgDawHU1+WjWQe4Q34/pWeGLysxTraMa+Ug9kPe+jy/qRX2xwvKBZ");

    byte[] testResp2 = Base64.decode(
        "MIII1QoBAKCCCM4wggjKBgkrBgEFBQcwAQEEggi7MIIItzCBjqADAgEAoSMw"
            + "ITEfMB0GA1UEAxMWT0NTUCBjZXJ0LVFBLUNMSUVOVC04NxgPMjAwMzA1MTky"
            + "MDI2MzBaMFEwTzA6MAkGBSsOAwIaBQAEFJniwiUuyrhKIEF2TjVdVdCAOw0z"
            + "BBR2olPKrPOJUVyGZ7BXOC4L2BmAqgIBL4AAGA8yMDAzMDUxOTIwMjYzMFow"
            + "DQYJKoZIhvcNAQEEBQADggEBALImFU3kUtpNVf4tIFKg/1sDHvGpk5Pk0uhH"
            + "TiNp6vdPfWjOgPkVXskx9nOTabVOBE8RusgwEcK1xeBXSHODb6mnjt9pkfv3"
            + "ZdbFLFvH/PYjOb6zQOgdIOXhquCs5XbcaSFCX63hqnSaEqvc9w9ctmQwds5X"
            + "tCuyCB1fWu/ie8xfuXR5XZKTBf5c6dO82qFE65gTYbGOxJBYiRieIPW1XutZ"
            + "A76qla4m+WdxubV6SPG8PVbzmAseqjsJRn4jkSKOGenqSOqbPbZn9oBsU0Ku"
            + "hul3pwsNJvcBvw2qxnWybqSzV+n4OvYXk+xFmtTjw8H9ChV3FYYDs8NuUAKf"
            + "jw1IjWegggcOMIIHCjCCAzMwggIboAMCAQICAQIwDQYJKoZIhvcNAQEEBQAw"
            + "bzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk1BMRAwDgYDVQQHEwdXYWx0aGFt"
            + "MRYwFAYDVQQKEw1Gb3J1bSBTeXN0ZW1zMQswCQYDVQQLEwJRQTEcMBoGA1UE"
            + "AxMTQ2VydGlmaWNhdGUgTWFuYWdlcjAeFw0wMzAzMjEwNTAwMDBaFw0yNTAz"
            + "MjEwNTAwMDBaMCExHzAdBgNVBAMTFk9DU1AgY2VydC1RQS1DTElFTlQtODcw"
            + "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVuxRCZgJAYAftYuRy"
            + "9axdtsHrkIJyVVRorLCTWOoLmx2tlrGqKbHOGKmvqEPEpeCDYQk+0WIlWMuM"
            + "2pgiYAolwqSFBwCjkjQN3fCIHXiby0JBgCCLoe7wa0pZffE+8XZH0JdSjoT3"
            + "2OYD19wWZeY2VB0JWJFWYAnIL+R5Eg7LwJ5QZSdvghnOWKTv60m/O1rC0see"
            + "9lbPO+3jRuaDyCUKYy/YIKBYC9rtC4hS47jg70dTfmE2nccjn7rFCPBrVr4M"
            + "5szqdRzwu3riL9W+IE99LTKXOH/24JX0S4woeGXMS6me7SyZE6x7P2tYkNXM"
            + "OfXk28b3SJF75K7vX6T6ecWjAgMBAAGjKDAmMBMGA1UdJQQMMAoGCCsGAQUF"
            + "BwMJMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQEEBQADggEBAKNSn7pp"
            + "UEC1VTN/Iqk8Sc2cAYM7KSmeB++tuyes1iXY4xSQaEgOxRa5AvPAKnXKSzfY"
            + "vqi9WLdzdkpTo4AzlHl5nqU/NCUv3yOKI9lECVMgMxLAvZgMALS5YXNZsqrs"
            + "hP3ASPQU99+5CiBGGYa0PzWLstXLa6SvQYoHG2M8Bb2lHwgYKsyrUawcfc/s"
            + "jE3jFJeyCyNwzH0eDJUVvW1/I3AhLNWcPaT9/VfyIWu5qqZU+ukV/yQXrKiB"
            + "glY8v4QDRD4aWQlOuiV2r9sDRldOPJe2QSFDBe4NtBbynQ+MRvF2oQs/ocu+"
            + "OAHX7uiskg9GU+9cdCWPwJf9cP/Zem6MemgwggPPMIICt6ADAgECAgEBMA0G"
            + "CSqGSIb3DQEBBQUAMG8xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJNQTEQMA4G"
            + "A1UEBxMHV2FsdGhhbTEWMBQGA1UEChMNRm9ydW0gU3lzdGVtczELMAkGA1UE"
            + "CxMCUUExHDAaBgNVBAMTE0NlcnRpZmljYXRlIE1hbmFnZXIwHhcNMDMwMzIx"
            + "MDUwMDAwWhcNMjUwMzIxMDUwMDAwWjBvMQswCQYDVQQGEwJVUzELMAkGA1UE"
            + "CBMCTUExEDAOBgNVBAcTB1dhbHRoYW0xFjAUBgNVBAoTDUZvcnVtIFN5c3Rl"
            + "bXMxCzAJBgNVBAsTAlFBMRwwGgYDVQQDExNDZXJ0aWZpY2F0ZSBNYW5hZ2Vy"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4VeU+48VBjI0mGRt"
            + "9qlD+WAhx3vv4KCOD5f3HWLj8D2DcoszVTVDqtRK+HS1eSpO/xWumyXhjV55"
            + "FhG2eYi4e0clv0WyswWkGLqo7IxYn3ZhVmw04ohdTjdhVv8oS+96MUqPmvVW"
            + "+MkVRyqm75HdgWhKRr/lEpDNm+RJe85xMCipkyesJG58p5tRmAZAAyRs3jYw"
            + "5YIFwDOnt6PCme7ui4xdas2zolqOlynMuq0ctDrUPKGLlR4mVBzgAVPeatcu"
            + "ivEQdB3rR6UN4+nv2jx9kmQNNb95R1M3J9xHfOWX176UWFOZHJwVq8eBGF9N"
            + "pav4ZGBAyqagW7HMlo7Hw0FzUwIDAQABo3YwdDARBglghkgBhvhCAQEEBAMC"
            + "AJcwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU64zBxl1yKES8tjU3/rBA"
            + "NaeBpjkwHwYDVR0jBBgwFoAU64zBxl1yKES8tjU3/rBANaeBpjkwDgYDVR0P"
            + "AQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4IBAQAzHnf+Z+UgxDVOpCu0DHF+"
            + "qYZf8IaUQxLhUD7wjwnt3lJ0QV1z4oyc6Vs9J5xa8Mvf7u1WMmOxvN8r8Kb0"
            + "k8DlFszLd0Qwr+NVu5NQO4Vn01UAzCtH4oX2bgrVzotqDnzZ4TcIr11EX3Nb"
            + "tO8yWWl+xWIuxKoAO8a0Rh97TyYfAj4++GIm43b2zIvRXEWAytjz7rXUMwRC"
            + "1ipRQwSA9gyw2y0s8emV/VwJQXsTe9xtDqlEC67b90V/BgL/jxck5E8yrY9Z"
            + "gNxlOgcqscObisAkB5I6GV+dfa+BmZrhSJ/bvFMUrnFzjLFvZp/9qiK11r5K"
            + "A5oyOoNv0w+8bbtMNEc1");

    /**
     * extra version number encoding.
     */
    private static byte[] irregReq = Base64.decode(
          "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");

    private static byte[] invalidResp = Base64.decode(
        "MIIGggoAoIIGfDCCBngGCSsGAQUFBzABAQSCBmkwggZlMIHeoTQwMjELMAkG"
      + "A1UEBhMCVVMxDTALBgNVBAoMBGlXYXkxFDASBgNVBAMMC2lXYXkgT3BlbkNB"
      + "GA8yMDEyMDEyMzIxMjkxMVowbjBsMEQwCQYFKw4DAhoFAAQUPA5ymcOyHyZJ"
      + "d7DAidsEh79Uh6QEFMHnDLGSc/VElMBzr5f0+LQnpN2YAgsA5xIzv2Ln0dAa"
      + "94IAGA8yMDEyMDEyMzIxMjkxMVqgERgPMjAxMjAxMjMyMTM0MTFaoSUwIzAh"
      + "BgkrBgEFBQcwAQIEFCHEdgCz5w64KgppPIetaRzxewinMA0GCSqGSIb3DQEB"
      + "CwUAA4IBAQBsW8cXR4eOLgclY/uRodjso/5xkHIAiJy+DpgqELRrnzKe87HO"
      + "Km7DCicz1nwsPJskK14xtIw1rfQ8nzgztriComAUVc/pxJ9wQWGZI3d2dNbW"
      + "AmecKb/mG0QrJrt3U5D0+CFTUq5u7NOs1jZRe+df9TDLBr0vIA6a0I6K9M9F"
      + "ZOPWU/j5KVjoi0/kv4wnxRzQ2zc4Z3b5gm9T0MXMH5bST3z4yhOs/NRezNTA"
      + "fBQvimS60d4fybH0pXcVYUH81y5fm9rCpuwQ6rMt2vi0ZKrfyVom4OIAr/gh"
      + "Doj8Yh/LdtI1RvFkAL3pvzs06cfg3qM38b9Uh9w93w4/Hguw14eroIIEbDCC"
      + "BGgwggRkMIIDTKADAgECAgEBMA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNVBAYT"
      + "AlVTMQ0wCwYDVQQKDARpV2F5MRQwEgYDVQQDDAtpV2F5IE9wZW5DQTAeFw0x"
      + "MjAxMjAxNTIyMjFaFw0zMjAxMTUxNTIyMjFaMDIxCzAJBgNVBAYTAlVTMQ0w"
      + "CwYDVQQKDARpV2F5MRQwEgYDVQQDDAtpV2F5IE9wZW5DQTCCASIwDQYJKoZI"
      + "hvcNAQEBBQADggEPADCCAQoCggEBALOnLWYPvGNLxodQQ16tqCKflpEQF2OA"
      + "0inZbIeUVxOgph5Qf562XV1Mtbv5Agv+z4/LSLbwuo28NTkhSlEEwf1k9vL9"
      + "/wFvpPZ4ecpqXOS6LJ6khmMh53IwK/QpG8CeF9UxTZskjQzD9XgnNGYd2BIj"
      + "qVbzU5qWhsPYPRrsAaE2jS6My5+xfiw46/Xj26VZQ/PR/rVURsc40fpCE30y"
      + "TyORQeeZfjb/LxXH3e/3wjya04MBACv+uX89n5YXG7OH6zTriMAOn/aiXPfE"
      + "E8g834RKvVS7ruELWG/IcZDC+Eoy2qtgG7y1rFlXd3H/6rny+Xd+BZrt0WP/"
      + "hfezklVw3asCAwEAAaOCAYMwggF/MA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0P"
      + "BAQDAgEGMB0GA1UdDgQWBBTB5wyxknP1RJTAc6+X9Pi0J6TdmDAfBgNVHSME"
      + "GDAWgBTB5wyxknP1RJTAc6+X9Pi0J6TdmDAjBgNVHREEHDAagRhzdXBwb3J0"
      + "QGl3YXlzb2Z0d2FyZS5jb20wIwYDVR0SBBwwGoEYc3VwcG9ydEBpd2F5c29m"
      + "dHdhcmUuY29tMIGYBggrBgEFBQcBAQSBizCBiDA5BggrBgEFBQcwAoYtaHR0"
      + "cDovL2l3NTRjZW50LXZtMi9wa2kvcHViL2NhY2VydC9jYWNlcnQuY3J0MCUG"
      + "CCsGAQUFBzABhhlodHRwOi8vaXc1NGNlbnQtdm0yOjI1NjAvMCQGCCsGAQUF"
      + "BzAMhhhodHRwOi8vaXc1NGNlbnQtdm0yOjgzMC8wOgYDVR0fBDMwMTAvoC2g"
      + "K4YpaHR0cDovL2l3NTRjZW50LXZtMi9wa2kvcHViL2NybC9jYWNybC5jcmww"
      + "DQYJKoZIhvcNAQELBQADggEBAE9wBjQ1c+HAO2gIzT+J5Gqgrcu/m7t4hnHN"
      + "m5eyIfwXD1T6wOhovFmzPTaO9BSNsi4G5R7yZxOHeLN4PIY2kwFIbSkg7mwe"
      + "5aGp2RPIuK/MtzMZT6pq8uMGhzyHGsqtdkz7p26/G0anU2u59eimcvISdwNE"
      + "QXOIp/KNUC+Vx+Pmfw8PuFYDNacZ6YXp5qKoEjyUoBhNicmVINTNfDu0CQhu"
      + "pDr2UmDMDT2cdmTSRC0rcTe3BNzWqtsXNmIBFL1oB7B0PZbmFm8Bgvk1azxa"
      + "ClrcOKZWKOWa14XJy/DJk6nlOiq5W2AglUt8JVOpa5oVdiNRIT2WoGnpqVV9"
      + "tUeoWog=");

    private static final String BC = "BC";

    public String getName()
    {
        return "OCSP";
    }

    private void testECDSA()
        throws Exception
    {
        String signDN = "O=Bouncy Castle, C=AU";
        KeyPair signKP = OCSPTestUtil.makeECKeyPair();
        X509CertificateHolder testCert = new JcaX509CertificateHolder(OCSPTestUtil.makeECDSACertificate(signKP, signDN, signKP, signDN));
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        GeneralName origName = new GeneralName(new X500Name(origDN));

        //
        // general id value for our test issuer cert and a serial number.
        //
        CertificateID id = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1));

        //
        // basic request generation
        //
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(id);

        OCSPReq req = gen.build();

        if (req.isSigned())
        {
            fail("signed but shouldn't be");
        }

        X509CertificateHolder[] certs = req.getCerts();

        if (certs.length != 0)
        {
            fail("0 certs expected, but not found");
        }

        Req[] requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // request generation with signing
        //
        X509CertificateHolder[] chain = new X509CertificateHolder[1];

        gen = new OCSPReqBuilder();

        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X500Name("CN=fred")));

        gen.addRequest(
            new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.build(new JcaContentSignerBuilder("SHA1withECDSA").setProvider(BC).build( signKP.getPrivate()), chain);

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("signature failed to verify");
        }

        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        certs = req.getCerts();

        if (certs == null)
        {
            fail("null certs found");
        }

        if (certs.length != 1 || !certs[0].equals(testCert))
        {
            fail("incorrect certs found in request");
        }

        //
        // encoding test
        //
        byte[] reqEnc = req.getEncoded();

        OCSPReq newReq = new OCSPReq(reqEnc);

        if (!newReq.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("newReq signature failed to verify");
        }

        //
        // request generation with signing and nonce
        //
        chain = new X509CertificateHolder[1];

        gen = new OCSPReqBuilder();

        Vector oids = new Vector();
        Vector values = new Vector();
        byte[] sampleNonce = new byte[16];
        Random rand = new Random();

        rand.nextBytes(sampleNonce);

        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X500Name("CN=fred")));

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(sampleNonce));

        gen.setRequestExtensions(extGen.generate());

        gen.addRequest(
            new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.build(new JcaContentSignerBuilder("SHA1withECDSA").setProvider(BC).build(signKP.getPrivate()), chain);

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("signature failed to verify");
        }

        //
        // extension check.
        //
        Set extOids = req.getCriticalExtensionOIDs();

        if (extOids.size() != 0)
        {
            fail("wrong number of critical extensions in OCSP request.");
        }

        extOids = req.getNonCriticalExtensionOIDs();

        if (extOids.size() != 1)
        {
            fail("wrong number of non-critical extensions in OCSP request.");
        }

        Extension extValue = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        ASN1Encodable extObj = extValue.getParsedValue();

        if (!(extObj instanceof ASN1OctetString))
        {
            fail("wrong extension type found.");
        }

        if (!areEqual(((ASN1OctetString)extObj).getOctets(), sampleNonce))
        {
            fail("wrong extension value found.");
        }

        //
        // request list check
        //
        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // response generation
        //
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(signKP.getPublic(), digCalcProv.get(RespID.HASH_SHA1));

        respGen.addResponse(id, CertificateStatus.GOOD);

        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withECDSA").setProvider(BC).build(signKP.getPrivate()), chain, new Date());
    }

    private void testRSA()
        throws Exception
    {
        String signDN = "O=Bouncy Castle, C=AU";
        KeyPair signKP = OCSPTestUtil.makeKeyPair();
        X509CertificateHolder testCert = new JcaX509CertificateHolder(OCSPTestUtil.makeCertificate(signKP, signDN, signKP, signDN));
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        GeneralName origName = new GeneralName(new X500Name(origDN));

        //
        // general id value for our test issuer cert and a serial number.
        //
        CertificateID id = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1));

        //
        // basic request generation
        //
        OCSPReqBuilder gen = new OCSPReqBuilder();

        gen.addRequest(
            new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1)));

        OCSPReq req = gen.build();

        if (req.isSigned())
        {
            fail("signed but shouldn't be");
        }

        X509CertificateHolder[] certs = req.getCerts();

        if (certs.length != 0)
        {
            fail("0 certs expected, but not found");
        }

        Req[] requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // request generation with signing
        //
        X509CertificateHolder[] chain = new X509CertificateHolder[1];

        gen = new OCSPReqBuilder();

        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X500Name("CN=fred")));

        gen.addRequest(
            new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(signKP.getPrivate()), chain);

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("signature failed to verify");
        }

        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        certs = req.getCerts();

        if (certs == null)
        {
            fail("null certs found");
        }

        if (certs.length != 1 || !certs[0].equals(testCert))
        {
            fail("incorrect certs found in request");
        }

        //
        // encoding test
        //
        byte[] reqEnc = req.getEncoded();

        OCSPReq newReq = new OCSPReq(reqEnc);

        if (!newReq.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("newReq signature failed to verify");
        }

        //
        // request generation with signing and nonce
        //
        chain = new X509CertificateHolder[1];

        gen = new OCSPReqBuilder();

        byte[] sampleNonce = new byte[16];
        Random rand = new Random();

        rand.nextBytes(sampleNonce);

        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X500Name("CN=fred")));

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(sampleNonce));

        gen.setRequestExtensions(extGen.generate());

        gen.addRequest(
            new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(signKP.getPrivate()), chain);

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("signature failed to verify");
        }

        //
        // extension check.
        //
        Set extOids = req.getCriticalExtensionOIDs();

        if (extOids.size() != 0)
        {
            fail("wrong number of critical extensions in OCSP request.");
        }

        extOids = req.getNonCriticalExtensionOIDs();

        if (extOids.size() != 1)
        {
            fail("wrong number of non-critical extensions in OCSP request.");
        }

        Extension ext = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        ASN1Encodable extObj = ext.getParsedValue();

        if (!(extObj instanceof ASN1OctetString))
        {
            fail("wrong extension type found.");
        }

        if (!areEqual(((ASN1OctetString)extObj).getOctets(), sampleNonce))
        {
            fail("wrong extension value found.");
        }

        //
        // request list check
        //
        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // response generation
        //
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(signKP.getPublic(), digCalcProv.get(RespID.HASH_SHA1));

        respGen.addResponse(id, CertificateStatus.GOOD);

        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(signKP.getPrivate()), chain, new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();

        byte[] enc = rGen.build(OCSPRespBuilder.SUCCESSFUL, resp).getEncoded();
    }

    private void testIrregularVersionReq()
        throws Exception
    {
        OCSPReq ocspRequest = new OCSPReq(irregReq);
        X509CertificateHolder cert = ocspRequest.getCerts()[0];
        if (!ocspRequest.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(cert)))
        {
            fail("extra version encoding test failed");
        }
    }

    public void testInvalidResp()
        throws Exception
    {
        try
        {
            OCSPResp response = new OCSPResp(invalidResp);
        }
        catch (CertIOException e)
        {
            if (e.getCause() instanceof ASN1Exception)
            {
                Throwable c = ((ASN1Exception)e.getCause()).getCause();

                if (!c.getMessage().equals("ENUMERATED has zero length"))
                {
                    fail("parsing failed, but for wrong reason: " + c.getMessage());
                }
            }
            else
            {
                fail("parsing failed, but for wrong reason: " + e.getMessage());
            }
        }


    }

    public void performTest()
        throws Exception
    {
        String signDN = "O=Bouncy Castle, C=AU";
        KeyPair signKP = OCSPTestUtil.makeKeyPair();
        X509CertificateHolder testCert = new JcaX509CertificateHolder(OCSPTestUtil.makeCertificate(signKP, signDN, signKP, signDN));

        String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        GeneralName origName = new GeneralName(new X500Name(origDN));
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        //
        // general id value for our test issuer cert and a serial number.
        //
        CertificateID id = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1));

        //
        // basic request generation
        //
        OCSPReqBuilder gen = new OCSPReqBuilder();

        gen.addRequest(
            new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1)));

        OCSPReq req = gen.build();

        if (req.isSigned())
        {
            fail("signed but shouldn't be");
        }

        X509CertificateHolder[] certs = req.getCerts();

        if (certs.length != 0)
        {
            fail("0 certs expected, but not found");
        }

        Req[] requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // request generation with signing
        //
        X509CertificateHolder[] chain = new X509CertificateHolder[1];

        gen = new OCSPReqBuilder();

        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X500Name("CN=fred")));

        gen.addRequest(
            new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(signKP.getPrivate()), chain);

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("signature failed to verify");
        }

        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        certs = req.getCerts();

        if (certs == null)
        {
            fail("null certs found");
        }

        if (certs.length != 1 || !certs[0].equals(testCert))
        {
            fail("incorrect certs found in request");
        }

        //
        // encoding test
        //
        byte[] reqEnc = req.getEncoded();

        OCSPReq newReq = new OCSPReq(reqEnc);

        if (!newReq.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("newReq signature failed to verify");
        }

        //
        // request generation with signing and nonce
        //
        chain = new X509CertificateHolder[1];

        gen = new OCSPReqBuilder();

        Vector oids = new Vector();
        Vector values = new Vector();
        byte[] sampleNonce = new byte[16];
        Random rand = new Random();

        rand.nextBytes(sampleNonce);

        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X500Name("CN=fred")));

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(sampleNonce));

        gen.setRequestExtensions(extGen.generate());

        gen.addRequest(
            new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(signKP.getPrivate()), chain);

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("signature failed to verify");
        }

        //
        // extension check.
        //
        Set extOids = req.getCriticalExtensionOIDs();

        if (extOids.size() != 0)
        {
            fail("wrong number of critical extensions in OCSP request.");
        }

        extOids = req.getNonCriticalExtensionOIDs();

        if (extOids.size() != 1)
        {
            fail("wrong number of non-critical extensions in OCSP request.");
        }

        Extension ext = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        ASN1Encodable extObj = ext.getParsedValue();

        if (!(extObj instanceof ASN1OctetString))
        {
            fail("wrong extension type found.");
        }

        if (!areEqual(((ASN1OctetString)extObj).getOctets(), sampleNonce))
        {
            fail("wrong extension value found.");
        }

        //
        // request list check
        //
        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // response parsing - test 1
        //
        OCSPResp response = new OCSPResp(testResp1);

        if (response.getStatus() != 0)
        {
            fail("response status not zero.");
        }

        BasicOCSPResp brep = (BasicOCSPResp)response.getResponseObject();
        chain = brep.getCerts();

        if (!brep.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(chain[0])))
        {
            fail("response 1 failed to verify.");
        }

        //
        // test 2
        //
        SingleResp[] singleResp = brep.getResponses();

        response = new OCSPResp(testResp2);

        if (response.getStatus() != 0)
        {
            fail("response status not zero.");
        }

        brep = (BasicOCSPResp)response.getResponseObject();
        chain = brep.getCerts();
        
        if (!brep.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(chain[0])))
        {
            fail("response 2 failed to verify.");
        }

        singleResp = brep.getResponses();

        //
        // simple response generation
        //
        OCSPRespBuilder respGen = new OCSPRespBuilder();
        OCSPResp resp = respGen.build(OCSPRespBuilder.SUCCESSFUL, response.getResponseObject());

        if (!resp.getResponseObject().equals(response.getResponseObject()))
        {
            fail("response fails to match");
        }

        testECDSA();
        testRSA();
        testIrregularVersionReq();
        testInvalidResp();

        //
        // Empty data test
        //
        try
        {
            response = new OCSPResp(new byte[0]);
            fail("no exception thrown");
        }
        catch (IOException e)
        {
             if (!e.getMessage().equals("malformed response: no response data found"))
             {
                 fail("wrong exception");
             }
        }

        try
        {
            req = new OCSPReq(new byte[0]);
            fail("no exception thrown");
        }
        catch (IOException e)
        {
             if (!e.getMessage().equals("malformed request: no request data found"))
             {
                 fail("wrong exception");
             }
        }
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OCSPTest());
    }
}
