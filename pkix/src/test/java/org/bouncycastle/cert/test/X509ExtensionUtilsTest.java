package org.bouncycastle.cert.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class X509ExtensionUtilsTest
    extends SimpleTest
{
    private static byte[] pubKeyInfo = Base64.decode(
        "MFgwCwYJKoZIhvcNAQEBA0kAMEYCQQC6wMMmHYMZszT/7bNFMn+gaZoiWJLVP8ODRuu1C2jeAe" +
        "QpxM+5Oe7PaN2GNy3nBE4EOYkB5pMJWA0y9n04FX8NAgED");

    private static byte[] shaID = Hex.decode("d8128a06d6c2feb0865994a2936e7b75b836a021");
    private static byte[] shaTruncID = Hex.decode("436e7b75b836a021");

    private static byte[] v0Cert = Base64.decode("MIIBuTCCASICAQEwDQYJKoZIhvcNAQEFBQAwJTEWMBQGA1UECgwNQm91bmN5IENhc3RsZTELMAkGA1UEBhMCQVUwHhcNMTUwNzIxMjIwNzI3WhcNMTUxMDI5MjIwNzI3WjAlMRYwFAYDVQQKDA1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA9MhYrfDoC69iS/56gdvuwOvXKMsx9dSBZnK9KOnCFtc3fTeVp+61CeExuKXafqz0ZK/5ps0D+RMCOcIZXtXZsdC3CwgVx3k/CHKgrnp51v8sbgFzRrGr68Mp9Dr01wdgxjDCGgToUiBybU8IhsUc2nmwn3+Y+ZoIOvyQDuh3hXUCAwEAATANBgkqhkiG9w0BAQUFAAOBgQDvpEa3KFe7b+y7/MPNloabj6lfwW4vdKk4bg9+yMHFsb62OB8/RP4sJ+XIB91cGYINgA4d511juc9t6t7kEp6GijqWwAUtQfbyhZIO8DsCl96y3RfUag1L7Q3pn0SfyW0NAI8O9eKG/Hl6WmxRlvx3zmKz1bU+VSlnZoYt+6qZyg==");
    private static byte[] v3Cert = Base64.decode("MIICKzCCAZSgAwIBAgIBAjANBgkqhkiG9w0BAQUFADAlMRYwFAYDVQQKDA1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTAeFw0xNTA3MjEyMjA3MjdaFw0xNTEwMjkyMjA3MjdaMEMxDDAKBgNVBAMMA0JvYjEOMAwGA1UECwwFU2FsZXMxFjAUBgNVBAoMDUJvdW5jeSBDYXN0bGUxCzAJBgNVBAYTAkFVMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHpUGlsn0Y+az7XGj3wq+om/kGNbdP+bKE6Du6x92Mq2SC8Fez5RdOkhJJqxk5U8O+Hj9dqoxBkpeqA5NA52agXNz4WlSDBii17U9PPoj7LPXlfXMujf18k/IY71M79/XRjj/xbqNEJQQAH+EHyFMVxFDaOHJ4huL3gq/C7v9tTQIDAQABo00wSzAdBgNVHQ4EFgQUxHM/5+X91RvdmNdbNFZ02Fug92wwHwYDVR0jBBgwFoAU8NRqCpfiTCDshX7mgx4L6KeXxJ0wCQYDVR0TBAIwADANBgkqhkiG9w0BAQUFAAOBgQCvqwjs+9IiWGlLmFc9b+ON7upBb8JCwVh5+Ks7F4waZ5gmLuUXZLEeMDvosSB6bPFgDWSIZsdxn/V4/hUMEJkvfRZJ5J/k1a7Yogi3XyFcE4k1p1W5ZQ+wm+CQwAWmOFdpJUCMsC1h2xJUu9agEPWowdc9P2+LL04ghFq9SnXsYg==");

    public String getName()
    {
        return "X509ExtensionUtilsTest";
    }

    public void performTest()
        throws Exception
    {
        basicTest();
        jcaTest();
    }

    public void basicTest()
        throws IOException
    {
        X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(new SHA1DigestCalculator());

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pubKeyInfo));

        SubjectKeyIdentifier ski = x509ExtensionUtils.createSubjectKeyIdentifier(pubInfo);

        if (!Arrays.areEqual(shaID, ski.getKeyIdentifier()))
        {
            fail("basic SHA-1 ID does not match");
        }

        ski = x509ExtensionUtils.createTruncatedSubjectKeyIdentifier(pubInfo);

        if (!Arrays.areEqual(shaTruncID, ski.getKeyIdentifier()))
        {
            fail("basic truncated SHA-1 ID does not match");
        }

        AuthorityKeyIdentifier authKeyId = x509ExtensionUtils.createAuthorityKeyIdentifier(new X509CertificateHolder(v0Cert));
        if (!authKeyId.getAuthorityCertIssuer().equals(new GeneralNames(new GeneralName(new X500Name("O=Bouncy Castle, C=AU")))))
        {
            fail("v0 issuer not matched");
        }
        if (!Arrays.areEqual(Hex.decode("f0d46a0a97e24c20ec857ee6831e0be8a797c49d"), authKeyId.getKeyIdentifier()))
        {
            fail("v0 keyID not matched");
        }
        if (!authKeyId.getAuthorityCertSerialNumber().equals(BigInteger.valueOf(1)))
        {
            fail("v0 serial not matched");
        }

        authKeyId = x509ExtensionUtils.createAuthorityKeyIdentifier(new X509CertificateHolder(v3Cert));
        if (!authKeyId.getAuthorityCertIssuer().equals(new GeneralNames(new GeneralName(new X500Name("O=Bouncy Castle, C=AU")))))
        {
            fail("v3 issuer not matched");
        }
        if (!Arrays.areEqual(Hex.decode("c4733fe7e5fdd51bdd98d75b345674d85ba0f76c"), authKeyId.getKeyIdentifier()))
        {
            fail("v3 keyID not matched");
        }
        if (!authKeyId.getAuthorityCertSerialNumber().equals(BigInteger.valueOf(2)))
        {
            fail("v3 serial not matched");
        }
    }

    public void jcaTest()
        throws Exception
    {
        JcaX509ExtensionUtils x509ExtensionUtils = new JcaX509ExtensionUtils();

        PublicKey key = KeyFactory.getInstance("RSA", "BC").generatePublic(new X509EncodedKeySpec(pubKeyInfo));

        SubjectKeyIdentifier ski = x509ExtensionUtils.createSubjectKeyIdentifier(key);

        if (!Arrays.areEqual(shaID, ski.getKeyIdentifier()))
        {
            fail("jca SHA-1 ID does not match");
        }

        ski = x509ExtensionUtils.createTruncatedSubjectKeyIdentifier(key);

        if (!Arrays.areEqual(shaTruncID, ski.getKeyIdentifier()))
        {
            fail("jca truncated SHA-1 ID does not match");
        }

        CertificateFactory cFact = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate v0certificate = (X509Certificate)cFact.generateCertificate(new ByteArrayInputStream(v0Cert));
        X509Certificate v3certificate = (X509Certificate)cFact.generateCertificate(new ByteArrayInputStream(v3Cert));

        AuthorityKeyIdentifier authKeyId = x509ExtensionUtils.createAuthorityKeyIdentifier(v0certificate);
        if (!authKeyId.getAuthorityCertIssuer().equals(new GeneralNames(new GeneralName(new X500Name("O=Bouncy Castle, C=AU")))))
        {
            fail("v0 issuer not matched");
        }
        if (!Arrays.areEqual(Hex.decode("f0d46a0a97e24c20ec857ee6831e0be8a797c49d"), authKeyId.getKeyIdentifier()))
        {
            fail("v0 keyID not matched");
        }
        if (!authKeyId.getAuthorityCertSerialNumber().equals(BigInteger.valueOf(1)))
        {
            fail("v0 serial not matched");
        }

        authKeyId = x509ExtensionUtils.createAuthorityKeyIdentifier(v3certificate);
        if (!authKeyId.getAuthorityCertIssuer().equals(new GeneralNames(new GeneralName(new X500Name("O=Bouncy Castle, C=AU")))))
        {
            fail("v3 issuer not matched");
        }
        if (!Arrays.areEqual(Hex.decode("c4733fe7e5fdd51bdd98d75b345674d85ba0f76c"), authKeyId.getKeyIdentifier()))
        {
            fail("v3 keyID not matched");
        }
        if (!authKeyId.getAuthorityCertSerialNumber().equals(BigInteger.valueOf(2)))
        {
            fail("v3 serial not matched");
        }

        // simulate the JCA X509Certificate.getExtension() method.
        authKeyId = AuthorityKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(new DEROctetString(authKeyId).getEncoded()));
        if (!authKeyId.getAuthorityCertIssuer().equals(new GeneralNames(new GeneralName(new X500Name("O=Bouncy Castle, C=AU")))))
        {
            fail("v3 issuer not matched");
        }
        if (!Arrays.areEqual(Hex.decode("c4733fe7e5fdd51bdd98d75b345674d85ba0f76c"), authKeyId.getKeyIdentifier()))
        {
            fail("v3 keyID not matched");
        }
        if (!authKeyId.getAuthorityCertSerialNumber().equals(BigInteger.valueOf(2)))
        {
            fail("v3 serial not matched");
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new X509ExtensionUtilsTest());
    }
}
