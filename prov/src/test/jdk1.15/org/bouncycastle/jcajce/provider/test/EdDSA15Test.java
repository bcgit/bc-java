package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EdDSA15Test
    extends TestCase
{
    public void testBCFromCert()
        throws Exception
    {
        String base64Cert = "MIICKzCCAd2gAwIBAgICBEwwBQYDK2VwMFUxGDAWBgNVBAMMD0VkMjU1MTktZ29vZC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTE5MTExNDA2MzgzOVoXDTIxMDkxNDA1MzgzOVowVzEaMBgGA1UEAwwRRWQyNTUxOS1nb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTAqMAUGAytlcAMhAB+6MntRr6dWLmCC8uZfoMWhxMRHPDnrTVz8wJIlzW88o4HOMIHLMA4GA1UdDwEB/wQEAwIGQDCBmQYIKwYBBQUHAQEEgYwwgYkwQQYIKwYBBQUHMAGGNWh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L29jc3AvRWQyNTUxOS1nb29kLWNhMEQGCCsGAQUFBzAChjhodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvRWQyNTUxOS1nb29kLWNhLmNydDAdBgNVHQ4EFgQU5Cf9+sOF2L2SNadlEriSE3erKE8wBQYDK2VwA0EA1kdAmC8cIRFVg10R/P++5Wru9fYcUhLjwVN85Uwq/a4JyKfoamxv9hlEq9LWkgJ1QKT3/VDngQ1+pyPrYmXDCA==";
        byte[] certBinaries = Base64.getDecoder().decode(base64Cert);
        try (InputStream is = new ByteArrayInputStream(certBinaries))
        {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate = certificateFactory.generateCertificate(is);

            Signature signature = Signature.getInstance("Ed25519", new BouncyCastleProvider());

            signature.initVerify(certificate.getPublicKey());
        }
    }

    public void testBCSig()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("Ed25519", "SunEC");

        KeyPair kp = kpGen.generateKeyPair();

        Signature signature = Signature.getInstance("Ed25519", new BouncyCastleProvider());

        signature.initSign(kp.getPrivate());

        signature.update(new byte[32]);

        byte[] sig = signature.sign();

        signature.initVerify(kp.getPublic());

        signature.update(new byte[32]);

        assertTrue(signature.verify(sig));
    }
}
