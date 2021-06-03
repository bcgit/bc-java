package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.EdECKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;

import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

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

    public void testBCSigEd25519()
        throws Exception
    {
        implTestBCSig("Ed25519");
    }

    public void testBCSigEd448()
        throws Exception
    {
        implTestBCSig("Ed448");
    }

    public void testInteropEd25519()
        throws Exception
    {
        implTestInterop("Ed25519");
    }

    public void testInteropEd448()
        throws Exception
    {
        implTestInterop("Ed448");
    }

    public void testShouldReturnNamedParamSpec()
        throws Exception
    {
        BouncyCastleProvider BC = new BouncyCastleProvider();

        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("Ed25519", BC);
            KeyPair kp = kpGen.generateKeyPair();
            checkNamedParamSpecEdECKey(kp.getPrivate(), "Ed25519");
            checkNamedParamSpecEdECKey(kp.getPublic(), "Ed25519");
        }
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("Ed448", BC);
            KeyPair kp = kpGen.generateKeyPair();
            checkNamedParamSpecEdECKey(kp.getPrivate(), "Ed448");
            checkNamedParamSpecEdECKey(kp.getPublic(), "Ed448");
        }
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EdDSA", BC);
            kpGen.initialize(255);
            KeyPair kp = kpGen.generateKeyPair();
            checkNamedParamSpecEdECKey(kp.getPrivate(), "Ed25519");
            checkNamedParamSpecEdECKey(kp.getPublic(), "Ed25519");
        }
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EdDSA", BC);
            kpGen.initialize(448);
            KeyPair kp = kpGen.generateKeyPair();
            checkNamedParamSpecEdECKey(kp.getPrivate(), "Ed448");
            checkNamedParamSpecEdECKey(kp.getPublic(), "Ed448");
        }
    }

    private void implTestBCSig(String algorithm)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "SunEC");
        Signature signature = Signature.getInstance(algorithm, new BouncyCastleProvider());

        for (int i = 0; i < 10; ++i)
        {
            KeyPair kp = kpGen.generateKeyPair();

            signature.initSign(kp.getPrivate());

            signature.update(new byte[32]);

            byte[] sig = signature.sign();

            signature.initVerify(kp.getPublic());

            signature.update(new byte[32]);

            assertTrue(signature.verify(sig));
        }
    }

    private void implTestInterop(String algorithm)
        throws Exception
    {
        BouncyCastleProvider bc = new BouncyCastleProvider();

        KeyPairGenerator kpGenBC = KeyPairGenerator.getInstance(algorithm, bc);
        KeyPairGenerator kpGenSunEC = KeyPairGenerator.getInstance(algorithm, "SunEC");

        Signature sigBC = Signature.getInstance(algorithm, bc);
        Signature sigSunEC = Signature.getInstance(algorithm, "SunEC");

        for (int i = 0; i < 10; ++i)
        {
            KeyPair kpBC = kpGenBC.generateKeyPair();
            KeyPair kpSunEC = kpGenSunEC.generateKeyPair();

            implTestInteropCase(kpBC, sigBC, sigBC);
            implTestInteropCase(kpBC, sigBC, sigSunEC);
            implTestInteropCase(kpBC, sigSunEC, sigBC);
            implTestInteropCase(kpBC, sigSunEC, sigSunEC);
            implTestInteropCase(kpSunEC, sigBC, sigBC);
            implTestInteropCase(kpSunEC, sigBC, sigSunEC);
            implTestInteropCase(kpSunEC, sigSunEC, sigBC);
//            implTestInteropCase(kpSunEC, sigSunEC, sigSunEC);
        }
    }

    private void implTestInteropCase(KeyPair kp, Signature signer, Signature verifier)
        throws Exception
    {
        signer.initSign(kp.getPrivate());
        signer.update(new byte[32]);

        byte[] sig = signer.sign();

        verifier.initVerify(kp.getPublic());
        verifier.update(new byte[32]);

        assertTrue(verifier.verify(sig));

        if (kp.getPrivate() instanceof EdDSAPrivateKey)
        {
            verifier.initVerify(((EdDSAPrivateKey)kp.getPrivate()).getPublicKey());
            verifier.update(new byte[32]);

            assertTrue(verifier.verify(sig));
        }
    }

    public void testRawEncodedKeySpec()
        throws Exception
    {
        KeyPair ed1 = generateKP("Ed448", new EdDSAParameterSpec(EdDSAParameterSpec.Ed448));

        checkRaw(ed1.getPublic(), "Ed448");

        KeyPair ed2 = generateKP("Ed25519", new EdDSAParameterSpec(EdDSAParameterSpec.Ed25519));

        checkRaw(ed2.getPublic(), "Ed25519");
    }

    private KeyPair generateKP(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        BouncyCastleProvider BC = new BouncyCastleProvider();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, BC);

        kpGen.initialize(spec);

        return kpGen.generateKeyPair();
    }

    private void checkRaw(PublicKey key, String algorithm)
        throws Exception
    {
        BouncyCastleProvider BC = new BouncyCastleProvider();

        KeyFactory kf = KeyFactory.getInstance(algorithm, BC);

        RawEncodedKeySpec rawSpec = (RawEncodedKeySpec)kf.getKeySpec(key, RawEncodedKeySpec.class);

        PublicKey pub = kf.generatePublic(rawSpec);

        assertEquals(key, pub);
    }

    private void checkNamedParamSpecEdECKey(Key key, String name)
    {
        assertTrue(key instanceof EdECKey);
        AlgorithmParameterSpec params = ((EdECKey)key).getParams();
        assertTrue(params instanceof NamedParameterSpec);
        NamedParameterSpec spec = (NamedParameterSpec)params;
        assertEquals(name, spec.getName());
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(EdDSA15Test.class);
    }

    public static Test suite()
        throws Exception
    {
        return new TestSuite(EdDSA15Test.class);
    }
}
