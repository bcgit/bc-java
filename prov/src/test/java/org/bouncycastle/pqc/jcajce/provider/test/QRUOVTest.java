package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.QRUOVKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.QRUOVParameterSpec;
import org.bouncycastle.util.Strings;

public class QRUOVTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        QRUOVTest test = new QRUOVTest();
        test.setUp();
        test.testPrivateKeyRecovery();
        test.testPublicKeyRecovery();
        test.testRestrictedKeyPairGen();
        test.testQRUOVRandomSig();
        test.testQRUOVSign();
        test.testBcProviderKeyInfoConverter();
    }

    private static final QRUOVParameterSpec[] SPECS = new QRUOVParameterSpec[]{
        QRUOVParameterSpec.qruov1q127L3v156m54,
        QRUOVParameterSpec.qruov1q31L3v165m60,
        QRUOVParameterSpec.qruov1q31L10v600m70,
        QRUOVParameterSpec.qruov1q7L10v740m100,
        QRUOVParameterSpec.qruov3q127L3v228m78,
        QRUOVParameterSpec.qruov3q31L3v246m87,
        QRUOVParameterSpec.qruov3q31L10v890m100,
        QRUOVParameterSpec.qruov3q7L10v1100m140,
        QRUOVParameterSpec.qruov5q127L3v306m105,
        QRUOVParameterSpec.qruov5q31L3v324m114,
        QRUOVParameterSpec.qruov5q31L10v1120m120,
        QRUOVParameterSpec.qruov5q7L10v1490m190,
    };

    byte[] msg = Strings.toByteArray("Hello World!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testPrivateKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("QRUOV", "BCPQC");
        kpg.initialize(QRUOVParameterSpec.qruov1q127L3v156m54, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("QRUOV", "BCPQC");
        QRUOVKey privKey = (QRUOVKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);
        assertEquals(kp.getPrivate().getAlgorithm(), privKey.getAlgorithm());
        assertEquals(kp.getPrivate().hashCode(), privKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        QRUOVKey privKey2 = (QRUOVKey)oIn.readObject();

        assertEquals(privKey, privKey2);
        assertEquals(privKey.getAlgorithm(), privKey2.getAlgorithm());
        assertEquals(privKey.hashCode(), privKey2.hashCode());
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("QRUOV", "BCPQC");
        kpg.initialize(QRUOVParameterSpec.qruov1q31L3v165m60, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance(QRUOVParameterSpec.qruov1q31L3v165m60.getName(), "BCPQC");
        QRUOVKey pubKey = (QRUOVKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);
        assertEquals(kp.getPublic().getAlgorithm(), pubKey.getAlgorithm());
        assertEquals(kp.getPublic().hashCode(), pubKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        QRUOVKey pubKey2 = (QRUOVKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
        assertEquals(pubKey.getAlgorithm(), pubKey2.getAlgorithm());
        assertEquals(pubKey.hashCode(), pubKey2.hashCode());
    }

    public void testQRUOVSign()
        throws Exception
    {
        // exercise the two smallest parameter sets fully (faster CI),
        // and confirm the wrong-key path for the cat-1 q=127 set.
        testQRUOV(QRUOVParameterSpec.qruov1q127L3v156m54, QRUOVParameterSpec.qruov1q31L3v165m60);
        testQRUOV(QRUOVParameterSpec.qruov1q31L3v165m60, QRUOVParameterSpec.qruov1q127L3v156m54);
    }

    private void testQRUOV(QRUOVParameterSpec spec, QRUOVParameterSpec wrongSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("QRUOV", "BCPQC");
        kpg.initialize(spec, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance(spec.getName(), "BCPQC");
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(msg, 0, msg.length);
        byte[] s = sig.sign();

        sig = Signature.getInstance(spec.getName(), "BCPQC");
        assertEquals(Strings.toUpperCase(spec.getName()), Strings.toUpperCase(sig.getAlgorithm()));
        sig.initVerify(kp.getPublic());
        sig.update(msg, 0, msg.length);
        assertTrue(sig.verify(s));

        kpg = KeyPairGenerator.getInstance("QRUOV", "BCPQC");
        kpg.initialize(wrongSpec, new SecureRandom());
        kp = kpg.generateKeyPair();

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("signature configured for " + Strings.toUpperCase(spec.getName()), e.getMessage());
        }
    }

    public void testRestrictedKeyPairGen()
        throws Exception
    {
        // The big cat-5 L=10 sets are very slow to generate keys for; restrict to the
        // smaller sets that run fast enough for a unit test.
        doTestRestrictedKeyPairGen(QRUOVParameterSpec.qruov1q127L3v156m54);
        doTestRestrictedKeyPairGen(QRUOVParameterSpec.qruov1q31L3v165m60);
        doTestRestrictedKeyPairGen(QRUOVParameterSpec.qruov3q127L3v228m78);
        doTestRestrictedKeyPairGen(QRUOVParameterSpec.qruov3q31L3v246m87);
        doTestRestrictedKeyPairGen(QRUOVParameterSpec.qruov5q127L3v306m105);
        doTestRestrictedKeyPairGen(QRUOVParameterSpec.qruov5q31L3v324m114);
    }

    private void doTestRestrictedKeyPairGen(QRUOVParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");
        kpg.initialize(spec, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        assertEquals(Strings.toUpperCase(spec.getName()), kp.getPublic().getAlgorithm());
        assertEquals(Strings.toUpperCase(spec.getName()), kp.getPrivate().getAlgorithm());
    }

    public void testQRUOVRandomSig()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("QRUOV", "BCPQC");
        kpg.initialize(QRUOVParameterSpec.qruov1q127L3v156m54, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("QRUOV", "BCPQC");
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(msg, 0, msg.length);
        byte[] s = sig.sign();

        sig = Signature.getInstance("QRUOV", "BCPQC");
        sig.initVerify(kp.getPublic());
        sig.update(msg, 0, msg.length);
        assertTrue(sig.verify(s));
    }

    /**
     * Verifies that {@code BouncyCastleProvider.loadPQCKeys()} registered QR-UOV
     * OIDs against the BCPQC-side {@code QRUOVKeyFactorySpi}, so the standard
     * {@code BC} provider can decode QR-UOV {@code SubjectPublicKeyInfo} /
     * {@code PrivateKeyInfo} structures. Forgetting that wiring is the
     * easy-to-miss half of a PQC port.
     */
    public void testBcProviderKeyInfoConverter()
        throws Exception
    {
        for (int i = 0; i < SPECS.length; i++)
        {
            // Skip the slowest parameter sets in default test runs;
            // they're exercised by the lightweight KAT test in core.
            String name = SPECS[i].getName();
            if (name.startsWith("qruov5q7L10") || name.startsWith("qruov5q31L10"))
            {
                continue;
            }
            doBcKeyInfoRoundTrip(SPECS[i]);
        }
    }

    private void doBcKeyInfoRoundTrip(QRUOVParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("QRUOV", "BCPQC");
        kpg.initialize(spec, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        PublicKey decPub = BouncyCastleProvider.getPublicKey(pubInfo);
        PrivateKey decPriv = BouncyCastleProvider.getPrivateKey(privInfo);

        assertNotNull(spec.getName() + ": BC provider returned null for SubjectPublicKeyInfo", decPub);
        assertNotNull(spec.getName() + ": BC provider returned null for PrivateKeyInfo", decPriv);

        assertTrue(spec.getName() + ": decoded public key is not a QRUOVKey", decPub instanceof QRUOVKey);
        assertTrue(spec.getName() + ": decoded private key is not a QRUOVKey", decPriv instanceof QRUOVKey);

        assertEquals(spec.getName() + ": public key parameter spec mismatch",
            spec.getName(), ((QRUOVKey)decPub).getParameterSpec().getName());
        assertEquals(spec.getName() + ": private key parameter spec mismatch",
            spec.getName(), ((QRUOVKey)decPriv).getParameterSpec().getName());

        assertEquals(spec.getName() + ": public key equality", kp.getPublic(), decPub);
        assertEquals(spec.getName() + ": private key equality", kp.getPrivate(), decPriv);
    }

    private static class RiggedRandom
        extends SecureRandom
    {
        public void nextBytes(byte[] bytes)
        {
            for (int i = 0; i != bytes.length; i++)
            {
                bytes[i] = (byte)(i & 0xff);
            }
        }
    }
}
