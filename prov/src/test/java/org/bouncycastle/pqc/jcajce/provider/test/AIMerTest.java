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
import org.bouncycastle.pqc.jcajce.interfaces.AIMerKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.AIMerParameterSpec;
import org.bouncycastle.util.Strings;

public class AIMerTest
    extends TestCase
{
    private static final AIMerParameterSpec[] SPECS =
        {
            AIMerParameterSpec.aimer128f, AIMerParameterSpec.aimer128s,
            AIMerParameterSpec.aimer192f, AIMerParameterSpec.aimer192s,
            AIMerParameterSpec.aimer256f, AIMerParameterSpec.aimer256s
        };

    // the registered restricted algorithm names, index-matched to SPECS
    private static final String[] ALG_NAMES =
        {
            "AIMer-128f", "AIMer-128s",
            "AIMer-192f", "AIMer-192s",
            "AIMer-256f", "AIMer-256s"
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("AIMer", "BCPQC");

        kpg.initialize(AIMerParameterSpec.aimer128f, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("AIMer", "BCPQC");

        AIMerKey privKey = (AIMerKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);
        assertEquals(kp.getPrivate().getAlgorithm(), privKey.getAlgorithm());
        assertEquals(kp.getPrivate().hashCode(), privKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        AIMerKey privKey2 = (AIMerKey)oIn.readObject();

        assertEquals(privKey, privKey2);
        assertEquals(privKey.getAlgorithm(), privKey2.getAlgorithm());
        assertEquals(privKey.hashCode(), privKey2.hashCode());
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("AIMer-128s", "BCPQC");

        kpg.initialize(AIMerParameterSpec.aimer128s, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("AIMer-128s", "BCPQC");

        AIMerKey pubKey = (AIMerKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);
        assertEquals(kp.getPublic().getAlgorithm(), pubKey.getAlgorithm());
        assertEquals(kp.getPublic().hashCode(), pubKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        AIMerKey pubKey2 = (AIMerKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
        assertEquals(pubKey.getAlgorithm(), pubKey2.getAlgorithm());
        assertEquals(pubKey.hashCode(), pubKey2.hashCode());
    }

    public void testRestrictedKeyPairGen()
        throws Exception
    {
        for (int i = 0; i != SPECS.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALG_NAMES[i], "BCPQC");

            kpg.initialize(SPECS[i], new SecureRandom());

            KeyPair kp = kpg.generateKeyPair();

            assertEquals(Strings.toUpperCase(SPECS[i].getName()), kp.getPublic().getAlgorithm());
            assertEquals(Strings.toUpperCase(SPECS[i].getName()), kp.getPrivate().getAlgorithm());
            assertEquals(SPECS[i].getName(), ((AIMerKey)kp.getPublic()).getParameterSpec().getName());
            assertEquals(SPECS[i].getName(), ((AIMerKey)kp.getPrivate()).getParameterSpec().getName());
        }
    }

    public void testAIMerRandomSig()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("AIMer", "BCPQC");

        kpg.initialize(AIMerParameterSpec.aimer128f, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("AIMer", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("AIMer", "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    public void testAIMerSign()
        throws Exception
    {
        testAIMer(AIMerParameterSpec.aimer128f, "AIMer-128f", AIMerParameterSpec.aimer128s, "AIMer-128s");
        testAIMer(AIMerParameterSpec.aimer192f, "AIMer-192f", AIMerParameterSpec.aimer128f, "AIMer-128f");
        testAIMer(AIMerParameterSpec.aimer256f, "AIMer-256f", AIMerParameterSpec.aimer128f, "AIMer-128f");
    }

    private void testAIMer(AIMerParameterSpec spec, String algName, AIMerParameterSpec wrongSpec, String wrongAlgName)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algName, "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance(algName, "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance(algName, "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        kpg = KeyPairGenerator.getInstance(wrongAlgName, "BCPQC");

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

    /**
     * Verify that the BC provider's key-info-converter mechanism (populated by
     * {@code BouncyCastleProvider.loadPQCKeys()}) recognises every AIMer OID
     * and decodes encoded key infos to AIMer keys equal to the originals.
     */
    public void testBcProviderKeyInfoConverter()
        throws Exception
    {
        for (int i = 0; i != SPECS.length; i++)
        {
            doBcKeyInfoRoundTrip(SPECS[i], ALG_NAMES[i]);
        }
    }

    private void doBcKeyInfoRoundTrip(AIMerParameterSpec spec, String algName)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algName, "BCPQC");
        kpg.initialize(spec, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        PublicKey decPub = BouncyCastleProvider.getPublicKey(pubInfo);
        PrivateKey decPriv = BouncyCastleProvider.getPrivateKey(privInfo);

        assertNotNull(spec.getName() + ": BC provider returned null for SubjectPublicKeyInfo", decPub);
        assertNotNull(spec.getName() + ": BC provider returned null for PrivateKeyInfo", decPriv);

        assertTrue(spec.getName() + ": decoded public key is not an AIMerKey", decPub instanceof AIMerKey);
        assertTrue(spec.getName() + ": decoded private key is not an AIMerKey", decPriv instanceof AIMerKey);

        assertEquals(spec.getName() + ": public key parameter spec mismatch",
            spec.getName(), ((AIMerKey)decPub).getParameterSpec().getName());
        assertEquals(spec.getName() + ": private key parameter spec mismatch",
            spec.getName(), ((AIMerKey)decPriv).getParameterSpec().getName());

        assertEquals(spec.getName() + ": public key equality", kp.getPublic(), decPub);
        assertEquals(spec.getName() + ": private key equality", kp.getPrivate(), decPriv);
    }
}
