package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
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
import org.bouncycastle.pqc.jcajce.interfaces.MQOMKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.MQOMParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class MQOMTest
    extends TestCase
{
    private static final String PROVIDER = "BCPQC";

    private final byte[] msg = Strings.toByteArray("Hello MQOM");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testParameterSpecFromName()
    {
        MQOMParameterSpec spec = MQOMParameterSpec.fromName("MQOM2-CAT1-GF256-FAST-R3");
        assertEquals("MQOM2-CAT1-GF256-FAST-R3", spec.getName());
        assertSame(spec, MQOMParameterSpec.fromName("mqom2-cat1-gf256-fast-r3"));
    }

    public void testKeyPairGeneratorAndSignature()
        throws Exception
    {
        runRoundTrip("MQOM2-CAT1-GF256-FAST-R3", MQOMParameterSpec.mqom2_cat1_gf256_fast_r3);
    }

    public void testGenericMqomKeyPairGenerator()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("MQOM", PROVIDER);
        kpg.initialize(MQOMParameterSpec.mqom2_cat1_gf2_fast_r3, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        assertTrue(kp.getPublic() instanceof MQOMKey);
        assertTrue(kp.getPrivate() instanceof MQOMKey);
        assertEquals("MQOM2-CAT1-GF2-FAST-R3", kp.getPublic().getAlgorithm());

        Signature signer = Signature.getInstance("MQOM", PROVIDER);
        signer.initSign(kp.getPrivate(), new SecureRandom());
        signer.update(msg);
        byte[] sig = signer.sign();

        signer.initVerify(kp.getPublic());
        signer.update(msg);
        assertTrue(signer.verify(sig));
    }

    public void testKeyFactoryRoundTrip()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("MQOM2-CAT1-GF256-FAST-R3", PROVIDER);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("MQOM", PROVIDER);
        MQOMKey pub = (MQOMKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        MQOMKey priv = (MQOMKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPublic(), pub);
        assertEquals(kp.getPrivate(), priv);
        assertEquals(kp.getPublic().hashCode(), pub.hashCode());
    }

    public void testSerializationRoundTrip()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("MQOM2-CAT1-GF256-FAST-R3", PROVIDER);
        KeyPair kp = kpg.generateKeyPair();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(kp.getPublic());
        oOut.writeObject(kp.getPrivate());
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        MQOMKey pub = (MQOMKey)oIn.readObject();
        MQOMKey priv = (MQOMKey)oIn.readObject();

        assertEquals(kp.getPublic(), pub);
        assertEquals(kp.getPrivate(), priv);
    }

    public void testRestrictedSignatureRejectsForeignVariant()
        throws Exception
    {
        KeyPair kp2 = newKeyPair(MQOMParameterSpec.mqom2_cat1_gf2_fast_r3);

        Signature sig = Signature.getInstance("MQOM2-CAT1-GF256-FAST-R3", PROVIDER);
        try
        {
            sig.initVerify(kp2.getPublic());
            fail("expected InvalidKeyException for mismatched parameter set");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("signature configured for MQOM2-CAT1-GF256-FAST-R3", e.getMessage());
        }
    }

    /**
     * initSign / initVerify start a new message: bytes passed to update() before a re-initialisation,
     * or before switching between signing and verifying, must not reach the next signature.
     */
    public void testReinitDiscardsBufferedMessage()
        throws Exception
    {
        byte[] stale = Strings.toByteArray("stale");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("MQOM", PROVIDER);
        kpg.initialize(MQOMParameterSpec.mqom2_cat1_gf2_fast_r3, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("MQOM", PROVIDER);
        signer.initSign(kp.getPrivate(), new SecureRandom());
        signer.update(msg);
        byte[] s = signer.sign();

        // an abandoned sign, then a sign of msg: the result is a signature on msg alone
        Signature sig = Signature.getInstance("MQOM", PROVIDER);
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(stale);
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(msg);
        byte[] s2 = sig.sign();

        Signature verifier = Signature.getInstance("MQOM", PROVIDER);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue("re-initSign kept the earlier update", verifier.verify(s2));

        // an abandoned verify, then a verify of msg
        sig.initVerify(kp.getPublic());
        sig.update(stale);
        sig.initVerify(kp.getPublic());
        sig.update(msg);
        assertTrue("re-initVerify kept the earlier update", sig.verify(s));

        // an abandoned sign, then a verify of msg on the same object
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(stale);
        sig.initVerify(kp.getPublic());
        sig.update(msg);
        assertTrue("initVerify after initSign kept the earlier update", sig.verify(s));
    }

    /**
     * A public key that is not an MQOM key is refused with an InvalidKeyException that keeps the
     * decoding failure as its cause.
     */
    public void testForeignPublicKeyKeepsCause()
        throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(256, new SecureRandom());
        PublicKey ecKey = kpg.generateKeyPair().getPublic();

        Signature sig = Signature.getInstance("MQOM", PROVIDER);
        try
        {
            sig.initVerify(ecKey);
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("unknown public key passed to MQOM: "));
            assertNotNull("cause dropped", e.getCause());
        }
    }

    private void runRoundTrip(String algName, MQOMParameterSpec spec)
        throws Exception
    {
        KeyPair kp = newKeyPair(spec);
        assertEquals(algName, kp.getPublic().getAlgorithm());
        assertEquals(algName, kp.getPrivate().getAlgorithm());

        Signature signer = Signature.getInstance(algName, PROVIDER);
        signer.initSign(kp.getPrivate(), new SecureRandom());
        signer.update(msg);
        byte[] sig = signer.sign();

        signer.initVerify(kp.getPublic());
        signer.update(msg);
        assertTrue(signer.verify(sig));

        byte[] tampered = Arrays.clone(sig);
        tampered[0] ^= 0x01;
        signer.initVerify(kp.getPublic());
        signer.update(msg);
        assertFalse(signer.verify(tampered));

        signer.initVerify(kp.getPublic());
        signer.update("different message".getBytes("UTF-8"));
        assertFalse(signer.verify(sig));
    }

    /**
     * Verify that the BC provider's key-info-converter mechanism (populated by
     * {@code BouncyCastleProvider.loadPQCKeys()}) recognises every MQOM OID
     * and decodes encoded key infos to MQOM keys equal to the originals.
     */
    public void testBcProviderKeyInfoConverter()
        throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        Field[] fields = MQOMParameterSpec.class.getDeclaredFields();
        int checked = 0;

        for (int i = 0; i != fields.length; i++)
        {
            Field f = fields[i];
            if (Modifier.isStatic(f.getModifiers()) && Modifier.isPublic(f.getModifiers())
                && f.getType() == MQOMParameterSpec.class)
            {
                MQOMParameterSpec spec = (MQOMParameterSpec)f.get(null);

                KeyPair kp = newKeyPair(spec);

                PublicKey decPub = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
                PrivateKey decPriv = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded()));

                assertNotNull(spec.getName() + ": BC provider returned null for SubjectPublicKeyInfo", decPub);
                assertNotNull(spec.getName() + ": BC provider returned null for PrivateKeyInfo", decPriv);

                assertTrue(spec.getName() + ": decoded public key is not an MQOMKey", decPub instanceof MQOMKey);
                assertTrue(spec.getName() + ": decoded private key is not an MQOMKey", decPriv instanceof MQOMKey);

                assertEquals(spec.getName() + ": public key equality", kp.getPublic(), decPub);
                assertEquals(spec.getName() + ": private key equality", kp.getPrivate(), decPriv);

                checked++;
            }
        }

        // sanity: the reflection actually swept the full parameter-set family.
        assertEquals("expected every MQOM parameter set to be covered", 36, checked);
    }

    private KeyPair newKeyPair(MQOMParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(Strings.toUpperCase(spec.getName()), PROVIDER);
        return kpg.generateKeyPair();
    }
}
