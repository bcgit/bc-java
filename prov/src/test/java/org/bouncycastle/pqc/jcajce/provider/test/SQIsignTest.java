package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SQIsignKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.sqisign.BCSQIsignPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.sqisign.BCSQIsignPublicKey;
import org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Provider-side wiring tests for SQIsign. These cover the BCPQC ↔ BC
 * plumbing — parameter-set spec lookup, key-encoding round trip, the
 * {@link BouncyCastleProvider} key-info-converter bridge, algorithm
 * registration and the SignatureSpi parameter-set check — using synthetic raw
 * key bytes so they stay fast and independent of the (comparatively expensive)
 * isogeny engine. {@link #testSQIsignSign()} additionally drives a real
 * keygen + sign + verify cycle through the JCE API to confirm the
 * {@code Signature.getInstance(...) → SQIsignSigner →} engine path is wired
 * end to end; it exercises the level-1 parameter set (the fastest) since the
 * per-level wiring is otherwise identical and already covered for all three
 * levels by the synthetic-byte tests. The reference known-answer vectors live
 * in {@code bc-test-data/pqc/crypto/sqisign/kat/sqisign_lvl*.rsp}.
 */
public class SQIsignTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        SQIsignTest test = new SQIsignTest();
        test.setUp();
        test.testParameterSpecLookup();
        test.testAlgorithmsRegistered();
        test.testKeyFactoryRoundTrip();
        test.testBcProviderKeyInfoConverter();
        test.testSignatureWrongParameterSet();
        test.testSQIsignSign();
    }

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

    public void testParameterSpecLookup()
    {
        assertSame(SQIsignParameterSpec.sqisign_lvl1, SQIsignParameterSpec.fromName("sqisign_lvl1"));
        assertSame(SQIsignParameterSpec.sqisign_lvl1, SQIsignParameterSpec.fromName("SQIsign_lvl1"));
        assertSame(SQIsignParameterSpec.sqisign_lvl3, SQIsignParameterSpec.fromName("sqisign_lvl3"));
        assertSame(SQIsignParameterSpec.sqisign_lvl5, SQIsignParameterSpec.fromName("sqisign_lvl5"));
        assertNull(SQIsignParameterSpec.fromName("not-a-sqisign-set"));

        assertEquals("sqisign_lvl1", SQIsignParameterSpec.sqisign_lvl1.getName());
        assertEquals("sqisign_lvl3", SQIsignParameterSpec.sqisign_lvl3.getName());
        assertEquals("sqisign_lvl5", SQIsignParameterSpec.sqisign_lvl5.getName());
    }

    public void testAlgorithmsRegistered()
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyFactory.getInstance("SQIsign", "BCPQC");
        KeyFactory.getInstance("sqisign_lvl1", "BCPQC");
        KeyFactory.getInstance("sqisign_lvl3", "BCPQC");
        KeyFactory.getInstance("sqisign_lvl5", "BCPQC");

        KeyFactory.getInstance(BCObjectIdentifiers.sqisign_lvl1.getId(), "BCPQC");

        KeyPairGenerator.getInstance("SQIsign", "BCPQC");
        KeyPairGenerator.getInstance("sqisign_lvl1", "BCPQC");

        Signature.getInstance("SQIsign", "BCPQC");
        Signature.getInstance("sqisign_lvl1", "BCPQC");
        Signature.getInstance("sqisign_lvl3", "BCPQC");
        Signature.getInstance("sqisign_lvl5", "BCPQC");
    }

    public void testKeyFactoryRoundTrip()
        throws Exception
    {
        doKeyFactoryRoundTrip(SQIsignParameters.sqisign_lvl1, SQIsignParameterSpec.sqisign_lvl1);
        doKeyFactoryRoundTrip(SQIsignParameters.sqisign_lvl3, SQIsignParameterSpec.sqisign_lvl3);
        doKeyFactoryRoundTrip(SQIsignParameters.sqisign_lvl5, SQIsignParameterSpec.sqisign_lvl5);
    }

    private void doKeyFactoryRoundTrip(SQIsignParameters params, SQIsignParameterSpec spec)
        throws Exception
    {
        byte[] pkBytes = patternedBytes(params.getPublicKeyLength(), 0x11);
        byte[] skBytes = patternedBytes(params.getPrivateKeyLength(), 0x22);

        BCSQIsignPublicKey pubKey = new BCSQIsignPublicKey(new SQIsignPublicKeyParameters(params, pkBytes));
        BCSQIsignPrivateKey privKey = new BCSQIsignPrivateKey(new SQIsignPrivateKeyParameters(params, skBytes));

        assertEquals(spec.getName(), pubKey.getAlgorithm());
        assertEquals(spec.getName(), privKey.getAlgorithm());
        assertEquals(spec.getName(), pubKey.getParameterSpec().getName());
        assertEquals(spec.getName(), privKey.getParameterSpec().getName());

        KeyFactory kf = KeyFactory.getInstance("SQIsign", "BCPQC");

        SQIsignKey decodedPub = (SQIsignKey)kf.generatePublic(new X509EncodedKeySpec(pubKey.getEncoded()));
        SQIsignKey decodedPriv = (SQIsignKey)kf.generatePrivate(new PKCS8EncodedKeySpec(privKey.getEncoded()));

        assertEquals(pubKey, decodedPub);
        assertEquals(privKey, decodedPriv);
        assertEquals(spec.getName(), decodedPub.getParameterSpec().getName());
        assertEquals(spec.getName(), decodedPriv.getParameterSpec().getName());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.writeObject(privKey);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SQIsignKey reReadPub = (SQIsignKey)oIn.readObject();
        SQIsignKey reReadPriv = (SQIsignKey)oIn.readObject();
        assertEquals(pubKey, reReadPub);
        assertEquals(privKey, reReadPriv);
    }

    /**
     * Verify the BC ↔ BCPQC bridge: BouncyCastleProvider.getPublicKey /
     * getPrivateKey must recognise SQIsign OIDs and produce SQIsignKey
     * instances equal to the originals. If this fails but
     * {@link #testKeyFactoryRoundTrip()} passes, the loadPQCKeys() entries
     * for SQIsign were forgotten.
     */
    public void testBcProviderKeyInfoConverter()
        throws Exception
    {
        doBcKeyInfoRoundTrip(SQIsignParameters.sqisign_lvl1, SQIsignParameterSpec.sqisign_lvl1);
        doBcKeyInfoRoundTrip(SQIsignParameters.sqisign_lvl3, SQIsignParameterSpec.sqisign_lvl3);
        doBcKeyInfoRoundTrip(SQIsignParameters.sqisign_lvl5, SQIsignParameterSpec.sqisign_lvl5);
    }

    private void doBcKeyInfoRoundTrip(SQIsignParameters params, SQIsignParameterSpec spec)
        throws IOException
    {
        byte[] pkBytes = patternedBytes(params.getPublicKeyLength(), 0x33);
        byte[] skBytes = patternedBytes(params.getPrivateKeyLength(), 0x44);

        SQIsignPublicKeyParameters pubParams = new SQIsignPublicKeyParameters(params, pkBytes);
        SQIsignPrivateKeyParameters privParams = new SQIsignPrivateKeyParameters(params, skBytes);

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubParams);
        PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privParams);

        PublicKey decPub = BouncyCastleProvider.getPublicKey(pubInfo);
        PrivateKey decPriv = BouncyCastleProvider.getPrivateKey(privInfo);

        assertNotNull(spec.getName() + ": BC provider returned null for SubjectPublicKeyInfo", decPub);
        assertNotNull(spec.getName() + ": BC provider returned null for PrivateKeyInfo", decPriv);

        assertTrue(spec.getName() + ": decoded public key is not an SQIsignKey", decPub instanceof SQIsignKey);
        assertTrue(spec.getName() + ": decoded private key is not an SQIsignKey", decPriv instanceof SQIsignKey);

        assertEquals(spec.getName() + ": public key parameter spec mismatch",
            spec.getName(), ((SQIsignKey)decPub).getParameterSpec().getName());
        assertEquals(spec.getName() + ": private key parameter spec mismatch",
            spec.getName(), ((SQIsignKey)decPriv).getParameterSpec().getName());

        assertEquals(spec.getName() + ": public key equality",
            new BCSQIsignPublicKey(pubParams), decPub);
        assertEquals(spec.getName() + ": private key equality",
            new BCSQIsignPrivateKey(privParams), decPriv);
    }

    /**
     * Confirm the SignatureSpi enforces the same parameter set on the key and
     * the algorithm name: initVerify with a key from a different parameter set
     * must throw the canonical "signature configured for ..." message.
     */
    public void testSignatureWrongParameterSet()
        throws Exception
    {
        byte[] pkBytes = patternedBytes(SQIsignParameters.sqisign_lvl1.getPublicKeyLength(), 0x55);
        BCSQIsignPublicKey lvl1Pub = new BCSQIsignPublicKey(
            new SQIsignPublicKeyParameters(SQIsignParameters.sqisign_lvl1, pkBytes));

        Signature lvl3Sig = Signature.getInstance("sqisign_lvl3", "BCPQC");

        try
        {
            lvl3Sig.initVerify(lvl1Pub);
            fail("initVerify accepted a key for a different parameter set");
        }
        catch (java.security.InvalidKeyException e)
        {
            assertEquals("signature configured for sqisign_lvl3", e.getMessage());
        }
    }

    /**
     * Drive a real keygen + sign + verify cycle through the JCE API, proving
     * the engine is reachable end to end via both the parameter-set-specific
     * ({@code "sqisign_lvl1"}) and the generic ({@code "SQIsign"}) Signature
     * forms, and that a tampered message is rejected. Level 1 only — the
     * per-level SignatureSpi / KeyPairGeneratorSpi wiring is identical and the
     * higher levels are materially slower; their plumbing is covered by the
     * synthetic-byte tests above.
     */
    public void testSQIsignSign()
        throws Exception
    {
        byte[] msg = Strings.toByteArray("the cat sat on the SQIsign mat");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("sqisign_lvl1", "BCPQC");
        kpg.initialize(SQIsignParameterSpec.sqisign_lvl1, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        assertTrue(kp.getPublic() instanceof SQIsignKey);
        assertTrue(kp.getPrivate() instanceof SQIsignKey);
        assertEquals("sqisign_lvl1", kp.getPublic().getAlgorithm());
        assertEquals("sqisign_lvl1", kp.getPrivate().getAlgorithm());

        // parameter-set-specific Signature form
        byte[] sig = doSign("sqisign_lvl1", kp.getPrivate(), msg);
        assertTrue("parameter-set Signature verify failed",
            doVerify("sqisign_lvl1", kp.getPublic(), msg, sig));

        // generic "SQIsign" Signature form (parameter set carried by the key)
        byte[] sig2 = doSign("SQIsign", kp.getPrivate(), msg);
        assertTrue("generic Signature verify failed",
            doVerify("SQIsign", kp.getPublic(), msg, sig2));

        // a tampered message must not verify
        byte[] tampered = Arrays.clone(msg);
        tampered[0] ^= 0x01;
        assertFalse("tampered message verified",
            doVerify("sqisign_lvl1", kp.getPublic(), tampered, sig));
    }

    private static byte[] doSign(String alg, PrivateKey key, byte[] msg)
        throws Exception
    {
        Signature s = Signature.getInstance(alg, "BCPQC");
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    private static boolean doVerify(String alg, PublicKey key, byte[] msg, byte[] sig)
        throws Exception
    {
        Signature s = Signature.getInstance(alg, "BCPQC");
        s.initVerify(key);
        s.update(msg);
        return s.verify(sig);
    }

    private static byte[] patternedBytes(int len, int seed)
    {
        byte[] out = new byte[len];
        for (int i = 0; i != len; i++)
        {
            out[i] = (byte)((seed + i) & 0xff);
        }
        return out;
    }
}
