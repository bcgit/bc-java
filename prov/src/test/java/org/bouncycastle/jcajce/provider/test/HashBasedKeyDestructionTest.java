package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.security.auth.Destroyable;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.LMSKeyPairGenerator;
import org.bouncycastle.crypto.params.HSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.crypto.signers.HSSSigner;
import org.bouncycastle.crypto.signers.LMSSigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.bouncycastle.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.jcajce.interfaces.XMSSMTPrivateKey;
import org.bouncycastle.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.jcajce.provider.asymmetric.lms.BCLMSPrivateKey;
import org.bouncycastle.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;
import org.bouncycastle.util.Strings;

/**
 * Verifies that the stateful hash-based private keys LMS/HSS, XMSS and XMSS^MT honour the JCA
 * {@link javax.security.auth.Destroyable} contract, extending {@link PQCKeyDestructionTest} to the
 * byte[]-backed keys that carry a one-time index: {@code destroy()} zeroizes the seeds,
 * {@code isDestroyed()} flips, {@code getEncoded()} and the secret accessors throw afterwards while
 * the index, usages remaining and public data survive, a Signature refuses the key at initSign, a
 * lightweight signing attempt fails before it spends an index, shards split off beforehand are
 * unaffected, and a destroyed key cannot be serialized. See github #2432.
 */
public class HashBasedKeyDestructionTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String BCPQC = BouncyCastlePQCProvider.PROVIDER_NAME;

    private static final byte[] MSG = Strings.toByteArray("Hello, world!");

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BCPQC) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testDestroyErasesLMSPrivateKey()
        throws Exception
    {
        LMSKeyGenParameterSpec h5 = new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4);

        // single tree, and a two level hierarchy
        checkLMSKey(h5);
        checkLMSKey(new LMSHSSKeyGenParameterSpec(new LMSKeyGenParameterSpec[]{ h5, h5 }));
    }

    private void checkLMSKey(AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("LMS", BC);
        kpg.initialize(spec, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        final LMSPrivateKey priv = (LMSPrivateKey)kp.getPrivate();

        // use the key once and split a shard off it, so the destroyed key has state behind it
        sign("LMS", BC, priv, kp);
        LMSPrivateKey shard = priv.extractKeyShard(2);

        long index = priv.getIndex();
        long usagesRemaining = priv.getUsagesRemaining();
        int levels = priv.getLevels();

        checkDestroy("LMS", BC, priv);

        // the position and shape of the key are not secret and stay available
        assertEquals("LMS: index should survive destroy()", index, priv.getIndex());
        assertEquals("LMS: usages remaining should survive destroy()", usagesRemaining, priv.getUsagesRemaining());
        assertEquals("LMS: levels should survive destroy()", levels, priv.getLevels());

        checkInitSignRefused("LMS", BC, priv);
        checkThrowsDestroyed("LMS: extractKeyShard()", new Callable()
        {
            public Object call()
            {
                return priv.extractKeyShard(1);
            }
        });

        // a shard split off before destruction is an independent copy and still signs
        sign("LMS", BC, shard, kp);
    }

    @SuppressWarnings("deprecation") // getMasterSecret is deprecated but must still refuse a destroyed key
    public void testLightweightLMSDestroy()
        throws Exception
    {
        LMSParameters lmsParams = LMSParameters.create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4);

        LMSKeyPairGenerator kpGen = new LMSKeyPairGenerator();
        kpGen.init(new LMSKeyGenerationParameters(lmsParams, new SecureRandom()));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        final LMSPrivateKeyParameters priv = (LMSPrivateKeyParameters)kp.getPrivate();

        final LMSSigner signer = new LMSSigner();
        signer.init(true, priv);
        byte[] sig = signer.generateSignature(MSG);

        int index = priv.getIndex();
        assertEquals(1, index);
        assertNotNull(priv.getMasterSecret());

        checkLightweightDestroy("LMS", priv);

        checkThrowsDestroyed("LMS params: getMasterSecret()", new Callable()
        {
            public Object call()
            {
                return priv.getMasterSecret();
            }
        });
        checkThrowsDestroyed("LMS params: getEncoded()", new Callable()
        {
            public Object call()
                throws Exception
            {
                return priv.getEncoded();
            }
        });

        // a signing attempt is refused before the one-time index is claimed
        checkThrowsDestroyed("LMS params: generateSignature()", new Callable()
        {
            public Object call()
            {
                return signer.generateSignature(MSG);
            }
        });
        assertEquals("LMS params: a refused signature must not spend an index", index, priv.getIndex());

        // the public side survives: identifier, parameters, index and the public key already derived
        assertNotNull(priv.getI());
        assertNotNull(priv.getSigParameters());
        assertEquals(kp.getPublic(), priv.getPublicKey());

        signer.init(false, kp.getPublic());
        assertTrue("LMS params: signature made before destroy() should still verify", signer.verifySignature(MSG, sig));
    }

    public void testLightweightHSSDestroy()
        throws Exception
    {
        LMSParameters h5 = LMSParameters.create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4);

        HSSKeyPairGenerator kpGen = new HSSKeyPairGenerator();
        kpGen.init(new HSSKeyGenerationParameters(new LMSParameters[]{ h5, h5 }, new SecureRandom()));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        final HSSPrivateKeyParameters priv = (HSSPrivateKeyParameters)kp.getPrivate();

        // a shard is a deep copy, so it must outlive the destruction of the key it came from
        HSSPrivateKeyParameters shard = priv.extractKeyShard(2);

        final HSSSigner signer = new HSSSigner();
        signer.init(true, priv);
        byte[] sig = signer.generateSignature(MSG);

        long index = priv.getIndex();

        // two JCA keys wrapping the one lightweight key: destroying one invalidates the other
        BCLMSPrivateKey wrapper = new BCLMSPrivateKey(priv);
        BCLMSPrivateKey otherWrapper = new BCLMSPrivateKey(priv);

        assertFalse(priv.isDestroyed());
        assertFalse(otherWrapper.isDestroyed());

        wrapper.destroy();

        assertTrue("HSS params: not destroyed with its wrapper", priv.isDestroyed());
        assertTrue("HSS: second wrapper not destroyed with the shared key", otherWrapper.isDestroyed());

        checkThrowsDestroyed("HSS params: getEncoded()", new Callable()
        {
            public Object call()
                throws Exception
            {
                return priv.getEncoded();
            }
        });
        checkThrowsDestroyed("HSS params: generateSignature()", new Callable()
        {
            public Object call()
            {
                return signer.generateSignature(MSG);
            }
        });
        assertEquals("HSS params: a refused signature must not spend an index", index, priv.getIndex());
        checkThrowsDestroyed("HSS params: extractKeyShard()", new Callable()
        {
            public Object call()
            {
                return priv.extractKeyShard(1);
            }
        });

        // the public side survives
        assertEquals(kp.getPublic(), priv.getPublicKey());
        assertEquals(2, priv.getLMSParameters().length);

        signer.init(false, kp.getPublic());
        assertTrue("HSS params: signature made before destroy() should still verify", signer.verifySignature(MSG, sig));

        // the shard split off beforehand still signs under the same public key
        assertFalse(shard.isDestroyed());
        signer.init(true, shard);
        byte[] shardSig = signer.generateSignature(MSG);
        signer.init(false, kp.getPublic());
        assertTrue("HSS params: shard should still sign after its source is destroyed", signer.verifySignature(MSG, shardSig));
    }

    public void testDestroyErasesXMSSPrivateKey()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", BCPQC);
        kpg.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        final XMSSPrivateKey priv = (XMSSPrivateKey)kp.getPrivate();

        sign("XMSS", BCPQC, priv, kp);
        XMSSPrivateKey shard = priv.extractKeyShard(2);

        long index = priv.getIndex();
        long usagesRemaining = priv.getUsagesRemaining();

        checkDestroy("XMSS", BCPQC, priv);

        assertEquals("XMSS: index should survive destroy()", index, priv.getIndex());
        assertEquals("XMSS: usages remaining should survive destroy()", usagesRemaining, priv.getUsagesRemaining());
        assertEquals("XMSS: height should survive destroy()", 4, priv.getHeight());
        assertEquals("XMSS: tree digest should survive destroy()", "SHA256", priv.getTreeDigest());

        checkInitSignRefused("XMSS", BCPQC, priv);
        checkThrowsDestroyed("XMSS: extractKeyShard()", new Callable()
        {
            public Object call()
            {
                return priv.extractKeyShard(1);
            }
        });

        // a shard split off before destruction holds its own seeds and still signs
        sign("XMSS", BCPQC, shard, kp);
    }

    public void testLightweightXMSSDestroy()
        throws Exception
    {
        XMSSKeyPairGenerator kpGen = new XMSSKeyPairGenerator();
        kpGen.init(new XMSSKeyGenerationParameters(new XMSSParameters(4, new SHA256Digest()), new SecureRandom()));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        final XMSSPrivateKeyParameters priv = (XMSSPrivateKeyParameters)kp.getPrivate();

        final XMSSSigner signer = new XMSSSigner();
        signer.init(true, priv);
        byte[] sig = signer.generateSignature(MSG);

        XMSSPrivateKeyParameters shard = priv.extractKeyShard(2);

        int index = priv.getIndex();
        byte[] publicSeed = priv.getPublicSeed();
        byte[] root = priv.getRoot();
        assertNotNull(priv.getSecretKeySeed());
        assertNotNull(priv.getSecretKeyPRF());

        checkLightweightDestroy("XMSS", priv);

        checkThrowsDestroyed("XMSS params: getSecretKeySeed()", new Callable()
        {
            public Object call()
            {
                return priv.getSecretKeySeed();
            }
        });
        checkThrowsDestroyed("XMSS params: getSecretKeyPRF()", new Callable()
        {
            public Object call()
            {
                return priv.getSecretKeyPRF();
            }
        });
        checkThrowsDestroyed("XMSS params: getEncoded()", new Callable()
        {
            public Object call()
                throws Exception
            {
                return priv.getEncoded();
            }
        });
        checkThrowsDestroyed("XMSS params: generateSignature()", new Callable()
        {
            public Object call()
            {
                return signer.generateSignature(MSG);
            }
        });
        assertEquals("XMSS params: a refused signature must not advance the index", index, priv.getIndex());
        checkThrowsDestroyed("XMSS params: getNextKey()", new Callable()
        {
            public Object call()
            {
                return priv.getNextKey();
            }
        });

        // the public side survives
        assertTrue(org.bouncycastle.util.Arrays.areEqual(publicSeed, priv.getPublicSeed()));
        assertTrue(org.bouncycastle.util.Arrays.areEqual(root, priv.getRoot()));
        assertNotNull(priv.getParameters());

        signer.init(false, kp.getPublic());
        assertTrue("XMSS params: signature made before destroy() should still verify", signer.verifySignature(MSG, sig));

        // the shard split off beforehand still signs under the same public key
        assertFalse(shard.isDestroyed());
        signer.init(true, shard);
        byte[] shardSig = signer.generateSignature(MSG);
        signer.init(false, kp.getPublic());
        assertTrue("XMSS params: shard should still sign after its source is destroyed", signer.verifySignature(MSG, shardSig));
    }

    public void testDestroyErasesXMSSMTPrivateKey()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", BCPQC);
        kpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHA256), new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        final XMSSMTPrivateKey priv = (XMSSMTPrivateKey)kp.getPrivate();

        sign("XMSSMT", BCPQC, priv, kp);
        XMSSMTPrivateKey shard = priv.extractKeyShard(2);

        long index = priv.getIndex();
        long usagesRemaining = priv.getUsagesRemaining();

        checkDestroy("XMSSMT", BCPQC, priv);

        assertEquals("XMSSMT: index should survive destroy()", index, priv.getIndex());
        assertEquals("XMSSMT: usages remaining should survive destroy()", usagesRemaining, priv.getUsagesRemaining());
        assertEquals("XMSSMT: height should survive destroy()", 4, priv.getHeight());
        assertEquals("XMSSMT: layers should survive destroy()", 2, priv.getLayers());
        assertEquals("XMSSMT: tree digest should survive destroy()", "SHA256", priv.getTreeDigest());

        checkInitSignRefused("XMSSMT", BCPQC, priv);
        checkThrowsDestroyed("XMSSMT: extractKeyShard()", new Callable()
        {
            public Object call()
            {
                return priv.extractKeyShard(1);
            }
        });

        sign("XMSSMT", BCPQC, shard, kp);
    }

    public void testLightweightXMSSMTDestroy()
        throws Exception
    {
        XMSSMTKeyPairGenerator kpGen = new XMSSMTKeyPairGenerator();
        kpGen.init(new XMSSMTKeyGenerationParameters(new XMSSMTParameters(4, 2, new SHA256Digest()), new SecureRandom()));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        final XMSSMTPrivateKeyParameters priv = (XMSSMTPrivateKeyParameters)kp.getPrivate();

        final XMSSMTSigner signer = new XMSSMTSigner();
        signer.init(true, priv);
        byte[] sig = signer.generateSignature(MSG);

        XMSSMTPrivateKeyParameters shard = priv.extractKeyShard(2);

        long index = priv.getIndex();
        byte[] publicSeed = priv.getPublicSeed();
        byte[] root = priv.getRoot();
        assertNotNull(priv.getSecretKeySeed());
        assertNotNull(priv.getSecretKeyPRF());

        checkLightweightDestroy("XMSSMT", priv);

        checkThrowsDestroyed("XMSSMT params: getSecretKeySeed()", new Callable()
        {
            public Object call()
            {
                return priv.getSecretKeySeed();
            }
        });
        checkThrowsDestroyed("XMSSMT params: getSecretKeyPRF()", new Callable()
        {
            public Object call()
            {
                return priv.getSecretKeyPRF();
            }
        });
        checkThrowsDestroyed("XMSSMT params: getEncoded()", new Callable()
        {
            public Object call()
                throws Exception
            {
                return priv.getEncoded();
            }
        });
        checkThrowsDestroyed("XMSSMT params: generateSignature()", new Callable()
        {
            public Object call()
            {
                return signer.generateSignature(MSG);
            }
        });
        assertEquals("XMSSMT params: a refused signature must not advance the index", index, priv.getIndex());
        checkThrowsDestroyed("XMSSMT params: getNextKey()", new Callable()
        {
            public Object call()
            {
                return priv.getNextKey();
            }
        });

        assertTrue(org.bouncycastle.util.Arrays.areEqual(publicSeed, priv.getPublicSeed()));
        assertTrue(org.bouncycastle.util.Arrays.areEqual(root, priv.getRoot()));
        assertNotNull(priv.getParameters());

        signer.init(false, kp.getPublic());
        assertTrue("XMSSMT params: signature made before destroy() should still verify", signer.verifySignature(MSG, sig));

        assertFalse(shard.isDestroyed());
        signer.init(true, shard);
        byte[] shardSig = signer.generateSignature(MSG);
        signer.init(false, kp.getPublic());
        assertTrue("XMSSMT params: shard should still sign after its source is destroyed", signer.verifySignature(MSG, shardSig));
    }

    private void sign(String algorithm, String provider, PrivateKey priv, KeyPair kp)
        throws Exception
    {
        Signature signer = Signature.getInstance(algorithm, provider);

        signer.initSign(priv);
        signer.update(MSG);
        byte[] sig = signer.sign();

        signer.initVerify(kp.getPublic());
        signer.update(MSG);
        assertTrue(algorithm + ": signature should verify", signer.verify(sig));
    }

    private void checkInitSignRefused(String algorithm, String provider, PrivateKey priv)
        throws Exception
    {
        Signature signer = Signature.getInstance(algorithm, provider);

        try
        {
            signer.initSign(priv);
            fail(algorithm + ": initSign should refuse a destroyed key");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
    }

    /**
     * The contract common to every key: destroy() succeeds and is idempotent, isDestroyed()
     * flips, getEncoded() throws, hashCode() is stable, equality collapses to identity and
     * serialization fails cleanly.
     */
    private void checkDestroy(String algorithm, String provider, final PrivateKey priv)
        throws Exception
    {
        byte[] enc = priv.getEncoded();
        assertNotNull(algorithm + ": no encoding", enc);

        // through the interface rather than off PrivateKey: PrivateKey extends Destroyable only
        // from Java 8, and this suite is compiled by the genuine 1.5 javac of the jdk15to18 build
        final Destroyable dPriv = (Destroyable)priv;

        assertFalse(algorithm + ": key reported destroyed before destroy()", dPriv.isDestroyed());

        int preHashCode = priv.hashCode();

        PrivateKey copy = KeyFactory.getInstance(algorithm, provider).generatePrivate(new PKCS8EncodedKeySpec(enc));
        assertEquals(algorithm + ": copy should equal original before destroy()", priv, copy);

        // must succeed without throwing DestroyFailedException
        dPriv.destroy();

        assertTrue(algorithm + ": key not reported destroyed after destroy()", dPriv.isDestroyed());

        checkThrowsDestroyed(algorithm + ": getEncoded()", new Callable()
        {
            public Object call()
            {
                return priv.getEncoded();
            }
        });

        assertEquals(algorithm + ": hashCode should be stable across destroy()", preHashCode, priv.hashCode());
        assertTrue(algorithm + ": destroyed key should still equal itself", priv.equals(priv));
        assertFalse(algorithm + ": destroyed key should not equal a live copy", priv.equals(copy));
        assertFalse(algorithm + ": live copy should not equal a destroyed key", copy.equals(priv));

        // serializing a destroyed key must fail with IOException, not a leaked IllegalStateException
        ObjectOutputStream oOut = new ObjectOutputStream(new ByteArrayOutputStream());
        try
        {
            oOut.writeObject(priv);
            fail(algorithm + ": serialization should throw once destroyed");
        }
        catch (IOException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
        catch (IllegalStateException e)
        {
            fail(algorithm + ": IllegalStateException must not escape writeObject");
        }

        // destroy() is idempotent - a second call must not throw
        dPriv.destroy();
        assertTrue(dPriv.isDestroyed());
    }

    private void checkLightweightDestroy(String algorithm, Object params)
        throws Exception
    {
        assertTrue(algorithm + " params: must be destroyable", params instanceof Destroyable);

        Destroyable dParams = (Destroyable)params;
        assertFalse(algorithm + " params: reported destroyed before destroy()", dParams.isDestroyed());

        dParams.destroy();

        assertTrue(algorithm + " params: not reported destroyed after destroy()", dParams.isDestroyed());

        // idempotent
        dParams.destroy();
        assertTrue(dParams.isDestroyed());
    }

    private void checkThrowsDestroyed(String what, Callable call)
        throws Exception
    {
        try
        {
            call.call();
            fail(what + " should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
    }

    private interface Callable
    {
        Object call()
            throws Exception;
    }
}
