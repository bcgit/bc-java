package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.util.Arrays;

/**
 * Destroyable on the promoted key parameter classes (github #2432).
 * <p>
 * The JCE half of this is covered by {@code HashBasedKeyDestructionTest} in prov, which drives
 * {@code BCXMSSPrivateKey} - and so these classes - through the provider. What is covered here is
 * the lightweight half, which reaches its traversal state through {@code XMSSEngine.clearSecrets}
 * rather than a package-private call, because the key parameter classes and the state classes sit
 * in different packages.
 * </p>
 */
public class KeyDestructionTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;
    private static final byte[] MSG = new byte[]{ 1, 2, 3, 4 };

    private AsymmetricCipherKeyPair xmssKeyPair()
    {
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(
            new XMSSParameters(HEIGHT, new SHA256Digest()), new SecureRandom()));

        return kpg.generateKeyPair();
    }

    private AsymmetricCipherKeyPair xmssMTKeyPair()
    {
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(
            new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()), new SecureRandom()));

        return kpg.generateKeyPair();
    }

    private static byte[] sign(XMSSSigner signer, XMSSPrivateKeyParameters key)
    {
        signer.init(true, key);
        signer.update(MSG, 0, MSG.length);

        return signer.generateSignature();
    }

    private static byte[] sign(XMSSMTSigner signer, XMSSMTPrivateKeyParameters key)
    {
        signer.init(true, key);
        signer.update(MSG, 0, MSG.length);

        return signer.generateSignature();
    }

    private static boolean verify(XMSSSigner signer, XMSSPublicKeyParameters key, byte[] sig)
    {
        signer.init(false, key);
        signer.update(MSG, 0, MSG.length);

        return signer.verifySignature(sig);
    }

    private static boolean verify(XMSSMTSigner signer, XMSSMTPublicKeyParameters key, byte[] sig)
    {
        signer.init(false, key);
        signer.update(MSG, 0, MSG.length);

        return signer.verifySignature(sig);
    }

    public void testXMSSDestroy()
        throws Exception
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair();
        XMSSPrivateKeyParameters priv = (XMSSPrivateKeyParameters)kp.getPrivate();
        XMSSPublicKeyParameters pub = (XMSSPublicKeyParameters)kp.getPublic();

        byte[] sig = sign(new XMSSSigner(), priv);

        // split off before destruction: it holds its own copies of the seeds
        XMSSPrivateKeyParameters shard = priv.extractKeyShard(2);

        int index = priv.getIndex();
        byte[] publicSeed = priv.getPublicSeed();
        byte[] root = priv.getRoot();

        assertFalse(priv.isDestroyed());
        assertNotNull(priv.getSecretKeySeed());

        priv.destroy();

        assertTrue(priv.isDestroyed());

        checkThrowsDestroyed("getSecretKeySeed", new Op()
        {
            public void run(XMSSPrivateKeyParameters key)
            {
                key.getSecretKeySeed();
            }
        }, priv);
        checkThrowsDestroyed("getSecretKeyPRF", new Op()
        {
            public void run(XMSSPrivateKeyParameters key)
            {
                key.getSecretKeyPRF();
            }
        }, priv);
        checkThrowsDestroyed("getEncoded", new Op()
        {
            public void run(XMSSPrivateKeyParameters key)
                throws Exception
            {
                key.getEncoded();
            }
        }, priv);
        checkThrowsDestroyed("getNextKey", new Op()
        {
            public void run(XMSSPrivateKeyParameters key)
            {
                key.getNextKey();
            }
        }, priv);
        checkThrowsDestroyed("extractKeyShard", new Op()
        {
            public void run(XMSSPrivateKeyParameters key)
            {
                key.extractKeyShard(1);
            }
        }, priv);
        checkThrowsDestroyed("generateSignature", new Op()
        {
            public void run(XMSSPrivateKeyParameters key)
            {
                sign(new XMSSSigner(), key);
            }
        }, priv);

        // the refusal is ahead of the try whose finally rolls the key, so nothing moved
        assertEquals("a refused signature advanced the index", index, priv.getIndex());
        assertFalse("a refused signature marked the traversal state used",
            priv.getBDSState().isUsed());

        // the public side is not secret and is kept
        assertTrue(Arrays.areEqual(publicSeed, priv.getPublicSeed()));
        assertTrue(Arrays.areEqual(root, priv.getRoot()));
        assertNotNull(priv.getParameters());

        assertTrue("a signature made before destroy() no longer verifies",
            verify(new XMSSSigner(), pub, sig));

        assertFalse(shard.isDestroyed());
        assertTrue("the shard stopped signing when its source was destroyed",
            verify(new XMSSSigner(), pub, sign(new XMSSSigner(), shard)));

        // idempotent
        priv.destroy();
        assertTrue(priv.isDestroyed());
    }

    public void testXMSSMTDestroy()
        throws Exception
    {
        AsymmetricCipherKeyPair kp = xmssMTKeyPair();
        XMSSMTPrivateKeyParameters priv = (XMSSMTPrivateKeyParameters)kp.getPrivate();
        XMSSMTPublicKeyParameters pub = (XMSSMTPublicKeyParameters)kp.getPublic();

        byte[] sig = sign(new XMSSMTSigner(), priv);

        XMSSMTPrivateKeyParameters shard = priv.extractKeyShard(2);

        long index = priv.getIndex();
        byte[] publicSeed = priv.getPublicSeed();
        byte[] root = priv.getRoot();

        assertFalse(priv.isDestroyed());

        priv.destroy();

        assertTrue(priv.isDestroyed());

        checkThrowsDestroyed("getSecretKeySeed", new MTOp()
        {
            public void run(XMSSMTPrivateKeyParameters key)
            {
                key.getSecretKeySeed();
            }
        }, priv);
        checkThrowsDestroyed("getSecretKeyPRF", new MTOp()
        {
            public void run(XMSSMTPrivateKeyParameters key)
            {
                key.getSecretKeyPRF();
            }
        }, priv);
        checkThrowsDestroyed("getEncoded", new MTOp()
        {
            public void run(XMSSMTPrivateKeyParameters key)
                throws Exception
            {
                key.getEncoded();
            }
        }, priv);
        checkThrowsDestroyed("getNextKey", new MTOp()
        {
            public void run(XMSSMTPrivateKeyParameters key)
            {
                key.getNextKey();
            }
        }, priv);
        checkThrowsDestroyed("extractKeyShard", new MTOp()
        {
            public void run(XMSSMTPrivateKeyParameters key)
            {
                key.extractKeyShard(1);
            }
        }, priv);
        checkThrowsDestroyed("generateSignature", new MTOp()
        {
            public void run(XMSSMTPrivateKeyParameters key)
            {
                sign(new XMSSMTSigner(), key);
            }
        }, priv);

        assertEquals("a refused signature advanced the index", index, priv.getIndex());
        assertFalse("a refused signature marked the traversal state used",
            priv.getBDSState().isUsed());

        assertTrue(Arrays.areEqual(publicSeed, priv.getPublicSeed()));
        assertTrue(Arrays.areEqual(root, priv.getRoot()));
        assertNotNull(priv.getParameters());

        assertTrue("a signature made before destroy() no longer verifies",
            verify(new XMSSMTSigner(), pub, sig));

        assertFalse(shard.isDestroyed());
        assertTrue("the shard stopped signing when its source was destroyed",
            verify(new XMSSMTSigner(), pub, sign(new XMSSMTSigner(), shard)));

        priv.destroy();
        assertTrue(priv.isDestroyed());
    }

    private interface Op
    {
        void run(XMSSPrivateKeyParameters key)
            throws Exception;
    }

    private interface MTOp
    {
        void run(XMSSMTPrivateKeyParameters key)
            throws Exception;
    }

    private static void checkThrowsDestroyed(String name, Op op, XMSSPrivateKeyParameters key)
    {
        try
        {
            op.run(key);
            fail(name + " did not refuse a destroyed key");
        }
        catch (IllegalStateException e)
        {
            assertEquals(name, "key destroyed", e.getMessage());
        }
        catch (Exception e)
        {
            fail(name + " refused a destroyed key with " + e);
        }
    }

    private static void checkThrowsDestroyed(String name, MTOp op, XMSSMTPrivateKeyParameters key)
    {
        try
        {
            op.run(key);
            fail(name + " did not refuse a destroyed key");
        }
        catch (IllegalStateException e)
        {
            assertEquals(name, "key destroyed", e.getMessage());
        }
        catch (Exception e)
        {
            fail(name + " refused a destroyed key with " + e);
        }
    }
}
