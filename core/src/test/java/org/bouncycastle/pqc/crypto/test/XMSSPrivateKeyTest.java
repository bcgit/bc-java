package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.Strings;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * Test cases for XMSSPrivateKey class.
 */
public class XMSSPrivateKeyTest
    extends TestCase
{
    public void testPrivateKeyParsing()
        throws ClassNotFoundException, IOException
    {
        parsingTest(new SHA256Digest());
        parsingTest(new SHA512Digest());
        parsingTest(new SHAKEDigest(128));
        parsingTest(new SHAKEDigest(256));
    }

    /**
     * A stored XMSS private key carries the tree root twice - its own field and the root of the BDS
     * state beside it - and decode requires them to agree. Until this check a corrupted root was
     * accepted and then poisoned every signature the key made: the root is hashed into the message
     * digest, so the signature did not verify, with nothing to say why (github #2414).
     */
    public void testRootCorruptionRejected()
        throws Exception
    {
        int n = 32;
        XMSSParameters params = new XMSSParameters(10, new SHA256Digest());
        XMSSKeyPairGenerator kpGen = new XMSSKeyPairGenerator();
        kpGen.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        XMSSSigner signer = new XMSSSigner();
        signer.init(true, kp.getPrivate());
        for (int i = 0; i != 3; i++)
        {
            signer.generateSignature(Strings.toByteArray("message"));
        }
        XMSSPrivateKeyParameters advanced = (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();
        byte[] enc = advanced.getEncoded();

        // index(4) | secretKeySeed(n) | secretKeyPRF(n) | publicSeed(n) | root(n) | BDS state
        int rootOff = 4 + 3 * n;
        assertTrue(Arrays.areEqual(advanced.getRoot(),
            Arrays.copyOfRange(enc, rootOff, rootOff + n)));

        for (int b = 0; b != n; b++)
        {
            byte[] corrupt = Arrays.clone(enc);
            corrupt[rootOff + b] ^= 0x01;
            try
            {
                new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(corrupt).build();
                fail("no exception on corrupt root byte " + b);
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("BDS state root does not match the private key root", e.getMessage());
            }
        }

        // the untouched encoding still decodes and still signs verifiably
        XMSSPrivateKeyParameters decoded =
            new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(enc).build();
        XMSSSigner s2 = new XMSSSigner();
        s2.init(true, decoded);
        byte[] sig = s2.generateSignature(Strings.toByteArray("message"));
        XMSSSigner v = new XMSSSigner();
        v.init(false, kp.getPublic());
        assertTrue(v.verifySignature(Strings.toByteArray("message"), sig));
    }

    private void parsingTest(Digest digest)
        throws ClassNotFoundException, IOException
    {
        //
        // A generated key rather than one assembled from placeholder fields: the private key carries
        // the tree root twice - its own field and the root of its BDS state - and decode now requires
        // the two to agree (github #2414), which a placeholder root does not. Such a key could never
        // produce a verifying signature anyway, since the root is hashed into the message digest.
        //
        XMSSParameters params = new XMSSParameters(4, digest);
        XMSSKeyPairGenerator kpGen = new XMSSKeyPairGenerator();
        kpGen.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));
        XMSSPrivateKeyParameters privateKey = (XMSSPrivateKeyParameters)kpGen.generateKeyPair().getPrivate();

        byte[] export = privateKey.toByteArray();

        XMSSPrivateKeyParameters privateKey2 = new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(export).build();

        assertEquals(privateKey.getIndex(), privateKey2.getIndex());
        assertEquals(true, Arrays.areEqual(privateKey.getSecretKeySeed(), privateKey2.getSecretKeySeed()));
        assertEquals(true, Arrays.areEqual(privateKey.getSecretKeyPRF(), privateKey2.getSecretKeyPRF()));
        assertEquals(true, Arrays.areEqual(privateKey.getPublicSeed(), privateKey2.getPublicSeed()));
        assertEquals(true, Arrays.areEqual(privateKey.getRoot(), privateKey2.getRoot()));
    }

    private byte[] generateRoot(Digest digest)
    {
        byte[] rv = new byte[digest.getDigestSize()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = (byte)i;
        }

        return rv;
    }

}
