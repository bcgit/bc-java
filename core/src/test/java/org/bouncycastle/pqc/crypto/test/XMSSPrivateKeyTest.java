package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
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

    private void parsingTest(Digest digest)
        throws ClassNotFoundException, IOException
    {
        XMSSParameters params = new XMSSParameters(10, digest);
        byte[] root = generateRoot(digest);
        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params).withRoot(root).build();

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
        int digestSize = (digest instanceof Xof) ? digest.getDigestSize() * 2 : digest.getDigestSize();
        byte[] rv = new byte[digestSize];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = (byte)i;
        }

        return rv;
    }

}
