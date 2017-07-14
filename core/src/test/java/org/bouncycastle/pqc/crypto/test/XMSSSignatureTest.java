package org.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSignature;
import org.bouncycastle.util.Arrays;

/**
 * Test cases for XMSSSignature class.
 */
public class XMSSSignatureTest
    extends TestCase
{

    public void testSignatureParsingSHA256()
    {
        XMSSParameters params = new XMSSParameters(10, new SHA256Digest());
        XMSS xmss = new XMSS(params, new NullPRNG());
        xmss.generateKeys();
        byte[] message = new byte[1024];
        byte[] sig1 = xmss.sign(message);
        XMSSSignature sig2 = new XMSSSignature.Builder(params).withSignature(sig1).build();

        byte[] sig3 = sig2.toByteArray();
        assertEquals(true, Arrays.areEqual(sig1, sig3));
    }

    public void testSignatureParsingSHA512()
    {
        XMSSParameters params = new XMSSParameters(10, new SHA512Digest());
        XMSS xmss = new XMSS(params, new NullPRNG());
        xmss.generateKeys();
        byte[] message = new byte[1024];
        byte[] sig1 = xmss.sign(message);
        XMSSSignature sig2 = new XMSSSignature.Builder(params).withSignature(sig1).build();

        byte[] sig3 = sig2.toByteArray();
        assertEquals(true, Arrays.areEqual(sig1, sig3));
    }

    public void testConstructor()
    {
        XMSSParameters params = new XMSSParameters(10, new SHA256Digest());
        XMSSSignature sig = new XMSSSignature.Builder(params).build();

        byte[] sigByte = sig.toByteArray();
        /* check everything is 0 */
        for (int i = 0; i < sigByte.length; i++)
        {
            assertEquals(0x00, sigByte[i]);
        }
    }
}
