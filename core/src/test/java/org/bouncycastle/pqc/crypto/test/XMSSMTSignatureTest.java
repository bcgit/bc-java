package org.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature;
import org.bouncycastle.util.Arrays;

/**
 * Test cases for XMSS^MT signature class.
 */
public class XMSSMTSignatureTest
    extends TestCase
{

    public void testSignatureParsingSHA256()
    {
        int totalHeight = 6;
        int layers = 3;
        byte[] message = new byte[1024];
        XMSSMTParameters params = new XMSSMTParameters(totalHeight, layers, new SHA256Digest());
        XMSSMT xmssMT = new XMSSMT(params, new NullPRNG());
        xmssMT.generateKeys();
        byte[] signature1 = xmssMT.sign(message);
        XMSSMTSignature mtSignature = new XMSSMTSignature.Builder(params).withSignature(signature1).build();
        byte[] signature2 = mtSignature.toByteArray();
        assertTrue(Arrays.areEqual(signature1, signature2));
    }

    public void testConstructor()
    {
        XMSSMTParameters params = new XMSSMTParameters(20, 10, new SHA256Digest());
        XMSSMTSignature sig = null;
        try
        {
            sig = new XMSSMTSignature.Builder(params).build();
        }
        catch (IllegalArgumentException ex)
        {
            ex.printStackTrace();
        }
        byte[] sigByte = sig.toByteArray();
        /* check everything is 0 */
        for (int i = 0; i < sigByte.length; i++)
        {
            assertEquals(0x00, sigByte[i]);
        }
    }
}
