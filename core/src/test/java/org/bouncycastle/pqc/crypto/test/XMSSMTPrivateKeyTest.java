package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.util.Arrays;

/**
 * Test cases for XMSSMTPrivateKey class.
 */
public class XMSSMTPrivateKeyTest
    extends TestCase
{

    public void testPrivateKeyParsingSHA256()
        throws IOException, ClassNotFoundException
    {
        XMSSMTParameters params = new XMSSMTParameters(20, 10, new SHA256Digest());
        XMSSMT mt = new XMSSMT(params, new SecureRandom());
        mt.generateKeys();
        byte[] privateKey = mt.exportPrivateKey();
        byte[] publicKey = mt.exportPublicKey();

        mt.importState(privateKey, publicKey);

        assertTrue(Arrays.areEqual(privateKey, mt.exportPrivateKey()));
    }
}
