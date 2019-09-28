package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

/**
 * Test cases for XMSSMTPrivateKey class.
 */
public class XMSSMTPrivateKeyTest
    extends TestCase
{
    public void testPrivateKeySerialisation()
        throws Exception
    {
        String stream = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArO0ABXNyACJzdW4ucm1pLnNlcnZlci5BY3RpdmF0aW9uR3JvdXBJbXBsT+r9SAwuMqcCAARaAA1ncm91cEluYWN0aXZlTAAGYWN0aXZldAAVTGphdmEvdXRpbC9IYXNodGFibGU7TAAHZ3JvdXBJRHQAJ0xqYXZhL3JtaS9hY3RpdmF0aW9uL0FjdGl2YXRpb25Hcm91cElEO0wACWxvY2tlZElEc3QAEExqYXZhL3V0aWwvTGlzdDt4cgAjamF2YS5ybWkuYWN0aXZhdGlvbi5BY3RpdmF0aW9uR3JvdXCVLvKwBSnVVAIAA0oAC2luY2FybmF0aW9uTAAHZ3JvdXBJRHEAfgACTAAHbW9uaXRvcnQAJ0xqYXZhL3JtaS9hY3RpdmF0aW9uL0FjdGl2YXRpb25Nb25pdG9yO3hyACNqYXZhLnJtaS5zZXJ2ZXIuVW5pY2FzdFJlbW90ZU9iamVjdEUJEhX14n4xAgADSQAEcG9ydEwAA2NzZnQAKExqYXZhL3JtaS9zZXJ2ZXIvUk1JQ2xpZW50U29ja2V0RmFjdG9yeTtMAANzc2Z0AChMamF2YS9ybWkvc2VydmVyL1JNSVNlcnZlclNvY2tldEZhY3Rvcnk7eHIAHGphdmEucm1pLnNlcnZlci5SZW1vdGVTZXJ2ZXLHGQcSaPM5+wIAAHhyABxqYXZhLnJtaS5zZXJ2ZXIuUmVtb3RlT2JqZWN002G0kQxhMx4DAAB4cHcSABBVbmljYXN0U2VydmVyUmVmeAAAFbNwcAAAAAAAAAAAcHAAcHBw";

        XMSSParameters params = new XMSSParameters(10, new SHA256Digest());

        byte[] output = Base64.decode(new String(stream).getBytes("UTF-8"));


        //Simple Exploit

        try
        {
            new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(output).build();
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue(e.getCause() instanceof IOException);
        }

        //Same Exploit other method

        XMSS xmss2 = new XMSS(params, new SecureRandom());

        xmss2.generateKeys();

        try
        {
            PrivateKeyFactory.createKey(output);
        }
        catch (IOException e)
        {
            assertTrue(e instanceof IOException);
        }
    }

    public void testPrivateKeyParsingSHA256()
        throws Exception
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
