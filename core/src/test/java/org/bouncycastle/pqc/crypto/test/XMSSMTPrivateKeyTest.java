package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

/**
 * Test cases for XMSSMTPrivateKey class.
 */
public class XMSSMTPrivateKeyTest
    extends TestCase
{
    /**
     * A stored XMSS^MT private key whose index has been rolled back while its BDS traversal state
     * stayed advanced is refused at decode. RFC 8391 sec. 1.1 requires each one-time key to be used
     * once, and until this check the rolled-back key was accepted and signed a second message under
     * a one-time key already used - a signature which verified, so nothing surfaced it. The XMSS side
     * has always tied its state to its index; this is the multi-tree counterpart.
     */
    public void testIndexRollbackRejected()
        throws Exception
    {
        int height = 6, layers = 2;
        XMSSMTParameters params = new XMSSMTParameters(height, layers, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();
        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        XMSSMTSigner signer = new XMSSMTSigner();
        signer.init(true, kp.getPrivate());
        for (int i = 0; i != 5; i++)
        {
            signer.generateSignature(Strings.toByteArray("message"));
        }
        XMSSMTPrivateKeyParameters advanced = (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();
        assertEquals(5, advanced.getIndex());

        byte[] enc = advanced.getEncoded();

        // the encoding opens with the index, in ceil(totalHeight / 8) octets
        int indexSize = (height + 7) / 8;
        for (int roll = 0; roll != 5; roll++)
        {
            byte[] rolled = Arrays.clone(enc);
            for (int i = 0; i != indexSize; i++)
            {
                rolled[i] = 0;
            }
            rolled[indexSize - 1] = (byte)roll;
            try
            {
                new XMSSMTPrivateKeyParameters.Builder(params).withPrivateKey(rolled).build();
                fail("no exception on index rolled back to " + roll);
            }
            catch (IllegalArgumentException e)
            {
                assertTrue(e.getMessage(), e.getMessage().startsWith("BDS state has wrong index for layer"));
            }
        }

        // the untouched encoding still decodes, and still signs verifiably
        XMSSMTPrivateKeyParameters decoded =
            new XMSSMTPrivateKeyParameters.Builder(params).withPrivateKey(enc).build();
        assertEquals(5, decoded.getIndex());

        XMSSMTSigner s2 = new XMSSMTSigner();
        s2.init(true, decoded);
        byte[] sig = s2.generateSignature(Strings.toByteArray("message"));
        XMSSMTSigner v = new XMSSMTSigner();
        v.init(false, kp.getPublic());
        assertTrue(v.verifySignature(Strings.toByteArray("message"), sig));
    }

    /**
     * Every index a key can reach still encodes and decodes, and the decoded key still signs
     * verifiably - the compatibility half of testIndexRollbackRejected. A layer whose leaf index is
     * zero legitimately carries the previous subtree's final index, so the binding above has to
     * tolerate that one position; walking the whole key space is what proves it does.
     */
    public void testEveryIndexRoundTrips()
        throws Exception
    {
        int height = 6, layers = 3;
        XMSSMTParameters params = new XMSSMTParameters(height, layers, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();
        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSMTPrivateKeyParameters key = (XMSSMTPrivateKeyParameters)kp.getPrivate();
        XMSSMTSigner signer = new XMSSMTSigner();

        int total = 1 << height;
        for (int i = 0; i != total; i++)
        {
            XMSSMTPrivateKeyParameters decoded = new XMSSMTPrivateKeyParameters.Builder(params)
                .withPrivateKey(key.getEncoded()).build();
            assertEquals(key.getIndex(), decoded.getIndex());

            XMSSMTSigner ds = new XMSSMTSigner();
            ds.init(true, decoded);
            byte[] sig = ds.generateSignature(Strings.toByteArray("message"));
            XMSSMTSigner v = new XMSSMTSigner();
            v.init(false, kp.getPublic());
            assertTrue("index " + key.getIndex(), v.verifySignature(Strings.toByteArray("message"), sig));

            if (i == total - 1)
            {
                break;
            }
            signer.init(true, key);
            signer.generateSignature(Strings.toByteArray("message"));
            key = (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();
        }
    }

    public void testPrivateKeySerialisation()
        throws Exception
    {
        String stream = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArO0ABXNyACJzdW4ucm1pLnNlcnZlci5BY3RpdmF0aW9uR3JvdXBJbXBsT+r9SAwuMqcCAARaAA1ncm91cEluYWN0aXZlTAAGYWN0aXZldAAVTGphdmEvdXRpbC9IYXNodGFibGU7TAAHZ3JvdXBJRHQAJ0xqYXZhL3JtaS9hY3RpdmF0aW9uL0FjdGl2YXRpb25Hcm91cElEO0wACWxvY2tlZElEc3QAEExqYXZhL3V0aWwvTGlzdDt4cgAjamF2YS5ybWkuYWN0aXZhdGlvbi5BY3RpdmF0aW9uR3JvdXCVLvKwBSnVVAIAA0oAC2luY2FybmF0aW9uTAAHZ3JvdXBJRHEAfgACTAAHbW9uaXRvcnQAJ0xqYXZhL3JtaS9hY3RpdmF0aW9uL0FjdGl2YXRpb25Nb25pdG9yO3hyACNqYXZhLnJtaS5zZXJ2ZXIuVW5pY2FzdFJlbW90ZU9iamVjdEUJEhX14n4xAgADSQAEcG9ydEwAA2NzZnQAKExqYXZhL3JtaS9zZXJ2ZXIvUk1JQ2xpZW50U29ja2V0RmFjdG9yeTtMAANzc2Z0AChMamF2YS9ybWkvc2VydmVyL1JNSVNlcnZlclNvY2tldEZhY3Rvcnk7eHIAHGphdmEucm1pLnNlcnZlci5SZW1vdGVTZXJ2ZXLHGQcSaPM5+wIAAHhyABxqYXZhLnJtaS5zZXJ2ZXIuUmVtb3RlT2JqZWN002G0kQxhMx4DAAB4cHcSABBVbmljYXN0U2VydmVyUmVmeAAAFbNwcAAAAAAAAAAAcHAAcHBw";

        XMSSParameters params = new XMSSParameters(10, new SHA256Digest());

        byte[] output = Base64.decode(Strings.toUTF8ByteArray(stream));
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
