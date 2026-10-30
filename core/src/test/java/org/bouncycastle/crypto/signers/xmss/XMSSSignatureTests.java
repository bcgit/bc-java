package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.pqc.crypto.test.NullPRNG;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.signers.xmss.XMSSHarnessTests.XMSS;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Test cases for XMSSSignature class.
 */
public class XMSSSignatureTests
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

    /**
     * An XMSS signature is a (4 + n + (len + h) * n)-byte string (RFC 8391 sec. 4.1.8), so a
     * signature carrying trailing data - or a truncated one - is not a signature for these
     * parameters. XMSSMTSignature has always checked this way (github #2408).
     */
    public void testSignatureWrongSizeRejected()
    {
        XMSSParameters params = new XMSSParameters(10, new SHA256Digest());
        XMSS xmss = new XMSS(params, new NullPRNG());
        xmss.generateKeys();
        byte[] sig = xmss.sign(new byte[1024]);

        byte[][] wrongSize = new byte[][]
            {
                Arrays.append(sig, (byte)0x2a),
                Arrays.copyOfRange(sig, 0, sig.length - 1),
                new byte[0]
            };

        for (int i = 0; i != wrongSize.length; i++)
        {
            try
            {
                new XMSSSignature.Builder(params).withSignature(wrongSize[i]).build();
                fail("no exception on signature of wrong size: " + i);
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("signature has wrong size", e.getMessage());
            }
        }
    }

    /**
     * The parse-level check above has to reach verification: a signature with bytes appended, or
     * one cut short, must answer false rather than verify (github #2408).
     */
    public void testVerifyRejectsWrongSize()
    {
        byte[] msg = Strings.toByteArray("Cthulhu Fthagn --What a wonderful phrase!");

        XMSSKeyPairGenerator kpGen = new XMSSKeyPairGenerator();

        kpGen.init(new XMSSKeyGenerationParameters(new XMSSParameters(4, new SHA256Digest()), new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());

        byte[] sig = XMSSHarnessTests.sign(signer, msg);

        signer.init(false, kp.getPublic());

        assertTrue(XMSSHarnessTests.verify(signer, msg, sig));
        assertFalse(XMSSHarnessTests.verify(signer, msg, Arrays.append(sig, (byte)0x2a)));
        assertFalse(XMSSHarnessTests.verify(signer, msg, Arrays.copyOfRange(sig, 0, sig.length - 1)));
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
