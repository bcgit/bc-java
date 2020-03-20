package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSSigner;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class LMSTest
    extends TestCase
{
    public void testKeyGenAndSign()
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");
        AsymmetricCipherKeyPairGenerator kpGen = new LMSKeyPairGenerator();

        kpGen.init(new LMSKeyGenerationParameters(
            new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4), new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        LMSSigner signer = new LMSSigner();

        signer.init(true, kp.getPrivate());

        byte[] sig = signer.generateSignature(msg);

        signer.init(false, kp.getPublic());

        assertTrue(signer.verifySignature(msg, sig));
    }

    public void testKeyGenAndSignTwoSigsWithShard()
        throws Exception
    {
        byte[] msg1 = Strings.toByteArray("Hello, world!");
        byte[] msg2 = Strings.toByteArray("Now is the time");

        AsymmetricCipherKeyPairGenerator kpGen = new LMSKeyPairGenerator();

        kpGen.init(new LMSKeyGenerationParameters(
            new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4), new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        LMSPrivateKeyParameters privKey = ((LMSPrivateKeyParameters)kp.getPrivate()).extractKeyShard(2);

        assertEquals(2, ((LMSPrivateKeyParameters)kp.getPrivate()).getIndex());

        LMSSigner signer = new LMSSigner();

        assertEquals(2, privKey.getUsagesRemaining());
        assertEquals(0, privKey.getIndex());

        signer.init(true, privKey);

        byte[] sig1 = signer.generateSignature(msg1);

        assertEquals(1, privKey.getIndex());

        signer.init(false, kp.getPublic());

        assertTrue(signer.verifySignature(msg1, sig1));

        signer.init(true, privKey);

        byte[] sig = signer.generateSignature(msg2);

        assertEquals(2, privKey.getIndex());

        signer.init(false, kp.getPublic());

        assertTrue(signer.verifySignature(msg2, sig));

        try
        {
            sig = signer.generateSignature(msg2);
            fail("no exception");
        }
        catch (ExhaustedPrivateKeyException e)
        {
            assertEquals("ots private key exhausted", e.getMessage());
        }

        signer.init(true, ((LMSPrivateKeyParameters)kp.getPrivate()));

        sig = signer.generateSignature(msg1);

        assertEquals(3, ((LMSPrivateKeyParameters)kp.getPrivate()).getIndex());

        assertFalse(Arrays.areEqual(sig1, sig));

        signer.init(false, kp.getPublic());

        assertTrue(signer.verifySignature(msg1, sig1));

        PrivateKeyInfo pInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate());
        AsymmetricKeyParameter pKey = PrivateKeyFactory.createKey(pInfo.getEncoded());

        signer.init(false, ((LMSPrivateKeyParameters)pKey).getPublicKey());

        assertTrue(signer.verifySignature(msg1, sig1));
    }
}
