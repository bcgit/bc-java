package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.LMSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LmOtsParameters;

public class LMSTest
    extends TestCase
{
    public void testKeyGenAndSign()
        throws Exception
    {
        AsymmetricCipherKeyPairGenerator kpGen = new LMSKeyPairGenerator();

        kpGen.init(new LMSKeyGenerationParameters(new SecureRandom(), LMSParameters.lms_sha256_n32_h5, LmOtsParameters.sha256_n32_w4));
    }
}
