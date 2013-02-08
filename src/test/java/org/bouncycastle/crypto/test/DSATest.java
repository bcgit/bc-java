package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAValidationParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Test based on FIPS 186-2, Appendix 5, an example of DSA.
 */
public class DSATest
    extends SimpleTest
{
    byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

    SecureRandom    random = new FixedSecureRandom(new byte[][] { k1, k2});

    byte[] keyData = Hex.decode("b5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    
    SecureRandom    keyRandom = new FixedSecureRandom(new byte[][] { keyData, keyData });
    
    BigInteger  pValue = new BigInteger("8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291", 16);
    BigInteger  qValue = new BigInteger("c773218c737ec8ee993b4f2ded30f48edace915f", 16);

    public String getName()
    {
        return "DSA";
    }

    public void performTest()
    {
        BigInteger              r = new BigInteger("68076202252361894315274692543577577550894681403");
        BigInteger              s = new BigInteger("1089214853334067536215539335472893651470583479365");
        DSAParametersGenerator  pGen = new DSAParametersGenerator();

        pGen.init(512, 80, random);

        DSAParameters           params = pGen.generateParameters();
        DSAValidationParameters pValid = params.getValidationParameters();

        if (pValid.getCounter() != 105)
        {
            fail("Counter wrong");
        }

        if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
        {
            fail("p or q wrong");
        }

        DSAKeyPairGenerator         dsaKeyGen = new DSAKeyPairGenerator();
        DSAKeyGenerationParameters  genParam = new DSAKeyGenerationParameters(keyRandom, params);

        dsaKeyGen.init(genParam);

        AsymmetricCipherKeyPair  pair = dsaKeyGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), keyRandom);

        DSASigner dsa = new DSASigner();

        dsa.init(true, param);

        byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
        BigInteger[] sig = dsa.generateSignature(message);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong.", r, sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong.", s, sig[1]);
        }

        dsa.init(false, pair.getPublic());

        if (!dsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("verification fails");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new DSATest());
    }
}
