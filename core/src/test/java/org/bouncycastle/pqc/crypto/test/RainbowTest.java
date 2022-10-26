package org.bouncycastle.pqc.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;

public class RainbowTest
    extends SimpleTest
{
    private RainbowParameters params;

    public RainbowTest(RainbowParameters params)
    {
        this.params = params;
    }

    public String getName()
    {
        return params.getName();
    }

    public void performTest()
    {
        byte[] seed = new byte[64];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(seed);
        NISTSecureRandom random = new NISTSecureRandom(seed, null);

        RainbowKeyPairGenerator rainbowKeyGen = new RainbowKeyPairGenerator();
        RainbowKeyGenerationParameters genParam = new RainbowKeyGenerationParameters(random, params);

        rainbowKeyGen.init(genParam);

        AsymmetricCipherKeyPair pair = rainbowKeyGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

        MessageSigner rainbowSigner = new RainbowSigner();

        rainbowSigner.init(true, param);

        byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));

        byte[] sig = rainbowSigner.generateSignature(message);

        rainbowSigner.init(false, pair.getPublic());

        if (!rainbowSigner.verifySignature(message, sig))
        {
            fail("verification fails");
        }
    }

    public static void main(String[] args)
    {
        runTest(new RainbowTest(RainbowParameters.rainbowIIIclassic));
        runTest(new RainbowTest(RainbowParameters.rainbowIIIcircumzenithal));
        runTest(new RainbowTest(RainbowParameters.rainbowIIIcompressed));
        runTest(new RainbowTest(RainbowParameters.rainbowVclassic));
        runTest(new RainbowTest(RainbowParameters.rainbowVcircumzenithal));
        runTest(new RainbowTest(RainbowParameters.rainbowVcompressed));
    }
}
