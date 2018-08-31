package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.Ed448phSigner;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.test.SimpleTest;

public class Ed448Test
    extends SimpleTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    public String getName()
    {
        return "Ed448";
    }

    public static void main(String[] args)
    {
        runTest(new Ed448Test());
    }

    public void performTest() throws Exception
    {
        for (int i = 0; i < 10; ++i)
        {
            byte[] context = randomContext(RANDOM.nextInt() & 255);
            testConsistency(Ed448.Algorithm.Ed448, context);
            testConsistency(Ed448.Algorithm.Ed448ph, context);
        }
    }

    private Signer createSigner(int algorithm, byte[] context)
    {
        switch (algorithm)
        {
        case Ed448.Algorithm.Ed448:
            return new Ed448Signer(context);
        case Ed448.Algorithm.Ed448ph:
            return new Ed448phSigner(context);
        default:
            throw new IllegalArgumentException("algorithm");
        }
    }

    private byte[] randomContext(int length)
    {
        byte[] context = new byte[length];
        RANDOM.nextBytes(context);
        return context;
    }

    private void testConsistency(int algorithm, byte[] context) throws Exception
    {
        Ed448KeyPairGenerator kpg = new Ed448KeyPairGenerator();
        kpg.init(new Ed448KeyGenerationParameters(RANDOM));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        Ed448PrivateKeyParameters privateKey = (Ed448PrivateKeyParameters)kp.getPrivate();
        Ed448PublicKeyParameters publicKey = (Ed448PublicKeyParameters)kp.getPublic();

        byte[] msg = new byte[RANDOM.nextInt() & 255];
        RANDOM.nextBytes(msg);

        Signer signer = createSigner(algorithm, context);
        signer.init(true, privateKey);
        signer.update(msg, 0, msg.length);
        byte[] signature = signer.generateSignature();

        Signer verifier = createSigner(algorithm, context);
        verifier.init(false, publicKey);
        verifier.update(msg, 0, msg.length);
        boolean shouldVerify = verifier.verifySignature(signature);

        if (!shouldVerify)
        {
            fail("Ed448(" + algorithm + ") signature failed to verify");
        }

        signature[(RANDOM.nextInt() >>> 1) % signature.length] ^= 1 << (RANDOM.nextInt() & 7);

        verifier.init(false, publicKey);
        verifier.update(msg, 0, msg.length);
        boolean shouldNotVerify = verifier.verifySignature(signature);

        if (shouldNotVerify)
        {
            fail("Ed448(" + algorithm + ") bad signature incorrectly verified");
        }
    }
}
