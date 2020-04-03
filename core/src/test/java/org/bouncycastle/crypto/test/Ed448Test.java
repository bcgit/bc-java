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
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
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
        basicSigTest();

        for (int i = 0; i < 10; ++i)
        {
            byte[] context = randomContext(RANDOM.nextInt() & 255);
            testConsistency(Ed448.Algorithm.Ed448, context);
            testConsistency(Ed448.Algorithm.Ed448ph, context);
        }
    }

    private void basicSigTest()
        throws Exception
    {
        Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(
            Hex.decode(
                "6c82a562cb808d10d632be89c8513ebf" +
                "6c929f34ddfa8c9f63c9960ef6e348a3" +
                "528c8a3fcc2f044e39a3fc5b94492f8f" +
                "032e7549a20098f95b"), 0);
        Ed448PublicKeyParameters publicKey = new Ed448PublicKeyParameters(
            Hex.decode("5fd7449b59b461fd2ce787ec616ad46a" +
                "1da1342485a70e1f8a0ea75d80e96778" +
                "edf124769b46c7061bd6783df1e50f6c" +
                "d1fa1abeafe8256180"), 0);

        byte[] sig = Hex.decode("533a37f6bbe457251f023c0d88f976ae" +
            "2dfb504a843e34d2074fd823d41a591f" +
            "2b233f034f628281f2fd7a22ddd47d78" +
            "28c59bd0a21bfd3980ff0d2028d4b18a" +
            "9df63e006c5d1c2d345b925d8dc00b41" +
            "04852db99ac5c7cdda8530a113a0f4db" +
            "b61149f05a7363268c71d95808ff2e65" +
            "2600");

        Signer signer = new Ed448Signer(new byte[0]);

        signer.init(true, privateKey);

        isTrue(areEqual(sig, signer.generateSignature()));

        signer.init(false, publicKey);

        isTrue(signer.verifySignature(sig));
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

        {
            verifier.init(false, publicKey);
            verifier.update(msg, 0, msg.length);
            boolean shouldVerify = verifier.verifySignature(signature);

            if (!shouldVerify)
            {
                fail("Ed448(" + algorithm + ") signature failed to verify");
            }
        }

        {
            byte[] wrongLengthSignature = Arrays.append(signature, (byte)0x00);

            verifier.init(false, publicKey);
            verifier.update(msg, 0, msg.length);
            boolean shouldNotVerify = verifier.verifySignature(wrongLengthSignature);

            if (shouldNotVerify)
            {
                fail("Ed448(" + algorithm + ") wrong length signature incorrectly verified");
            }
        }

        if (msg.length > 0)
        {
            boolean shouldNotVerify = verifier.verifySignature(signature);

            if (shouldNotVerify)
            {
                fail("Ed448(" + algorithm + ") wrong length failure did not reset verifier");
            }
        }

        {
            byte[] badSignature = Arrays.clone(signature);
            badSignature[(RANDOM.nextInt() >>> 1) % badSignature.length] ^= 1 << (RANDOM.nextInt() & 7);

            verifier.init(false, publicKey);
            verifier.update(msg, 0, msg.length);
            boolean shouldNotVerify = verifier.verifySignature(badSignature);

            if (shouldNotVerify)
            {
                fail("Ed448(" + algorithm + ") bad signature incorrectly verified");
            }
        }
    }
}
