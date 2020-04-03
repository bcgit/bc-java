package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed25519ctxSigner;
import org.bouncycastle.crypto.signers.Ed25519phSigner;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class Ed25519Test
    extends SimpleTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    public String getName()
    {
        return "Ed25519";
    }

    public static void main(String[] args)
    {
        runTest(new Ed25519Test());
    }

    public void performTest() throws Exception
    {
        for (int i = 0; i < 10; ++i)
        {
            testConsistency(Ed25519.Algorithm.Ed25519, null);

            byte[] context = randomContext(RANDOM.nextInt() & 255);
            testConsistency(Ed25519.Algorithm.Ed25519ctx, context);
            testConsistency(Ed25519.Algorithm.Ed25519ph, context);
        }

        basicSigTest();
    }

    private void basicSigTest()
        throws Exception
    {
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(
            Hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), 0);
        Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(
            Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"), 0);

        byte[] sig = Hex.decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        Signer signer = new Ed25519Signer();

        signer.init(true, privateKey);

        isTrue(areEqual(sig, signer.generateSignature()));

        signer.init(false, publicKey);

        isTrue(signer.verifySignature(sig));
    }

    private Signer createSigner(int algorithm, byte[] context)
    {
        switch (algorithm)
        {
        case Ed25519.Algorithm.Ed25519:
            return new Ed25519Signer();
        case Ed25519.Algorithm.Ed25519ctx:
            return new Ed25519ctxSigner(context);
        case Ed25519.Algorithm.Ed25519ph:
            return new Ed25519phSigner(context);
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
        Ed25519KeyPairGenerator kpg = new Ed25519KeyPairGenerator();
        kpg.init(new Ed25519KeyGenerationParameters(RANDOM));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)kp.getPrivate();
        Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters)kp.getPublic();

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
                fail("Ed25519(" + algorithm + ") signature failed to verify");
            }
        }

        {
            byte[] wrongLengthSignature = Arrays.append(signature, (byte)0x00);

            verifier.init(false, publicKey);
            verifier.update(msg, 0, msg.length);
            boolean shouldNotVerify = verifier.verifySignature(wrongLengthSignature);

            if (shouldNotVerify)
            {
                fail("Ed25519(" + algorithm + ") wrong length signature incorrectly verified");
            }
        }

        if (msg.length > 0)
        {
            boolean shouldNotVerify = verifier.verifySignature(signature);

            if (shouldNotVerify)
            {
                fail("Ed25519(" + algorithm + ") wrong length failure did not reset verifier");
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
                fail("Ed25519(" + algorithm + ") bad signature incorrectly verified");
            }
        }
    }
}
