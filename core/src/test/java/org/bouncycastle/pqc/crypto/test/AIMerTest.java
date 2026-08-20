package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.aimer.AIMerKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerKeyPairGenerator;
import org.bouncycastle.pqc.crypto.aimer.AIMerParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerPublicKeyParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class AIMerTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        AIMerTest test = new AIMerTest();
        test.testTestVectors();
        test.testWrongLengthSignatureRejected();
    }

    private static final AIMerParameters[] PARAMETER_SETS = new AIMerParameters[]
        {
            AIMerParameters.aimer128f,
            AIMerParameters.aimer128s,
            AIMerParameters.aimer192f,
            AIMerParameters.aimer192s,
            AIMerParameters.aimer256f,
            AIMerParameters.aimer256s,
        };

    private static final String[] files = new String[]{
        "aimer128f/PQCsignKAT_48.rsp",
        "aimer128s/PQCsignKAT_48.rsp",
        "aimer192f/PQCsignKAT_72.rsp",
        "aimer192s/PQCsignKAT_72.rsp",
        "aimer256f/PQCsignKAT_96.rsp",
        "aimer256s/PQCsignKAT_96.rsp",
    };


    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(false, true, false, "pqc/crypto/aimer", files, new TestUtils.SignerOperation()
        {
            @Override
            public SecureRandom getSecureRandom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                AIMerParameters parameters = PARAMETER_SETS[fileIndex];

                AIMerKeyPairGenerator kpGen = new AIMerKeyPairGenerator();
                kpGen.init(new AIMerKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(CipherParameters pubParams)
            {
                return ((AIMerPublicKeyParameters)pubParams).getEncoded();
            }

            @Override
            public byte[] getPrivateKeyEncoded(CipherParameters privParams)
            {
                return ((AIMerPrivateKeyParameters)privParams).getEncoded();
            }

            @Override
            public Signer getSigner()
            {
                return null;
            }

            @Override
            public MessageSigner getMessageSigner()
            {
                return new AIMerSigner();
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }

    public void testWrongLengthSignatureRejected()
    {
        SecureRandom random = new SecureRandom();
        byte[] message = Strings.toByteArray("AIMer wrong length signature");

        for (int i = 0; i != PARAMETER_SETS.length; i++)
        {
            AIMerParameters parameters = PARAMETER_SETS[i];

            AIMerKeyPairGenerator kpGen = new AIMerKeyPairGenerator();
            kpGen.init(new AIMerKeyGenerationParameters(random, parameters));
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            AIMerSigner signer = new AIMerSigner();
            signer.init(true, kp.getPrivate());
            byte[] signature = signer.generateSignature(message);

            AIMerSigner verifier = new AIMerSigner();
            verifier.init(false, kp.getPublic());

            assertEquals(parameters.getName(), message.length + parameters.getSignatureBytes(), signature.length);
            assertTrue(parameters.getName(), verifier.verifySignature(message, signature));

            // a short buffer must be rejected rather than indexed past its end
            assertFalse(parameters.getName(), verifier.verifySignature(message, new byte[0]));
            assertFalse(parameters.getName(), verifier.verifySignature(message, Arrays.copyOf(signature, signature.length - 1)));
            assertFalse(parameters.getName(), verifier.verifySignature(message, Arrays.copyOf(signature, message.length)));

            // trailing data must not be silently ignored
            assertFalse(parameters.getName(), verifier.verifySignature(message, Arrays.append(signature, (byte)0)));
            assertFalse(parameters.getName(), verifier.verifySignature(message, Arrays.concatenate(signature, new byte[16])));
        }
    }
}
