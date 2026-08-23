package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.TestCase;
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
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

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

            // the KAT files record the NIST crypto_sign "sm" envelope, which
            // AIMer's reference harness lays out as message || signature;
            // the signer returns the bare signature.
            @Override
            public byte[] toVectorSignature(byte[] signature, byte[] message)
            {
                return Arrays.concatenate(message, signature);
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }

    /**
     * verifySignature() takes the bare signature, so it has to require exactly
     * getSignatureBytes(): a shorter buffer used to be indexed past its end, and
     * a longer one had its trailing bytes ignored, so a valid signature with data
     * appended still verified.
     *
     * The first KAT vector of each parameter set supplies a public key and the
     * message || signature envelope the reference harness records, which keeps
     * this off the key generation and signing paths - a valid signature is what
     * makes the appended-data cases bite. It also pins the envelope itself:
     * handing verify the whole thing must now fail.
     */
    public void testWrongLengthSignatureRejected()
        throws Exception
    {
        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            AIMerParameters parameters = PARAMETER_SETS[fileIndex];
            String name = parameters.getName();

            HashMap vector = readFirstVector(files[fileIndex]);
            byte[] message = Hex.decode((String)vector.get("msg"));
            byte[] pk = Hex.decode((String)vector.get("pk"));
            byte[] sm = Hex.decode((String)vector.get("sm"));

            AIMerSigner verifier = new AIMerSigner();
            verifier.init(false, new AIMerPublicKeyParameters(parameters, pk));

            assertEquals(name, message.length + parameters.getSignatureBytes(), sm.length);
            byte[] signature = Arrays.copyOfRange(sm, message.length, sm.length);
            assertTrue(name, verifier.verifySignature(message, signature));

            // a short signature must be rejected rather than indexed past its end
            assertFalse(name, verifier.verifySignature(message, new byte[0]));
            assertFalse(name, verifier.verifySignature(message, Arrays.copyOf(signature, signature.length - 1)));

            // trailing data must not be silently ignored
            assertFalse(name, verifier.verifySignature(message, Arrays.append(signature, (byte)0)));
            assertFalse(name, verifier.verifySignature(message, Arrays.concatenate(signature, new byte[16])));

            // and the KAT envelope is not itself a signature
            assertFalse(name, verifier.verifySignature(message, sm));
        }
    }

    private static HashMap readFirstVector(String name)
        throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/aimer", name);
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));

        HashMap buf = new HashMap();
        String line;
        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if (line.startsWith("#") || line.length() == 0)
            {
                // the vectors are separated by a blank line - stop at the end of the first
                if (buf.size() > 0)
                {
                    break;
                }
                continue;
            }

            int a = line.indexOf('=');
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        bin.close();

        return buf;
    }
}
