package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPublicKeyParameters;
import org.bouncycastle.util.Arrays;

public class NTRUPlusTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        NTRUPlusTest test = new NTRUPlusTest();
        test.testTestVectors();
        //test.testKeyGen();
    }

    private static final NTRUPlusParameters[] PARAMETER_SETS = new NTRUPlusParameters[]
        {
            NTRUPlusParameters.ntruplus_kem_768,
            NTRUPlusParameters.ntruplus_kem_864,
            NTRUPlusParameters.ntruplus_kem_1152,
        };

    private static final String[] files = new String[]{
        "PQCkemKAT_2336.rsp",
        "PQCkemKAT_2624.rsp",
        "PQCkemKAT_3488.rsp",
    };


    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(true, true, "pqc/crypto/ntruplus", files, new TestUtils.KeyEncapsulationOperation()
        {
            int sessionKeySize = 0;

            @Override
            public SecureRandom getSecureRandom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                NTRUPlusParameters parameters = PARAMETER_SETS[fileIndex];
                sessionKeySize = parameters.getSsBytes() * 8;
                NTRUPlusKeyPairGenerator kpGen = new NTRUPlusKeyPairGenerator();
                kpGen.init(new NTRUPlusKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams)
            {
                return ((NTRUPlusPublicKeyParameters)pubParams).getEncoded();
            }

            @Override
            public byte[] getPrivateKeyEncoded(AsymmetricKeyParameter privParams)
            {
                return ((NTRUPlusPrivateKeyParameters)privParams).getEncoded();
            }

            @Override
            public EncapsulatedSecretGenerator getKEMGenerator(SecureRandom random)
            {
                return new NTRUPlusKEMGenerator(random);
            }

            @Override
            public EncapsulatedSecretExtractor getKEMExtractor(AsymmetricKeyParameter privParams)
            {
                return new NTRUPlusKEMExtractor((NTRUPlusPrivateKeyParameters)privParams);
            }

            @Override
            public int getSessionKeySize()
            {
                return 0;
            }

        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }

    /**
     * NTRU+ rejects explicitly: an encapsulation that does not re-encrypt has no secret, so
     * extractSecret must refuse it rather than return one. It used to return a secret of all zero
     * bytes, the same for every rejected encapsulation, and when the message decoding failed it
     * returned the real K' with only the low bit of each byte cleared - either way telling an
     * attacker whether, or to what, a chosen ciphertext decrypts.
     * <p>
     * The perturbations add +-1 to one packed NTT coefficient, mod q, so each tampered ciphertext is
     * still canonical and goes through decryption rather than the encoding check.
     */
    public void testRejectedEncapsulation()
    {
        SecureRandom random = new SecureRandom();
        for (int p = 0; p != PARAMETER_SETS.length; p++)
        {
            NTRUPlusParameters parameters = PARAMETER_SETS[p];
            NTRUPlusKeyPairGenerator kpGen = new NTRUPlusKeyPairGenerator();
            kpGen.init(new NTRUPlusKeyGenerationParameters(random, parameters));
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            SecretWithEncapsulation secWenc = new NTRUPlusKEMGenerator(random).generateEncapsulated(kp.getPublic());
            byte[] ct = secWenc.getEncapsulation();
            NTRUPlusKEMExtractor extractor = new NTRUPlusKEMExtractor((NTRUPlusPrivateKeyParameters)kp.getPrivate());

            // the untouched encapsulation still gives the encapsulated secret
            assertTrue(Arrays.areEqual(secWenc.getSecret(), extractor.extractSecret(ct)));

            int coefficients = ct.length * 2 / 3;
            for (int j = 0; j < coefficients; j += 7)
            {
                for (int delta = 1; delta >= -1; delta -= 2)
                {
                    byte[] tampered = Arrays.clone(ct);
                    setCoefficient(tampered, j, (getCoefficient(ct, j) + delta + Q) % Q);
                    assertRejected(parameters.getName() + " coefficient " + j, extractor, tampered);
                }
            }

            // a coefficient of q or more is not a canonical encoding, as the reference poly_frombytes checks
            byte[] nonCanonical = Arrays.clone(ct);
            setCoefficient(nonCanonical, 0, Q);
            assertRejected(parameters.getName() + " non-canonical", extractor, nonCanonical);
            nonCanonical = Arrays.clone(ct);
            setCoefficient(nonCanonical, coefficients - 1, 0xFFF);
            assertRejected(parameters.getName() + " non-canonical", extractor, nonCanonical);

            // nor is a public key with such a coefficient accepted for encapsulation
            byte[] pk = Arrays.clone(((NTRUPlusPublicKeyParameters)kp.getPublic()).getEncoded());
            setCoefficient(pk, 1, Q);
            try
            {
                new NTRUPlusKEMGenerator(random).generateEncapsulated(new NTRUPlusPublicKeyParameters(parameters, pk));
                fail(parameters.getName() + " non-canonical public key accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("invalid public key", e.getMessage());
            }
        }
    }

    private static final int Q = 3457;

    private static void assertRejected(String label, NTRUPlusKEMExtractor extractor, byte[] encapsulation)
    {
        try
        {
            byte[] secret = extractor.extractSecret(encapsulation);
            fail(label + ": rejected encapsulation gave a secret " + org.bouncycastle.util.encoders.Hex.toHexString(secret));
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("invalid encapsulation", e.getMessage());
        }
    }

    // polynomials are packed two 12-bit coefficients to three bytes, little-endian
    private static int getCoefficient(byte[] a, int j)
    {
        int off = 3 * (j / 2);
        if ((j & 1) == 0)
        {
            return ((a[off] & 0xFF) | ((a[off + 1] & 0xFF) << 8)) & 0xFFF;
        }
        return ((a[off + 1] & 0xFF) >> 4) | ((a[off + 2] & 0xFF) << 4);
    }

    private static void setCoefficient(byte[] a, int j, int v)
    {
        int off = 3 * (j / 2);
        if ((j & 1) == 0)
        {
            a[off] = (byte)v;
            a[off + 1] = (byte)((a[off + 1] & 0xF0) | (v >> 8));
        }
        else
        {
            a[off + 1] = (byte)((a[off + 1] & 0x0F) | (v << 4));
            a[off + 2] = (byte)(v >> 4);
        }
    }
}
