package org.bouncycastle.crypto.signers.mldsa;

import java.security.MessageDigest;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class AllTests
    extends TestCase
{
    public void testMalformedEtaEncoding()
        throws Exception
    {
        MLDSAParameters[] parameters = { MLDSAParameters.ml_dsa_44, MLDSAParameters.ml_dsa_65,
            MLDSAParameters.ml_dsa_87 };
        // Digests of complete derived public components from the previous per-product reduction.
        String[] expected = {
            "48ed74fd45a8908963eb56cc609a237dd25c2da16e59941ed19b6dd61a38aad1",
            "6adb931578ae3fbbb291056deef41dd368955ed30e68329b488066ad56ff3eb4",
            "36a7267d6784b0d8ceada07a6885b66194da6c71f7f01f01d90ed687f54ce414"
        };
        for (int i = 0; i < parameters.length; ++i)
        {
            MLDSAEngine engine = MLDSAEngine.getInstance(parameters[i], null);
            byte[][] key = engine.generateKeyPairInternal(new byte[32]);
            Arrays.fill(key[3], (byte)-1);
            Arrays.fill(key[4], (byte)-1);
            byte[] t1 = engine.deriveT1(key[0], key[1], key[2], key[3], key[4], key[5]);
            assertEquals(expected[i], Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(t1)));
        }
    }

    public void testMatrixRowProduct()
    {
        MLDSAParameters[] parameters = { MLDSAParameters.ml_dsa_44, MLDSAParameters.ml_dsa_65,
            MLDSAParameters.ml_dsa_87 };
        Random random = new Random(20261120);
        int q = MLDSAEngine.DilithiumQ;
        for (int index = 0; index < parameters.length; ++index)
        {
            MLDSAEngine engine = MLDSAEngine.getInstance(parameters[index], null);
            int length = engine.getDilithiumL();
            PolyVec a = new PolyVec(engine, length), b = new PolyVec(engine, length);
            for (int sample = 0; sample < 32; ++sample)
            {
                Poly expected = new Poly(engine);
                for (int row = 0; row < length; ++row)
                {
                    for (int j = 0; j < 256; ++j)
                    {
                        int x = sample < 2 ? q - 1 : random.nextInt(q);
                        int y = sample < 2 ? (sample == 0 ? 34162429 : -34162429)
                            : random.nextInt(68324859) - 34162429;
                        a.getVectorIndex(row).setCoeffIndex(j, x);
                        b.getVectorIndex(row).setCoeffIndex(j, y);
                        expected.getCoeffs()[j] += Reduce.montgomeryReduce((long)x * y);
                    }
                }
                // Original callers use distinct outputs. Aliasing the first row also works.
                int[][] originalA = new int[length][], originalB = new int[length][];
                for (int row = 0; row < length; ++row)
                {
                    originalA[row] = Arrays.clone(a.getVectorIndex(row).getCoeffs());
                    originalB[row] = Arrays.clone(b.getVectorIndex(row).getCoeffs());
                }
                Poly actual = sample % 2 == 0 ? new Poly(engine) : a.getVectorIndex(0);
                actual.pointwiseAccountMontgomery(a, b);
                for (int row = 0; row < length; ++row)
                {
                    if (actual != a.getVectorIndex(row))
                    {
                        assertTrue(Arrays.areEqual(originalA[row], a.getVectorIndex(row).getCoeffs()));
                    }
                    assertTrue(Arrays.areEqual(originalB[row], b.getVectorIndex(row).getCoeffs()));
                }
                for (int j = 0; j < 256; ++j)
                {
                    assertEquals(0, (actual.getCoeffIndex(j) - expected.getCoeffIndex(j)) % q);
                }
                expected.reduce();
                expected.invNttToMont();
                expected.conditionalAddQ();
                actual.reduce();
                actual.invNttToMont();
                actual.conditionalAddQ();
                for (int j = 0; j < 256; ++j)
                {
                    assertEquals(expected.getCoeffIndex(j), actual.getCoeffIndex(j));
                }
            }
        }
    }
}
