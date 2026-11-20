package org.bouncycastle.crypto.kems.mlkem;

import java.security.MessageDigest;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class PointwiseProductTest
    extends TestCase
{
    public void testDecodedNonCanonicalKey()
        throws Exception
    {
        MLKEMParameters[] parameters = { MLKEMParameters.ml_kem_512, MLKEMParameters.ml_kem_768,
            MLKEMParameters.ml_kem_1024 };
        // Digests of complete ciphertexts from the previous per-product reduction.
        String[] expected = {
            "215a060ef8b488f72b73d849a20a20f69db8946cde7c7223c14bf9e7f996d216",
            "34d460928f61b9a497ae039ebd583f411bb02c88fa41b772f4a3c5f6024aafb6",
            "71e76f2da0520d9d36cbe6ad76dbea9b13125e45485b0e7dfded92ca1dc179e3"
        };
        for (int i = 0; i < parameters.length; ++i)
        {
            MLKEMEngine engine = MLKEMEngine.getInstance(parameters[i]);
            byte[] pk = new byte[engine.getIndCpaPublicKeyBytes()];
            Arrays.fill(pk, 0, pk.length - 32, (byte)-1);
            // The re-encryption inside decapsulation can read this 12-bit representation
            // from an expanded private key, even though a standalone public key rejects it.
            byte[] ciphertext = new MLKEMIndCpa(engine).encrypt(pk, 0, new byte[32], 0, new byte[32], 0);
            assertEquals(expected[i], Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(ciphertext)));
        }
    }

    public void testVectorProduct()
    {
        MLKEMParameters[] parameters = { MLKEMParameters.ml_kem_512, MLKEMParameters.ml_kem_768,
            MLKEMParameters.ml_kem_1024 };
        Random random = new Random(20261120);
        for (int index = 0; index < parameters.length; ++index)
        {
            MLKEMEngine engine = MLKEMEngine.getInstance(parameters[index]);
            int k = engine.getK();
            PolyVec a = new PolyVec(k), b = new PolyVec(k);
            for (int sample = 0; sample < 64; ++sample)
            {
                Poly expected = new Poly();
                for (int row = 0; row < k; ++row)
                {
                    for (int j = 0; j < MLKEMEngine.N; j += 2)
                    {
                        short a0 = (short)(sample < 16 ? ((sample & 1) != 0 ? 4095 : 0) : random.nextInt(4096));
                        short a1 = (short)(sample < 16 ? ((sample & 2) != 0 ? 4095 : 0) : random.nextInt(4096));
                        short b0 = (short)(sample < 16 ? ((sample & 4) != 0 ? 3329 : 0) : random.nextInt(3330));
                        short b1 = (short)(sample < 16 ? ((sample & 8) != 0 ? 3329 : 0) : random.nextInt(3330));
                        a.vec[row].setCoeffIndex(j, a0);
                        a.vec[row].setCoeffIndex(j + 1, a1);
                        b.vec[row].setCoeffIndex(j, b0);
                        b.vec[row].setCoeffIndex(j + 1, b1);
                        short zeta = Ntt.ZETAS[64 + j / 4];
                        if ((j & 2) != 0)
                        {
                            zeta = (short)-zeta;
                        }
                        // Preserve the original per-row narrowing to short explicitly.
                        expected.setCoeffIndex(j, (short)(expected.getCoeffIndex(j)
                            + Ntt.mulMont(a0, b0) + Ntt.mulMont(zeta, Ntt.mulMont(a1, b1))));
                        expected.setCoeffIndex(j + 1, (short)(expected.getCoeffIndex(j + 1)
                            + Ntt.mulMont(a0, b1) + Ntt.mulMont(a1, b0)));
                    }
                }
                short[][] originalA = new short[k][], originalB = new short[k][];
                for (int row = 0; row < k; ++row)
                {
                    originalA[row] = Arrays.clone(a.getVectorIndex(row).getCoeffs());
                    originalB[row] = Arrays.clone(b.getVectorIndex(row).getCoeffs());
                }
                Poly actual = sample % 2 == 0 ? new Poly() : a.vec[0];
                PolyVec.pointwiseAccountMontgomery(actual, a, b, engine);
                for (int row = 0; row < k; ++row)
                {
                    if (actual != a.getVectorIndex(row))
                    {
                        assertTrue(Arrays.areEqual(originalA[row], a.getVectorIndex(row).getCoeffs()));
                    }
                    assertTrue(Arrays.areEqual(originalB[row], b.getVectorIndex(row).getCoeffs()));
                }
                expected.reduce();
                for (int j = 0; j < MLKEMEngine.N; ++j)
                {
                    assertEquals(0, (actual.getCoeffIndex(j) - expected.getCoeffIndex(j)) % MLKEMEngine.Q);
                    assertTrue(actual.getCoeffIndex(j) >= 0 && actual.getCoeffIndex(j) <= MLKEMEngine.Q);
                }
                expected.polyInverseNttToMont();
                actual.polyInverseNttToMont();
                expected.reduce();
                actual.reduce();
                expected.condSubQ();
                actual.condSubQ();
                for (int j = 0; j < MLKEMEngine.N; ++j)
                {
                    assertEquals(expected.getCoeffIndex(j), actual.getCoeffIndex(j));
                }
            }
        }
    }
}
