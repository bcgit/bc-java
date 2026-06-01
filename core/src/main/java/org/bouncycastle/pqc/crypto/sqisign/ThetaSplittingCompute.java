package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Level-independent core of {@code splitting_compute} from
 * {@code src/hd/ref/lvlx/theta_isogenies.c}. Callers pass the level's field
 * instance and the four level-specific {@code HdSplittingTransformsLvlN}
 * arrays.
 *
 * <p>Enumerates the 10 precomputed splitting transforms and selects the one
 * that zeroes out the {@code U_cst} sum. The chosen transform is applied to
 * the input null point. Returns {@code true} iff exactly one transform
 * produced a zero — the precondition for a valid splitting.</p>
 */
final class ThetaSplittingCompute
{
    private ThetaSplittingCompute()
    {
    }

    /**
     * Sample a random normalisation index in {@code [0, 5]} mirroring C
     * {@code sample_random_index}: consume 4 bytes from {@code random}
     * interpreted little-endian as uint32, retry while the seed is in the
     * biased upper-tail (≥ 4 294 967 292), then return {@code seed % 6}.
     * Keeps random-tape consumption byte-identical to the C reference, which
     * is critical for KAT-compatible signing.
     */
    static int sampleRandomIndex(java.security.SecureRandom random)
    {
        byte[] buf = new byte[4];
        long seed;
        do
        {
            random.nextBytes(buf);
            seed = (buf[0] & 0xffL)
                | ((buf[1] & 0xffL) << 8)
                | ((buf[2] & 0xffL) << 16)
                | ((buf[3] & 0xffL) << 24);
        } while (seed >= 4294967292L);
        return (int)(seed % 6);
    }

    static boolean splittingCompute(GfField field,
                                    Fp2[] fp2Constants,
                                    int[][] evenIndex,
                                    int[][] chiEval,
                                    int[][][] splittingTransformIndices,
                                    int[][][] normalizationTransformIndices,
                                    ThetaSplitting out, ThetaStructure A,
                                    int zeroIndex, boolean randomize,
                                    java.security.SecureRandom random)
    {
        out.B.field = A.field;
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Fp2.setZero(out.M.m[i][j]);
            }
        }

        int count = 0;
        Fp2 Ucst = Fp2.zero();
        Fp2 t1 = Fp2.zero();
        Fp2 t2 = Fp2.zero();
        Fp2 negT1 = Fp2.zero();

        for (int i = 0; i < 10; i++)
        {
            Fp2.setZero(Ucst);
            for (int t = 0; t < 4; t++)
            {
                ThetaIsogenyOps.chooseIndexThetaPoint(t2, t, A.nullPoint);
                ThetaIsogenyOps.chooseIndexThetaPoint(t1, t ^ evenIndex[i][1], A.nullPoint);

                field.fp2Mul(t1, t1, t2);

                int chi = chiEval[evenIndex[i][0]][t];
                if (chi == -1)
                {
                    field.fp2Neg(negT1, t1);
                    Fp2.copy(t1, negT1);
                }
                field.fp2Add(Ucst, Ucst, t1);
            }

            int ctl = Fp2.isZero(Ucst);
            if (ctl != 0)
            {
                count++;
                int[][] indices = splittingTransformIndices[i];
                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < 4; c++)
                    {
                        Fp2.copy(out.M.m[r][c], fp2Constants[indices[r][c]]);
                    }
                }
            }
            if (zeroIndex != -1 && i == zeroIndex && ctl == 0)
            {
                return false;
            }
        }

        if (randomize)
        {
            if (random == null)
            {
                throw new IllegalStateException(
                    "splittingCompute: randomize=true requires a non-null SecureRandom");
            }
            int secretIndex = sampleRandomIndex(random);
            BasisChangeMatrix mRandom = new BasisChangeMatrix();
            int[][] idx0 = normalizationTransformIndices[secretIndex];
            for (int r = 0; r < 4; r++)
            {
                for (int c = 0; c < 4; c++)
                {
                    Fp2.copy(mRandom.m[r][c], fp2Constants[idx0[r][c]]);
                }
            }
            BasisChangeMatrix product = new BasisChangeMatrix();
            ThetaIsogenyOps.baseChangeMatrixMultiplication(field, product, mRandom, out.M);
            for (int r = 0; r < 4; r++)
            {
                for (int c = 0; c < 4; c++)
                {
                    Fp2.copy(out.M.m[r][c], product.m[r][c]);
                }
            }
        }

        ThetaIsogenyOps.applyIsomorphism(field, out.B.nullPoint, out.M, A.nullPoint);

        return count == 1;
    }
}
