package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * SQIsign signature struct, level-independent. Java mirror of
 * {@code signature_t} from
 * {@code src/verification/ref/include/verification.h}.
 *
 * <p>Wire-format byte counts differ per level (lvl1 = 148, lvl3 = 224,
 * lvl5 = 292), but the in-memory shape is identical: an fp² auxiliary curve
 * coefficient, two small integer hints / lengths, a 2×2 BigInteger basis-
 * change matrix, the challenge scalar, and two byte-sized hints.</p>
 *
 * <p>{@link SQIsignSignatureLvl1}, {@link SQIsignSignatureLvl3},
 * {@link SQIsignSignatureLvl5} are thin subclasses kept for level-specific
 * static-type checks at call sites.</p>
 */
class SQIsignSignature
{
    /** Auxiliary curve Montgomery A-coefficient (as an fp2 element). */
    public final Fp2 eAuxA;
    /** Backtracking length in 2-power isogeny. */
    public int backtracking;
    /** Length of the response 2-power chain. */
    public int twoRespLength;
    /** 2×2 basis-change matrix from the canonical challenge basis to B_chall. */
    public final BigInteger[][] matBchallCanToBChall;
    /** Challenge scalar (such that ker = P + [s]·Q). */
    public BigInteger challCoeff;
    /** Auxiliary basis hint (for deterministic basis recomputation). */
    public int hintAux;
    /** Challenge basis hint. */
    public int hintChall;

    protected SQIsignSignature()
    {
        this.eAuxA = Fp2.zero();
        this.backtracking = 0;
        this.twoRespLength = 0;
        this.matBchallCanToBChall = new BigInteger[2][2];
        for (int i = 0; i < 2; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                this.matBchallCanToBChall[i][j] = BigInteger.ZERO;
            }
        }
        this.challCoeff = BigInteger.ZERO;
        this.hintAux = 0;
        this.hintChall = 0;
    }
}
