package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Polymorphic GF(p²) arithmetic interface for the three SQIsign security
 * levels. Concrete implementations carry the level's prime modulus and
 * encode/decode byte length; all operations dispatch through this
 * interface so EC/HD/theta code can be written once and reused at every
 * level.
 *
 * <p>The {@link Fp} / {@link Fp2} value cells are level-agnostic
 * (canonical {@link BigInteger}-backed); the level-dependent piece is
 * the modulus.</p>
 *
 * <p>Mirrors a subset of the static-method APIs of {@code FpLvl1} /
 * {@code Fp2Lvl1} (and their lvl3 / lvl5 siblings) — only the level-
 * dependent reductions are dispatched here. Level-independent helpers
 * (set, copy, isZero, ...) are invoked directly on {@link Fp} /
 * {@link Fp2} without going through the field interface.</p>
 */
interface GfField
{
    /**
     * Byte length of {@link #fp2Encode(byte[], int, Fp2)} output for one {@link Fp2}.
     */
    int fp2EncodedBytes();

    // ---- Fp single-tower ops (real-only) -----------------------------------

    int fpIsSquare(Fp a);

    void fpAdd(Fp out, Fp a, Fp b);

    void fpSub(Fp out, Fp a, Fp b);

    void fpNeg(Fp out, Fp a);

    void fpDiv3(Fp out, Fp a);

    // ---- Fp2 tower ops ------------------------------------------------------

    int fp2IsSquare(Fp2 a);

    void fp2Add(Fp2 x, Fp2 y, Fp2 z);

    void fp2AddOne(Fp2 x, Fp2 y);

    void fp2Sub(Fp2 x, Fp2 y, Fp2 z);

    void fp2Neg(Fp2 x, Fp2 y);

    void fp2Mul(Fp2 x, Fp2 y, Fp2 z);

    void fp2MulSmall(Fp2 x, Fp2 y, long n);

    void fp2Sqr(Fp2 x, Fp2 y);

    void fp2Inv(Fp2 x);

    void fp2Half(Fp2 x, Fp2 y);

    void fp2Sqrt(Fp2 a);

    int fp2SqrtVerify(Fp2 a);

    void fp2PowVartime(Fp2 out, Fp2 x, BigInteger exp);

    void fp2BatchedInv(Fp2[] x, int len);

    void fp2Encode(byte[] dst, int off, Fp2 a);

    int fp2Decode(Fp2 d, byte[] src, int off);
}
