package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * SQIsign level-1 implementation of {@link GfField}. Delegates each
 * operation to the corresponding static method on {@link FpLvl1} /
 * {@link Fp2Lvl1} so existing tested code remains the source of truth.
 *
 * <p>Use {@link #INSTANCE} as the singleton field for lvl1 dispatch.</p>
 */
final class GfFieldLvl1
    implements GfField
{
    public static final GfFieldLvl1 INSTANCE = new GfFieldLvl1();

    private GfFieldLvl1()
    {
    }

    public int fp2EncodedBytes()
    {
        return Fp2Lvl1.ENCODED_BYTES;
    }

    // Fp ops
    public int fpIsSquare(Fp a)
    {
        return FpLvl1.isSquare(a);
    }

    public void fpAdd(Fp out, Fp a, Fp b)
    {
        FpLvl1.add(out, a, b);
    }

    public void fpSub(Fp out, Fp a, Fp b)
    {
        FpLvl1.sub(out, a, b);
    }

    public void fpNeg(Fp out, Fp a)
    {
        FpLvl1.neg(out, a);
    }

    public void fpDiv3(Fp out, Fp a)
    {
        FpLvl1.div3(out, a);
    }

    // Fp2 ops
    public int fp2IsSquare(Fp2 a)
    {
        return Fp2Lvl1.isSquare(a);
    }

    public void fp2Add(Fp2 x, Fp2 y, Fp2 z)
    {
        Fp2Lvl1.add(x, y, z);
    }

    public void fp2AddOne(Fp2 x, Fp2 y)
    {
        Fp2Lvl1.addOne(x, y);
    }

    public void fp2Sub(Fp2 x, Fp2 y, Fp2 z)
    {
        Fp2Lvl1.sub(x, y, z);
    }

    public void fp2Neg(Fp2 x, Fp2 y)
    {
        Fp2Lvl1.neg(x, y);
    }

    public void fp2Mul(Fp2 x, Fp2 y, Fp2 z)
    {
        Fp2Lvl1.mul(x, y, z);
    }

    public void fp2MulSmall(Fp2 x, Fp2 y, long n)
    {
        Fp2Lvl1.mulSmall(x, y, n);
    }

    public void fp2Sqr(Fp2 x, Fp2 y)
    {
        Fp2Lvl1.sqr(x, y);
    }

    public void fp2Inv(Fp2 x)
    {
        Fp2Lvl1.inv(x);
    }

    public void fp2Half(Fp2 x, Fp2 y)
    {
        Fp2Lvl1.half(x, y);
    }

    public void fp2Sqrt(Fp2 a)
    {
        Fp2Lvl1.sqrt(a);
    }

    public int fp2SqrtVerify(Fp2 a)
    {
        return Fp2Lvl1.sqrtVerify(a);
    }

    public void fp2PowVartime(Fp2 out, Fp2 x, BigInteger exp)
    {
        Fp2Lvl1.powVartime(out, x, exp);
    }

    public void fp2BatchedInv(Fp2[] x, int len)
    {
        Fp2Lvl1.batchedInv(x, len);
    }

    public void fp2Encode(byte[] dst, int off, Fp2 a)
    {
        Fp2Lvl1.encode(dst, off, a);
    }

    public int fp2Decode(Fp2 d, byte[] src, int off)
    {
        return Fp2Lvl1.decode(d, src, off);
    }
}
