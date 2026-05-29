package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * SQIsign level-5 implementation of {@link GfField}. Delegates to
 * {@link FpLvl5} / {@link Fp2Lvl5} static methods.
 */
final class GfFieldLvl5
    implements GfField
{
    public static final GfFieldLvl5 INSTANCE = new GfFieldLvl5();

    private GfFieldLvl5()
    {
    }

    public int fp2EncodedBytes()
    {
        return Fp2Lvl5.ENCODED_BYTES;
    }

    public int fpIsSquare(Fp a)
    {
        return FpLvl5.isSquare(a);
    }

    public void fpAdd(Fp out, Fp a, Fp b)
    {
        FpLvl5.add(out, a, b);
    }

    public void fpSub(Fp out, Fp a, Fp b)
    {
        FpLvl5.sub(out, a, b);
    }

    public void fpNeg(Fp out, Fp a)
    {
        FpLvl5.neg(out, a);
    }

    public void fpDiv3(Fp out, Fp a)
    {
        FpLvl5.div3(out, a);
    }

    public int fp2IsSquare(Fp2 a)
    {
        return Fp2Lvl5.isSquare(a);
    }

    public void fp2Add(Fp2 x, Fp2 y, Fp2 z)
    {
        Fp2Lvl5.add(x, y, z);
    }

    public void fp2AddOne(Fp2 x, Fp2 y)
    {
        Fp2Lvl5.addOne(x, y);
    }

    public void fp2Sub(Fp2 x, Fp2 y, Fp2 z)
    {
        Fp2Lvl5.sub(x, y, z);
    }

    public void fp2Neg(Fp2 x, Fp2 y)
    {
        Fp2Lvl5.neg(x, y);
    }

    public void fp2Mul(Fp2 x, Fp2 y, Fp2 z)
    {
        Fp2Lvl5.mul(x, y, z);
    }

    public void fp2MulSmall(Fp2 x, Fp2 y, long n)
    {
        Fp2Lvl5.mulSmall(x, y, n);
    }

    public void fp2Sqr(Fp2 x, Fp2 y)
    {
        Fp2Lvl5.sqr(x, y);
    }

    public void fp2Inv(Fp2 x)
    {
        Fp2Lvl5.inv(x);
    }

    public void fp2Half(Fp2 x, Fp2 y)
    {
        Fp2Lvl5.half(x, y);
    }

    public void fp2Sqrt(Fp2 a)
    {
        Fp2Lvl5.sqrt(a);
    }

    public int fp2SqrtVerify(Fp2 a)
    {
        return Fp2Lvl5.sqrtVerify(a);
    }

    public void fp2PowVartime(Fp2 out, Fp2 x, BigInteger exp)
    {
        Fp2Lvl5.powVartime(out, x, exp);
    }

    public void fp2BatchedInv(Fp2[] x, int len)
    {
        Fp2Lvl5.batchedInv(x, len);
    }

    public void fp2Encode(byte[] dst, int off, Fp2 a)
    {
        Fp2Lvl5.encode(dst, off, a);
    }

    public int fp2Decode(Fp2 d, byte[] src, int off)
    {
        return Fp2Lvl5.decode(d, src, off);
    }
}
