package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * SQIsign level-3 implementation of {@link GfField}. Delegates to
 * {@link FpLvl3} / {@link Fp2Lvl3} static methods.
 */
final class GfFieldLvl3
    implements GfField
{
    public static final GfFieldLvl3 INSTANCE = new GfFieldLvl3();

    private GfFieldLvl3()
    {
    }

    public int fp2EncodedBytes()
    {
        return Fp2Lvl3.ENCODED_BYTES;
    }

    public int fpIsSquare(Fp a)
    {
        return FpLvl3.isSquare(a);
    }

    public void fpAdd(Fp out, Fp a, Fp b)
    {
        FpLvl3.add(out, a, b);
    }

    public void fpSub(Fp out, Fp a, Fp b)
    {
        FpLvl3.sub(out, a, b);
    }

    public void fpNeg(Fp out, Fp a)
    {
        FpLvl3.neg(out, a);
    }

    public void fpDiv3(Fp out, Fp a)
    {
        FpLvl3.div3(out, a);
    }

    public int fp2IsSquare(Fp2 a)
    {
        return Fp2Lvl3.isSquare(a);
    }

    public void fp2Add(Fp2 x, Fp2 y, Fp2 z)
    {
        Fp2Lvl3.add(x, y, z);
    }

    public void fp2AddOne(Fp2 x, Fp2 y)
    {
        Fp2Lvl3.addOne(x, y);
    }

    public void fp2Sub(Fp2 x, Fp2 y, Fp2 z)
    {
        Fp2Lvl3.sub(x, y, z);
    }

    public void fp2Neg(Fp2 x, Fp2 y)
    {
        Fp2Lvl3.neg(x, y);
    }

    public void fp2Mul(Fp2 x, Fp2 y, Fp2 z)
    {
        Fp2Lvl3.mul(x, y, z);
    }

    public void fp2MulSmall(Fp2 x, Fp2 y, long n)
    {
        Fp2Lvl3.mulSmall(x, y, n);
    }

    public void fp2Sqr(Fp2 x, Fp2 y)
    {
        Fp2Lvl3.sqr(x, y);
    }

    public void fp2Inv(Fp2 x)
    {
        Fp2Lvl3.inv(x);
    }

    public void fp2Half(Fp2 x, Fp2 y)
    {
        Fp2Lvl3.half(x, y);
    }

    public void fp2Sqrt(Fp2 a)
    {
        Fp2Lvl3.sqrt(a);
    }

    public int fp2SqrtVerify(Fp2 a)
    {
        return Fp2Lvl3.sqrtVerify(a);
    }

    public void fp2PowVartime(Fp2 out, Fp2 x, BigInteger exp)
    {
        Fp2Lvl3.powVartime(out, x, exp);
    }

    public void fp2BatchedInv(Fp2[] x, int len)
    {
        Fp2Lvl3.batchedInv(x, len);
    }

    public void fp2Encode(byte[] dst, int off, Fp2 a)
    {
        Fp2Lvl3.encode(dst, off, a);
    }

    public int fp2Decode(Fp2 d, byte[] src, int off)
    {
        return Fp2Lvl3.decode(d, src, off);
    }
}
