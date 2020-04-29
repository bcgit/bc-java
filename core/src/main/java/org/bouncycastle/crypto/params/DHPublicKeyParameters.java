package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Integers;

public class DHPublicKeyParameters
    extends DHKeyParameters
{
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private BigInteger      y;

    public DHPublicKeyParameters(
        BigInteger      y,
        DHParameters    params)
    {
        super(false, params);

        this.y = validate(y, params);
    }   

    private BigInteger validate(BigInteger y, DHParameters dhParams)
    {
        if (y == null)
        {
            throw new NullPointerException("y value cannot be null");
        }

        BigInteger p = dhParams.getP();

        // TLS check
        if (y.compareTo(TWO) < 0 || y.compareTo(p.subtract(TWO)) > 0)
        {
            throw new IllegalArgumentException("invalid DH public key");
        }

        BigInteger q = dhParams.getQ();
        if (q == null)
        {
            return y;         // we can't validate without Q.
        }

        if (p.testBit(0)
            && p.bitLength() - 1 == q.bitLength()
            && p.shiftRight(1).equals(q))
        {
            // Safe prime case
            if (1 == legendre(y, p))
            {
                return y;
            }
        }
        else
        {
            if (ONE.equals(y.modPow(q, p)))
            {
                return y;
            }
        }

        throw new IllegalArgumentException("Y value does not appear to be in correct group");
    }

    public BigInteger getY()
    {
        return y;
    }

    public int hashCode()
    {
        return y.hashCode() ^ super.hashCode();
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof DHPublicKeyParameters))
        {
            return false;
        }

        DHPublicKeyParameters   other = (DHPublicKeyParameters)obj;

        return other.getY().equals(y) && super.equals(obj);
    }

    private static int legendre(BigInteger a, BigInteger b)
    {
//        int r = 0, bits = b.intValue();
//
//        for (;;)
//        {
//            int lowestSetBit = a.getLowestSetBit();
//            a = a.shiftRight(lowestSetBit);
//            r ^= (bits ^ (bits >>> 1)) & (lowestSetBit << 1);
//
//            int cmp = a.compareTo(b);
//            if (cmp == 0)
//            {
//                break;
//            }
//
//            if (cmp < 0)
//            {
//                BigInteger t = a; a = b; b = t;
//
//                int oldBits = bits;
//                bits = b.intValue();
//                r ^= oldBits & bits;
//            }
//
//            a = a.subtract(b);
//        }
//
//        return ONE.equals(b) ? (1 - (r & 2)) : 0;

        int bitLength = b.bitLength();
        int[] A = Nat.fromBigInteger(bitLength, a);
        int[] B = Nat.fromBigInteger(bitLength, b);

        int r = 0;

        int len = B.length;
        for (;;)
        {
            while (A[0] == 0)
            {
                Nat.shiftDownWord(len, A, 0);
            }

            int shift = Integers.numberOfTrailingZeros(A[0]);
            if (shift > 0)
            {
                Nat.shiftDownBits(len, A, shift, 0);
                int bits = B[0];
                r ^= (bits ^ (bits >>> 1)) & (shift << 1);
            }

            int cmp = Nat.compare(len, A, B);
            if (cmp == 0)
            {
                break;
            }

            if (cmp < 0)
            {
                r ^= A[0] & B[0];
                int[] t = A; A = B; B = t;
            }

            while (A[len - 1] == 0)
            {
                len = len - 1;
            }

            Nat.sub(len, A, B, A);
        }

        return Nat.isOne(len, B) ? (1 - (r & 2)) : 0;
    }
}
