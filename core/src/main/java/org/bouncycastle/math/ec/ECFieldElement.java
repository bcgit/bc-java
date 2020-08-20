package org.bouncycastle.math.ec;

import java.math.BigInteger;
import java.util.Random;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;

public abstract class ECFieldElement
    implements ECConstants
{
    public abstract BigInteger     toBigInteger();
    public abstract String         getFieldName();
    public abstract int            getFieldSize();
    public abstract ECFieldElement add(ECFieldElement b);
    public abstract ECFieldElement addOne();
    public abstract ECFieldElement subtract(ECFieldElement b);
    public abstract ECFieldElement multiply(ECFieldElement b);
    public abstract ECFieldElement divide(ECFieldElement b);
    public abstract ECFieldElement negate();
    public abstract ECFieldElement square();
    public abstract ECFieldElement invert();
    public abstract ECFieldElement sqrt();

    public ECFieldElement()
    {

    }
    
    public int bitLength()
    {
        return toBigInteger().bitLength();
    }

    public boolean isOne()
    {
        return bitLength() == 1;
    }

    public boolean isZero()
    {
        return 0 == toBigInteger().signum();
    }

    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        return multiply(b).subtract(x.multiply(y));
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        return multiply(b).add(x.multiply(y));
    }

    public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
    {
        return square().subtract(x.multiply(y));
    }

    public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
    {
        return square().add(x.multiply(y));
    }

    public ECFieldElement squarePow(int pow)
    {
        ECFieldElement r = this;
        for (int i = 0; i < pow; ++i)
        {
            r = r.square();
        }
        return r;
    }

    public boolean testBitZero()
    {
        return toBigInteger().testBit(0);
    }

    public String toString()
    {
        return this.toBigInteger().toString(16);
    }

    public byte[] getEncoded()
    {
        return BigIntegers.asUnsignedByteArray((getFieldSize() + 7) / 8, toBigInteger());
    }

    public static abstract class AbstractFp extends ECFieldElement
    {
    }

    public static class Fp extends AbstractFp
    {
        BigInteger q, r, x;

        static BigInteger calculateResidue(BigInteger p)
        {
            int bitLength = p.bitLength();
            if (bitLength >= 96)
            {
                BigInteger firstWord = p.shiftRight(bitLength - 64);
                if (firstWord.longValue() == -1L)
                {
                    return ONE.shiftLeft(bitLength).subtract(p);
                }
            }
            return null;
        }

        /**
         * @deprecated Use ECCurve.fromBigInteger to construct field elements
         */
        public Fp(BigInteger q, BigInteger x)
        {
            this(q, calculateResidue(q), x);
        }

        Fp(BigInteger q, BigInteger r, BigInteger x)
        {
            if (x == null || x.signum() < 0 || x.compareTo(q) >= 0)
            {
                throw new IllegalArgumentException("x value invalid in Fp field element");
            }

            this.q = q;
            this.r = r;
            this.x = x;
        }

        public BigInteger toBigInteger()
        {
            return x;
        }

        /**
         * return the field name for this field.
         *
         * @return the string "Fp".
         */
        public String getFieldName()
        {
            return "Fp";
        }

        public int getFieldSize()
        {
            return q.bitLength();
        }

        public BigInteger getQ()
        {
            return q;
        }

        public ECFieldElement add(ECFieldElement b)
        {
            return new Fp(q, r, modAdd(x, b.toBigInteger()));
        }

        public ECFieldElement addOne()
        {
            BigInteger x2 = x.add(ECConstants.ONE);
            if (x2.compareTo(q) == 0)
            {
                x2 = ECConstants.ZERO;
            }
            return new Fp(q, r, x2);
        }

        public ECFieldElement subtract(ECFieldElement b)
        {
            return new Fp(q, r, modSubtract(x, b.toBigInteger()));
        }

        public ECFieldElement multiply(ECFieldElement b)
        {
            return new Fp(q, r, modMult(x, b.toBigInteger()));
        }

        public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = this.x, bx = b.toBigInteger(), xx = x.toBigInteger(), yx = y.toBigInteger();
            BigInteger ab = ax.multiply(bx);
            BigInteger xy = xx.multiply(yx);
            return new Fp(q, r, modReduce(ab.subtract(xy)));
        }

        public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = this.x, bx = b.toBigInteger(), xx = x.toBigInteger(), yx = y.toBigInteger();
            BigInteger ab = ax.multiply(bx);
            BigInteger xy = xx.multiply(yx);
            return new Fp(q, r, modReduce(ab.add(xy)));
        }

        public ECFieldElement divide(ECFieldElement b)
        {
            return new Fp(q, r, modMult(x, modInverse(b.toBigInteger())));
        }

        public ECFieldElement negate()
        {
            return x.signum() == 0 ? this : new Fp(q, r, q.subtract(x));
        }

        public ECFieldElement square()
        {
            return new Fp(q, r, modMult(x, x));
        }

        public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = this.x, xx = x.toBigInteger(), yx = y.toBigInteger();
            BigInteger aa = ax.multiply(ax);
            BigInteger xy = xx.multiply(yx);
            return new Fp(q, r, modReduce(aa.subtract(xy)));
        }

        public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = this.x, xx = x.toBigInteger(), yx = y.toBigInteger();
            BigInteger aa = ax.multiply(ax);
            BigInteger xy = xx.multiply(yx);
            return new Fp(q, r, modReduce(aa.add(xy)));
        }

        public ECFieldElement invert()
        {
            // TODO Modular inversion can be faster for a (Generalized) Mersenne Prime.
            return new Fp(q, r, modInverse(x));
        }

        // D.1.4 91
        /**
         * return a sqrt root - the routine verifies that the calculation
         * returns the right value - if none exists it returns null.
         */
        public ECFieldElement sqrt()
        {
            if (this.isZero() || this.isOne()) // earlier JDK compatibility
            {
                return this;
            }

            if (!q.testBit(0))
            {
                throw new RuntimeException("not done yet");
            }

            // note: even though this class implements ECConstants don't be tempted to
            // remove the explicit declaration, some J2ME environments don't cope.

            if (q.testBit(1)) // q == 4m + 3
            {
                BigInteger e = q.shiftRight(2).add(ECConstants.ONE);
                return checkSqrt(new Fp(q, r, x.modPow(e, q)));
            }

            if (q.testBit(2)) // q == 8m + 5
            {
                BigInteger t1 = x.modPow(q.shiftRight(3), q);
                BigInteger t2 = modMult(t1, x);
                BigInteger t3 = modMult(t2, t1);

                if (t3.equals(ECConstants.ONE))
                {
                    return checkSqrt(new Fp(q, r, t2));
                }

                // TODO This is constant and could be precomputed
                BigInteger t4 = ECConstants.TWO.modPow(q.shiftRight(2), q);

                BigInteger y = modMult(t2, t4);

                return checkSqrt(new Fp(q, r, y));
            }

            // q == 8m + 1

            BigInteger legendreExponent = q.shiftRight(1);
            if (!(x.modPow(legendreExponent, q).equals(ECConstants.ONE)))
            {
                return null;
            }

            BigInteger X = this.x;
            BigInteger fourX = modDouble(modDouble(X));

            BigInteger k = legendreExponent.add(ECConstants.ONE), qMinusOne = q.subtract(ECConstants.ONE);

            BigInteger U, V;
            Random rand = new Random();
            do
            {
                BigInteger P;
                do
                {
                    P = new BigInteger(q.bitLength(), rand);
                }
                while (P.compareTo(q) >= 0
                    || !modReduce(P.multiply(P).subtract(fourX)).modPow(legendreExponent, q).equals(qMinusOne));

                BigInteger[] result = lucasSequence(P, X, k);
                U = result[0];
                V = result[1];

                if (modMult(V, V).equals(fourX))
                {
                    return new ECFieldElement.Fp(q, r, modHalfAbs(V));
                }
            }
            while (U.equals(ECConstants.ONE) || U.equals(qMinusOne));

            return null;
        }

        private ECFieldElement checkSqrt(ECFieldElement z)
        {
            return z.square().equals(this) ? z : null;
        }

        private BigInteger[] lucasSequence(
            BigInteger  P,
            BigInteger  Q,
            BigInteger  k)
        {
            // TODO Research and apply "common-multiplicand multiplication here"

            int n = k.bitLength();
            int s = k.getLowestSetBit();

            // assert k.testBit(s);

            BigInteger Uh = ECConstants.ONE;
            BigInteger Vl = ECConstants.TWO;
            BigInteger Vh = P;
            BigInteger Ql = ECConstants.ONE;
            BigInteger Qh = ECConstants.ONE;

            for (int j = n - 1; j >= s + 1; --j)
            {
                Ql = modMult(Ql, Qh);

                if (k.testBit(j))
                {
                    Qh = modMult(Ql, Q);
                    Uh = modMult(Uh, Vh);
                    Vl = modReduce(Vh.multiply(Vl).subtract(P.multiply(Ql)));
                    Vh = modReduce(Vh.multiply(Vh).subtract(Qh.shiftLeft(1)));
                }
                else
                {
                    Qh = Ql;
                    Uh = modReduce(Uh.multiply(Vl).subtract(Ql));
                    Vh = modReduce(Vh.multiply(Vl).subtract(P.multiply(Ql)));
                    Vl = modReduce(Vl.multiply(Vl).subtract(Ql.shiftLeft(1)));
                }
            }

            Ql = modMult(Ql, Qh);
            Qh = modMult(Ql, Q);
            Uh = modReduce(Uh.multiply(Vl).subtract(Ql));
            Vl = modReduce(Vh.multiply(Vl).subtract(P.multiply(Ql)));
            Ql = modMult(Ql, Qh);

            for (int j = 1; j <= s; ++j)
            {
                Uh = modMult(Uh, Vl);
                Vl = modReduce(Vl.multiply(Vl).subtract(Ql.shiftLeft(1)));
                Ql = modMult(Ql, Ql);
            }

            return new BigInteger[]{ Uh, Vl };
        }

        protected BigInteger modAdd(BigInteger x1, BigInteger x2)
        {
            BigInteger x3 = x1.add(x2);
            if (x3.compareTo(q) >= 0)
            {
                x3 = x3.subtract(q);
            }
            return x3;
        }

        protected BigInteger modDouble(BigInteger x)
        {
            BigInteger _2x = x.shiftLeft(1);
            if (_2x.compareTo(q) >= 0)
            {
                _2x = _2x.subtract(q);
            }
            return _2x;
        }

        protected BigInteger modHalf(BigInteger x)
        {
            if (x.testBit(0))
            {
                x = q.add(x);
            }
            return x.shiftRight(1);
        }

        protected BigInteger modHalfAbs(BigInteger x)
        {
            if (x.testBit(0))
            {
                x = q.subtract(x);
            }
            return x.shiftRight(1);
        }

        protected BigInteger modInverse(BigInteger x)
        {
            return BigIntegers.modOddInverse(q, x);
        }

        protected BigInteger modMult(BigInteger x1, BigInteger x2)
        {
            return modReduce(x1.multiply(x2));
        }

        protected BigInteger modReduce(BigInteger x)
        {
            if (r != null)
            {
                boolean negative = x.signum() < 0;
                if (negative)
                {
                    x = x.abs();
                }
                int qLen = q.bitLength();
                boolean rIsOne = r.equals(ECConstants.ONE);
                while (x.bitLength() > (qLen + 1))
                {
                    BigInteger u = x.shiftRight(qLen);
                    BigInteger v = x.subtract(u.shiftLeft(qLen));
                    if (!rIsOne)
                    {
                        u = u.multiply(r);
                    }
                    x = u.add(v); 
                }
                while (x.compareTo(q) >= 0)
                {
                    x = x.subtract(q);
                }
                if (negative && x.signum() != 0)
                {
                    x = q.subtract(x);
                }
            }
            else
            {
                x = x.mod(q);
            }
            return x;
        }

        protected BigInteger modSubtract(BigInteger x1, BigInteger x2)
        {
            BigInteger x3 = x1.subtract(x2);
            if (x3.signum() < 0)
            {
                x3 = x3.add(q);
            }
            return x3;
        }

        public boolean equals(Object other)
        {
            if (other == this)
            {
                return true;
            }

            if (!(other instanceof ECFieldElement.Fp))
            {
                return false;
            }
            
            ECFieldElement.Fp o = (ECFieldElement.Fp)other;
            return q.equals(o.q) && x.equals(o.x);
        }

        public int hashCode()
        {
            return q.hashCode() ^ x.hashCode();
        }
    }

    public static abstract class AbstractF2m extends ECFieldElement
    {
        public ECFieldElement halfTrace()
        {
            int m = this.getFieldSize();
            if ((m & 1) == 0)
            {
                throw new IllegalStateException("Half-trace only defined for odd m");
            }

//            ECFieldElement ht = this;
//            for (int i = 1; i < m; i += 2)
//            {
//                ht = ht.squarePow(2).add(this);
//            }

            int n = (m + 1) >>> 1;
            int k = 31 - Integers.numberOfLeadingZeros(n);
            int nk = 1;

            ECFieldElement ht = this;
            while (k > 0)
            {
                ht = ht.squarePow(nk << 1).add(ht);
                nk = n >>> --k;
                if (0 != (nk & 1))
                {
                    ht = ht.squarePow(2).add(this);
                }
            }

            return ht;
        }

        public boolean hasFastTrace()
        {
            return false;
        }

        public int trace()
        {
            int m = this.getFieldSize();

//            ECFieldElement tr = this;
//            for (int i = 1; i < m; ++i)
//            {
//                tr = tr.square().add(this);
//            }

            int k = 31 - Integers.numberOfLeadingZeros(m);
            int mk = 1;

            ECFieldElement tr = this;
            while (k > 0)
            {
                tr = tr.squarePow(mk).add(tr);
                mk = m >>> --k;
                if (0 != (mk & 1))
                {
                    tr = tr.square().add(this);
                }
            }

            if (tr.isZero())
            {
                return 0;
            }
            if (tr.isOne())
            {
                return 1;
            }
            throw new IllegalStateException("Internal error in trace calculation");
        }
    }

    /**
     * Class representing the Elements of the finite field
     * <code>F<sub>2<sup>m</sup></sub></code> in polynomial basis (PB)
     * representation. Both trinomial (TPB) and pentanomial (PPB) polynomial
     * basis representations are supported. Gaussian normal basis (GNB)
     * representation is not supported.
     */
    public static class F2m extends AbstractF2m
    {
        /**
         * Indicates gaussian normal basis representation (GNB). Number chosen
         * according to X9.62. GNB is not implemented at present.
         */
        public static final int GNB = 1;

        /**
         * Indicates trinomial basis representation (TPB). Number chosen
         * according to X9.62.
         */
        public static final int TPB = 2;

        /**
         * Indicates pentanomial basis representation (PPB). Number chosen
         * according to X9.62.
         */
        public static final int PPB = 3;

        /**
         * TPB or PPB.
         */
        private int representation;

        /**
         * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
         */
        private int m;

        private int[] ks;

        /**
         * The <code>LongArray</code> holding the bits.
         */
        LongArray x;

        /**
         * Constructor for PPB.
         * @param m  The exponent <code>m</code> of
         * <code>F<sub>2<sup>m</sup></sub></code>.
         * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param x The BigInteger representing the value of the field element.
         * @deprecated Use ECCurve.fromBigInteger to construct field elements
         */
        public F2m(
            int m, 
            int k1, 
            int k2, 
            int k3,
            BigInteger x)
        {
            if (x == null || x.signum() < 0 || x.bitLength() > m)
            {
                throw new IllegalArgumentException("x value invalid in F2m field element");
            }

            if ((k2 == 0) && (k3 == 0))
            {
                this.representation = TPB;
                this.ks = new int[]{ k1 }; 
            }
            else
            {
                if (k2 >= k3)
                {
                    throw new IllegalArgumentException(
                            "k2 must be smaller than k3");
                }
                if (k2 <= 0)
                {
                    throw new IllegalArgumentException(
                            "k2 must be larger than 0");
                }
                this.representation = PPB;
                this.ks = new int[]{ k1, k2, k3 }; 
            }

            this.m = m;
            this.x = new LongArray(x);
        }

        F2m(int m, int[] ks, LongArray x)
        {
            this.m = m;
            this.representation = (ks.length == 1) ? TPB : PPB;
            this.ks = ks;
            this.x = x;
        }

        public int bitLength()
        {
            return x.degree();
        }

        public boolean isOne()
        {
            return x.isOne();
        }

        public boolean isZero()
        {
            return x.isZero();
        }

        public boolean testBitZero()
        {
            return x.testBitZero();
        }

        public BigInteger toBigInteger()
        {
            return x.toBigInteger();
        }

        public String getFieldName()
        {
            return "F2m";
        }

        public int getFieldSize()
        {
            return m;
        }

        public ECFieldElement add(final ECFieldElement b)
        {
            // No check performed here for performance reasons. Instead the
            // elements involved are checked in ECPoint.F2m
            // checkFieldElements(this, b);
            LongArray iarrClone = (LongArray)this.x.clone();
            F2m bF2m = (F2m)b;
            iarrClone.addShiftedByWords(bF2m.x, 0);
            return new F2m(m, ks, iarrClone);
        }

        public ECFieldElement addOne()
        {
            return new F2m(m, ks, x.addOne());
        }

        public ECFieldElement subtract(final ECFieldElement b)
        {
            // Addition and subtraction are the same in F2m
            return add(b);
        }

        public ECFieldElement multiply(final ECFieldElement b)
        {
            // Right-to-left comb multiplication in the LongArray
            // Input: Binary polynomials a(z) and b(z) of degree at most m-1
            // Output: c(z) = a(z) * b(z) mod f(z)

            // No check performed here for performance reasons. Instead the
            // elements involved are checked in ECPoint.F2m
            // checkFieldElements(this, b);
            return new F2m(m, ks, x.modMultiply(((F2m)b).x, m, ks));
        }

        public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
        {
            return multiplyPlusProduct(b, x, y);
        }

        public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
        {
            LongArray ax = this.x, bx = ((F2m)b).x, xx = ((F2m)x).x, yx = ((F2m)y).x;

            LongArray ab = ax.multiply(bx, m, ks);
            LongArray xy = xx.multiply(yx, m, ks);

            if (ab == ax || ab == bx)
            {
                ab = (LongArray)ab.clone();
            }

            ab.addShiftedByWords(xy, 0);
            ab.reduce(m, ks);

            return new F2m(m, ks, ab);
        }

        public ECFieldElement divide(final ECFieldElement b)
        {
            // There may be more efficient implementations
            ECFieldElement bInv = b.invert();
            return multiply(bInv);
        }

        public ECFieldElement negate()
        {
            // -x == x holds for all x in F2m
            return this;
        }

        public ECFieldElement square()
        {
            return new F2m(m, ks, x.modSquare(m, ks));
        }

        public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
        {
            return squarePlusProduct(x, y);
        }

        public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
        {
            LongArray ax = this.x, xx = ((F2m)x).x, yx = ((F2m)y).x;

            LongArray aa = ax.square(m, ks);
            LongArray xy = xx.multiply(yx, m, ks);

            if (aa == ax)
            {
                aa = (LongArray)aa.clone();
            }

            aa.addShiftedByWords(xy, 0);
            aa.reduce(m, ks);

            return new F2m(m, ks, aa);
        }

        public ECFieldElement squarePow(int pow)
        {
            return pow < 1 ? this : new F2m(m, ks, x.modSquareN(pow, m, ks));
        }

        public ECFieldElement invert()
        {
            return new ECFieldElement.F2m(this.m, this.ks, this.x.modInverse(m, ks));
        }

        public ECFieldElement sqrt()
        {
            return (x.isZero() || x.isOne()) ? this : squarePow(m - 1);
        }

        /**
         * @return the representation of the field
         * <code>F<sub>2<sup>m</sup></sub></code>, either of
         * TPB (trinomial
         * basis representation) or
         * PPB (pentanomial
         * basis representation).
         */
        public int getRepresentation()
        {
            return this.representation;
        }

        /**
         * @return the degree <code>m</code> of the reduction polynomial
         * <code>f(z)</code>.
         */
        public int getM()
        {
            return this.m;
        }

        /**
         * @return TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction polynomial
         * <code>f(z)</code>.<br>
         * PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        public int getK1()
        {
            return this.ks[0];
        }

        /**
         * @return TPB: Always returns <code>0</code><br>
         * PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        public int getK2()
        {
            return this.ks.length >= 2 ? this.ks[1] : 0;
        }

        /**
         * @return TPB: Always set to <code>0</code><br>
         * PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        public int getK3()
        {
            return this.ks.length >= 3 ? this.ks[2] : 0;
        }

        public boolean equals(Object anObject)
        {
            if (anObject == this) 
            {
                return true;
            }

            if (!(anObject instanceof ECFieldElement.F2m)) 
            {
                return false;
            }

            ECFieldElement.F2m b = (ECFieldElement.F2m)anObject;
            
            return ((this.m == b.m)
                && (this.representation == b.representation)
                && Arrays.areEqual(this.ks, b.ks)
                && (this.x.equals(b.x)));
        }

        public int hashCode()
        {
            return x.hashCode() ^ m ^ Arrays.hashCode(ks);
        }
    }
}
