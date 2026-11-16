package org.bouncycastle.crypto.bls;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.BLSPrivateKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

/**
 * The fixed-width pieces of the BLS12-381 constant-time multiplications against
 * their variable-time counterparts: the reduction of a scalar mod r and its GLS
 * digits against {@link BigInteger}, the masked table read and select, and the
 * G1 and G2 multiplications, built on the complete formulas, against the
 * variable-time multiplications, with scalars chosen to put the point at
 * infinity and equal points into the formulas.
 */
public class BLS12_381ConstantTimeTest
    extends TestCase
{
    private static final BigInteger R = BLS12_381G1.ORDER;
    private static final BigInteger ABS_X = new BigInteger("d201000000010000", 16);
    private static final BigInteger TWO_256 = BigInteger.ONE.shiftLeft(256);

    private final SecureRandom random = new SecureRandom();

    private BigInteger[] scalars()
    {
        return new BigInteger[]{ BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2), BigInteger.valueOf(3),
            BigInteger.valueOf(15), BigInteger.valueOf(16), ABS_X.subtract(BigInteger.ONE), ABS_X,
            ABS_X.add(BigInteger.ONE), ABS_X.pow(2), ABS_X.pow(3), ABS_X.pow(3).add(ABS_X.pow(2)).add(ABS_X)
            .add(BigInteger.ONE), R.subtract(BigInteger.ONE), R, R.add(BigInteger.ONE), R.shiftLeft(1),
            TWO_256.subtract(BigInteger.ONE), TWO_256.add(BigInteger.valueOf(5)),
            new BigInteger(256, random), new BigInteger(255, random), new BigInteger(64, random),
            new BigInteger(300, random) };
    }

    public void testModOrder()
    {
        BigInteger[] ks = scalars();
        for (int i = 0; i < ks.length; ++i)
        {
            checkModOrder(ks[i]);
        }
        for (int i = 0; i < 1000; ++i)
        {
            checkModOrder(new BigInteger(256, random));
        }
    }

    private void checkModOrder(BigInteger k)
    {
        assertEquals(k.toString(16), k.mod(R), Nat.toBigInteger(8, BLS12_381Scalar.modOrder(k)));
    }

    public void testLow256()
    {
        BigInteger[] ks = scalars();
        for (int i = 0; i < ks.length; ++i)
        {
            assertEquals(ks[i].mod(TWO_256), Nat.toBigInteger(8, BLS12_381Scalar.low256(ks[i])));
        }
    }

    public void testGlsDigits()
    {
        BigInteger[] ks = scalars();
        for (int i = 0; i < ks.length; ++i)
        {
            checkGlsDigits(ks[i].mod(R));
        }
        for (int i = 0; i < 1000; ++i)
        {
            checkGlsDigits(new BigInteger(256, random).mod(R));
        }
    }

    private void checkGlsDigits(BigInteger k)
    {
        long[] d = BLS12_381Scalar.glsDigits(Nat.fromBigInteger(256, k));
        BigInteger q = k;
        BigInteger sum = BigInteger.ZERO;
        for (int i = 0; i < 4; ++i)
        {
            BigInteger[] qr = q.divideAndRemainder(ABS_X);
            BigInteger digit = new BigInteger(1, longBytes(d[i]));
            assertEquals("digit " + i + " of " + k.toString(16), qr[1], digit);
            assertTrue(digit.compareTo(ABS_X) < 0);
            sum = sum.add(digit.multiply(ABS_X.pow(i)));
            q = qr[0];
        }
        assertEquals(k, sum);
    }

    private static byte[] longBytes(long v)
    {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; ++i)
        {
            b[i] = (byte)(v >>> (56 - 8 * i));
        }
        return b;
    }

    public void testLookupAndSelect()
    {
        Fp2Element[] t = new Fp2Element[16];
        for (int i = 0; i < t.length; ++i)
        {
            t[i] = Fp2Element.of(new BigInteger(380, random), new BigInteger(380, random));
        }
        for (int i = 0; i < t.length; ++i)
        {
            assertEquals(t[i], Fp2Element.lookup(t, i));
        }
        assertEquals(t[3], Fp2Element.select(1, t[3], t[4]));
        assertEquals(t[4], Fp2Element.select(0, t[3], t[4]));
    }

    public void testG2InSubgroup()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        BLS12_381G2Point p = g.multiply(new BigInteger(255, random));
        BigInteger[] ks = scalars();
        for (int i = 0; i < ks.length; ++i)
        {
            BigInteger k = ks[i];
            assertEquals("G2 generator by " + k.toString(16), g.multiply(k.mod(R)), g.constantTimeMultiplyInG2(k));
            assertEquals("G2 point by " + k.toString(16), p.multiply(k.mod(R)), p.constantTimeMultiply(k));
        }
        assertEquals(p.negate().multiply(BigInteger.TEN), p.constantTimeMultiply(BigInteger.TEN.negate()));
    }

    public void testG2OutsideSubgroup()
    {
        BLS12_381G2Point p = nonSubgroupG2Point();
        assertFalse(BLS12_381SubgroupCheck.isInG2Subgroup(p));
        BigInteger[] ks = scalars();
        for (int i = 0; i < ks.length; ++i)
        {
            BigInteger k = ks[i];
            assertEquals("by " + k.toString(16), p.multiply(k.mod(TWO_256)), p.constantTimeMultiply(k));
        }
    }

    public void testG1()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        ECPoint outside = nonSubgroupG1Point(curve);
        BigInteger[] ks = scalars();
        for (int i = 0; i < ks.length; ++i)
        {
            BigInteger k = ks[i];
            BigInteger low = k.mod(TWO_256);
            assertEquals("G1 generator by " + k.toString(16), g.multiply(low).normalize(),
                BLS12_381G1.constantTimeMultiply(g, k));
            assertEquals("G1 point outside the subgroup by " + k.toString(16), outside.multiply(low).normalize(),
                BLS12_381G1.constantTimeMultiply(outside, k));
        }
        assertEquals(g.negate().multiply(BigInteger.TEN).normalize(),
            BLS12_381G1.constantTimeMultiply(g, BigInteger.TEN.negate()));
    }

    public void testScalarBytes()
    {
        for (int i = 0; i < 200; ++i)
        {
            BigInteger k = new BigInteger(256, random);
            byte[] b = BigIntegers.asUnsignedByteArray(32, k);
            assertEquals(k, Nat.toBigInteger(8, BLS12_381Scalar.fromBytes(b)));
            assertTrue(Arrays.areEqual(b, BLS12_381Scalar.toBytes(BLS12_381Scalar.fromBytes(b))));
            byte[] shortB = BigIntegers.asUnsignedByteArray(k.shiftRight(100));
            assertEquals(k.shiftRight(100), Nat.toBigInteger(8, BLS12_381Scalar.fromBytes(shortB)));
        }
        try
        {
            BLS12_381Scalar.fromBytes(new byte[33]);
            fail("33-byte scalar accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public void testIsValidSecret()
    {
        assertFalse(valid(BigInteger.ZERO));
        assertTrue(valid(BigInteger.ONE));
        assertTrue(valid(R.subtract(BigInteger.ONE)));
        assertFalse(valid(R));
        assertFalse(valid(R.add(BigInteger.ONE)));
        assertFalse(valid(TWO_256.subtract(BigInteger.ONE)));
        assertFalse(valid(BigInteger.ONE.shiftLeft(255)));
        for (int i = 0; i < 200; ++i)
        {
            BigInteger k = new BigInteger(256, random);
            assertEquals(k.signum() > 0 && k.compareTo(R) < 0, valid(k));
        }
    }

    private static boolean valid(BigInteger k)
    {
        return BLS12_381Scalar.isValidSecret(Nat.fromBigInteger(256, k));
    }

    public void testReduceBytes()
    {
        byte[] ff = new byte[48];
        Arrays.fill(ff, (byte)0xFF);
        byte[][] edge = { new byte[48], ff, BigIntegers.asUnsignedByteArray(48, R),
            BigIntegers.asUnsignedByteArray(48, R.multiply(BigInteger.valueOf(12345))),
            BigIntegers.asUnsignedByteArray(48, R.subtract(BigInteger.ONE)), new byte[]{ 7 } };
        for (int i = 0; i < edge.length; ++i)
        {
            checkReduce(edge[i]);
        }
        for (int i = 0; i < 1000; ++i)
        {
            byte[] b = new byte[48];
            random.nextBytes(b);
            checkReduce(b);
        }
    }

    private void checkReduce(byte[] b)
    {
        assertEquals(new BigInteger(1, b).mod(R), Nat.toBigInteger(8, BLS12_381Scalar.reduce(b, 0, b.length)));
    }

    public void testKeyGenEncoded()
    {
        for (int i = 0; i < 20; ++i)
        {
            byte[] ikm = new byte[32 + i];
            random.nextBytes(ikm);
            byte[] info = new byte[i];
            random.nextBytes(info);
            byte[] enc = BLS12_381BasicScheme.keyGenEncoded(ikm, info);
            assertEquals(32, enc.length);
            assertEquals(BLS12_381BasicScheme.keyGen(ikm, info), new BigInteger(1, enc));
        }
    }

    public void testByteScalarMultiplication()
    {
        BLS12_381G2Point g2 = BLS12_381G2.getGenerator().multiply(new BigInteger(255, random));
        BLS12_381G2Point outside = nonSubgroupG2Point();
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g1 = BLS12_381G1.getGenerator(curve);
        BigInteger[] ks = scalars();
        for (int i = 0; i < ks.length; ++i)
        {
            BigInteger k = ks[i].mod(TWO_256);
            byte[] b = BigIntegers.asUnsignedByteArray(k);
            assertEquals("G2 by " + k.toString(16), g2.constantTimeMultiply(k), g2.constantTimeMultiply(b));
            assertEquals("G2 outside by " + k.toString(16), outside.constantTimeMultiply(k),
                outside.constantTimeMultiply(b));
            assertEquals("G1 by " + k.toString(16), BLS12_381G1.constantTimeMultiply(g1, k),
                BLS12_381G1.constantTimeMultiply(g1, b));
        }
        assertTrue(BLS12_381G2Point.INFINITY.constantTimeMultiply(new byte[]{ 5 }).isInfinity());
    }

    public void testByteSecretKeySchemes()
    {
        byte[] msg = Strings.toByteArray("message");
        for (int i = 0; i < 3; ++i)
        {
            BigInteger sk = new BigInteger(255, random).mod(R.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            byte[] enc = BigIntegers.asUnsignedByteArray(32, sk);
            assertEquals(BLS12_381BasicScheme.skToPk(sk), BLS12_381BasicScheme.skToPk(enc));
            assertEquals(BLS12_381BasicScheme.sign(sk, msg), BLS12_381BasicScheme.sign(enc, msg));
            assertEquals(BLS12_381ProofOfPossession.sign(sk, msg), BLS12_381ProofOfPossession.sign(enc, msg));
            assertEquals(BLS12_381ProofOfPossession.popProve(sk), BLS12_381ProofOfPossession.popProve(enc));
            assertEquals(BLS12_381MessageAugmentation.sign(sk, msg), BLS12_381MessageAugmentation.sign(enc, msg));

            BLSPrivateKeyParameters fromBig = new BLSPrivateKeyParameters(null, sk);
            BLSPrivateKeyParameters fromEnc = new BLSPrivateKeyParameters(null, enc);
            assertTrue(Arrays.areEqual(enc, fromBig.getEncoded()));
            assertEquals(sk, fromEnc.getSecret());
            fromEnc.getEncoded()[0] ^= 1;
            assertTrue(Arrays.areEqual(enc, fromEnc.getEncoded()));
            enc[0] ^= 1;
            assertEquals(sk, fromEnc.getSecret());
        }

        byte[][] bad = { null, new byte[32], BigIntegers.asUnsignedByteArray(32, R),
            BigIntegers.asUnsignedByteArray(32, TWO_256.subtract(BigInteger.ONE)), new byte[31], new byte[33] };
        for (int i = 0; i < bad.length; ++i)
        {
            try
            {
                BLS12_381BasicScheme.sign(bad[i], msg);
                fail("bad secret key " + i + " accepted by sign");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("invalid secret key", e.getMessage());
            }
            try
            {
                new BLSPrivateKeyParameters(null, bad[i]);
                fail("bad secret key " + i + " accepted by BLSPrivateKeyParameters");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("invalid BLS secret key", e.getMessage());
            }
        }
    }

    private BLS12_381G2Point nonSubgroupG2Point()
    {
        for (;;)
        {
            Fp2Element x = Fp2Element.of(new BigInteger(380, random), new BigInteger(380, random));
            Fp2Element y = x.square().mul(x).add(BLS12_381G2Point.B).sqrtOrNull();
            if (y != null)
            {
                return BLS12_381G2Point.of(x, y);
            }
        }
    }

    private ECPoint nonSubgroupG1Point(ECCurve curve)
    {
        BigInteger q = BLS12_381G1.Q;
        for (;;)
        {
            BigInteger x = new BigInteger(380, random);
            BigInteger rhs = x.pow(3).add(BigInteger.valueOf(4)).mod(q);
            // q = 3 mod 4, so a square root of a square is its (q + 1) / 4 power
            BigInteger y = rhs.modPow(q.add(BigInteger.ONE).shiftRight(2), q);
            if (y.multiply(y).mod(q).equals(rhs))
            {
                ECPoint p = curve.createPoint(x, y);
                if (!p.multiply(R).isInfinity())
                {
                    return p;
                }
            }
        }
    }
}
