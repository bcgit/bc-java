package org.bouncycastle.math.ec.custom.gm;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;

/**
 * Prime-field arithmetic for the SM9 256-bit Barreto-Naehrig base field F_q
 * (GM/T 0044.5-2016), used by the G1 curve {@link SM9P256V1Curve}.
 * <p>
 * Unlike {@link SM2P256V1Field} (whose sparse prime admits a fast Solinas
 * reduction and stores elements in the ordinary residue representation), the SM9
 * BN prime is a general 256-bit prime, so this field keeps elements in
 * <b>Montgomery form</b> (a&middot;R mod q, R = 2^256) and multiplies with a
 * Montgomery (SOS) reduction. Fixed-limb {@link Nat256} arithmetic makes the
 * field operations constant time (no data-dependent branches beyond the standard
 * conditional subtractions), unlike the variable-length {@code BigInteger} the
 * generic {@code ECCurve.Fp} would use.
 * <p>
 * The constants n0 = -q^-1 mod 2^32 and R^2 mod q are derived from q at class
 * load (a micro-optimisation would inline them as int[] literals as SM2 does).
 */
public class SM9P256V1Field
{
    private static final long M = 0xFFFFFFFFL;

    static final BigInteger Q = SM9P256V1FieldElement.Q;

    static final int[] P = Nat256.fromBigInteger(Q);            // q as 8 little-endian limbs
    private static final int N0 = deriveN0();                   // -q^-1 mod 2^32
    private static final int[] R2 = Nat256.fromBigInteger(BigInteger.ONE.shiftLeft(512).mod(Q));
    static final int[] ONE = Nat256.fromBigInteger(BigInteger.ONE.shiftLeft(256).mod(Q)); // R mod q = 1 in Montgomery form

    private static int deriveN0()
    {
        BigInteger b32 = BigInteger.ONE.shiftLeft(32);
        return Q.modInverse(b32).negate().mod(b32).intValue();
    }

    // ---- modular add/subtract/negate (Montgomery form is additively homomorphic) ----

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat256.add(x, y, z);
        if (c != 0 || Nat256.gte(z, P))
        {
            Nat256.subFrom(P, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat256.sub(x, y, z);
        if (c != 0)
        {
            Nat.addTo(8, P, z);
        }
    }

    public static void negate(int[] x, int[] z)
    {
        if (Nat256.isZero(x))
        {
            Nat256.zero(z);
        }
        else
        {
            Nat256.sub(P, x, z);
        }
    }

    public static void twice(int[] x, int[] z)
    {
        add(x, x, z);
    }

    // ---- Montgomery multiply / square / reduce ----

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = new int[18];
        Nat256.mul(x, y, tt);
        montReduce(tt, z);
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = new int[18];
        Nat256.square(x, tt);
        montReduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
        square(x, z);
        while (--n > 0)
        {
            square(z, z);
        }
    }

    // Montgomery (SOS) reduction: tt (low 16 limbs = product, [16],[17] = 0)
    // -> z (8 limbs) = tt * R^-1 mod q. Result in [0, 2q) then one conditional subtract.
    private static void montReduce(int[] tt, int[] z)
    {
        for (int i = 0; i < 8; ++i)
        {
            long m = ((tt[i] & M) * (N0 & M)) & M;
            long c = 0;
            for (int j = 0; j < 8; ++j)
            {
                long s = (tt[i + j] & M) + m * (P[j] & M) + c;
                tt[i + j] = (int)s;
                c = s >>> 32;
            }
            // fixed-length carry propagation (c provably never passes tt[16]) - no
            // data-dependent loop bound, so the reduction has no secret-dependent branch.
            for (int k = i + 8; k <= 16; ++k)
            {
                long s = (tt[k] & M) + c;
                tt[k] = (int)s;
                c = s >>> 32;
            }
        }
        System.arraycopy(tt, 8, z, 0, 8);
        if (tt[16] != 0 || Nat256.gte(z, P))       // include overflow limb before the subtract
        {
            Nat256.subFrom(P, z);
        }
    }

    // ---- conversions and inverse ----

    public static int[] fromBigInteger(BigInteger x)
    {
        // caller guarantees 0 <= x < q; convert to Montgomery form (x*R mod q = montMul(x, R^2))
        int[] z = Nat256.create();
        multiply(Nat256.fromBigInteger(x), R2, z);
        return z;
    }

    public static BigInteger toBigInteger(int[] xMont)
    {
        // leave Montgomery form: montReduce(xMont) = xMont * R^-1 mod q
        int[] tt = new int[18];
        System.arraycopy(xMont, 0, tt, 0, 8);
        int[] z = Nat256.create();
        montReduce(tt, z);
        return Nat256.toBigInteger(z);
    }

    public static void inv(int[] x, int[] z)
    {
        // Fermat inverse: x^(q-2). In Montgomery form montPow(aR, e) = a^e R, so this
        // yields a^-1 R. The exponent q-2 is a public constant, so the square-and-multiply
        // pattern reveals nothing about the secret base.
        BigInteger e = Q.subtract(BigInteger.valueOf(2));
        int[] result = Nat256.create();
        System.arraycopy(ONE, 0, result, 0, 8);
        int[] base = Nat256.create();
        System.arraycopy(x, 0, base, 0, 8);
        for (int i = e.bitLength() - 1; i >= 0; --i)
        {
            square(result, result);
            if (e.testBit(i))
            {
                multiply(result, base, result);
            }
        }
        System.arraycopy(result, 0, z, 0, 8);
    }

    public static boolean isZero(int[] x)
    {
        return Nat256.isZero(x);
    }

    private SM9P256V1Field()
    {
    }
}
