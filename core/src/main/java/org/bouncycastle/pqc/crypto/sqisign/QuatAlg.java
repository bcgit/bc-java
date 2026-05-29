package org.bouncycastle.pqc.crypto.sqisign;

/**
 * The quaternion algebra ramified at p ≡ 3 (mod 4) and ∞: {1, i, j, ij} with
 * i² = -1 and j² = -p. Java port of
 * {@code src/quaternion/ref/generic/algebra.c}.
 *
 * <p>Elements are 4-coordinate integer vectors with a common denominator; see
 * {@link Elem}. The algebra itself is just the prime p (held in
 * {@link #p}).</p>
 */
final class QuatAlg
{
    /**
     * The prime p of the algebra. Required to satisfy p ≡ 3 (mod 4).
     */
    public final Ibz p;

    public QuatAlg(Ibz p)
    {
        this.p = p.copy();
    }

    public QuatAlg(java.math.BigInteger pVal)
    {
        this.p = new Ibz(pVal);
    }

    /**
     * Element of the quaternion algebra represented as {@code (coord[0] +
     * coord[1] i + coord[2] j + coord[3] ij) / denom}. The representation is
     * not necessarily normalised — call {@link #normalize(Elem)} to reduce.
     */
    public static final class Elem
    {
        public final Ibz denom;
        public final Ibz[] coord;

        public Elem()
        {
            this.denom = new Ibz(1);
            this.coord = IbzVec.init4();
        }

        public Elem copy()
        {
            Elem out = new Elem();
            QuatAlg.copyElem(out, this);
            return out;
        }
    }

    /**
     * {@code quat_alg_elem_copy}.
     */
    public static void copyElem(Elem dst, Elem src)
    {
        Ibz.copy(dst.denom, src.denom);
        for (int i = 0; i < 4; i++)
        {
            Ibz.copy(dst.coord[i], src.coord[i]);
        }
    }

    /**
     * {@code quat_alg_scalar}: set element to (numerator / denominator).
     */
    public static void scalar(Elem out, Ibz numerator, Ibz denominator)
    {
        Ibz.copy(out.denom, denominator);
        Ibz.copy(out.coord[0], numerator);
        Ibz.set(out.coord[1], 0);
        Ibz.set(out.coord[2], 0);
        Ibz.set(out.coord[3], 0);
    }

    /**
     * {@code quat_alg_elem_is_zero}.
     */
    public static int isZero(Elem x)
    {
        return IbzVec.isZero4(x.coord);
    }

    // ---- arithmetic ---------------------------------------------------------

    /**
     * Put two elements on a common denominator (the LCM of their denominators
     * via gcd trick). {@code resA.denom == resB.denom} after the call.
     * Mirrors C {@code quat_alg_equal_denom}.
     */
    private static void equalDenom(Elem resA, Elem resB, Elem a, Elem b)
    {
        Ibz gcd = new Ibz();
        Ibz r = new Ibz();
        Ibz.gcd(gcd, a.denom, b.denom);
        Ibz.div(resA.denom, r, a.denom, gcd);    // a.denom / gcd
        Ibz.div(resB.denom, r, b.denom, gcd);    // b.denom / gcd
        for (int i = 0; i < 4; i++)
        {
            // multiply a-coords by reduced b-denom, b-coords by reduced a-denom
            Ibz.mul(resA.coord[i], a.coord[i], resB.denom);
            Ibz.mul(resB.coord[i], b.coord[i], resA.denom);
        }
        // common denominator: (a.denom / gcd) * (b.denom / gcd) * gcd
        Ibz.mul(resA.denom, resA.denom, resB.denom);
        Ibz.mul(resB.denom, resA.denom, gcd);
        Ibz.mul(resA.denom, resA.denom, gcd);
    }

    public static void add(Elem res, Elem a, Elem b)
    {
        Elem ra = new Elem(), rb = new Elem();
        equalDenom(ra, rb, a, b);
        Ibz.copy(res.denom, ra.denom);
        IbzVec.add4(res.coord, ra.coord, rb.coord);
    }

    public static void sub(Elem res, Elem a, Elem b)
    {
        Elem ra = new Elem(), rb = new Elem();
        equalDenom(ra, rb, a, b);
        Ibz.copy(res.denom, ra.denom);
        IbzVec.sub4(res.coord, ra.coord, rb.coord);
    }

    /**
     * Quaternion multiplication using basis (1, i, j, ij) with i² = -1, j² = -p.
     * Mirrors C {@code quat_alg_coord_mul} + {@code quat_alg_mul}.
     * </p>
     */
    public static void mul(Elem res, Elem a, Elem b, QuatAlg alg)
    {
        Ibz.mul(res.denom, a.denom, b.denom);
        coordMul(res.coord, a.coord, b.coord, alg);
    }

    /**
     * {@code quat_alg_coord_mul}: multiply just the numerator vectors.
     */
    public static void coordMul(Ibz[] res, Ibz[] a, Ibz[] b, QuatAlg alg)
    {
        Ibz prod = new Ibz();
        Ibz[] sum = IbzVec.init4();

        // ---- 1-coord ---------------------------------------------------
        Ibz.mul(prod, a[2], b[2]);
        Ibz.sub(sum[0], sum[0], prod);
        Ibz.mul(prod, a[3], b[3]);
        Ibz.sub(sum[0], sum[0], prod);
        Ibz.mul(sum[0], sum[0], alg.p);
        Ibz.mul(prod, a[0], b[0]);
        Ibz.add(sum[0], sum[0], prod);
        Ibz.mul(prod, a[1], b[1]);
        Ibz.sub(sum[0], sum[0], prod);

        // ---- i-coord ---------------------------------------------------
        Ibz.mul(prod, a[2], b[3]);
        Ibz.add(sum[1], sum[1], prod);
        Ibz.mul(prod, a[3], b[2]);
        Ibz.sub(sum[1], sum[1], prod);
        Ibz.mul(sum[1], sum[1], alg.p);
        Ibz.mul(prod, a[0], b[1]);
        Ibz.add(sum[1], sum[1], prod);
        Ibz.mul(prod, a[1], b[0]);
        Ibz.add(sum[1], sum[1], prod);

        // ---- j-coord ---------------------------------------------------
        Ibz.mul(prod, a[0], b[2]);
        Ibz.add(sum[2], sum[2], prod);
        Ibz.mul(prod, a[2], b[0]);
        Ibz.add(sum[2], sum[2], prod);
        Ibz.mul(prod, a[1], b[3]);
        Ibz.sub(sum[2], sum[2], prod);
        Ibz.mul(prod, a[3], b[1]);
        Ibz.add(sum[2], sum[2], prod);

        // ---- ij-coord --------------------------------------------------
        Ibz.mul(prod, a[0], b[3]);
        Ibz.add(sum[3], sum[3], prod);
        Ibz.mul(prod, a[3], b[0]);
        Ibz.add(sum[3], sum[3], prod);
        Ibz.mul(prod, a[2], b[1]);
        Ibz.sub(sum[3], sum[3], prod);
        Ibz.mul(prod, a[1], b[2]);
        Ibz.add(sum[3], sum[3], prod);

        IbzVec.copy4(res, sum);
    }

    /**
     * {@code quat_alg_conj}: conjugate negates the i, j, ij components.
     */
    public static void conj(Elem conj, Elem x)
    {
        Ibz.copy(conj.denom, x.denom);
        Ibz.copy(conj.coord[0], x.coord[0]);
        Ibz.neg(conj.coord[1], x.coord[1]);
        Ibz.neg(conj.coord[2], x.coord[2]);
        Ibz.neg(conj.coord[3], x.coord[3]);
    }

    /**
     * {@code quat_alg_norm}: norm of the quaternion = x * conj(x). The result
     * is the real coordinate of x * conj(x); the imaginary coords are always
     * zero. The result is returned as a reduced rational (numerator,
     * denominator), both non-negative.
     */
    public static void norm(Ibz resNum, Ibz resDenom, Elem x, QuatAlg alg)
    {
        Elem c = new Elem();
        Elem n = new Elem();
        conj(c, x);
        mul(n, x, c, alg);

        Ibz g = new Ibz();
        Ibz r = new Ibz();
        Ibz.gcd(g, n.coord[0], n.denom);
        Ibz.div(resNum, r, n.coord[0], g);
        Ibz.div(resDenom, r, n.denom, g);
        Ibz.abs(resDenom, resDenom);
        Ibz.abs(resNum, resNum);
    }

    /**
     * {@code quat_alg_normalize}: reduce to lowest terms and ensure positive
     * denominator.
     */
    public static void normalize(Elem x)
    {
        Ibz gcd = new Ibz();
        Ibz r = new Ibz();
        IbzVec.content4(gcd, x.coord);
        Ibz.gcd(gcd, gcd, x.denom);

        if (Ibz.isZero(gcd) == 1)
        {
            // Degenerate (all-zero coord and zero denom shouldn't occur)
            return;
        }
        Ibz.div(x.denom, r, x.denom, gcd);
        IbzVec.scalarDiv4(x.coord, gcd, x.coord);

        // Ensure positive denominator: if denom < 0, negate both denom and coords.
        if (Ibz.cmp(x.denom, Ibz.ZERO) < 0)
        {
            Ibz.neg(x.denom, x.denom);
            IbzVec.negate4(x.coord, x.coord);
        }
    }

    /**
     * {@code quat_alg_make_primitive}: write {@code x} as {@code content} times
     * a primitive element of {@code order}, returning that primitive element
     * in {@code primitiveX} (using the order's basis, not the algebra's
     * standard (1,i,j,ij) basis). Mirrors C signature.
     */
    public static void makePrimitive(Ibz[] primitiveX, Ibz content, Elem x, QuatLattice order)
    {
        int ok = QuatLattice.contains(primitiveX, order, x);
        if (ok != 1)
        {
            throw new IllegalStateException("makePrimitive: element not in order");
        }
        IbzVec.content4(content, primitiveX);
        Ibz r = new Ibz();
        for (int i = 0; i < 4; i++)
        {
            Ibz.div(primitiveX[i], r, primitiveX[i], content);
        }
    }
}
