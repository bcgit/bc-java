package org.bouncycastle.pqc.crypto.sqisign;

/**
 * L²-flavoured LLL reduction for 4-dimensional integer lattices, operating on
 * the Gram matrix and basis in place. Java port of
 * {@code src/quaternion/ref/generic/lll/l2.c}.
 *
 * <p>Uses {@link Dpe} (double + exponent) for the floating-point Gram-Schmidt
 * coefficients, matching the C reference's use of the DPE library.</p>
 */
final class Lll
{
    /**
     * Lovász condition threshold (DELTA in classical LLL).
     */
    public static final double DELTABAR = 0.995;
    /**
     * Size-reduction threshold (ETA in classical LLL).
     */
    public static final double ETABAR = 0.505;

    private Lll()
    {
    }

    /**
     * Access an entry of a symmetric matrix: G[max(i,j)][min(i,j)] (lower
     * triangle only). Mirrors the SYM macro in the C reference.
     */
    private static Ibz sym(Ibz[][] m, int i, int j)
    {
        return i < j ? m[j][i] : m[i][j];
    }

    private static void symSwap(Ibz[][] m, int i, int j, int k, int l)
    {
        // Swap m[max(i,j)][min(i,j)] with m[max(k,l)][min(k,l)].
        Ibz a = sym(m, i, j);
        Ibz b = sym(m, k, l);
        BigIntegerSwap(a, b);
    }

    private static void BigIntegerSwap(Ibz a, Ibz b)
    {
        java.math.BigInteger t = a.v;
        a.v = b.v;
        b.v = t;
    }

    /**
     * In-place L² LLL reduction. Both {@code G} (the lower-triangular Gram
     * matrix) and {@code basis} are modified. On exit, {@code basis} is a
     * size-reduced basis satisfying the Lovász condition for {@link #DELTABAR}.
     */
    public static void core(Ibz[][] G, Ibz[][] basis)
    {
        Dpe[][] r = new Dpe[4][4];
        Dpe[][] u = new Dpe[4][4];
        Dpe[] lovasz = new Dpe[4];
        for (int i = 0; i < 4; i++)
        {
            lovasz[i] = new Dpe();
            for (int j = 0; j <= i; j++)
            {
                r[i][j] = new Dpe();
                u[i][j] = new Dpe();
            }
        }
        Dpe deltaBar = new Dpe();
        Dpe.setD(deltaBar, DELTABAR);
        Dpe Xf = new Dpe();
        Dpe tmpF = new Dpe();
        Ibz X = new Ibz();
        Ibz tmpI = new Ibz();

        Dpe.setZ(r[0][0], G[0][0]);
        int kappa = 1;
        while (kappa < 4)
        {
            boolean done = false;
            while (!done)
            {
                // Recompute Choleski row κ.
                for (int j = 0; j <= kappa; j++)
                {
                    Dpe.setZ(r[kappa][j], G[kappa][j]);
                    for (int k = 0; k < j; k++)
                    {
                        Dpe.mul(tmpF, r[kappa][k], u[j][k]);
                        Dpe.sub(r[kappa][j], r[kappa][j], tmpF);
                    }
                    if (j < kappa)
                    {
                        Dpe.div(u[kappa][j], r[kappa][j], r[j][j]);
                    }
                }

                done = true;
                for (int i = kappa - 1; i >= 0; i--)
                {
                    if (Dpe.cmpD(u[kappa][i], ETABAR) > 0 || Dpe.cmpD(u[kappa][i], -ETABAR) < 0)
                    {
                        done = false;
                        Dpe.set(Xf, u[kappa][i]);
                        Dpe.round(Xf, Xf);
                        Dpe.getZ(X, Xf);

                        // basis[*][κ] ← basis[*][κ] − X·basis[*][i]
                        for (int jj = 0; jj < 4; jj++)
                        {
                            Ibz.mul(tmpI, X, basis[jj][i]);
                            Ibz.sub(basis[jj][kappa], basis[jj][kappa], tmpI);
                        }
                        // G[κ][κ] -= X·G[κ][i]
                        Ibz.mul(tmpI, X, G[kappa][i]);
                        Ibz.sub(G[kappa][kappa], G[kappa][kappa], tmpI);
                        // For all j: G_sym(κ, j) -= X·G_sym(i, j)
                        for (int jj = 0; jj < 4; jj++)
                        {
                            Ibz.mul(tmpI, X, sym(G, i, jj));
                            Ibz sKj = sym(G, kappa, jj);
                            Ibz.sub(sKj, sKj, tmpI);
                        }
                        // u[κ][j] -= Xf·u[i][j]
                        for (int jj = 0; jj < i; jj++)
                        {
                            Dpe.mul(tmpF, Xf, u[i][jj]);
                            Dpe.sub(u[kappa][jj], u[kappa][jj], tmpF);
                        }
                    }
                }
            }

            // Lovász test
            Dpe.setZ(lovasz[0], G[kappa][kappa]);
            for (int i = 1; i < kappa; i++)
            {
                Dpe.mul(tmpF, u[kappa][i - 1], r[kappa][i - 1]);
                Dpe.sub(lovasz[i], lovasz[i - 1], tmpF);
            }
            int swap;
            for (swap = kappa; swap > 0; swap--)
            {
                Dpe.mul(tmpF, deltaBar, r[swap - 1][swap - 1]);
                if (Dpe.cmp(tmpF, lovasz[swap - 1]) < 0)
                {
                    break;
                }
            }

            if (kappa != swap)
            {
                for (int jj = kappa; jj > swap; jj--)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        BigIntegerSwap(basis[i][jj], basis[i][jj - 1]);
                        if (i == jj - 1)
                        {
                            BigIntegerSwap(G[i][i], G[jj][jj]);
                        }
                        else if (i != jj)
                        {
                            symSwap(G, i, jj, i, jj - 1);
                        }
                    }
                }
                for (int i = 0; i < swap; i++)
                {
                    Dpe.set(u[swap][i], u[kappa][i]);
                    Dpe.set(r[swap][i], r[kappa][i]);
                }
                Dpe.set(r[swap][swap], lovasz[swap]);
                kappa = swap;
            }
            kappa += 1;
        }

        // Fill upper triangle of G from lower.
        for (int i = 0; i < 4; i++)
        {
            for (int j = i + 1; j < 4; j++)
            {
                Ibz.copy(G[i][j], G[j][i]);
            }
        }
    }

}
