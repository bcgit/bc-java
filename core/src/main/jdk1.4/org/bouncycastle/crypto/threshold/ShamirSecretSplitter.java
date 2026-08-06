package org.bouncycastle.crypto.threshold;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;


public class ShamirSecretSplitter
    implements SecretSplitter
{
    static final int _AES = 0;
    static final int _RSA = 1;

    public static class Algorithm
    {
        public static final Algorithm AES = new Algorithm(_AES);
        public static final Algorithm RSA = new Algorithm(_RSA);

        int ord;

        private Algorithm(int ord)
        {
            this.ord = ord;
        }
    }

    static final int _Native = 0;
    static final int _Table = 1;

    /**
     * The GF(256) arithmetic to use.
     *
     * @deprecated no longer selects anything. Mode.Table indexed log/exp tables with the secret being
     * split and with the share bytes, so which cache line it touched revealed them; both values now
     * use the same constant-time arithmetic. Use {@link #getInstance(Algorithm, int, SecureRandom)},
     * which takes no mode.
     */
    @Deprecated
    public static class Mode
    {
        public static final Mode Native = new Mode(_Native);
        public static final Mode Table = new Mode(_Table);

        int ord;

        private Mode(int ord)
        {
            this.ord = ord;
        }
    }

    private final Polynomial poly;
    /**
     * Length of the secret
     */
    protected int l;

    protected SecureRandom random;

    /**
     * Create a splitter using constant-time GF(256) arithmetic.
     *
     * @param algorithm the reduction polynomial to work over.
     * @param l length in bytes of the secret to be split.
     * @param random source of randomness for the polynomial coefficients.
     */
    public static ShamirSecretSplitter getInstance(Algorithm algorithm, int l, SecureRandom random)
    {
        return new ShamirSecretSplitter(algorithm, l, random);
    }

    /**
     * @deprecated the mode is ignored - see {@link Mode}. Use
     * {@link #getInstance(Algorithm, int, SecureRandom)}.
     */
    @Deprecated
    public ShamirSecretSplitter(Algorithm algorithm, Mode mode, int l, SecureRandom random)
    {
        this(algorithm, l, random);
    }

    private ShamirSecretSplitter(Algorithm algorithm, int l, SecureRandom random)
    {
        if (l < 0 || l > 65534)
        {
            throw new IllegalArgumentException("Invalid input: l ranges from 0 to 65534 (2^16-2) bytes.");
        }

        poly = new Polynomial(algorithm);
        this.l = l;
        this.random = random;
    }


    public SplitSecret split(int m, int n)
    {
        byte[][] p = initP(m, n);
        byte[][] sr = new byte[m][l];
        ShamirSplitSecretShare[] secretShares = new ShamirSplitSecretShare[n];
        int i;
        for (i = 0; i < m; i++)
        {
            random.nextBytes(sr[i]);
        }
        for (i = 0; i < p.length; i++)
        {
            secretShares[i] = new ShamirSplitSecretShare(poly.gfVecMul(p[i], sr), i + 1);
        }
        return new ShamirSplitSecret(poly, secretShares);
    }

    @Override
    public SplitSecret splitAround(SecretShare s, int m, int n)
        throws IOException
    {
        byte[][] p = initP(m, n);
        byte[][] sr = new byte[m][l];
        ShamirSplitSecretShare[] secretShares = new ShamirSplitSecretShare[n];
        byte[] ss0 = s.getEncoded();
        if (ss0.length != l)
        {
            throw new IllegalArgumentException("Invalid input: the secret share must be l bytes long.");
        }
        secretShares[0] = new ShamirSplitSecretShare(ss0, 1);
        int i, j;
        byte tmp;
        for (i = 0; i < m; i++)
        {
            random.nextBytes(sr[i]);
        }
        // the share at x = 1 is the XOR of every coefficient row, so sr[0] is chosen to make it come
        // out as the supplied share - with m == 1 there are no other rows and sr[0] is that share
        for (i = 0; i < l; i++)
        {
            tmp = ss0[i];
            for (j = 1; j < m; j++)
            {
                tmp ^= sr[j][i];
            }
            sr[0][i] = tmp;
        }
        for (i = 1; i < p.length; i++)
        {
            secretShares[i] = new ShamirSplitSecretShare(poly.gfVecMul(p[i], sr), i + 1);
        }

        return new ShamirSplitSecret(poly, secretShares);
    }

    @Override
    public SplitSecret resplit(byte[] secret, int m, int n)
    {
        if (secret.length != l)
        {
            throw new IllegalArgumentException("Invalid input: the secret must be l bytes long.");
        }

        byte[][] p = initP(m, n);
        byte[][] sr = new byte[m][l];
        ShamirSplitSecretShare[] secretShares = new ShamirSplitSecretShare[n];
        sr[0] = Arrays.clone(secret);
        int i;
        for (i = 1; i < m; i++)
        {
            random.nextBytes(sr[i]);
        }
        for (i = 0; i < p.length; i++)
        {
            secretShares[i] = new ShamirSplitSecretShare(poly.gfVecMul(p[i], sr), i + 1);
        }
        return new ShamirSplitSecret(poly, secretShares);
    }

    private byte[][] initP(int m, int n)
    {
        if (m < 1 || m > 255)
        {
            throw new IllegalArgumentException("Invalid input: m must be less than 256 and positive.");
        }
        if (n < m || n > 255)
        {
            throw new IllegalArgumentException("Invalid input: n must be less than 256 and greater than or equal to m.");
        }
        byte[][] p = new byte[n][m];
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < m; j++)
            {
                p[i][j] = poly.gfPow((byte)(i + 1), (byte)j);
            }
        }
        return p;
    }
}
