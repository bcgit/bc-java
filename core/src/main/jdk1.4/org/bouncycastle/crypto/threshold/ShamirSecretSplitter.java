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

    public ShamirSecretSplitter(Algorithm algorithm, Mode mode, int l, SecureRandom random)
    {
        if (l < 0 || l > 65534)
        {
            throw new IllegalArgumentException("Invalid input: l ranges from 0 to 65534 (2^16-2) bytes.");
        }

        poly = Polynomial.newInstance(algorithm, mode);
        this.l = l;
        this.random = random;
    }


    public SplitSecret split(int m, int n)
    {
        byte[][] p = initP(m, n);
        byte[][] sr = new byte[m][l];
        ShamirSplitSecretShare[] secretShares = new ShamirSplitSecretShare[l];
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
        ShamirSplitSecretShare[] secretShares = new ShamirSplitSecretShare[l];
        byte[] ss0 = s.getEncoded();
        secretShares[0] = new ShamirSplitSecretShare(ss0, 1);
        int i, j;
        byte tmp;
        for (i = 0; i < m; i++)
        {
            random.nextBytes(sr[i]);
        }
        for (i = 0; i < l; i++)
        {
            tmp = sr[1][i];
            for (j = 2; j < m; j++)
            {
                tmp ^= sr[j][i];
            }
            sr[0][i] = (byte)(tmp ^ ss0[i]);
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
        byte[][] p = initP(m, n);
        byte[][] sr = new byte[m][l];
        ShamirSplitSecretShare[] secretShares = new ShamirSplitSecretShare[l];
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
            throw new IllegalArgumentException("Invalid input: n must be less than 256 and greater than or equal to n.");
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
