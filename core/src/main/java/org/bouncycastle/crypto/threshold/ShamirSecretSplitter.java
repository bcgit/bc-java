package org.bouncycastle.crypto.threshold;

import java.io.IOException;
import java.security.SecureRandom;

public class ShamirSecretSplitter
    implements SecretSplitter
{
    public enum Algorithm
    {
        AES,
        RSA
    }

    public enum Mode
    {
        Native,
        Table
    }

    private final Polynomial poly;
    /**
     * Length of the secret
     */
    protected int l;
    /**
     * A threshold number of shares
     */
    protected int m;
    /**
     * Total number of shares
     * m <= n <= 255
     */
    protected int n;
    protected byte[][] p;
    protected SecureRandom random;

    public ShamirSecretSplitter(Algorithm algorithm, Mode mode, int l, int m, int n, SecureRandom random)
    {
        if (l < 0 || l > 65534)
        {
            throw new IllegalArgumentException("Invalid input: l ranges from 0 to 65534 (2^16-2) bytes.");
        }
        if (m < 1 || m > 255)
        {
            throw new IllegalArgumentException("Invalid input: m must be less than 256 and positive.");
        }
        if (n < m || n > 255)
        {
            throw new IllegalArgumentException("Invalid input: n must be less than 256 and greater than or equal to n.");
        }
        poly = Polynomial.newInstance(algorithm, mode);
        this.l = l;
        this.m = m;
        this.n = n;
        this.random = random;
        p = new byte[n][m];
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < m; j++)
            {
                p[i][j] = poly.gfPow((byte)(i + 1), (byte)j);
            }
        }
    }

    public ShamirSplitSecret split()
    {
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
    public ShamirSplitSecret splitAround(SecretShare s)
        throws IOException
    {
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
}
