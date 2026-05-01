package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

abstract class FrodoMatrixGenerator
{
    final int n;
    final int q;

    FrodoMatrixGenerator(int n, int q)
    {
        this.n = n;
        this.q = q;
    }

    abstract short[] genMatrix(byte[] seed, int seedOff, int seedLen);

    static class Shake128MatrixGenerator extends FrodoMatrixGenerator
    {
        public Shake128MatrixGenerator(int n, int q)
        {
            super(n, q);
        }

        short[] genMatrix(byte[] seed, int seedOff, int seedLen)
        {
            short[] A = new short[n * n];
            byte[] tmp = new byte[(16 * n) / 8];
            byte[] b = new byte[2 + seedLen];
            System.arraycopy(seed, seedOff, b, 2, seedLen);

            SHAKEDigest digest = new SHAKEDigest(128);

            for (int i = 0; i < n; i++)
            {
                // 1. b = i || seedA in {0,1}^{16 + len_seedA}, where i is encoded as 16-bit LE
                Pack.shortToLittleEndian((short)i, b, 0);

                // 2. c_{i,0} || c_{i,1} || ... || c_{i,n-1} = SHAKE128(b, 16n) (length in bits) where each c_{i,j}
                // is parsed as 16-bit LE
                digest.update(b, 0, b.length);
                digest.doFinal(tmp, 0, tmp.length);

                for (int j = 0; j < n; j++)
                {
                    A[i * n + j] = (short)(Pack.littleEndianToShort(tmp, 2 * j) & (q - 1));
                }
            }
            return A;
        }
    }

    static class Aes128MatrixGenerator extends FrodoMatrixGenerator
    {
        public Aes128MatrixGenerator(int n, int q)
        {
            super(n, q);
        }

        short[] genMatrix(byte[] seed, int seedOff, int seedLen)
        {
            // """Generate matrix A using AES-128 (FrodoKEM specification, Algorithm 7)"""
            // A = [[None for j in range(self.n)] for i in range(self.n)]
            short[] A = new short[n * n];
            byte[] b = new byte[16];
            byte[] c = new byte[16];

            BlockCipher cipher = AESEngine.newInstance();
            cipher.init(true, new KeyParameter(seed, seedOff, seedLen));

            for (int i = 0; i < n; i++)
            {
                Pack.shortToLittleEndian((short)i, b, 0);

                for (int j = 0; j < n; j += 8)
                {
                    // 3. b = i || j || 0 || ... || 0 in {0,1}^128, where i and j are encoded as 16-bit LE
                    Pack.shortToLittleEndian((short)j, b, 2);
                    // 4. c = AES128(seedA, b)
                    cipher.processBlock(b, 0, c, 0);

                    for (int k = 0; k < 8; k++)
                    {
                        // 6. A[i][j+k] = c[k] where c is treated as a sequence of 8 16-bit LE
                        A[i * n + j + k] = (short)(Pack.littleEndianToShort(c, 2 * k) & (q - 1));
                    }
                }
            }
            return A;
        }
    }
}
