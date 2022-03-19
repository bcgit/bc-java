package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Pack;

abstract class FrodoMatrixGenerator
{
    int n;
    int q;

    public FrodoMatrixGenerator(int n, int q)
    {
        this.n = n;
        this.q = q;
    }

    abstract short[] genMatrix(byte[] seedA);

    static class Shake128MatrixGenerator
            extends FrodoMatrixGenerator
    {
        public Shake128MatrixGenerator(int n, int q)
        {
            super(n, q);
        }

        short[] genMatrix(byte[] seedA)
        {
            short[] A = new short[n*n];
            short i, j;
            byte[] b, tmp = new byte[(16 * n) / 8];
            for (i = 0; i < n; i++)
            {
                // 1. b = i || seedA in {0,1}^{16 + len_seedA}, where i is encoded as a 16-bit integer in little-endian byte order
                b = Arrays.concatenate(Pack.shortToLittleEndian(i), seedA);

                // 2. c_{i,0} || c_{i,1} || ... || c_{i,n-1} = SHAKE128(b, 16n) (length in bits) where each c_{i,j} is parsed as a 16-bit integer in little-endian byte order format
                Xof digest = new SHAKEDigest(128);
                digest.update(b, 0, b.length);
                digest.doFinal(tmp, 0, tmp.length);
                for (j = 0; j < n; j++)
                {
                    A[i*n+j] = (short) (Pack.littleEndianToShort(tmp, 2 * j) % q);
                }
            }
            return A;
        }

    }
    static class Aes128MatrixGenerator
            extends FrodoMatrixGenerator
    {
        BufferedBlockCipher cipher;
        public Aes128MatrixGenerator(int n, int q)
        {
            super(n, q);
            cipher = new BufferedBlockCipher(new AESEngine());

        }

        short[] genMatrix(byte[] seedA)
        {
            //        """Generate matrix A using AES-128 (FrodoKEM specification, Algorithm 7)"""
            //        A = [[None for j in range(self.n)] for i in range(self.n)]
            short[] A = new short[n*n];
            byte[] b = new byte[16];
            byte[] c = new byte[16];

            // 1. for i = 0; i < n; i += 1
            for (int i = 0; i < n; i++)
            {
                // 2. for j = 0; j < n; j += 8
                for (int j = 0; j < n; j+=8)
                {

                    // 3. b = i || j || 0 || ... || 0 in {0,1}^128, where i and j are encoded as 16-bit integers in little-endian byte order
                    System.arraycopy(Pack.shortToLittleEndian((short) (i&0xffff)), 0, b, 0, 2);
                    System.arraycopy(Pack.shortToLittleEndian((short) (j&0xffff)), 0, b, 2, 2);
                    //                b = bytearray(16)
                    //                struct.pack_into('<H', b, 0, i)
                    //                struct.pack_into('<H', b, 2, j)
                    // 4. c = AES128(seedA, b)
                    aes128(c, seedA, b);
                    // 5. for k = 0; k < 8; k += 1
                    for (int k = 0; k < 8; k++)
                    {
                        // 6. A[i][j+k] = c[k] where c is treated as a sequence of 8 16-bit integers each in little-endian byte order
                        A[i*n+ j + k] = (short) (Pack.littleEndianToShort(c, 2 * k) % q);
                    }
                }
            }
            return A;
        }

        void aes128(byte[] out, byte[] keyBytes, byte[] msg)
        {
            try
            {
                KeyParameter kp = new KeyParameter(keyBytes);
                cipher.init(true, kp);
                int len = cipher.processBytes(msg, 0, msg.length, out, 0);
                cipher.doFinal(out, len);
            }
            catch (InvalidCipherTextException e)
            {
                throw Exceptions.illegalStateException(e.toString(), e);
            }
        }
    }
}
