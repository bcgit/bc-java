package org.bouncycastle.crypto.kems.frodo;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Pack;

/**
 * Generation of the public matrix A for the standardised FrodoKEM "SHAKE" parameter sets, using
 * SHAKE128 (ISO/IEC 18033-2 Clause 14.5.8.3). The "AES" matrix-generation variant of FrodoKEM is
 * not assigned an object identifier by the standard and is not provided here.
 */
class FrodoMatrixGenerator
{
    private final int n;
    private final int q;

    FrodoMatrixGenerator(int n, int q)
    {
        this.n = n;
        this.q = q;
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

            // 2. c_{i,0} || ... || c_{i,n-1} = SHAKE128(b, 16n), each c_{i,j} parsed as 16-bit LE
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
