package org.bouncycastle.crypto.kems.mlkem;

class PolyVec
{
    final Poly[] vec;

    PolyVec(int K)
    {
        this.vec = new Poly[K];
        for (int i = 0; i < K; i++)
        {
            vec[i] = new Poly();
        }
    }

    Poly getVectorIndex(int i)
    {
        return vec[i];
    }

    void polyVecNtt()
    {
        for (int i = 0; i < vec.length; i++)
        {
            vec[i].polyNtt();
        }
    }

    void polyVecInverseNttToMont()
    {
        for (int i = 0; i < vec.length; i++)
        {
            vec[i].polyInverseNttToMont();
        }
    }

    void compressPolyVec(byte[] rBuf, int rOff)
    {
        int pos = rOff;

        condSubQ();

        if (vec.length == 4)
        {
            // PolyVecCompressedBytes == K * 352

            short[] t = new short[8];
            for (int i = 0; i < vec.length; i++)
            {
                for (int j = 0; j < MLKEMEngine.N / 8; j++)
                {
                    for (int k = 0; k < 8; k++)
                    {
                        /*t[k] = (short)
                            (
                                (
                                    ((this.getVectorIndex(i).getCoeffIndex(8 * j + k) << 11)
                                        + (KyberEngine.KyberQ / 2))
                                        / KyberEngine.KyberQ)
                                    & 0x7ff);*/
                        // Fix for KyberSlash2: division by KyberQ above is not
                        // constant time.
                        long t_k = vec[i].getCoeffIndex(8 * j + k);
                        t_k <<= 11;
                        t_k += 1664;
                        t_k *= 645084;
                        t_k >>= 31;
                        t_k &= 0x7ff;
                        t[k] = (short)t_k;
                    }
                    rBuf[pos + 0] = (byte)((t[0] >> 0));
                    rBuf[pos + 1] = (byte)((t[0] >> 8) | (t[1] << 3));
                    rBuf[pos + 2] = (byte)((t[1] >> 5) | (t[2] << 6));
                    rBuf[pos + 3] = (byte)((t[2] >> 2));
                    rBuf[pos + 4] = (byte)((t[2] >> 10) | (t[3] << 1));
                    rBuf[pos + 5] = (byte)((t[3] >> 7) | (t[4] << 4));
                    rBuf[pos + 6] = (byte)((t[4] >> 4) | (t[5] << 7));
                    rBuf[pos + 7] = (byte)((t[5] >> 1));
                    rBuf[pos + 8] = (byte)((t[5] >> 9) | (t[6] << 2));
                    rBuf[pos + 9] = (byte)((t[6] >> 6) | (t[7] << 5));
                    rBuf[pos + 10] = (byte)((t[7] >> 3));
                    pos += 11;
                }
            }
        }
        else
        {
            // PolyVecCompressedBytes == K * 320

            short[] t = new short[4];
            for (int i = 0; i < vec.length; i++)
            {
                for (int j = 0; j < MLKEMEngine.N / 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        /*t[k] = (short)
                            (
                                (
                                    ((this.getVectorIndex(i).getCoeffIndex(4 * j + k) << 10)
                                        + (KyberEngine.KyberQ / 2))
                                        / KyberEngine.KyberQ)
                                    & 0x3ff);*/
                        // Fix for KyberSlash2: division by KyberQ above is not
                        // constant time.
                        long t_k = vec[i].getCoeffIndex(4 * j + k);
                        t_k <<= 10;
                        t_k += 1665;
                        t_k *= 1290167;
                        t_k >>= 32;
                        t_k &= 0x3ff;
                        t[k] = (short)t_k;
                    }
                    rBuf[pos + 0] = (byte)(t[0] >> 0);
                    rBuf[pos + 1] = (byte)((t[0] >> 8) | (t[1] << 2));
                    rBuf[pos + 2] = (byte)((t[1] >> 6) | (t[2] << 4));
                    rBuf[pos + 3] = (byte)((t[2] >> 4) | (t[3] << 6));
                    rBuf[pos + 4] = (byte)((t[3] >> 2));
                    pos += 5;
                }
            }
        }
    }

    void decompressPolyVec(byte[] cBuf, int cOff)
    {
        int pos = cOff;

        if (vec.length == 4)
        {
            // PolyVecCompressedBytes == K * 352
            
            short[] t = new short[8];
            for (int i = 0; i < vec.length; i++)
            {
                for (int j = 0; j < MLKEMEngine.N / 8; j++)
                {
                    t[0] = (short)(((cBuf[pos] & 0xFF) >> 0) | ((short)(cBuf[pos + 1] & 0xFF) << 8));
                    t[1] = (short)(((cBuf[pos + 1] & 0xFF) >> 3) | ((short)(cBuf[pos + 2] & 0xFF) << 5));
                    t[2] = (short)(((cBuf[pos + 2] & 0xFF) >> 6) | ((short)(cBuf[pos + 3] & 0xFF) << 2) | ((short)((cBuf[pos + 4] & 0xFF) << 10)));
                    t[3] = (short)(((cBuf[pos + 4] & 0xFF) >> 1) | ((short)(cBuf[pos + 5] & 0xFF) << 7));
                    t[4] = (short)(((cBuf[pos + 5] & 0xFF) >> 4) | ((short)(cBuf[pos + 6] & 0xFF) << 4));
                    t[5] = (short)(((cBuf[pos + 6] & 0xFF) >> 7) | ((short)(cBuf[pos + 7] & 0xFF) << 1) | ((short)((cBuf[pos + 8] & 0xFF) << 9)));
                    t[6] = (short)(((cBuf[pos + 8] & 0xFF) >> 2) | ((short)(cBuf[pos + 9] & 0xFF) << 6));
                    t[7] = (short)(((cBuf[pos + 9] & 0xFF) >> 5) | ((short)(cBuf[pos + 10] & 0xFF) << 3));
                    pos += 11;
                    for (int k = 0; k < 8; k++)
                    {
                        this.vec[i].setCoeffIndex(8 * j + k, (short)(((t[k] & 0x7FF) * MLKEMEngine.Q + 1024) >> 11));
                    }
                }
            }
        }
        else
        {
            // PolyVecCompressedBytes == K * 320

            short[] t = new short[4];
            for (int i = 0; i < vec.length; i++)
            {
                for (int j = 0; j < MLKEMEngine.N / 4; j++)
                {
                    t[0] = (short)(((cBuf[pos] & 0xFF) >> 0) | (short)((cBuf[pos + 1] & 0xFF) << 8));
                    t[1] = (short)(((cBuf[pos + 1] & 0xFF) >> 2) | (short)((cBuf[pos + 2] & 0xFF) << 6));
                    t[2] = (short)(((cBuf[pos + 2] & 0xFF) >> 4) | (short)((cBuf[pos + 3] & 0xFF) << 4));
                    t[3] = (short)(((cBuf[pos + 3] & 0xFF) >> 6) | (short)((cBuf[pos + 4] & 0xFF) << 2));
                    pos += 5;
                    for (int k = 0; k < 4; k++)
                    {
                        this.vec[i].setCoeffIndex(4 * j + k, (short)(((t[k] & 0x3FF) * MLKEMEngine.Q + 512) >> 10));
                    }
                }
            }
        }
    }

    static void pointwiseAccountMontgomery(Poly out, PolyVec inp1, PolyVec inp2, MLKEMEngine engine)
    {
        int k = engine.getK();
        // Decoded coefficients fit 12 bits, and the second operand is reduced after its NTT.
        // At K <= 4 the diagonal sums are <= 54529020 and the cross sum is <= 109058040.
        short[] a0 = inp1.vec[0].getCoeffs(), b0 = inp2.vec[0].getCoeffs();
        short[] a1 = inp1.vec[1].getCoeffs(), b1 = inp2.vec[1].getCoeffs();
        short[] a2 = k >= 3 ? inp1.vec[2].getCoeffs() : null;
        short[] b2 = k >= 3 ? inp2.vec[2].getCoeffs() : null;
        short[] a3 = k == 4 ? inp1.vec[3].getCoeffs() : null;
        short[] b3 = k == 4 ? inp2.vec[3].getCoeffs() : null;
        for (int j = 0; j < MLKEMEngine.N; j += 2)
        {
            int next = j + 1;
            int a00 = a0[j] * b0[j] + a1[j] * b1[j];
            int a11 = a0[next] * b0[next] + a1[next] * b1[next];
            int cross = a0[j] * b0[next] + a0[next] * b0[j]
                + a1[j] * b1[next] + a1[next] * b1[j];
            if (k >= 3)
            {
                a00 += a2[j] * b2[j];
                a11 += a2[next] * b2[next];
                cross += a2[j] * b2[next] + a2[next] * b2[j];
            }
            if (k == 4)
            {
                a00 += a3[j] * b3[j];
                a11 += a3[next] * b3[next];
                cross += a3[j] * b3[next] + a3[next] * b3[j];
            }
            int zeta = Ntt.ZETAS[64 + (j >> 2)];
            if ((j & 2) != 0)
            {
                zeta = -zeta;
            }
            int v = Reduce.montgomeryReduce(a11);
            int even = Reduce.montgomeryReduce(a00 + zeta * v);
            int odd = Reduce.montgomeryReduce(cross);
            out.setCoeffIndex(j, Reduce.barrettReduce((short)even));
            out.setCoeffIndex(j + 1, Reduce.barrettReduce((short)odd));
        }
    }

    void reducePoly()
    {
        for (int i = 0; i < vec.length; i++)
        {
            vec[i].reduce();
        }
    }

    void addPoly(PolyVec b)
    {
        for (int i = 0; i < vec.length; i++)
        {
            vec[i].add(b.vec[i]);
        }
    }

    void toBytes(byte[] buf, int off)
    {
        for (int i = 0; i < vec.length; i++)
        {
            vec[i].toBytes(buf, off + i * MLKEMEngine.PolyBytes);
        }
    }

    void fromBytes(byte[] buf, int off)
    {
        for (int i = 0; i < vec.length; i++)
        {
            vec[i].fromBytes(buf, off + i * MLKEMEngine.PolyBytes);
        }
    }

    private void condSubQ()
    {
        for (int i = 0; i < vec.length; i++)
        {
            vec[i].condSubQ();
        }
    }

    static int checkModulus(MLKEMEngine engine, byte[] inputBytes)
    {
        int result = -1;
        for (int i = 0, k = engine.getK(); i < k; i++)
        {
            result &= Poly.checkModulus(inputBytes, i * MLKEMEngine.PolyBytes);
        }
        return result;
    }
}
