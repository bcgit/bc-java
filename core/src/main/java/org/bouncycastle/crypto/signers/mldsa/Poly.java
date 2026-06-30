package org.bouncycastle.crypto.signers.mldsa;

import org.bouncycastle.crypto.digests.SHAKEDigest;

class Poly
{
    private final static int DilithiumN = MLDSAEngine.DilithiumN;

    private final int polyUniformNBlocks;
    private int[] coeffs;
    private final MLDSAEngine engine;

    private final Symmetric symmetric;

    public Poly(MLDSAEngine engine)
    {
        this.coeffs = new int[DilithiumN];
        this.engine = engine;
        this.symmetric = engine.GetSymmetric();
        this.polyUniformNBlocks = (768 + symmetric.stream128BlockBytes - 1) / symmetric.stream128BlockBytes;
    }

    void copyTo(Poly z)
    {
        System.arraycopy(coeffs, 0, z.coeffs, 0, DilithiumN);
    }

    public int getCoeffIndex(int i)
    {
        return this.coeffs[i];
    }

    public int[] getCoeffs()
    {
        return this.coeffs;
    }

    public void setCoeffIndex(int i, int val)
    {
        this.coeffs[i] = val;
    }

    public void setCoeffs(int[] coeffs)
    {
        this.coeffs = coeffs;
    }

    public void uniformBlocks(byte[] seed, short nonce)
    {
        int i, ctr, off,
            buflen = polyUniformNBlocks * symmetric.stream128BlockBytes;
        byte[] buf = new byte[buflen + 2];

        symmetric.stream128init(seed, nonce);

        symmetric.stream128squeezeBlocks(buf, 0, buflen);

        ctr = rejectUniform(this, 0, DilithiumN, buf, buflen);

        // ctr can be less than N

        while (ctr < DilithiumN)
        {
            off = buflen % 3;
            for (i = 0; i < off; ++i)
            {
                buf[i] = buf[buflen - off + i];
            }
            symmetric.stream128squeezeBlocks(buf, off, symmetric.stream128BlockBytes);
            buflen = symmetric.stream128BlockBytes + off;
            ctr += rejectUniform(this, ctr, DilithiumN - ctr, buf, buflen);
        }

    }

    private static int rejectUniform(Poly outputPoly, int coeffOff, int len, byte[] inpBuf, int buflen)
    {
        int[] outCoeffs = outputPoly.coeffs;
        int ctr = 0, pos = 0;
        int t;

        while (ctr < len && pos + 3 <= buflen)
        {
            t = (inpBuf[pos++] & 0xFF);
            t |= (inpBuf[pos++] & 0xFF) << 8;
            t |= (inpBuf[pos++] & 0xFF) << 16;
            t &= 0x7FFFFF;

            if (t < MLDSAEngine.DilithiumQ)
            {
                outCoeffs[coeffOff + ctr] = t;
                ctr++;
            }
        }

        return ctr;
    }

    public void uniformEta(byte[] seed, short nonce)
    {
        int ctr, polyUniformEtaNBlocks, eta = engine.getDilithiumEta();

        if (engine.getDilithiumEta() == 2)
        {
            polyUniformEtaNBlocks = ((136 + symmetric.stream256BlockBytes - 1) / symmetric.stream256BlockBytes); // TODO: change with class
        }
        else if (engine.getDilithiumEta() == 4)
        {
            polyUniformEtaNBlocks = ((227 + symmetric.stream256BlockBytes - 1) / symmetric.stream256BlockBytes); // TODO: change with class
        }
        else
        {
            throw new RuntimeException("Wrong Dilithium Eta!");
        }

        int buflen = polyUniformEtaNBlocks * symmetric.stream256BlockBytes;

        byte[] buf = new byte[buflen];

        symmetric.stream256init(seed, nonce);
        symmetric.stream256squeezeBlocks(buf, 0, buflen);

        ctr = rejectEta(this, 0, DilithiumN, buf, buflen, eta);

        while (ctr < MLDSAEngine.DilithiumN)
        {
            symmetric.stream256squeezeBlocks(buf, 0, symmetric.stream256BlockBytes);
            ctr += rejectEta(this, ctr, DilithiumN - ctr, buf, symmetric.stream256BlockBytes, eta);
        }

    }

    // Constant-time note: rejection sampling of the secret s1/s2. Acceptance branches and the
    // number of bytes/SHAKE blocks consumed depend on the secret seed, but only the reject COUNT
    // between accepts leaks — never an accepted coefficient value. Matches reference rej_eta;
    // accepted by FIPS 204's side-channel model. See MLDSAEngine class javadoc.
    private static int rejectEta(Poly outputPoly, int coeffOff, int len, byte[] buf, int buflen, int eta)
    {
        int[] outCoeffs = outputPoly.coeffs;
        int ctr = 0, pos = 0;
        int t0, t1;

        while (ctr < len && pos < buflen)
        {
            t0 = (buf[pos] & 0xFF) & 0x0F;
            t1 = (buf[pos++] & 0xFF) >> 4;
            if (eta == 2)
            {
                if (t0 < 15)
                {
                    t0 = t0 - (205 * t0 >> 10) * 5;
                    outCoeffs[coeffOff + ctr] = 2 - t0;
                    ctr++;
                }
                if (t1 < 15 && ctr < len)
                {
                    t1 = t1 - (205 * t1 >> 10) * 5;
                    outCoeffs[coeffOff + ctr] = 2 - t1;
                    ctr++;
                }
            }
            else if (eta == 4)
            {
                if (t0 < 9)
                {
                    outCoeffs[coeffOff + ctr] = 4 - t0;
                    ctr++;
                }
                if (t1 < 9 && ctr < len)
                {
                    outCoeffs[coeffOff + ctr] = 4 - t1;
                    ctr++;
                }
            }
        }
        return ctr;
    }

    public void polyNtt()
    {
        Ntt.ntt(this.coeffs);
    }

    public void pointwiseMontgomery(Poly v, Poly w)
    {
        int[] thisCoeffs = this.coeffs;
        int[] vCoeffs = v.coeffs;
        int[] wCoeffs = w.coeffs;
        for (int i = 0; i < DilithiumN; ++i)
        {
            thisCoeffs[i] = Reduce.montgomeryReduce((long)vCoeffs[i] * (long)wCoeffs[i]);
        }
    }

    public void pointwiseAccountMontgomery(PolyVec u, PolyVec v)
    {
        int[] thisCoeffs = this.coeffs;
        int L = engine.getDilithiumL();

        int[] u0 = u.getVectorIndex(0).coeffs;
        int[] v0 = v.getVectorIndex(0).coeffs;
        for (int k = 0; k < DilithiumN; ++k)
        {
            thisCoeffs[k] = Reduce.montgomeryReduce((long)u0[k] * (long)v0[k]);
        }

        for (int i = 1; i < L; ++i)
        {
            int[] ui = u.getVectorIndex(i).coeffs;
            int[] vi = v.getVectorIndex(i).coeffs;
            for (int k = 0; k < DilithiumN; ++k)
            {
                thisCoeffs[k] += Reduce.montgomeryReduce((long)ui[k] * (long)vi[k]);
            }
        }
    }

    public void addPoly(Poly a)
    {
        int[] thisCoeffs = this.coeffs;
        int[] aCoeffs = a.coeffs;
        for (int i = 0; i < DilithiumN; i++)
        {
            thisCoeffs[i] += aCoeffs[i];
        }
    }


    public void reduce()
    {
        int[] thisCoeffs = this.coeffs;
        for (int i = 0; i < DilithiumN; ++i)
        {
            thisCoeffs[i] = Reduce.reduce32(thisCoeffs[i]);
        }
    }

    public void invNttToMont()
    {
        Ntt.invNttToMont(this.coeffs);
    }

    public void conditionalAddQ()
    {
        int[] thisCoeffs = this.coeffs;
        for (int i = 0; i < DilithiumN; ++i)
        {
            thisCoeffs[i] = Reduce.conditionalAddQ(thisCoeffs[i]);
        }
    }

    public void power2Round(Poly a)
    {
        Rounding.power2RoundAll(this.coeffs, a.coeffs);
    }

    public byte[] polyt1Pack()
    {
        byte[] out = new byte[MLDSAEngine.DilithiumPolyT1PackedBytes];

        for (int i = 0; i < DilithiumN / 4; ++i)
        {
            out[5 * i + 0] = (byte)(this.coeffs[4 * i + 0] >> 0);
            out[5 * i + 1] = (byte)((this.coeffs[4 * i + 0] >> 8) | (this.coeffs[4 * i + 1] << 2));
            out[5 * i + 2] = (byte)((this.coeffs[4 * i + 1] >> 6) | (this.coeffs[4 * i + 2] << 4));
            out[5 * i + 3] = (byte)((this.coeffs[4 * i + 2] >> 4) | (this.coeffs[4 * i + 3] << 6));
            out[5 * i + 4] = (byte)(this.coeffs[4 * i + 3] >> 2);
        }
        return out;
    }

    public void polyt1Unpack(byte[] a)
    {
        int[] c = this.coeffs;
        for (int i = 0; i < DilithiumN / 4; ++i)
        {
            c[4 * i + 0] = (((a[5 * i + 0] & 0xFF) >> 0) | ((a[5 * i + 1] & 0xFF) << 8)) & 0x3FF;
            c[4 * i + 1] = (((a[5 * i + 1] & 0xFF) >> 2) | ((a[5 * i + 2] & 0xFF) << 6)) & 0x3FF;
            c[4 * i + 2] = (((a[5 * i + 2] & 0xFF) >> 4) | ((a[5 * i + 3] & 0xFF) << 4)) & 0x3FF;
            c[4 * i + 3] = (((a[5 * i + 3] & 0xFF) >> 6) | ((a[5 * i + 4] & 0xFF) << 2)) & 0x3FF;
        }
    }

    public byte[] polyEtaPack(byte[] out, int outOff)
    {
        int[] c = this.coeffs;
        int eta = engine.getDilithiumEta();
        byte[] t = new byte[8];

        if (eta == 2)
        {
            for (int i = 0; i < DilithiumN / 8; ++i)
            {
                t[0] = (byte)(eta - c[8 * i + 0]);
                t[1] = (byte)(eta - c[8 * i + 1]);
                t[2] = (byte)(eta - c[8 * i + 2]);
                t[3] = (byte)(eta - c[8 * i + 3]);
                t[4] = (byte)(eta - c[8 * i + 4]);
                t[5] = (byte)(eta - c[8 * i + 5]);
                t[6] = (byte)(eta - c[8 * i + 6]);
                t[7] = (byte)(eta - c[8 * i + 7]);

                out[outOff + 3 * i + 0] = (byte)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
                out[outOff + 3 * i + 1] = (byte)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
                out[outOff + 3 * i + 2] = (byte)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
            }
        }
        else if (eta == 4)
        {
            for (int i = 0; i < DilithiumN / 2; ++i)
            {
                t[0] = (byte)(eta - c[2 * i + 0]);
                t[1] = (byte)(eta - c[2 * i + 1]);
                out[outOff + i] = (byte)(t[0] | t[1] << 4);
            }
        }
        else
        {
            throw new RuntimeException("Eta needs to be 2 or 4!");
        }
        return out;
    }

    public void polyEtaUnpack(byte[] a, int aOff)
    {
        int[] c = this.coeffs;
        int eta = engine.getDilithiumEta();

        if (eta == 2)
        {
            for (int i = 0; i < DilithiumN / 8; ++i)
            {
                int base = aOff + 3 * i;
                c[8 * i + 0] = (((a[base + 0] & 0xFF) >> 0)) & 7;
                c[8 * i + 1] = (((a[base + 0] & 0xFF) >> 3)) & 7;
                c[8 * i + 2] = ((a[base + 0] & 0xFF) >> 6) | ((a[base + 1] & 0xFF) << 2) & 7;
                c[8 * i + 3] = (((a[base + 1] & 0xFF) >> 1)) & 7;
                c[8 * i + 4] = (((a[base + 1] & 0xFF) >> 4)) & 7;
                c[8 * i + 5] = ((a[base + 1] & 0xFF) >> 7) | ((a[base + 2] & 0xFF) << 1) & 7;
                c[8 * i + 6] = (((a[base + 2] & 0xFF) >> 2)) & 7;
                c[8 * i + 7] = (((a[base + 2] & 0xFF) >> 5)) & 7;

                c[8 * i + 0] = eta - c[8 * i + 0];
                c[8 * i + 1] = eta - c[8 * i + 1];
                c[8 * i + 2] = eta - c[8 * i + 2];
                c[8 * i + 3] = eta - c[8 * i + 3];
                c[8 * i + 4] = eta - c[8 * i + 4];
                c[8 * i + 5] = eta - c[8 * i + 5];
                c[8 * i + 6] = eta - c[8 * i + 6];
                c[8 * i + 7] = eta - c[8 * i + 7];
            }
        }
        else if (eta == 4)
        {
            for (int i = 0; i < DilithiumN / 2; ++i)
            {
                c[2 * i + 0] = a[aOff + i] & 0x0F;
                c[2 * i + 1] = (a[aOff + i] & 0xFF) >> 4;
                c[2 * i + 0] = eta - c[2 * i + 0];
                c[2 * i + 1] = eta - c[2 * i + 1];
            }
        }
    }

    public byte[] polyt0Pack(byte[] out, int outOff)
    {
        int[] c = this.coeffs;
        int[] t = new int[8];

        for (int i = 0; i < DilithiumN / 8; ++i)
        {
            t[0] = (1 << (MLDSAEngine.DilithiumD - 1)) - c[8 * i + 0];
            t[1] = (1 << (MLDSAEngine.DilithiumD - 1)) - c[8 * i + 1];
            t[2] = (1 << (MLDSAEngine.DilithiumD - 1)) - c[8 * i + 2];
            t[3] = (1 << (MLDSAEngine.DilithiumD - 1)) - c[8 * i + 3];
            t[4] = (1 << (MLDSAEngine.DilithiumD - 1)) - c[8 * i + 4];
            t[5] = (1 << (MLDSAEngine.DilithiumD - 1)) - c[8 * i + 5];
            t[6] = (1 << (MLDSAEngine.DilithiumD - 1)) - c[8 * i + 6];
            t[7] = (1 << (MLDSAEngine.DilithiumD - 1)) - c[8 * i + 7];

            int base = outOff + 13 * i;
            out[base + 0] = (byte)(t[0]);
            out[base + 1] = (byte)(t[0] >> 8);
            out[base + 1] = (byte)(out[base + 1] | (byte)(t[1] << 5));
            out[base + 2] = (byte)(t[1] >> 3);
            out[base + 3] = (byte)(t[1] >> 11);
            out[base + 3] = (byte)(out[base + 3] | (byte)(t[2] << 2));
            out[base + 4] = (byte)(t[2] >> 6);
            out[base + 4] = (byte)(out[base + 4] | (byte)(t[3] << 7));
            out[base + 5] = (byte)(t[3] >> 1);
            out[base + 6] = (byte)(t[3] >> 9);
            out[base + 6] = (byte)(out[base + 6] | (byte)(t[4] << 4));
            out[base + 7] = (byte)(t[4] >> 4);
            out[base + 8] = (byte)(t[4] >> 12);
            out[base + 8] = (byte)(out[base + 8] | (byte)(t[5] << 1));
            out[base + 9] = (byte)(t[5] >> 7);
            out[base + 9] = (byte)(out[base + 9] | (byte)(t[6] << 6));
            out[base + 10] = (byte)(t[6] >> 2);
            out[base + 11] = (byte)(t[6] >> 10);
            out[base + 11] = (byte)(out[base + 11] | (byte)(t[7] << 3));
            out[base + 12] = (byte)(t[7] >> 5);
        }
        return out;
    }

    public void polyt0Unpack(byte[] a, int aOff)
    {
        int[] c = this.coeffs;
        int bias = 1 << (MLDSAEngine.DilithiumD - 1);
        for (int i = 0; i < DilithiumN / 8; ++i)
        {
            int base = aOff + 13 * i;
            c[8 * i + 0] = (
                (a[base + 0] & 0xFF) |
                    ((a[base + 1] & 0xFF) << 8)
                ) & 0x1FFF;
            c[8 * i + 1] = (
                (((a[base + 1] & 0xFF) >> 5) |
                    ((a[base + 2] & 0xFF) << 3)) |
                    ((a[base + 3] & 0xFF) << 11)
                ) & 0x1FFF;
            c[8 * i + 2] = (
                (((a[base + 3] & 0xFF) >> 2) |
                    ((a[base + 4] & 0xFF) << 6))
                ) & 0x1FFF;
            c[8 * i + 3] = (
                (((a[base + 4] & 0xFF) >> 7) |
                    ((a[base + 5] & 0xFF) << 1)) |
                    ((a[base + 6] & 0xFF) << 9)
                ) & 0x1FFF;
            c[8 * i + 4] = (
                (((a[base + 6] & 0xFF) >> 4) |
                    ((a[base + 7] & 0xFF) << 4)) |
                    ((a[base + 8] & 0xFF) << 12)
                ) & 0x1FFF;
            c[8 * i + 5] = (
                (((a[base + 8] & 0xFF) >> 1) |
                    ((a[base + 9] & 0xFF) << 7))
                ) & 0x1FFF;
            c[8 * i + 6] = (
                (((a[base + 9] & 0xFF) >> 6) |
                    ((a[base + 10] & 0xFF) << 2)) |
                    ((a[base + 11] & 0xFF) << 10)
                ) & 0x1FFF;
            c[8 * i + 7] = (
                ((a[base + 11] & 0xFF) >> 3 |
                    ((a[base + 12] & 0xFF) << 5))
                ) & 0x1FFF;

            c[8 * i + 0] = bias - c[8 * i + 0];
            c[8 * i + 1] = bias - c[8 * i + 1];
            c[8 * i + 2] = bias - c[8 * i + 2];
            c[8 * i + 3] = bias - c[8 * i + 3];
            c[8 * i + 4] = bias - c[8 * i + 4];
            c[8 * i + 5] = bias - c[8 * i + 5];
            c[8 * i + 6] = bias - c[8 * i + 6];
            c[8 * i + 7] = bias - c[8 * i + 7];
        }
    }


    public void uniformGamma1(byte[] seed, short nonce)
    {
        byte[] buf = new byte[engine.getPolyUniformGamma1NBlocks() * symmetric.stream256BlockBytes];

        symmetric.stream256init(seed, nonce);
        symmetric.stream256squeezeBlocks(buf, 0, engine.getPolyUniformGamma1NBlocks() * symmetric.stream256BlockBytes);// todo this is final

        this.unpackZ(buf);
    }

    private void unpackZ(byte[] a)
    {
        int[] c = this.coeffs;
        int gamma1 = engine.getDilithiumGamma1();
        if (gamma1 == (1 << 17))
        {
            for (int i = 0; i < DilithiumN / 4; ++i)
            {
                c[4 * i + 0] = (
                    (((a[9 * i + 0] & 0xFF)) |
                        ((a[9 * i + 1] & 0xFF) << 8)) |
                        ((a[9 * i + 2] & 0xFF) << 16)
                    ) & 0x3FFFF;
                c[4 * i + 1] = (
                    (((a[9 * i + 2] & 0xFF) >> 2) |
                        ((a[9 * i + 3] & 0xFF) << 6)) |
                        ((a[9 * i + 4] & 0xFF) << 14)
                    ) & 0x3FFFF;
                c[4 * i + 2] = (
                    (((a[9 * i + 4] & 0xFF) >> 4) |
                        ((a[9 * i + 5] & 0xFF) << 4)) |
                        ((a[9 * i + 6] & 0xFF) << 12)
                    ) & 0x3FFFF;
                c[4 * i + 3] = (
                    (((a[9 * i + 6] & 0xFF) >> 6) |
                        ((a[9 * i + 7] & 0xFF) << 2)) |
                        ((a[9 * i + 8] & 0xFF) << 10)
                    ) & 0x3FFFF;

                c[4 * i + 0] = gamma1 - c[4 * i + 0];
                c[4 * i + 1] = gamma1 - c[4 * i + 1];
                c[4 * i + 2] = gamma1 - c[4 * i + 2];
                c[4 * i + 3] = gamma1 - c[4 * i + 3];
            }
        }
        else if (gamma1 == (1 << 19))
        {
            for (int i = 0; i < DilithiumN / 2; ++i)
            {
                c[2 * i + 0] = (
                    (((a[5 * i + 0] & 0xFF)) |
                        ((a[5 * i + 1] & 0xFF) << 8)) |
                        ((a[5 * i + 2] & 0xFF) << 16)
                    ) & 0xFFFFF;
                c[2 * i + 1] = (
                    (((a[5 * i + 2] & 0xFF) >> 4) |
                        ((a[5 * i + 3] & 0xFF) << 4)) |
                        ((a[5 * i + 4] & 0xFF) << 12)
                    ) & 0xFFFFF;

                c[2 * i + 0] = gamma1 - c[2 * i + 0];
                c[2 * i + 1] = gamma1 - c[2 * i + 1];
            }
        }
        else
        {
            throw new RuntimeException("Wrong Dilithiumn Gamma1!");
        }
    }

    public void decompose(Poly a)
    {
        int[] thisCoeffs = this.coeffs;
        int[] aCoeffs = a.coeffs;
        int gamma2 = engine.getDilithiumGamma2();
        for (int i = 0; i < DilithiumN; ++i)
        {
            long packed = Rounding.decompose(thisCoeffs[i], gamma2);
            aCoeffs[i] = (int)(packed >> 32);
            thisCoeffs[i] = (int)packed;
        }
    }

    void packW1(byte[] r, int rOff)
    {
        int[] c = this.coeffs;
        int gamma2 = engine.getDilithiumGamma2();
        if (gamma2 == (MLDSAEngine.DilithiumQ - 1) / 88)
        {
            for (int i = 0; i < DilithiumN / 4; ++i)
            {
                r[rOff + 3 * i + 0] = (byte)(((byte)c[4 * i + 0]) | (c[4 * i + 1] << 6));
                r[rOff + 3 * i + 1] = (byte)((byte)(c[4 * i + 1] >> 2) | (c[4 * i + 2] << 4));
                r[rOff + 3 * i + 2] = (byte)((byte)(c[4 * i + 2] >> 4) | (c[4 * i + 3] << 2));
            }
        }
        else if (gamma2 == (MLDSAEngine.DilithiumQ - 1) / 32)
        {
            for (int i = 0; i < DilithiumN / 2; ++i)
            {
                r[rOff + i] = (byte)(c[2 * i + 0] | (c[2 * i + 1] << 4));
            }
        }
    }

    // Constant-time note: SampleInBall. The do/while rejection and the c[b] read/write index on
    // a value b derived from the seed — but the seed here is the public commitment hash c~ (part of
    // the signature, recomputed by the verifier), so no secret is involved. The sign assignment is
    // branchless (1 - 2*(signs&1)). Matches reference poly_challenge.
    public void challenge(byte[] seed, int seedOff, int seedLen)
    {
        int[] c = this.coeffs;
        int b = 0, pos;
        long signs;
        byte[] buf = new byte[symmetric.stream256BlockBytes];

        SHAKEDigest shake256Digest = new SHAKEDigest(256);
        shake256Digest.update(seed, seedOff, seedLen);
        shake256Digest.doOutput(buf, 0, symmetric.stream256BlockBytes);

        signs = 0L;
        for (int i = 0; i < 8; ++i)
        {
            signs |= (long)(buf[i] & 0xFF) << 8 * i;
        }

        pos = 8;

        for (int i = 0; i < DilithiumN; ++i)
        {
            c[i] = 0;
        }
        for (int i = DilithiumN - engine.getDilithiumTau(); i < DilithiumN; ++i)
        {
            do
            {
                if (pos >= symmetric.stream256BlockBytes)
                {
                    shake256Digest.doOutput(buf, 0, symmetric.stream256BlockBytes);
                    pos = 0;
                }
                b = (buf[pos++] & 0xFF);
            }
            while (b > i);

            c[i] = c[b];
            c[b] = (int)(1 - 2 * (signs & 1));
            signs = signs >> 1;
        }
    }

    public boolean checkNorm(int B)
    {
        if (B > (MLDSAEngine.DilithiumQ - 1) / 8)
        {
            return true;
        }

        int[] c = this.coeffs;
        for (int i = 0; i < DilithiumN; ++i)
        {
            // Constant-time: abs(ci) is computed branchlessly so a secret coefficient's
            // sign never leaks (FIPS 204 / poly_chknorm). The >= B test below may branch —
            // it only reveals the rejection event, which the abort loop leaks anyway — but
            // the abs above must stay branchless. Do not replace with a ternary or Math.abs.
            int ci = c[i];
            int t = ci >> 31;
            t = ci - (t & 2 * ci);

            if (t >= B)
            {
                return true;
            }
        }
        return false;
    }

    public void subtract(Poly inpPoly)
    {
        int[] thisCoeffs = this.coeffs;
        int[] inCoeffs = inpPoly.coeffs;
        for (int i = 0; i < DilithiumN; ++i)
        {
            thisCoeffs[i] -= inCoeffs[i];
        }
    }

    public int polyMakeHint(Poly a0, Poly a1)
    {
        int[] thisCoeffs = this.coeffs;
        int[] a0Coeffs = a0.coeffs;
        int[] a1Coeffs = a1.coeffs;
        int s = 0;

        for (int i = 0; i < DilithiumN; ++i)
        {
            int h = Rounding.makeHint(a0Coeffs[i], a1Coeffs[i], engine);
            thisCoeffs[i] = h;
            s += h;
        }
        return s;
    }

    public void polyUseHint(Poly a, Poly h)
    {
        int[] thisCoeffs = this.coeffs;
        int[] aCoeffs = a.coeffs;
        int[] hCoeffs = h.coeffs;
        int gamma2 = engine.getDilithiumGamma2();
        for (int i = 0; i < DilithiumN; ++i)
        {
            thisCoeffs[i] = Rounding.useHint(aCoeffs[i], hCoeffs[i], gamma2);
        }
    }

    public void zPack(byte[] z, int zOff)
    {
        int[] c = this.coeffs;
        int gamma1 = engine.getDilithiumGamma1();
        if (gamma1 == (1 << 17))
        {
            for (int i = 0; i < DilithiumN / 4; ++i)
            {
                int t0 = gamma1 - c[4 * i + 0];
                int t1 = gamma1 - c[4 * i + 1];
                int t2 = gamma1 - c[4 * i + 2];
                int t3 = gamma1 - c[4 * i + 3];

                z[zOff + 9 * i + 0] = (byte)t0;
                z[zOff + 9 * i + 1] = (byte)(t0 >> 8);
                z[zOff + 9 * i + 2] = (byte)((byte)(t0 >> 16) | (t1 << 2));
                z[zOff + 9 * i + 3] = (byte)(t1 >> 6);
                z[zOff + 9 * i + 4] = (byte)((byte)(t1 >> 14) | (t2 << 4));
                z[zOff + 9 * i + 5] = (byte)(t2 >> 4);
                z[zOff + 9 * i + 6] = (byte)((byte)(t2 >> 12) | (t3 << 6));
                z[zOff + 9 * i + 7] = (byte)(t3 >> 2);
                z[zOff + 9 * i + 8] = (byte)(t3 >> 10);
            }
        }
        else if (gamma1 == (1 << 19))
        {
            for (int i = 0; i < DilithiumN / 2; ++i)
            {
                int t0 = gamma1 - c[2 * i + 0];
                int t1 = gamma1 - c[2 * i + 1];

                z[zOff + 5 * i + 0] = (byte)t0;
                z[zOff + 5 * i + 1] = (byte)(t0 >> 8);
                z[zOff + 5 * i + 2] = (byte)((byte)(t0 >> 16) | (t1 << 4));
                z[zOff + 5 * i + 3] = (byte)(t1 >> 4);
                z[zOff + 5 * i + 4] = (byte)(t1 >> 12);
            }
        }
        else
        {
            throw new RuntimeException("Wrong Dilithium Gamma1!");
        }
    }

    void zUnpack(byte[] a)
    {
        int[] c = this.coeffs;
        int gamma1 = engine.getDilithiumGamma1();
        if (gamma1 == (1 << 17))
        {
            for (int i = 0; i < DilithiumN / 4; ++i)
            {
                c[4 * i + 0] = (
                    ((a[9 * i + 0] & 0xFF)
                        | ((a[9 * i + 1] & 0xFF) << 8))
                        | ((a[9 * i + 2] & 0xFF) << 16))
                        & 0x3FFFF;

                c[4 * i + 1] = (
                    (((a[9 * i + 2] & 0xFF) >>> 2)
                        | ((a[9 * i + 3] & 0xFF) << 6))
                        | ((a[9 * i + 4] & 0xFF) << 14))
                        & 0x3FFFF;

                c[4 * i + 2] = (
                    (((a[9 * i + 4] & 0xFF) >>> 4)
                        | ((a[9 * i + 5] & 0xFF) << 4))
                        | ((a[9 * i + 6] & 0xFF) << 12))
                        & 0x3FFFF;

                c[4 * i + 3] = (
                    (((a[9 * i + 6] & 0xFF) >>> 6)
                        | ((a[9 * i + 7] & 0xFF) << 2))
                        | ((a[9 * i + 8] & 0xFF) << 10))
                        & 0x3FFFF;

                c[4 * i + 0] = gamma1 - c[4 * i + 0];
                c[4 * i + 1] = gamma1 - c[4 * i + 1];
                c[4 * i + 2] = gamma1 - c[4 * i + 2];
                c[4 * i + 3] = gamma1 - c[4 * i + 3];
            }
        }
        else if (gamma1 == (1 << 19))
        {
            for (int i = 0; i < DilithiumN / 2; ++i)
            {
                c[2 * i + 0] = (
                    (((a[5 * i + 0] & 0xFF))
                        | ((a[5 * i + 1] & 0xFF) << 8))
                        | ((a[5 * i + 2] & 0xFF) << 16))
                        & 0xFFFFF;

                c[2 * i + 1] = (
                    (((a[5 * i + 2] & 0xFF) >>> 4)
                        | ((a[5 * i + 3] & 0xFF) << 4))
                        | ((a[5 * i + 4] & 0xFF) << 12))
                        & 0xFFFFF;

                c[2 * i + 0] = gamma1 - c[2 * i + 0];
                c[2 * i + 1] = gamma1 - c[2 * i + 1];
            }
        }
        else
        {
            throw new RuntimeException("Wrong Dilithium Gamma1!");
        }
    }

    public void shiftLeft()
    {
        int[] c = this.coeffs;
        for (int i = 0; i < DilithiumN; ++i)
        {
            c[i] <<= MLDSAEngine.DilithiumD;
        }
    }

    public String toString()
    {
        StringBuilder out = new StringBuilder();
        out.append("[");
        for (int i = 0; i < coeffs.length; i++)
        {
            out.append(coeffs[i]);
            if (i != coeffs.length - 1)
            {
                out.append(", ");
            }
        }
        out.append("]");
        return out.toString();
    }
}
