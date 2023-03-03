package org.bouncycastle.pqc.crypto.frodo;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class FrodoEngine
{
    // constant parameters
    static final int nbar = 8;

    private static final int mbar = 8;
    private static final int len_seedA = 128;
    private static final int len_z = 128;
    private static final int len_chi = 16;

    private static final int len_seedA_bytes = len_seedA / 8;
    private static final int len_z_bytes = len_z / 8;
    private static final int len_chi_bytes = len_chi / 8;

    // parameters for Frodo{n}
    private final int D;
    private final int q;
    private final int n;
    private final int B;

    private final int len_sk_bytes;
    private final int len_pk_bytes;
    private final int len_ct_bytes;

    private final short[] T_chi;

    // all same size
    private final int len_mu;
    private final int len_seedSE;
    private final int len_s;
    private final int len_k;
    private final int len_pkh;
    private final int len_ss;

    private final int len_mu_bytes;
    private final int len_seedSE_bytes;
    private final int len_s_bytes;
    private final int len_k_bytes;
    private final int len_pkh_bytes;
    private final int len_ss_bytes;
    //
    private final Xof digest;
    private final FrodoMatrixGenerator gen;

    public int getCipherTextSize()
    {
        return len_ct_bytes;
    }

    public int getSessionKeySize()
    {
        return len_ss_bytes;
    }

    public int getPrivateKeySize()
    {
        return len_sk_bytes;
    }
    
    public int getPublicKeySize()
    {
        return len_pk_bytes;
    }

    public FrodoEngine(int n, int D, int B, short[] cdf_table, Xof digest, FrodoMatrixGenerator mGen)
    {
        this.n = n;
        this.D = D;
        this.q = (1 << D);
        this.B = B;

        this.len_mu = (B*nbar*nbar);
        this.len_seedSE = len_mu;
        this.len_s = len_mu;
        this.len_k = len_mu;
        this.len_pkh = len_mu;
        this.len_ss = len_mu;

        this.len_mu_bytes = len_mu/8;
        this.len_seedSE_bytes = len_seedSE/8;
        this.len_s_bytes = len_s/8;
        this.len_k_bytes = len_k/8;
        this.len_pkh_bytes = len_pkh/8;
        this.len_ss_bytes = len_ss/8;

        this.len_ct_bytes = (D*n*nbar)/8 + (D*nbar*nbar)/8;
        this.len_pk_bytes = len_seedA_bytes + (D*n*nbar)/8;
        this.len_sk_bytes = len_s_bytes + len_pk_bytes + (2*n*nbar + len_pkh_bytes);

        this.T_chi = cdf_table;
        this.digest = digest;
        this.gen = mGen;
    }

    private short sample(short r)
    {
        short t, e;
        // 1. t = sum_{i=1}^{len_x - 1} r_i * 2^{i-1}
        t = (short) ((r & 0xffff) >>> 1);
        e = 0; // 2. e = 0
        for (int z = 0; z < T_chi.length; z++)
        {
            if (t > T_chi[z]) // 4. if t > T_chi(z)
                e++; // 5. e = e + 1
        }
        // 6. e = (-1)^{r_0} * e

        if (((r & 0xffff) % 2) == 1)
            e = (short) ((e) * (-1) & 0xffff);

        return e;
    }

    private short[] sample_matrix(short[] r, int offset, int n1, int n2)
    {
        short[] E = new short[n1 * n2];
        for (int i = 0; i < n1; i++)
            for (int j = 0; j < n2; j++)
                E[i*n2+j] = sample(r[i * n2 + j + offset]);
        return E;
    }

    private short[] matrix_transpose(short[] X, int n1, int n2)
    {
        short[] res = new short[n1 * n2];

        for (int i = 0; i < n2; i++)
            for (int j = 0; j < n1; j++)
                res[i*n1 +j] = X[j*n2+ i];
        return res;
    }

    private short[] matrix_mul(short[] X, int Xrow, int Xcol, short[] Y, int Yrow, int Ycol)
    {
        int qMask = q - 1;
        short[] res = new short[Xrow * Ycol];
        for (int i = 0; i < Xrow; i++)
        {
            for (int j = 0; j < Ycol; j++)
            {
                int accum = 0;
                for (int k = 0; k < Xcol; k++)
                {
                    accum += X[i * Xcol + k] * Y[k * Ycol + j];
                }
                res[i * Ycol + j] = (short)(accum & qMask);
            }
        }
        return res;
    }

    private short[] matrix_add(short[] X, short[] Y, int n1, int m1)
    {
        int qMask = q - 1;
        short[] res = new short[n1*m1];
        for (int i = 0; i < n1; i++)
            for (int j = 0; j < m1; j++)
                res[i*m1+j] = (short)((X[i*m1+j] + Y[i*m1+j]) & qMask);

        return res;
    }

    // Packs a short array into a byte array using only the D amount of least significant bits
    private byte[] pack(short[] C)
    {
        int n = C.length;
        byte[] out = new byte[D * n / 8];
        short i = 0;    // whole bytes already filled in
        short j = 0;    // whole uint16_t already copied
        short w = 0;    // the leftover, not yet copied
        byte bits = 0;  // the number of lsb in w

        while (i < out.length && (j < n || ((j == n) && (bits > 0))))
        {

            byte b = 0;  // bits in out[i] already filled in
            while (b < 8)
            {
                int nbits = Math.min(8 - b, bits);
                short mask = (short) ((1 << nbits) - 1);
                byte t = (byte) ((w >> (bits - nbits)) & mask);  // the bits to copy from w to out
                out[i] = (byte) (out[i] + (t << (8 - b - nbits)));
                b += nbits;
                bits -= nbits;

                if (bits == 0)
                {
                    if (j < n)
                    {
                        w = C[j];
                        bits = (byte) D;
                        j++;
                    }
                    else
                    {
                        break;  // the input vector is exhausted
                    }
                }
            }
            if (b == 8)
            {  // out[i] is filled in
                i++;
            }
        }
        return out;
    }

    public void kem_keypair(byte[] pk, byte[] sk, SecureRandom random)
    {
        // 1. Choose uniformly random seeds s || seedSE || z
        byte[] s_seedSE_z = new byte[len_s_bytes + len_seedSE_bytes + len_z_bytes];
        random.nextBytes(s_seedSE_z);

        byte[] s = Arrays.copyOfRange(s_seedSE_z, 0, len_s_bytes);
        byte[] seedSE = Arrays.copyOfRange(s_seedSE_z, len_s_bytes, len_s_bytes + len_seedSE_bytes);
        byte[] z = Arrays.copyOfRange(s_seedSE_z, len_s_bytes + len_seedSE_bytes, len_s_bytes + len_seedSE_bytes + len_z_bytes);

        // 2. Generate pseudorandom seed seedA = SHAKE(z, len_seedA) (length in bits)
        byte[] seedA = new byte[len_seedA_bytes];
        digest.update(z, 0, z.length);
        digest.doFinal(seedA, 0, seedA.length);

        // 3. A = Frodo.Gen(seedA)
        short[] A = gen.genMatrix(seedA);

        // 4. r = SHAKE(0x5F || seedSE, 2*n*nbar*len_chi) (length in bits), parsed as 2*n*nbar len_chi-bit integers in little-endian byte order
        byte[] rbytes = new byte[2 * n * nbar * len_chi_bytes];

        digest.update((byte)0x5f);
        digest.update(seedSE, 0, seedSE.length);
        digest.doFinal(rbytes, 0, rbytes.length);

        short[] r = new short[2 * n * nbar];
        for (int i = 0; i < r.length; i++)
            r[i] = Pack.littleEndianToShort(rbytes, i * 2);

        // 5. S^T = Frodo.SampleMatrix(r[0 .. n*nbar-1], nbar, n)
        short[] S_T = sample_matrix(r, 0, nbar, n);
        short[] S = matrix_transpose(S_T, nbar, n);

        // 6. E = Frodo.SampleMatrix(r[n*nbar .. 2*n*nbar-1], n, nbar)
        short[] E = sample_matrix(r, n * nbar, n, nbar);

        // 7. B = A * S + E
        short[] B = matrix_add(matrix_mul(A, n, n, S, n, nbar), E, n, nbar);

        // 8. b = Pack(B)
        byte[] b = pack(B);

        // 9. pkh = SHAKE(seedA || b, len_pkh) (length in bits)
        // 10. pk = seedA || b
        System.arraycopy(Arrays.concatenate(seedA, b), 0, pk, 0, len_pk_bytes);

        byte[] pkh = new byte[len_pkh_bytes];
        digest.update(pk, 0, pk.length);
        digest.doFinal(pkh, 0, pkh.length);

        //10. sk = (s || seedA || b, S^T, pkh)
        System.arraycopy(Arrays.concatenate(s, pk), 0,
                sk, 0, len_s_bytes + len_pk_bytes);

        for (int i = 0; i < nbar; i++)
            for (int j = 0; j < n; j++)
                System.arraycopy(Pack.shortToLittleEndian(S_T[i*n+j]), 0,
                        sk, len_s_bytes + len_pk_bytes + i * n * 2 + j * 2, 2);

        System.arraycopy(pkh, 0, sk, len_sk_bytes - len_pkh_bytes, len_pkh_bytes);
    }

    private short[] unpack(byte[] in, int n1, int n2)
    {
        short[] out = new short[n1 * n2];

        short i = 0;    // whole uint16_t already filled in
        short j = 0;    // whole bytes already copied
        byte w = 0;    // the leftover, not yet copied
        byte bits = 0;  // the number of lsb bits of w

        while (i < out.length && (j < in.length || ((j == in.length) && (bits > 0))))
        {
            byte b = 0;  // bits in out[i] already filled in
            while (b < D)
            {
                int nbits = Math.min(D - b, bits);
                short mask = (short) (((1 << nbits) - 1) & 0xffff);
                byte t = (byte) ((((w & 0xff) >>> ((bits & 0xff) - nbits)) & (mask & 0xffff)) & 0xff);  // the bits to copy from w to out
                out[i] = (short) ((out[i] & 0xffff) + (((t & 0xff) << (D - (b & 0xff) - nbits))) & 0xffff);
                b += nbits;
                bits -= nbits;
                w &= ~(mask << bits);

                if (bits == 0)
                {
                    if (j < in.length)
                    {
                        w = in[j];
                        bits = 8;
                        j++;
                    }
                    else
                    {
                        break;  // the input vector is exhausted
                    }
                }
            }
            if (b == D)
            {  // out[i] is filled in
                i++;
            }
        }
        return out;
    }

    private short[] encode(byte[] k)
    {
        int l, byte_index = 0;
        byte mask = 1;
        short[] K = new short[mbar*nbar];
        int temp;
        // 1. for i = 0; i < mbar; i += 1
        for (int i = 0; i < mbar; i++)
        {
            // 2. for j = 0; j < nbar; j += 1
            for (int j = 0; j < nbar; j++)
            {
                // 3. tmp = sum_{l=0}^{B-1} k_{(i*nbar+j)*B+l} 2^l
                temp = 0;
                for (l = 0; l < B; l++)
                {
                    //mask
                    int mult = ((k[byte_index] & mask) == mask) ? 1 : 0;
                    temp += (1 << l) * mult;
                    mask <<= 1;
                    if (mask == 0)
                    {
                        mask = 1;
                        byte_index++;
                    }
                }
                // 4. K[i][j] = ec(tmp) = tmp * q/2^B
                K[i*nbar+j] = (short) (temp * (q / (1 << B)));
            }
        }
        return K;
    }

    public void kem_enc(byte[] ct, byte[] ss, byte[] pk, SecureRandom random)
    {
        // Parse pk = seedA || b
        byte[] seedA = Arrays.copyOfRange(pk, 0, len_seedA_bytes);
        byte[] b = Arrays.copyOfRange(pk, len_seedA_bytes, len_pk_bytes);

        // 1. Choose a uniformly random key mu in {0,1}^len_mu (length in bits)
        byte[] mu = new byte[len_mu_bytes];
        random.nextBytes(mu);

        // 2. pkh = SHAKE(pk, len_pkh)
        byte[] pkh = new byte[len_pkh_bytes];
        digest.update(pk, 0, len_pk_bytes);
        digest.doFinal(pkh, 0, len_pkh_bytes);

        // 3. seedSE || k = SHAKE(pkh || mu, len_seedSE + len_k) (length in bits)
        byte[] seedSE_k = new byte[len_seedSE + len_k];
        digest.update(pkh, 0, len_pkh_bytes);
        digest.update(mu, 0, len_mu_bytes);
        digest.doFinal(seedSE_k, 0, len_seedSE_bytes + len_k_bytes);

        byte[] seedSE = Arrays.copyOfRange(seedSE_k, 0, len_seedSE_bytes);
        byte[] k = Arrays.copyOfRange(seedSE_k, len_seedSE_bytes, len_seedSE_bytes + len_k_bytes);

        // 4. r = SHAKE(0x96 || seedSE, 2*mbar*n + mbar*nbar*len_chi) (length in bits)
        byte[] rbytes = new byte[(2 * mbar * n + mbar * nbar) * len_chi_bytes];
        digest.update((byte)0x96);
        digest.update(seedSE, 0, seedSE.length);
        digest.doFinal(rbytes, 0, rbytes.length);

        short[] r = new short[rbytes.length / 2];
        for (int i = 0; i < r.length; i++)
            r[i] = Pack.littleEndianToShort(rbytes, i * 2);

        // 5. S' = Frodo.SampleMatrix(r[0 .. mbar*n-1], mbar, n)
        short[] Sprime = sample_matrix(r, 0, mbar, n);

        // 6. E' = Frodo.SampleMatrix(r[mbar*n .. 2*mbar*n-1], mbar, n)
        short[] Eprime = sample_matrix(r, mbar * n, mbar, n);

        // 7. A = Frodo.Gen(seedA)
        short[] A = gen.genMatrix(seedA);

        // 8. B' = S' A + E'
        short[] Bprime = matrix_add(matrix_mul(Sprime, mbar, n, A, n, n), Eprime, mbar, n);

        // 9. c1 = Frodo.Pack(B')
        byte[] c1 = pack(Bprime);

        // 10. E'' = Frodo.SampleMatrix(r[2*mbar*n .. 2*mbar*n + mbar*nbar-1], mbar, n)
        short[] Eprimeprime = sample_matrix(r, 2 * mbar * n, mbar, nbar);

        // 11. B = Frodo.Unpack(b, n, nbar)
        short[] B = unpack(b, n, nbar);


        // 12. V = S' B + E''
        short[] V = matrix_add(matrix_mul(Sprime, mbar, n, B, n, nbar), Eprimeprime, mbar, nbar);

        // 13. C = V + Frodo.Encode(mu)
        short[] EncodedMU = encode(mu);
        short[] C = matrix_add(V, EncodedMU, nbar, mbar);

        // 14. c2 = Frodo.Pack(C)
        byte[] c2 = pack(C);

        // 15. ss = SHAKE(c1 || c2 || k, len_ss)
        // ct = c1 + c2
        System.arraycopy(Arrays.concatenate(c1, c2), 0, ct, 0, len_ct_bytes);
        digest.update(c1, 0, c1.length);
        digest.update(c2, 0, c2.length);
        digest.update(k, 0, len_k_bytes);
        digest.doFinal(ss, 0, len_s_bytes);
    }

    private short[] matrix_sub(short[] X, short[] Y, int n1, int n2)
    {
        int qMask = q - 1;
        short[] res = new short[n1*n2];
        for (int i = 0; i < n1; i++)
            for (int j = 0; j < n2; j++)
                res[i*n2+j] = (short)((X[i*n2+j] - Y[i*n2+j]) & qMask);

        return res;
    }

    private byte[] decode(short[] in)
    {
        int i, j, index = 0, npieces_word = 8;
        int nwords = (nbar * nbar) / 8;
        short temp;
        short maskex = (short) ((1 << B) - 1);
        short maskq = (short) ((1 << D) - 1);
        byte[] out = new byte[npieces_word * B];
        long templong;

        for (i = 0; i < nwords; i++)
        {
            templong = 0;
            for (j = 0; j < npieces_word; j++)
            {  // temp = floor(in*2^{-11}+0.5)
                temp = (short) (((in[index] & maskq) + (1 << (D - B - 1))) >> (D - B));
                templong |= ((long) (temp & maskex)) << (B * j);
                index++;
            }
            for (j = 0; j < B; j++)
                out[i * B + j] = (byte) ((templong >> (8 * j)) & 0xFF);
        }
        return out;
    }


    private short ctverify(short[] a1, short[] a2, short[] b1, short[] b2)
    {
        // Compare two arrays in constant time.
        // Returns 0 if the byte arrays are equal, -1 otherwise.
        short r = 0;

        for (short i = 0; i < a1.length; i++)
            r |= a1[i] ^ b1[i];

        for (short i = 0; i < a2.length; i++)
            r |= a2[i] ^ b2[i];

//        r = (short) ((-(short)(r >> 1) | -(short)(r & 1)) >> (8*2-1));
        if (r == 0)
            return 0;
        return -1;
    }

    private byte[] ctselect(byte[] a, byte[] b, short selector)
    {
        // Select one of the two input arrays to be moved to r
        // If (selector == 0) then load r with a, else if (selector == -1) load r with b
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++)
            r[i] = (byte) (((~selector & a[i]) & 0xff) | ((selector & b[i]) & 0xff));

        return r;
    }

    public void kem_dec(byte[] ss, byte[] ct, byte[] sk)
    {
        // Parse ct = c1 || c2
        int offset = 0;
        int length = mbar * n * D / 8;
        byte[] c1 = Arrays.copyOfRange(ct, offset, offset + length);

        offset += length;
        length = mbar * nbar * D / 8;
        byte[] c2 = Arrays.copyOfRange(ct, offset, offset + length);

        // Parse sk = (s || seedA || b, S^T, pkh)
        offset = 0;
        length = len_s_bytes;
        byte[] s = Arrays.copyOfRange(sk, offset, offset + length);

        offset += length;
        length = len_seedA_bytes;
        byte[] seedA = Arrays.copyOfRange(sk, offset, offset + length);

        offset += length;
        length = (D * n * nbar) / 8;
        byte[] b = Arrays.copyOfRange(sk, offset, offset + length);

        offset += length;
        length = n * nbar * 16 / 8;
        byte[] Sbytes = Arrays.copyOfRange(sk, offset, offset + length);

        short[] Stransposed = new short[nbar * n];

        for (int i = 0; i < nbar; i++)
            for (int j = 0; j < n; j++)
                Stransposed[i*n+j] = Pack.littleEndianToShort(Sbytes, i * n * 2 + j * 2);

        short[] S = matrix_transpose(Stransposed, nbar, n);

        offset += length;
        length = len_pkh_bytes;
        byte[] pkh = Arrays.copyOfRange(sk, offset, offset + length);

        // 1. B' = Frodo.Unpack(c1, mbar, n)
        short[] Bprime = unpack(c1, mbar, n);

        // 2. C = Frodo.Unpack(c2, mbar, nbar)
        short[] C = unpack(c2, mbar, nbar);

        // 3. M = C - B' S
        short[] BprimeS = matrix_mul(Bprime, mbar, n, S, n, nbar);
        short[] M = matrix_sub(C, BprimeS, mbar, nbar);

        // 4. mu' = Frodo.Decode(M)
        byte[] muprime = decode(M);

        /// 5. Parse pk = seedA || b  (done above)

        // 6. seedSE' || k' = SHAKE(pkh || mu', len_seedSE + len_k) (length in bits)
        byte[] seedSEprime_kprime = new byte[len_seedSE_bytes + len_k_bytes];
        digest.update(pkh, 0, len_pkh_bytes);
        digest.update(muprime, 0, len_mu_bytes);
        digest.doFinal(seedSEprime_kprime, 0, len_seedSE_bytes + len_k_bytes);

        byte[] kprime = Arrays.copyOfRange(seedSEprime_kprime, len_seedSE_bytes, len_seedSE_bytes + len_k_bytes);

        // 7. r = SHAKE(0x96 || seedSE', 2*mbar*n + mbar*nbar*len_chi) (length in bits)
        byte[] rbytes = new byte[(2 * mbar * n + mbar * mbar) * len_chi_bytes];
        digest.update((byte)0x96);
        digest.update(seedSEprime_kprime, 0, len_seedSE_bytes);
        digest.doFinal(rbytes, 0, rbytes.length);

        short[] r = new short[2 * mbar * n + mbar * nbar];
        for (int i = 0; i < r.length; i++)
        {
            r[i] = Pack.littleEndianToShort(rbytes, i * 2);
        }

        // 8. S' = Frodo.SampleMatrix(r[0 .. mbar*n-1], mbar, n)
        short[] Sprime = sample_matrix(r, 0, mbar, n);

        // 9. E' = Frodo.SampleMatrix(r[mbar*n .. 2*mbar*n-1], mbar, n)
        short[] Eprime = sample_matrix(r, mbar * n, mbar, n);

        // 10. A = Frodo.Gen(seedA)
        short[] A = gen.genMatrix(seedA);

        // 11. B'' = S' A + E'
        short[] Bprimeprime = matrix_add(matrix_mul(Sprime, mbar, n, A, n, n), Eprime, mbar, n);

        // 12. E'' = Frodo.SampleMatrix(r[2*mbar*n .. 2*mbar*n + mbar*nbar-1], mbar, n)
        short[] Eprimeprime = sample_matrix(r, 2 * mbar * n, mbar, nbar);

        // 13. B = Frodo.Unpack(b, n, nbar)
        short[] B = unpack(b, n, nbar);

        // 14. V = S' B + E''
        short[] V = matrix_add(matrix_mul(Sprime, mbar, n, B, n, nbar), Eprimeprime, mbar, nbar);

        // 15. C' = V + Frodo.Encode(muprime)
        short[] Cprime = matrix_add(V, encode(muprime), mbar, nbar);

        // 16. (in constant time) kbar = kprime if (B' || C == B'' || C') else kbar = s
        // Needs to avoid branching on secret data as per:
        // Qian Guo, Thomas Johansson, Alexander Nilsson. A key-recovery timing attack on post-quantum
        // primitives using the Fujisaki-Okamoto transformation and its application on FrodoKEM. In CRYPTO 2020.
        //TODO change it so Bprime and C are in the same array same with B'' and C'
        short use_kprime = ctverify(Bprime, C, Bprimeprime, Cprime);
        byte[] kbar = ctselect(kprime, s, use_kprime);

        // 17. ss = SHAKE(c1 || c2 || kbar, len_ss) (length in bits)
        digest.update(c1, 0, c1.length);
        digest.update(c2, 0, c2.length);
        digest.update(kbar, 0, kbar.length);
        digest.doFinal(ss, 0, len_ss_bytes);
    }

}