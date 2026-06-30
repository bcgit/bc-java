package org.bouncycastle.crypto.kems.frodo;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.FrodoKEMParameters;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;

/**
 * FrodoKEM as standardised in ISO/IEC 18033-2:2006/Amd 2:2026, Clause 14, for the SHAKE parameter
 * sets at security levels 976 and 1344. A single engine implements both the salted "FrodoKEM"
 * (Salted Fujisaki-Okamoto transform) and the ephemeral "eFrodoKEM" (no salt) variants, selected by
 * the {@code salted} flag: when salted, the seed seedSE is enlarged to 2*len_mu bits and a salt of
 * 2*len_mu bits is folded into the G_2 hash and the shared secret and carried in the ciphertext;
 * when not salted, len_salt is zero and every salt operation below is a no-op.
 */
public class FrodoKEMEngine
{
    // constant parameters
    public static final int nbar = 8;

    private static final int mbar = 8;
    private static final int len_seedA = 128;
    private static final int len_z = 128;
    private static final int len_chi = 16;

    private static final int len_seedA_bytes = len_seedA / 8;
    private static final int len_z_bytes = len_z / 8;
    private static final int len_chi_bytes = len_chi / 8;

    // CDF tables for the noise distribution (ISO/IEC 18033-2 Table 14.9-4)
    private static final short[] cdf_table976  = new short[]{5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767};
    private static final short[] cdf_table1344 = new short[]{9142, 23462, 30338, 32361, 32725, 32765, 32767};

    // parameters for Frodo{n}
    private final int D;
    private final int q;
    private final int n;
    private final int B;

    private final int len_sk_bytes;
    private final int len_pk_bytes;
    private final int len_ct_bytes;

    private final short[] T_chi;

    private final int len_mu_bytes;
    private final int len_seedSE_bytes;
    private final int len_s_bytes;
    private final int len_k_bytes;
    private final int len_pkh_bytes;
    private final int len_ss_bytes;
    private final int len_salt_bytes;
    //
    private final Xof digest;
    private final FrodoMatrixGenerator gen;

    public static FrodoKEMEngine getInstance(FrodoKEMParameters params)
    {
        return new FrodoKEMEngine(params.isAes(), params.getN(), params.getD(), params.getB(), params.isSalted());
    }

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

    FrodoKEMEngine(boolean useAes, int n, int D, int B, boolean salted)
    {
        this.n = n;
        this.D = D;
        this.q = (1 << D);
        this.B = B;

        // all same size
        int len_mu = (B * nbar * nbar);
        // Salted FrodoKEM enlarges seedSE to 2*len_mu bits and uses a salt of 2*len_mu bits;
        // ephemeral eFrodoKEM uses seedSE = len_mu bits and no salt (len_salt = 0).
        int len_seedSE = salted ? 2 * len_mu : len_mu;

        this.len_mu_bytes = len_mu /8;
        this.len_seedSE_bytes = len_seedSE /8;
        this.len_s_bytes = len_mu /8;
        this.len_k_bytes = len_mu /8;
        this.len_pkh_bytes = len_mu /8;
        this.len_ss_bytes = len_mu /8;
        this.len_salt_bytes = salted ? 2 * len_mu_bytes : 0;

        this.len_ct_bytes = (D*n*nbar)/8 + (D*nbar*nbar)/8 + len_salt_bytes;
        this.len_pk_bytes = len_seedA_bytes + (D*n*nbar)/8;
        this.len_sk_bytes = len_s_bytes + len_pk_bytes + (2*n*nbar + len_pkh_bytes);

        this.T_chi = (n == 976) ? cdf_table976 : cdf_table1344;
        this.digest = new SHAKEDigest(256);
        this.gen = useAes
            ? (FrodoMatrixGenerator)new FrodoMatrixGenerator.Aes128MatrixGenerator(n, q)
            : new FrodoMatrixGenerator.Shake128MatrixGenerator(n, q);
    }

    private short[] sample_matrix(short[] r, int offset, int n1, int n2)
    {
        short[] E = new short[n1 * n2];
        sample(T_chi, r, offset, E);
        return E;
    }

    private short[] matrix_transpose(short[] X, int n2)
    {
        short[] res = new short[FrodoKEMEngine.nbar * n2];
        for (int i = 0; i < n2; i++)
        {
            for (int j = 0; j < FrodoKEMEngine.nbar; j++)
            {
                res[i * FrodoKEMEngine.nbar + j] = X[j * n2 + i];
            }
        }
        return res;
    }

    private short[] matrix_mul(short[] X, int Xrow, int Xcol, short[] Y, int Ycol)
    {
        int qMask = q - 1;
        short[] res = new short[Xrow * Ycol];
        // ikj ordering with an int row accumulator: the inner loop walks Y[] and acc[] contiguously
        // in j against a loop-invariant X[i][k], which C2 SuperWord can auto-vectorize. Each acc[j]
        // still sums over k in increasing order, exactly as the ijk schoolbook form did, so the int
        // accumulation - and hence the final (short)(acc & qMask), even where the products overflow
        // int and wrap mod 2^32 for q = 2^16 - is bit-for-bit identical to the original.
        int[] acc = new int[Ycol];
        for (int i = 0; i < Xrow; i++)
        {
            Arrays.fill(acc, 0);
            int xRow = i * Xcol;
            for (int k = 0; k < Xcol; k++)
            {
                int xik = X[xRow + k];
                int yRow = k * Ycol;
                for (int j = 0; j < Ycol; j++)
                {
                    acc[j] += xik * Y[yRow + j];
                }
            }
            int resRow = i * Ycol;
            for (int j = 0; j < Ycol; j++)
            {
                res[resRow + j] = (short)(acc[j] & qMask);
            }
        }
        return res;
    }

    private short[] matrix_add(short[] X, short[] Y, int n1, int m1)
    {
        int qMask = q - 1;
        short[] res = new short[n1 * m1];
        for (int i = 0; i < n1; i++)
        {
            for (int j = 0; j < m1; j++)
            {
                res[i * m1 + j] = (short)((X[i * m1 + j] + Y[i * m1 + j]) & qMask);
            }
        }
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
                short mask = (short)((1 << nbits) - 1);
                byte t = (byte)((w >> (bits - nbits)) & mask); // the bits to copy from w to out
                out[i] = (byte)(out[i] + (t << (8 - b - nbits)));
                b += nbits;
                bits -= nbits;

                if (bits == 0)
                {
                    if (j >= n)
                    {
                        break; // the input vector is exhausted
                    }

                    w = C[j];
                    bits = (byte)D;
                    j++;
                }
            }
            if (b == 8)
            {
                // out[i] is filled in
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

        // 2. Generate pseudo-random seed seedA = SHAKE(z, len_seedA) (length in bits)
        byte[] seedA = new byte[len_seedA_bytes];
        digest.update(z, 0, z.length);
        digest.doFinal(seedA, 0, seedA.length);

        // 3. A = Frodo.Gen(seedA)
        short[] A = gen.genMatrix(seedA, 0, seedA.length);

        // 4. r = SHAKE(0x5F || seedSE, 2*n*nbar*len_chi) (length in bits)
        byte[] rbytes = new byte[2 * n * nbar * len_chi_bytes];
        digest.update((byte)0x5f);
        digest.update(seedSE, 0, seedSE.length);
        digest.doFinal(rbytes, 0, rbytes.length);

        short[] r = Pack.littleEndianToShort(rbytes, 0, rbytes.length / 2);

        // 5. S^T = Frodo.SampleMatrix(r[0 .. n*nbar-1], nbar, n)
        short[] S_T = sample_matrix(r, 0, nbar, n);
        short[] S = matrix_transpose(S_T, n);

        // 6. E = Frodo.SampleMatrix(r[n*nbar .. 2*n*nbar-1], n, nbar)
        short[] E = sample_matrix(r, n * nbar, n, nbar);

        // 7. B = A * S + E
        short[] B = matrix_add(matrix_mul(A, n, n, S, nbar), E, n, nbar);

        // 8. b = Pack(B)
        byte[] b = pack(B);

        // 9. pkh = SHAKE(seedA || b, len_pkh) (length in bits)
        // 10. pk = seedA || b
        System.arraycopy(seedA, 0, pk, 0, len_seedA_bytes);
        System.arraycopy(b, 0, pk, len_seedA_bytes, len_pk_bytes - len_seedA_bytes);

        byte[] pkh = new byte[len_pkh_bytes];
        digest.update(pk, 0, pk.length);
        digest.doFinal(pkh, 0, pkh.length);

        //10. sk = (s || seedA || b, S^T, pkh)
        System.arraycopy(s, 0, sk, 0, len_s_bytes);
        System.arraycopy(pk, 0, sk, len_s_bytes, len_pk_bytes);
        Pack.shortToLittleEndian(S_T, sk, len_s_bytes + len_pk_bytes);
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
                short mask = (short)(((1 << nbits) - 1) & 0xffff);
                byte t = (byte)((((w & 0xff) >>> ((bits & 0xff) - nbits)) & (mask & 0xffff)) & 0xff); // the bits to copy from w to out
                out[i] = (short)((out[i] & 0xffff) + (((t & 0xff) << (D - (b & 0xff) - nbits))) & 0xffff);
                b += nbits;
                bits -= nbits;
                w &= ~(mask << bits);

                if (bits == 0)
                {
                    if (j >= in.length)
                    {
                        break; // the input vector is exhausted
                    }

                    w = in[j];
                    bits = 8;
                    j++;
                }
            }
            if (b == D)
            {
                // out[i] is filled in
                i++;
            }
        }
        return out;
    }

    private short[] encode(byte[] k)
    {
        int byte_index = 0;
        int bit = 0;
        short[] K = new short[mbar*nbar];

        // 1. for i = 0; i < mbar; i += 1
        for (int i = 0; i < mbar; i++)
        {
            // 2. for j = 0; j < nbar; j += 1
            for (int j = 0; j < nbar; j++)
            {
                // 3. tmp = sum_{l=0}^{B-1} k_{(i*nbar+j)*B+l} 2^l
                int temp = 0;
                for (int l = 0; l < B; l++)
                {
                    temp += ((k[byte_index] >>> bit) & 1) << l;

                    ++bit;
                    byte_index += bit >>> 3;
                    bit &= 7;
                }

                // 4. K[i][j] = ec(tmp) = tmp * q/2^B
                K[i * nbar + j] = (short)(temp * (q / (1 << B)));
            }
        }
        return K;
    }

    public void kem_enc(byte[] ct, byte[] ss, byte[] pk, SecureRandom random)
    {
        // Parse pk = seedA || b
        byte[] b = Arrays.copyOfRange(pk, len_seedA_bytes, len_pk_bytes);

        // 1. Choose a uniformly random key mu in {0,1}^len_mu and, for the salted variant, a salt
        //    in {0,1}^len_salt. They are drawn together as mu || salt in a single request so the KAT
        //    DRBG consumption matches the standard; for eFrodoKEM len_salt_bytes == 0, so this draws
        //    exactly mu.
        byte[] mu_salt = new byte[len_mu_bytes + len_salt_bytes];
        random.nextBytes(mu_salt);
        byte[] mu = Arrays.copyOfRange(mu_salt, 0, len_mu_bytes);
        byte[] salt = Arrays.copyOfRange(mu_salt, len_mu_bytes, len_mu_bytes + len_salt_bytes);

        // 2. pkh = SHAKE(pk, len_pkh)
        byte[] pkh = new byte[len_pkh_bytes];
        digest.update(pk, 0, len_pk_bytes);
        digest.doFinal(pkh, 0, len_pkh_bytes);

        // 3. seedSE || k = SHAKE(pkh || mu || salt, len_seedSE + len_k) (length in bits)
        //    (salt is empty for eFrodoKEM, reducing this to SHAKE(pkh || mu))
        byte[] seedSE_k = new byte[len_seedSE_bytes + len_k_bytes];
        digest.update(pkh, 0, len_pkh_bytes);
        digest.update(mu, 0, len_mu_bytes);
        digest.update(salt, 0, len_salt_bytes);
        digest.doFinal(seedSE_k, 0, len_seedSE_bytes + len_k_bytes);

        byte[] seedSE = Arrays.copyOfRange(seedSE_k, 0, len_seedSE_bytes);
        byte[] k = Arrays.copyOfRange(seedSE_k, len_seedSE_bytes, len_seedSE_bytes + len_k_bytes);

        // 4. r = SHAKE(0x96 || seedSE, 2*mbar*n + mbar*nbar*len_chi) (length in bits)
        byte[] rbytes = new byte[(2 * mbar * n + mbar * nbar) * len_chi_bytes];
        digest.update((byte)0x96);
        digest.update(seedSE, 0, seedSE.length);
        digest.doFinal(rbytes, 0, rbytes.length);

        short[] r = Pack.littleEndianToShort(rbytes, 0, rbytes.length / 2);

        // 5. S' = Frodo.SampleMatrix(r[0 .. mbar*n-1], mbar, n)
        short[] Sprime = sample_matrix(r, 0, mbar, n);

        // 6. E' = Frodo.SampleMatrix(r[mbar*n .. 2*mbar*n-1], mbar, n)
        short[] Eprime = sample_matrix(r, mbar * n, mbar, n);

        // 7. A = Frodo.Gen(seedA)
        short[] A = gen.genMatrix(pk, 0, len_seedA_bytes);

        // 8. B' = S' A + E'
        short[] Bprime = matrix_add(matrix_mul(Sprime, mbar, n, A, n), Eprime, mbar, n);

        // 9. c1 = Frodo.Pack(B')
        byte[] c1 = pack(Bprime);

        // 10. E'' = Frodo.SampleMatrix(r[2*mbar*n .. 2*mbar*n + mbar*nbar-1], mbar, n)
        short[] Eprimeprime = sample_matrix(r, 2 * mbar * n, mbar, nbar);

        // 11. B = Frodo.Unpack(b, n, nbar)
        short[] B = unpack(b, n, nbar);

        // 12. V = S' B + E''
        short[] V = matrix_add(matrix_mul(Sprime, mbar, n, B, nbar), Eprimeprime, mbar, nbar);

        // 13. C = V + Frodo.Encode(mu)
        short[] EncodedMU = encode(mu);
        short[] C = matrix_add(V, EncodedMU, nbar, mbar);

        // 14. c2 = Frodo.Pack(C)
        byte[] c2 = pack(C);

        // 15. ss = SHAKE(c1 || c2 || salt || k, len_ss)
        // ct = c1 || c2 || salt   (salt is empty for eFrodoKEM)
        System.arraycopy(c1, 0, ct, 0, c1.length);
        System.arraycopy(c2, 0, ct, c1.length, c2.length);
        System.arraycopy(salt, 0, ct, c1.length + c2.length, len_salt_bytes);

        digest.update(ct, 0, len_ct_bytes);
        digest.update(k, 0, len_k_bytes);
        digest.doFinal(ss, 0, len_s_bytes);
    }

    private short[] matrix_sub(short[] X, short[] Y)
    {
        int qMask = q - 1;
        short[] res = new short[FrodoKEMEngine.mbar * FrodoKEMEngine.nbar];
        for (int i = 0; i < FrodoKEMEngine.mbar; i++)
        {
            for (int j = 0; j < FrodoKEMEngine.nbar; j++)
            {
                res[i * FrodoKEMEngine.nbar + j] = (short)((X[i * FrodoKEMEngine.nbar + j] - Y[i * FrodoKEMEngine.nbar + j]) & qMask);
            }
        }
        return res;
    }

    private byte[] decode(short[] in)
    {
        int index = 0, npieces_word = 8;
        int nwords = (nbar * nbar) / 8;
        short maskex = (short)((1 << B) - 1);
        short maskq = (short)((1 << D) - 1);
        byte[] out = new byte[npieces_word * B];

        for (int i = 0; i < nwords; i++)
        {
            long templong = 0;
            for (int j = 0; j < npieces_word; j++)
            {
                // temp = floor(in*2^{-11}+0.5)
                short temp = (short)(((in[index] & maskq) + (1 << (D - B - 1))) >> (D - B));
                templong |= ((long)(temp & maskex)) << (B * j);
                index++;
            }
            for (int j = 0; j < B; j++)
            {
                out[i * B + j] = (byte)((templong >> (8 * j)) & 0xFF);
            }
        }
        return out;
    }

    public void kem_dec(byte[] ss, byte[] ct, byte[] sk)
    {
        // Parse ct = c1 || c2 || salt
        int offset = 0;
        int length = mbar * n * D / 8;
        byte[] c1 = Arrays.copyOfRange(ct, offset, offset + length);

        offset += length;
        length = mbar * nbar * D / 8;
        byte[] c2 = Arrays.copyOfRange(ct, offset, offset + length);

        // salt (salted variant): the trailing len_salt_bytes of ct; empty for eFrodoKEM
        offset += length;
        byte[] salt = Arrays.copyOfRange(ct, offset, offset + len_salt_bytes);

        // Parse sk = (s || seedA || b, S^T, pkh)
        offset = len_s_bytes + len_seedA_bytes;
        length = (D * n * nbar) / 8;
        byte[] b = Arrays.copyOfRange(sk, offset, offset + length);

        offset += length;
        length = n * nbar * 16 / 8;
        byte[] Sbytes = Arrays.copyOfRange(sk, offset, offset + length);

        short[] Stransposed = new short[nbar * n];

        for (int i = 0; i < nbar; i++)
        {
            for (int j = 0; j < n; j++)
            {
                Stransposed[i*n+j] = Pack.littleEndianToShort(Sbytes, i * n * 2 + j * 2);
            }
        }

        short[] S = matrix_transpose(Stransposed, n);

        offset += length;
        length = len_pkh_bytes;
        byte[] pkh = Arrays.copyOfRange(sk, offset, offset + length);

        // 1. B' = Frodo.Unpack(c1, mbar, n)
        short[] Bprime = unpack(c1, mbar, n);

        // 2. C = Frodo.Unpack(c2, mbar, nbar)
        short[] C = unpack(c2, mbar, nbar);

        // 3. M = C - B' S
        short[] BprimeS = matrix_mul(Bprime, mbar, n, S, nbar);
        short[] M = matrix_sub(C, BprimeS);

        // 4. mu' = Frodo.Decode(M)
        byte[] muprime = decode(M);

        /// 5. Parse pk = seedA || b  (done above)

        // 6. seedSE' || k' = SHAKE(pkh || mu' || salt, len_seedSE + len_k) (length in bits)
        //    (salt is empty for eFrodoKEM)
        byte[] seedSEprime_kprime = new byte[len_seedSE_bytes + len_k_bytes];
        digest.update(pkh, 0, len_pkh_bytes);
        digest.update(muprime, 0, len_mu_bytes);
        digest.update(salt, 0, len_salt_bytes);
        digest.doFinal(seedSEprime_kprime, 0, len_seedSE_bytes + len_k_bytes);

        byte[] K = Arrays.copyOfRange(seedSEprime_kprime, len_seedSE_bytes, len_seedSE_bytes + len_k_bytes);

        // 7. r = SHAKE(0x96 || seedSE', 2*mbar*n + mbar*nbar*len_chi) (length in bits)
        byte[] rbytes = new byte[(2 * mbar * n + mbar * nbar) * len_chi_bytes];
        digest.update((byte)0x96);
        digest.update(seedSEprime_kprime, 0, len_seedSE_bytes);
        digest.doFinal(rbytes, 0, rbytes.length);

        short[] r = Pack.littleEndianToShort(rbytes, 0, rbytes.length / 2);

        // 8. S' = Frodo.SampleMatrix(r[0 .. mbar*n-1], mbar, n)
        short[] Sprime = sample_matrix(r, 0, mbar, n);

        // 9. E' = Frodo.SampleMatrix(r[mbar*n .. 2*mbar*n-1], mbar, n)
        short[] Eprime = sample_matrix(r, mbar * n, mbar, n);

        // 10. A = Frodo.Gen(seedA)
        short[] A = gen.genMatrix(sk, len_s_bytes, len_seedA_bytes);

        // 11. B'' = S' A + E'
        short[] Bprimeprime = matrix_add(matrix_mul(Sprime, mbar, n, A, n), Eprime, mbar, n);

        // 12. E'' = Frodo.SampleMatrix(r[2*mbar*n .. 2*mbar*n + mbar*nbar-1], mbar, n)
        short[] Eprimeprime = sample_matrix(r, 2 * mbar * n, mbar, nbar);

        // 13. B = Frodo.Unpack(b, n, nbar)
        short[] B = unpack(b, n, nbar);

        // 14. V = S' B + E''
        short[] V = matrix_add(matrix_mul(Sprime, mbar, n, B, nbar), Eprimeprime, mbar, nbar);

        // 15. C' = V + Frodo.Encode(muprime)
        short[] Cprime = matrix_add(V, encode(muprime), mbar, nbar);

        // 16. (in constant time) kbar = kprime if (B' || C == B'' || C') else kbar = s
        // Needs to avoid branching on secret data as per:
        // Qian Guo, Thomas Johansson, Alexander Nilsson. A key-recovery timing attack on post-quantum
        // primitives using the Fujisaki-Okamoto transformation and its application on FrodoKEM. In CRYPTO 2020.
        int use_kprime = ctverify(Bprime, C, Bprimeprime, Cprime);
        Bytes.cmov(K.length, ~use_kprime, sk, K);

        // 17. ss = SHAKE(c1 || c2 || salt || kbar, len_ss) (length in bits)
        //     (salt is empty for eFrodoKEM)
        digest.update(c1, 0, c1.length);
        digest.update(c2, 0, c2.length);
        digest.update(salt, 0, len_salt_bytes);
        digest.update(K, 0, K.length);
        digest.doFinal(ss, 0, len_ss_bytes);
    }

    private static int ctverify(short[] a1, short[] a2, short[] b1, short[] b2)
    {
        int r = 0;
        for (int i = 0; i < a1.length; i++)
        {
            r |= a1[i] ^ b1[i];
        }
        for (int i = 0; i < a2.length; i++)
        {
            r |= a2[i] ^ b2[i];
        }
        return Nat.czero(r);
    }

    private static void sample(short[] cdf, short[] r, int rOff, short[] s)
    {
        // Fills 's' with samples from the noise distribution 'cdf' using pseudo-random values 'r[rOff..]'
        for (int i = 0, n = s.length; i < n; ++i)
        {
            int sample = 0;
            int r_i = r[rOff + i] & 0xFFFF;
            int prnd = r_i >>> 1;   // Drop the least significant bit
            int sign = r_i & 1;     // Pick the least significant bit

            for (int j = 0; j < cdf.length - 1; ++j)
            {
                // Constant time comparison: 1 if cdf[j] < prnd, 0 otherwise.
                sample += (cdf[j] - prnd) >>> 31;
            }

            // Assuming that sign is either 0 or 1, flips sample iff sign = 1
            sample = ((-sign) ^ sample) + sign;

            s[i] = (short)sample;
        }
    }
}
