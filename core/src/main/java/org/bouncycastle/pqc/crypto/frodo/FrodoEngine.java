package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.Pack;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;

class FrodoEngine
{
    // constant parameters
    private static int nbar = 8;
    private static int mbar = 8;
    private static int len_seedA = 128;
    private static int len_z = 128;
    private static int len_chi = 16;

    private static int len_seedA_bytes = len_seedA / 8;
    private static int len_z_bytes = len_z / 8;
    private static int len_chi_bytes = len_chi / 8;

    // parameters for Frodo{n}
    private static int D;
    private static int q;
    private static int n;
    private static int B;

    private static int len_sk_bytes;
    private static int len_pk_bytes;
    private static int len_ct_bytes;

    private static short[] T_chi;
    // all same size
    private static int len_mu;
    private static int len_seedSE;
    private static int len_s;
    private static int len_k;
    private static int len_pkh;
    private static int len_ss;

    private static int len_mu_bytes;
    private static int len_seedSE_bytes;
    private static int len_s_bytes;
    private static int len_k_bytes;
    private static int len_pkh_bytes;
    private static int len_ss_bytes;
    //
    private static Xof digest;
    private static FrodoMatrixGenerator gen;

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

    public FrodoEngine(int n, boolean isAES128)
    {
        switch (n)
        {
            case 640: initFrodoKEM640Parameters();
                break;
            case 976: initFrodoKEM976Parameters();
                break;
            case 1344: initFrodoKEM1344Parameters();
                break;
        }
        if (isAES128)
            gen = new FrodoMatrixGenerator.Aes128MatrixGenerator(n, q);
        else
            gen = new FrodoMatrixGenerator.Shake128MatrixGenerator(n, q);

    }

    private static void initFrodoKEM640Parameters()
    {
        digest = new SHAKEDigest(128);

        D = 15;
        q = 32768;
        n = 640;
        B = 2;

        len_sk_bytes = 19888;
        len_pk_bytes = 9616;
        len_ct_bytes = 9720;

        short[] error_distribution = {9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1};
        // setting T_chi
        cdf_zero_centred_symmetric(error_distribution);


        // all same size
        len_mu = 128;
        len_seedSE = 128;
        len_s = 128;
        len_k = 128;
        len_pkh = 128;
        len_ss = 128;

        len_mu_bytes = len_mu / 8;
        len_seedSE_bytes = len_seedSE / 8;
        len_s_bytes = len_s / 8;
        len_k_bytes = len_k / 8;
        len_pkh_bytes = len_pkh / 8;
        len_ss_bytes = len_ss / 8;
    }

    private static void initFrodoKEM976Parameters()
    {
        digest = new SHAKEDigest(256);

        D = 16;
        q = 65536;
        n = 976;
        B = 3;

        len_sk_bytes = 31296;
        len_pk_bytes = 15632;
        len_ct_bytes = 15744;

        short[] error_distribution = {11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1};
        // setting T_chi
        cdf_zero_centred_symmetric(error_distribution);

        // all same size
        len_mu = 192;
        len_seedSE = 192;
        len_s = 192;
        len_k = 192;
        len_pkh = 192;
        len_ss = 192;

        len_mu_bytes = len_mu / 8;
        len_seedSE_bytes = len_seedSE / 8;
        len_s_bytes = len_s / 8;
        len_k_bytes = len_k / 8;
        len_pkh_bytes = len_pkh / 8;
        len_ss_bytes = len_ss / 8;
    }

    private static void initFrodoKEM1344Parameters()
    {
        digest = new SHAKEDigest(256);

        D = 16;
        q = 65536;
        n = 1344;
        B = 4;

        len_sk_bytes = 43088;
        len_pk_bytes = 21520;
        len_ct_bytes = 21632;

        short[] error_distribution = {18286, 14320, 6876, 2023, 364, 40, 2};
        // setting T_chi
        cdf_zero_centred_symmetric(error_distribution);
        System.out.print("T_chi: ");
        for (int i = 0; i < T_chi.length; i++)
            System.out.print(  T_chi[i] + " ");
        System.out.println();

        // all same size
        len_mu = 256;
        len_seedSE = 256;
        len_s = 256;
        len_k = 256;
        len_pkh = 256;
        len_ss = 256;

        len_mu_bytes = len_mu / 8;
        len_seedSE_bytes = len_seedSE / 8;
        len_s_bytes = len_s / 8;
        len_k_bytes = len_k / 8;
        len_pkh_bytes = len_pkh / 8;
        len_ss_bytes = len_ss / 8;
    }

    private static void cdf_zero_centred_symmetric(short[] chi)
    {
        T_chi = new short[chi.length];
        T_chi[0] = (short) ((chi[0] / 2) - 1);
        short sum;
        int i, z;
        for (z = 1; z < chi.length; z++)
        {
            sum = 0;
            for (i = 1; i < z + 1; i++)
                sum += chi[i];
            T_chi[z] = (short) (T_chi[0] + sum);
        }
    }

    private static short sample(short r)
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

    private static short[] sample_matrix(short[] r, int offset, int n1, int n2)
    {
        short[] E = new short[n1 * n2];
        for (int i = 0; i < n1; i++)
            for (int j = 0; j < n2; j++)
                E[i*n2+j] = (short) (sample(r[i * n2 + j + offset]));
        return E;
    }

    private static short[] matrix_transpose(short[] X, int n1, int n2)
    {
        short[] res = new short[n1 * n2];

        for (int i = 0; i < n2; i++)
            for (int j = 0; j < n1; j++)
                res[i*n1 +j] = X[j*n2+ i];
        return res;
    }

    private static short[] matrix_mul(short[] X, int Xrow, int Xcol, short[] Y, int Yrow, int Ycol)
    {
        short[] res = new short[Xrow * Ycol];
        for (int i = 0; i < Xrow; i++)
            for (int j = 0; j < Ycol; j++)
            {
                for (int k = 0; k < Xcol; k++)
                    res[i*Ycol+j] = (short) ((res[i*Ycol+j] & 0xffff) + ((X[i*Xcol+k] & 0xffff) * (Y[k*Ycol+j] & 0xffff))&0xffff);
                res[i*Ycol+j] = (short) (((res[i*Ycol+j] & 0xffff) % q)&0xffff);
            }
        return res;
    }

    private static short[] matrix_add(short[] X, short[] Y, int n1, int m1)
    {
        short[] res = new short[n1*m1];
        for (int i = 0; i < n1; i++)
            for (int j = 0; j < m1; j++)
                res[i*m1+j] = (short) (((X[i*m1+j]&0xffff) + (Y[i*m1+j]&0xffff)) % q);

        return res;
    }

    // Packs a short array into a byte array using only the D amount of least significant bits;
    private static byte[] pack(short[] C)
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

        System.out.println("randomness: " + ByteUtils.toHexString(s_seedSE_z));

        byte[] s = ByteUtils.subArray(s_seedSE_z, 0, len_s_bytes);
        byte[] seedSE = ByteUtils.subArray(s_seedSE_z, len_s_bytes, len_s_bytes + len_seedSE_bytes);
        byte[] z = ByteUtils.subArray(s_seedSE_z, len_s_bytes + len_seedSE_bytes, len_s_bytes + len_seedSE_bytes + len_z_bytes);

        // 2. Generate pseudorandom seed seedA = SHAKE(z, len_seedA) (length in bits)
        byte[] seedA = new byte[len_seedA_bytes];
        digest.update(z, 0, z.length);
        digest.doFinal(seedA, 0, seedA.length);

        System.out.println("seedA: " + ByteUtils.toHexString(seedA));

        // 3. A = Frodo.Gen(seedA)
        short[] A = gen.genMatrix(seedA);

        // 4. r = SHAKE(0x5F || seedSE, 2*n*nbar*len_chi) (length in bits), parsed as 2*n*nbar len_chi-bit integers in little-endian byte order
        byte[] temp = ByteUtils.concatenate(new byte[]{0x5f}, seedSE);
        byte[] rbytes = new byte[2 * n * nbar * len_chi_bytes];

        digest.update(temp, 0, temp.length);
        digest.doFinal(rbytes, 0, rbytes.length);

        short[] r = new short[2 * n * nbar];
        for (int i = 0; i < r.length; i++)
        {
            r[i] = Pack.littleEndianToShort(rbytes, i * 2);
        }
//        r = [struct.unpack_from('<H', rbytes, 2*i)[0] for i in range(2 * self.n * self.nbar)]
//        self.__print_intermediate_value("r", r)
        System.out.print("r: ");
        for (int i = 0; i < r.length; i++)
            System.out.printf("%04x, ", (r[i]));
//        System.out.print(r[i] + " ");
        System.out.println();

        // 5. S^T = Frodo.SampleMatrix(r[0 .. n*nbar-1], nbar, n)
        short[] S_T = sample_matrix(r, 0, nbar, n);

        System.out.print("S^T: ");
        for (int i = 0; i < S_T.length; i++)
            System.out.printf("%04x, ", (S_T[i]));
        //System.out.print(S_T[i][j] + " ");
        System.out.println();

        short[] S = matrix_transpose(S_T, nbar, n);
        // 6. E = Frodo.SampleMatrix(r[n*nbar .. 2*n*nbar-1], n, nbar)
        short[] E = sample_matrix(r, n * nbar, n, nbar);

        System.out.print("E: ");
        for (int i = 0; i < E.length; i++)
            System.out.printf("%04x, ", (E[i]));
        //System.out.print(E[i][j] + " ");
        System.out.println();
        // 7. B = A * S + E
        short[] B = matrix_add(matrix_mul(A, n, n, S, n, nbar), E, n, nbar);

        System.out.print("B: ");
        for (int i = 0; i < B.length; i++)
            System.out.printf("%04x, ", (B[i]));
//        System.out.print(B[i][j] + ",");
//                System.out.printf("%02x ",Pack.bigEndianToShort(Pack.shortToBigEndian(B[i][j]),0));
        System.out.println();

        // 8. b = Pack(B)
        byte[] b = pack(B);
        System.out.println("b: " + ByteUtils.toHexString(b));

        // 9. pkh = SHAKE(seedA || b, len_pkh) (length in bits)
        // 10. pk = seedA || b
        System.arraycopy(ByteUtils.concatenate(seedA, b), 0, pk, 0, len_pk_bytes);

        byte[] pkh = new byte[len_pkh_bytes];
        digest.update(pk, 0, pk.length);
        digest.doFinal(pkh, 0, pkh.length);
        System.out.println("pkh: " + ByteUtils.toHexString(pkh));

        //10. sk = (s || seedA || b, S^T, pkh)
        System.arraycopy(ByteUtils.concatenate(s, pk), 0,
                sk, 0, len_s_bytes + len_pk_bytes);
        System.out.println("sk: " + ByteUtils.toHexString(sk).toUpperCase());

        for (int i = 0; i < nbar; i++)
        {
            for (int j = 0; j < n; j++)
            {
                System.arraycopy(Pack.shortToLittleEndian(S_T[i*n+j]), 0,
                        sk, len_s_bytes + len_pk_bytes + i * n * 2 + j * 2, 2);
            }
        }

        System.arraycopy(pkh, 0, sk, len_sk_bytes - len_pkh_bytes, len_pkh_bytes);

        System.out.println("pk: " + ByteUtils.toHexString(pk).toUpperCase());
        System.out.println("sk: " + ByteUtils.toHexString(sk).toUpperCase());
    }

    private static short[] unpack(byte[] in, int n1, int n2)
    {
//    frodo_unpack(B, PARAMS_N*PARAMS_NBAR, pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);
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

    private static short[] encode(byte[] k)
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
                    if ((k[byte_index] & mask) == mask)
                    {
                        temp += (1 << l);
                    }
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
        byte[] seedA = ByteUtils.subArray(pk, 0, len_seedA_bytes);
        byte[] b = ByteUtils.subArray(pk, len_seedA_bytes, len_pk_bytes);

        // 1. Choose a uniformly random key mu in {0,1}^len_mu (length in bits)
        byte[] mu = new byte[len_mu_bytes];
        random.nextBytes(mu);
        System.out.println("mu: " + ByteUtils.toHexString(mu));

        // 2. pkh = SHAKE(pk, len_pkh)
        byte[] pkh = new byte[len_pkh_bytes];
        digest.update(pk, 0, len_pk_bytes);
        digest.doFinal(pkh, 0, len_pkh_bytes);
        System.out.println("pkh: " + ByteUtils.toHexString(pkh));

        // 3. seedSE || k = SHAKE(pkh || mu, len_seedSE + len_k) (length in bits)
        byte[] seedSE_k = new byte[len_seedSE + len_k];
        digest.update(ByteUtils.concatenate(pkh, mu), 0, len_pkh_bytes + len_mu_bytes);
        digest.doFinal(seedSE_k, 0, len_seedSE_bytes + len_k_bytes);

        byte[] seedSE = ByteUtils.subArray(seedSE_k, 0, len_seedSE_bytes);
        System.out.println("seedSE: " + ByteUtils.toHexString(seedSE));

        byte[] k = ByteUtils.subArray(seedSE_k, len_seedSE_bytes, len_seedSE_bytes + len_k_bytes);
        System.out.println("k: " + ByteUtils.toHexString(k));

        // 4. r = SHAKE(0x96 || seedSE, 2*mbar*n + mbar*nbar*len_chi) (length in bits)
        byte[] rbytes = new byte[(2 * mbar * n + mbar * nbar) * len_chi_bytes];
        digest.update(ByteUtils.concatenate(new byte[]{(byte) 0x96}, seedSE), 0, seedSE.length + 1);
        digest.doFinal(rbytes, 0, rbytes.length);

        short[] r = new short[rbytes.length / 2];
        for (int i = 0; i < r.length; i++)
        {
            r[i] = Pack.littleEndianToShort(rbytes, i * 2);
        }
        System.out.print("r: ");
        for (int i = 0; i < r.length; i++)
            System.out.printf("%04x, ", (r[i]));
        //System.out.print(r[i] + ",");
        System.out.println();

        // 5. S' = Frodo.SampleMatrix(r[0 .. mbar*n-1], mbar, n)
        short[] Sprime = sample_matrix(r, 0, mbar, n);
        System.out.print("S': ");
        for (int i = 0; i < Sprime.length; i++)
            System.out.printf("%04x, ", (Sprime[i]));
        //System.out.print(Sprime[i][j] + ",");
        System.out.println();

        // 6. E' = Frodo.SampleMatrix(r[mbar*n .. 2*mbar*n-1], mbar, n)
        short[] Eprime = sample_matrix(r, mbar * n, mbar, n);
        System.out.print("E': ");
        for (int i = 0; i < Eprime.length; i++)
            System.out.printf("%04x, ", (Eprime[i]));
        //System.out.print(Eprime[i][j] + ",");
        System.out.println();

        // 7. A = Frodo.Gen(seedA)
        short[] A = gen.genMatrix(seedA);

        // 8. B' = S' A + E'
        short[] Bprime = matrix_add(matrix_mul(Sprime, mbar, n, A, n, n), Eprime, mbar, n);
        System.out.print("B': ");
        for (int i = 0; i < Bprime.length; i++)
            System.out.printf("%04x, ", (Bprime[i]));
        //System.out.print(Bprime[i][j] + ",");
        System.out.println();

        // 9. c1 = Frodo.Pack(B')
        byte[] c1 = pack(Bprime);
        System.out.println("c1: " + ByteUtils.toHexString(c1).toUpperCase());

        // 10. E'' = Frodo.SampleMatrix(r[2*mbar*n .. 2*mbar*n + mbar*nbar-1], mbar, n)
        short[] Eprimeprime = sample_matrix(r, 2 * mbar * n, mbar, nbar);
        System.out.print("E'': ");
        for (int i = 0; i < Eprimeprime.length; i++)
                System.out.printf("%04x, ", (Eprimeprime[i]));
        //System.out.print((Eprimeprime[i][j]) + ",");
        System.out.println();

        // 11. B = Frodo.Unpack(b, n, nbar)
        short[] B = unpack(b, n, nbar);
        System.out.print("B: ");
        for (int i = 0; i < B.length; i++)
            System.out.printf("%04x, ", B[i]);
//        System.out.print(B[i] + ",");
        System.out.println();


        // 12. V = S' B + E''
        short[] V = matrix_add(matrix_mul(Sprime, mbar, n, B, n, nbar), Eprimeprime, mbar, nbar);

        System.out.print("V: ");
        for (int i = 0; i < V.length; i++)
            System.out.printf("%04x, ", (V[i]));
        System.out.println();
        // 13. C = V + Frodo.Encode(mu)
        short[] EncodedMU = encode(mu);
        System.out.print("encMU: ");
        for (int i = 0; i < EncodedMU.length; i++)
            System.out.printf("%04x, ", (EncodedMU[i]));
        System.out.println();

        short[] C = matrix_add(V, EncodedMU, nbar, mbar);
        System.out.print("C: ");
        for (int i = 0; i < C.length; i++)
            System.out.printf("%04x, ", (C[i]));
        System.out.println();

        // 14. c2 = Frodo.Pack(C)
        byte[] c2 = pack(C);
        System.out.println("c2: " + ByteUtils.toHexString(c2));

        // 15. ss = SHAKE(c1 || c2 || k, len_ss)

        // ct = c1 + c2
        System.arraycopy(ByteUtils.concatenate(c1, c2), 0, ct, 0, len_ct_bytes);

        digest.update(ByteUtils.concatenate(ct, k), 0, c1.length + c2.length + len_k_bytes);
        digest.doFinal(ss, 0, len_s_bytes);

        System.out.println("ss: " + ByteUtils.toHexString(ss));
        System.out.println("ct: " + ByteUtils.toHexString(ct));
    }

    private static short[] matrix_sub(short[] X, short[] Y, int n1, int n2)
    {
        short[] res = new short[n1*n2];
        for (int i = 0; i < n1; i++)
        {
            for (int j = 0; j < n2; j++)
            {
                res[i*n2+j] = (short) ((((X[i*n2+j]) - (Y[i*n2+j])) & 0xffff) % q);
            }
        }
        return res;
    }

    private static byte[] decode(short[] in)
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


    private static short ctverify(short[] a1, short[] a2, short[] b1, short[] b2)
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

    private static byte[] ctselect(byte[] a, byte[] b, short selector)
    {
        // Select one of the two input arrays to be moved to r
        // If (selector == 0) then load r with a, else if (selector == -1) load r with b
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++)
        {
//            r[i] = (byte) ((a[i]&0xff & (~mask&0xff))&0xff | (b[i]&0xff & ((mask)&0xff))&0xff);
            r[i] = (byte) (((~selector & a[i]) & 0xff) | ((selector & b[i]) & 0xff));
        }
        return r;
    }

    public void kem_dec(byte[] ss, byte[] ct, byte[] sk)
    {
        // Parse ct = c1 || c2
        int offset = 0;
        int length = mbar * n * D / 8;
        byte[] c1 = ByteUtils.subArray(ct, offset, offset + length);
        System.out.println("c1: " + ByteUtils.toHexString(c1));

        offset += length;
        length = mbar * nbar * D / 8;
        byte[] c2 = ByteUtils.subArray(ct, offset, offset + length);
        System.out.println("c2: " + ByteUtils.toHexString(c2));

        // Parse sk = (s || seedA || b, S^T, pkh)
        offset = 0;
        length = len_s_bytes;
        byte[] s = ByteUtils.subArray(sk, offset, offset + length);
        System.out.println("s: " + ByteUtils.toHexString(s));

        offset += length;
        length = len_seedA_bytes;
        byte[] seedA = ByteUtils.subArray(sk, offset, offset + length);
        System.out.println("seedA: " + ByteUtils.toHexString(seedA));
        offset += length;
        length = (D * n * nbar) / 8;
        byte[] b = ByteUtils.subArray(sk, offset, offset + length);
        System.out.println("b: " + ByteUtils.toHexString(b));

        offset += length;
        length = n * nbar * 16 / 8;
        byte[] Sbytes = ByteUtils.subArray(sk, offset, offset + length);
        System.out.println("Sbytes: " + ByteUtils.toHexString(Sbytes));

        short[] Stransposed = new short[nbar * n];

        for (int i = 0; i < nbar; i++)
        {
            for (int j = 0; j < n; j++)
            {
                Stransposed[i*n+j] = Pack.littleEndianToShort(Sbytes, i * n * 2 + j * 2);
            }
        }
        System.out.print("S^T: ");
        for (int i = 0; i < Stransposed.length; i++)
            System.out.printf("%04x, ", (Stransposed[i]));
        System.out.println();

        short[] S = matrix_transpose(Stransposed, nbar, n);
        System.out.print("S: ");
        for (int i = 0; i < S.length; i++)
            System.out.printf("%04x, ", (S[i]));
        System.out.println();


        offset += length;
        length = len_pkh_bytes;
        byte[] pkh = ByteUtils.subArray(sk, offset, offset + length);
        System.out.println("pkh: " + ByteUtils.toHexString(pkh));

        // 1. B' = Frodo.Unpack(c1, mbar, n)
        short[] Bprime = unpack(c1, mbar, n);
        System.out.print("B': ");
        for (int i = 0; i < Bprime.length; i++)
            System.out.printf("%04x, ", (Bprime[i]));
        System.out.println();

        // 2. C = Frodo.Unpack(c2, mbar, nbar)
        short[] C = unpack(c2, mbar, nbar);
        System.out.print("C: ");
        for (int i = 0; i < C.length; i++)
            System.out.printf("%04x, ", (C[i]));
        System.out.println();

        // 3. M = C - B' S
        short[] BprimeS = matrix_mul(Bprime, mbar, n, S, n, nbar);
        System.out.print("B'S: ");
        for (int i = 0; i < BprimeS.length; i++)
            System.out.printf("%04x, ", (BprimeS[i]));
        System.out.println();

        short[] M = matrix_sub(C, BprimeS, mbar, nbar);
        System.out.print("M: ");
        for (int i = 0; i < M.length; i++)
            System.out.printf("%04x, ", (M[i]));
        System.out.println();


        // 4. mu' = Frodo.Decode(M)
        byte[] muprime = decode(M);
        System.out.println("mu': " + ByteUtils.toHexString(muprime));

        /// 5. Parse pk = seedA || b  (done above)

        // 6. seedSE' || k' = SHAKE(pkh || mu', len_seedSE + len_k) (length in bits)
        byte[] seedSEprime_kprime = new byte[len_seedSE_bytes + len_k_bytes];
        digest.update(ByteUtils.concatenate(pkh, muprime), 0, len_pkh_bytes + len_mu_bytes);
        digest.doFinal(seedSEprime_kprime, 0, len_seedSE_bytes + len_k_bytes);

        byte[] seedSEprime = ByteUtils.subArray(seedSEprime_kprime, 0, len_seedSE_bytes);
        System.out.println("seedSE': " + ByteUtils.toHexString(seedSEprime));

        byte[] kprime = ByteUtils.subArray(seedSEprime_kprime, len_seedSE_bytes, len_seedSE_bytes + len_k_bytes);
        System.out.println("k': " + ByteUtils.toHexString(kprime));

        // 7. r = SHAKE(0x96 || seedSE', 2*mbar*n + mbar*nbar*len_chi) (length in bits)
        byte[] rbytes = new byte[(2 * mbar * n + mbar * mbar) * len_chi_bytes];
        digest.update(ByteUtils.concatenate(new byte[]{(byte) 0x96}, seedSEprime), 0, len_seedSE_bytes + 1);
        digest.doFinal(rbytes, 0, rbytes.length);
        System.out.println("rbyte: " + ByteUtils.toHexString(rbytes));
        //        r = [struct.unpack_from('<H', rbytes, 2*i)[0] for i in range(2 * self.mbar * self.n + self.mbar * self.nbar)]
        //        self.__print_intermediate_value("r", r)
        short[] r = new short[2 * mbar * n + mbar * nbar];
        for (int i = 0; i < r.length; i++)
        {
            r[i] = Pack.littleEndianToShort(rbytes, i * 2);
        }
//        r = [struct.unpack_from('<H', rbytes, 2*i)[0] for i in range(2 * self.n * self.nbar)]
//        self.__print_intermediate_value("r", r)
        System.out.print("r: ");
        for (int i = 0; i < r.length; i++)
            System.out.printf("%04x, ", (r[i]));
        System.out.println();

        // 8. S' = Frodo.SampleMatrix(r[0 .. mbar*n-1], mbar, n)
        short[] Sprime = sample_matrix(r, 0, mbar, n);
        System.out.print("S': ");
        for (int i = 0; i < Sprime.length; i++)
            System.out.printf("%04x, ", (Sprime[i]));
        System.out.println();

        // 9. E' = Frodo.SampleMatrix(r[mbar*n .. 2*mbar*n-1], mbar, n)
        short[] Eprime = sample_matrix(r, mbar * n, mbar, n);
        System.out.print("E': ");
        for (int i = 0; i < Eprime.length; i++)
            System.out.printf("%04x, ", (Eprime[i]));
        System.out.println();

        // 10. A = Frodo.Gen(seedA)
        short[] A = gen.genMatrix(seedA);

        System.out.println();
        // 11. B'' = S' A + E'
        short[] Bprimeprime = matrix_add(matrix_mul(Sprime, mbar, n, A, n, n), Eprime, mbar, n);
        System.out.print("B'': ");
        for (int i = 0; i < Bprimeprime.length; i++)
            System.out.printf("%04x, ", (Bprimeprime[i]));
        System.out.println();

        // 12. E'' = Frodo.SampleMatrix(r[2*mbar*n .. 2*mbar*n + mbar*nbar-1], mbar, n)
        short[] Eprimeprime = sample_matrix(r, 2 * mbar * n, mbar, nbar);
        System.out.print("E'': ");
        for (int i = 0; i < Eprimeprime.length; i++)
            System.out.printf("%04x, ", (Eprimeprime[i]));
        System.out.println();

        // 13. B = Frodo.Unpack(b, n, nbar)
        short[] B = unpack(b, n, nbar);
        System.out.print("B: ");
        for (int i = 0; i < B.length; i++)
            System.out.printf("%04x, ", (B[i]));
        System.out.println();


        // 14. V = S' B + E''
        short[] V = matrix_add(matrix_mul(Sprime, mbar, n, B, n, nbar), Eprimeprime, mbar, nbar);
        System.out.print("V: ");
        for (int i = 0; i < V.length; i++)
            System.out.printf("%04x, ", (V[i]));
        System.out.println();

        // 15. C' = V + Frodo.Encode(muprime)
        short[] Cprime = matrix_add(V, encode(muprime), mbar, nbar);
        System.out.print("C': ");
        for (int i = 0; i < Cprime.length; i++)
            System.out.printf("%04x, ", (Cprime[i]));
        System.out.println();

        // 16. (in constant time) kbar = kprime if (B' || C == B'' || C') else kbar = s
        // Needs to avoid branching on secret data as per:
        // Qian Guo, Thomas Johansson, Alexander Nilsson. A key-recovery timing attack on post-quantum
        // primitives using the Fujisaki-Okamoto transformation and its application on FrodoKEM. In CRYPTO 2020.
        //TODO change it so Bprime and C are in the same array same with B'' and C'
        short use_kprime = ctverify(Bprime, C, Bprimeprime, Cprime);
        System.out.println("use_kprime: " + use_kprime);
        byte[] kbar = ctselect(kprime, s, use_kprime);
        System.out.println("kbar: " + ByteUtils.toHexString(kbar));

        // 17. ss = SHAKE(c1 || c2 || kbar, len_ss) (length in bits)
        digest.update(ByteUtils.concatenate(ByteUtils.concatenate(c1, c2), kbar), 0, c1.length + c2.length + kbar.length);
        digest.doFinal(ss, 0, len_ss_bytes);
        System.out.println("ss: " + ByteUtils.toHexString(ss));
    }

}