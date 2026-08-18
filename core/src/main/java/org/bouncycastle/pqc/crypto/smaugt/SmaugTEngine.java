package org.bouncycastle.pqc.crypto.smaugt;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * Reference implementation of SMAUG-T KEM, translated from the SMAUG-T 1.2.0 C
 * reference code.
 * <p>
 * <b>Must remain immutable.</b> SmaugTParameters holds one instance per parameter set for the life
 * of the JVM and hands it to every extractor, generator and key pair generator, so this class is
 * shared across threads. javax.crypto.KEM requires a Decapsulator to be safe for concurrent use and
 * SmaugTKEMExtractor relies on that sharing being safe. Every field here is final and set at
 * construction, and every operation allocates its own buffers and digests - adding a scratch buffer
 * or a cached digest field would silently corrupt concurrent users rather than fail. If one is ever
 * needed, make getEngine() return a new instance instead.
 */
class SmaugTEngine
{
    // common parameters
    static final int N = 256;
    static final int DELTA_BYTES = N / 8;          // 32
    static final int T_BYTES = N / 8;              // 32
    static final int LOG_T = 1;
    static final int CRYPTO_BYTES = 32;
    static final int PKSEED_BYTES = 32;
    static final int SKPOLY_BYTES = N / 4;         // 64
    static final int MODULUS_16_LOG_T = 16 - LOG_T; // 15
    static final int DEC_ADD = 0x4000;             // 2^(15-LOG_T)
    static final int SHA3_256_HASH_SIZE = 32;

    // discrete gaussian
    static final int DG_RAND_BITS = 10;
    static final int DG_SLEN = 2;
    static final int DG_SEED_LEN = DG_RAND_BITS * N / 64; // = 40

    // hwt sampling
    static final int HWTSEEDBYTES = (16 * 308) / 8; // = 616

    // mode-T constant
    static final int MODULUS_SCALED_Q_HALF = 32767;

    private final int mode;

    // mode-specific
    private final int K;
    private final int LOG_Q;
    private final int LOG_P;
    private final int LOG_P_PRIME;
    private final int CBDSEED_BYTES;
    private final int MSG_BYTES;
    private final int HS;
    private final int RD_ADD;
    private final int RD_AND;
    private final int RD_ADD2;
    private final int RD_AND2;

    // derived
    private final int MODULUS_16_LOG_Q;
    private final int MODULUS_16_LOG_P;
    private final int MODULUS_16_LOG_P_PRIME;
    private final int PKPOLY_BYTES;
    private final int PKPOLYVEC_BYTES;
    private final int PUBLICKEY_BYTES;
    private final int SKPOLYVEC_BYTES;
    private final int PKE_SECRETKEY_BYTES;
    private final int KEM_SECRETKEY_BYTES;
    private final int CTPOLY1_BYTES;
    private final int CTPOLY2_BYTES;
    private final int CTPOLYVEC_BYTES;
    private final int CIPHERTEXT_BYTES;

    SmaugTEngine(int mode)
    {
        this.mode = mode;
        switch (mode)
        {
        case SmaugTParameters.MODE1:
            K = 2;
            LOG_Q = 10;
            LOG_P = 8;
            LOG_P_PRIME = 5;
            CBDSEED_BYTES = (3 * N) / 8;
            MSG_BYTES = DELTA_BYTES;
            HS = 70;
            RD_ADD = 0x80;
            RD_AND = 0xff00;
            RD_ADD2 = 0x0400;
            RD_AND2 = 0xf800;
            break;
        case SmaugTParameters.MODE3:
            K = 3;
            LOG_Q = 11;
            LOG_P = 9;
            LOG_P_PRIME = 4;
            CBDSEED_BYTES = (2 * N) / 8;
            MSG_BYTES = DELTA_BYTES;
            HS = 88;
            RD_ADD = 0x40;
            RD_AND = 0xff80;
            RD_ADD2 = 0x0800;
            RD_AND2 = 0xf000;
            break;
        case SmaugTParameters.MODE5:
            K = 4;
            LOG_Q = 11;
            LOG_P = 9;
            LOG_P_PRIME = 7;
            CBDSEED_BYTES = (4 * N) / 8;
            MSG_BYTES = DELTA_BYTES;
            HS = 87;
            RD_ADD = 0x40;
            RD_AND = 0xff80;
            RD_ADD2 = 0x0100;
            RD_AND2 = 0xfe00;
            break;
        case SmaugTParameters.MODET:
            K = 2;
            LOG_Q = 10;
            LOG_P = 8;
            LOG_P_PRIME = 3;
            CBDSEED_BYTES = (3 * N) / 8;
            MSG_BYTES = 16;
            HS = 70;
            RD_ADD = 0x80;
            RD_AND = 0xff00;
            RD_ADD2 = 0x1000;
            RD_AND2 = 0xe000;
            break;
        default:
            throw new IllegalArgumentException("invalid SMAUG-T mode");
        }

        MODULUS_16_LOG_Q = 16 - LOG_Q;
        MODULUS_16_LOG_P = 16 - LOG_P;
        MODULUS_16_LOG_P_PRIME = 16 - LOG_P_PRIME;
        PKPOLY_BYTES = (LOG_Q * N) / 8;
        PKPOLYVEC_BYTES = PKPOLY_BYTES * K;
        PUBLICKEY_BYTES = PKSEED_BYTES + PKPOLYVEC_BYTES;
        SKPOLYVEC_BYTES = SKPOLY_BYTES * K;
        PKE_SECRETKEY_BYTES = SKPOLYVEC_BYTES;
        KEM_SECRETKEY_BYTES = PKE_SECRETKEY_BYTES + T_BYTES + PUBLICKEY_BYTES;
        CTPOLY1_BYTES = (LOG_P * N) / 8;
        CTPOLY2_BYTES = (LOG_P_PRIME * N) / 8;
        CTPOLYVEC_BYTES = CTPOLY1_BYTES * K;
        CIPHERTEXT_BYTES = CTPOLYVEC_BYTES + CTPOLY2_BYTES;
    }

    int getPublicKeyBytes()
    {
        return PUBLICKEY_BYTES;
    }

    int getKemSecretKeyBytes()
    {
        return KEM_SECRETKEY_BYTES;
    }

    int getCipherTextBytes()
    {
        return CIPHERTEXT_BYTES;
    }

    int getSharedSecretBytes()
    {
        return CRYPTO_BYTES;
    }

    // ============================================================
    // KEM-level API
    // ============================================================

    void cryptoKemKeypair(byte[] pk, byte[] sk, SecureRandom random)
    {
        byte[] d = new byte[T_BYTES];
        byte[] seed = new byte[CRYPTO_BYTES];
        random.nextBytes(d);
        random.nextBytes(seed);
        cryptoKemKeypairInternal(pk, sk, d, seed);
    }

    void cryptoKemKeypairInternal(byte[] pk, byte[] sk, byte[] d, byte[] seed)
    {
        indcpaKeypair(pk, sk, seed);
        System.arraycopy(d, 0, sk, PKE_SECRETKEY_BYTES, T_BYTES);
        System.arraycopy(pk, 0, sk, PKE_SECRETKEY_BYTES + T_BYTES, PUBLICKEY_BYTES);
    }

    void cryptoKemEnc(byte[] ctxt, byte[] ss, byte[] pk, SecureRandom random)
    {
        byte[] mu = new byte[MSG_BYTES];
        random.nextBytes(mu);
        cryptoKemEncInternal(ctxt, ss, pk, mu);
    }

    void cryptoKemEncInternal(byte[] ctxt, byte[] ss, byte[] pk, byte[] mu)
    {
        byte[] seed_r = new byte[DELTA_BYTES + CRYPTO_BYTES];
        // hash_h(seed_r, pk, PUBLICKEY_BYTES) == sha3_256
        sha3_256(seed_r, 0, pk, 0, PUBLICKEY_BYTES);
        // hash_g(seed_r, DELTA+CRYPTO, mu, MSG_BYTES, seed_r, SHA3_256_HASH_SIZE)
        // hash_g is shake256_absorb_twice_squeeze; in_2 is the seed_r[:32]
        byte[] in2 = new byte[SHA3_256_HASH_SIZE];
        System.arraycopy(seed_r, 0, in2, 0, SHA3_256_HASH_SIZE);
        shake256AbsorbTwiceSqueeze(seed_r, DELTA_BYTES + CRYPTO_BYTES, mu, MSG_BYTES, in2, SHA3_256_HASH_SIZE);

        // ss = 0
        java.util.Arrays.fill(ss, 0, CRYPTO_BYTES, (byte)0);
        indcpaEnc(ctxt, pk, mu, seed_r); // seed for r is first DELTA_BYTES of seed_r
        // cmov(ss, seed_r+DELTA, CRYPTO, 1)  => copy
        System.arraycopy(seed_r, DELTA_BYTES, ss, 0, CRYPTO_BYTES);
    }

    void cryptoKemDec(byte[] ss, byte[] ctxt, byte[] sk)
    {
        byte[] mu = new byte[MSG_BYTES];
        byte[] buf = new byte[DELTA_BYTES + CRYPTO_BYTES];
        byte[] bufTmp = new byte[DELTA_BYTES + CRYPTO_BYTES];
        byte[] hashRes = new byte[SHA3_256_HASH_SIZE];
        int pkOff = PKE_SECRETKEY_BYTES + T_BYTES;

        indcpaDec(mu, sk, ctxt);
        // hash_h(hashRes, pk, PUBLICKEY_BYTES)
        sha3_256(hashRes, 0, sk, pkOff, PUBLICKEY_BYTES);
        // hash_g(buf, ..., mu, MSG_BYTES, hashRes, 32)
        shake256AbsorbTwiceSqueeze(buf, DELTA_BYTES + CRYPTO_BYTES, mu, MSG_BYTES, hashRes, SHA3_256_HASH_SIZE);

        byte[] ctxtTemp = new byte[CIPHERTEXT_BYTES];
        // indcpa_enc with pk=sk+offset, mu, buf as seed_r
        indcpaEncWithPkOffset(ctxtTemp, sk, pkOff, mu, buf);

        int fail = verify(ctxt, 0, ctxtTemp, 0, CIPHERTEXT_BYTES);

        sha3_256(hashRes, 0, ctxt, 0, CIPHERTEXT_BYTES);
        // sk + PKE_SECRETKEY_BYTES is the t value (T_BYTES long)
        byte[] tArr = new byte[T_BYTES];
        System.arraycopy(sk, PKE_SECRETKEY_BYTES, tArr, 0, T_BYTES);
        shake256AbsorbTwiceSqueeze(bufTmp, DELTA_BYTES + CRYPTO_BYTES, tArr, T_BYTES, hashRes, SHA3_256_HASH_SIZE);

        java.util.Arrays.fill(ss, 0, CRYPTO_BYTES, (byte)0);
        // cmov(buf+DELTA, bufTmp+DELTA, CRYPTO, fail)
        cmov(buf, DELTA_BYTES, bufTmp, DELTA_BYTES, CRYPTO_BYTES, (byte)fail);
        // cmov(ss, buf+DELTA, CRYPTO, 1)
        System.arraycopy(buf, DELTA_BYTES, ss, 0, CRYPTO_BYTES);
    }

    // ============================================================
    // IND-CPA PKE
    // ============================================================

    private void indcpaKeypair(byte[] pk, byte[] sk, byte[] seed)
    {
        // sha3_512(extseed, seed, CRYPTO_BYTES)
        byte[] extseed = new byte[CRYPTO_BYTES + PKSEED_BYTES]; // 64
        sha3_512(extseed, 0, seed, 0, CRYPTO_BYTES);

        // secret_key (vector of K polys)
        short[][] skVec = new short[K][N];
        expand_s(skVec, extseed);

        // public_key: seed = extseed[32:64], A[K][K], b[K]
        byte[] pkSeed = new byte[PKSEED_BYTES];
        System.arraycopy(extseed, CRYPTO_BYTES, pkSeed, 0, PKSEED_BYTES);

        short[][][] A = new short[K][K][N];
        short[][] b = new short[K][N];
        expand_A(A, pkSeed);
        // b = -A*s + e
        d_gaussian(b, extseed); // err_seed is extseed (first CRYPTO_BYTES used inside)
        matrix_vec_mult_sub(b, A, skVec);

        // pack pk = (seed || pack_ring_vec(b))
        pack_enck(pk, pkSeed, b);
        // pack sk = pack_deck(s)
        pack_deck(sk, skVec);
    }

    private void indcpaEnc(byte[] ctxt, byte[] pk, byte[] mu, byte[] seed_r)
    {
        indcpaEncWithPkOffset(ctxt, pk, 0, mu, seed_r);
    }

    private void indcpaEncWithPkOffset(byte[] ctxt, byte[] pkArr, int pkOff, byte[] mu, byte[] seed_r)
    {
        // unpack_enck
        byte[] pkSeed = new byte[PKSEED_BYTES];
        System.arraycopy(pkArr, pkOff, pkSeed, 0, PKSEED_BYTES);

        short[][][] A = new short[K][K][N];
        expand_A(A, pkSeed);
        short[][] b = new short[K][N];
        unpack_ring_vec(b, pkArr, pkOff + PKSEED_BYTES);

        // seed_r is non-null (provided by KEM caller).
        byte[] seedR = new byte[DELTA_BYTES];
        System.arraycopy(seed_r, 0, seedR, 0, DELTA_BYTES);

        short[][] r = new short[K][N];
        expand_r(r, seedR);

        short[][] c1 = new short[K][N];
        short[] c2 = new short[N];
        computeC1(c1, A, r);
        computeC2(c2, mu, b, r);

        pack_ct(ctxt, c1, c2);
    }

    private void indcpaDec(byte[] mu, byte[] sk, byte[] ctxt)
    {
        short[][] skVec = new short[K][N];
        unpack_deck(skVec, sk, 0);

        short[][] c1 = new short[K][N];
        short[] c2 = new short[N];
        unpack_ct(c1, c2, ctxt);

        short[] delta = c2;
        for (int i = 0; i < N; ++i)
        {
            delta[i] = (short)(delta[i] << MODULUS_16_LOG_P_PRIME);
        }
        for (int i = 0; i < K; ++i)
        {
            for (int j = 0; j < N; ++j)
            {
                c1[i][j] = (short)(c1[i][j] << MODULUS_16_LOG_P);
            }
        }

        vec_vec_mult_add(delta, c1, skVec, MODULUS_16_LOG_P);

        if (mode == SmaugTParameters.MODET)
        {
            d2_dcd(mu, delta);
        }
        else
        {
            // delta = 2/p * delta with rounding
            short[] tmp = new short[N];
            for (int i = 0; i < N; ++i)
            {
                int v = (delta[i] & 0xFFFF) + DEC_ADD;
                v = (v & 0xFFFF) >>> MODULUS_16_LOG_T;
                tmp[i] = (short)(v & 0x01);
            }
            java.util.Arrays.fill(mu, (byte)0);
            for (int i = 0; i < MSG_BYTES; ++i)
            {
                int b = 0;
                for (int j = 0; j < 8; ++j)
                {
                    b ^= ((tmp[8 * i + j] & 0xFF) << j);
                }
                mu[i] = (byte)b;
            }
        }
    }

    // ============================================================
    // expand_A / expand_s / expand_b / expand_r
    // ============================================================

    private void expand_A(short[][][] A, byte[] seed)
    {
        byte[] extseed = new byte[PKSEED_BYTES + 2];
        System.arraycopy(seed, 0, extseed, 0, PKSEED_BYTES);

        byte[] buf = new byte[PKPOLY_BYTES];
        for (int i = 0; i < K; ++i)
        {
            for (int j = 0; j < K; ++j)
            {
                extseed[32] = (byte)i;
                extseed[33] = (byte)j;
                shake128(buf, PKPOLY_BYTES, extseed, PKSEED_BYTES + 2);
                unpack_ring(A[i][j], buf, 0);
            }
        }
    }

    private void expand_s(short[][] s, byte[] seed)
    {
        byte[] extseed = new byte[CRYPTO_BYTES + 2];
        System.arraycopy(seed, 0, extseed, 0, CRYPTO_BYTES);
        for (int i = 0; i < K; ++i)
        {
            extseed[CRYPTO_BYTES] = (byte)(i * K);
            int j = 0;
            int rv;
            do
            {
                extseed[CRYPTO_BYTES + 1] = (byte)j;
                j += 1;
                rv = hwt(s[i], extseed);
            }
            while (rv != 0);
        }
    }

    private void expand_r(short[][] r, byte[] seed)
    {
        byte[] buf = new byte[CBDSEED_BYTES];
        byte[] extseed = new byte[DELTA_BYTES + 1];
        System.arraycopy(seed, 0, extseed, 0, DELTA_BYTES);
        for (int i = 0; i < K; ++i)
        {
            extseed[DELTA_BYTES] = (byte)i;
            shake256(buf, CBDSEED_BYTES, extseed, DELTA_BYTES + 1);
            sp_cbd(r[i], buf);
        }
    }

    // ============================================================
    // HWT sampling
    // ============================================================

    private int hwt(short[] res, byte[] seed)
    {
        short[] si = new short[N];
        int[] rand = new int[HWTSEEDBYTES / 2]; // uint16_t values
        byte[] sign = new byte[N / 4];
        byte[] buf = new byte[HWTSEEDBYTES];

        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(seed, 0, CRYPTO_BYTES + 2);
        shake.doOutput(buf, 0, HWTSEEDBYTES);
        // load 2-byte little-endian into rand
        for (int i = 0; i < HWTSEEDBYTES / 2; ++i)
        {
            rand[i] = (buf[2 * i] & 0xFF) | ((buf[2 * i + 1] & 0xFF) << 8);
        }
        if (rej_sample_mod(si, rand) != 0)
        {
            return -1;
        }
        shake.doOutput(sign, 0, N / 4);

        int c0 = N - HS;
        for (int i = 0; i < N; ++i)
        {
            int t0 = (si[i] - c0) >> 15;
            c0 += t0;
            int ri = 1 + t0;
            int signByte = sign[(((i >> 4) >> 3) << 4) + (i & 0x0F)] & 0xFF;
            int bit = (signByte >> ((i >> 4) & 0x07)) & 0x01;
            int mask = ((bit << 1) & 0x02) - 1; // -1 or +1
            res[i] = (short)(((-ri) & 0xFFFF) & (mask & 0xFFFF));
        }
        return 0;
    }

    private int rej_sample_mod(short[] si, int[] rand)
    {
        int j = N;
        for (int i = 0; i < N; ++i)
        {
            int s = N - i;
            int t = 65536 % s;
            long m = (long)(rand[i] & 0xFFFF) * s;
            int l = (int)(m & 0xFFFF);
            while (l < t)
            {
                if (j >= (HWTSEEDBYTES / 2))
                {
                    return -1;
                }
                m = (long)(rand[j++] & 0xFFFF) * s;
                l = (int)(m & 0xFFFF);
            }
            si[i] = (short)((m >>> 16) & 0xFFFF);
        }
        return 0;
    }

    // ============================================================
    // CBD sampling
    // ============================================================

    private void sp_cbd(short[] r, byte[] buf)
    {
        if (mode == SmaugTParameters.MODE1 || mode == SmaugTParameters.MODET)
        {
            sp_cbd1(r, buf);
        }
        else if (mode == SmaugTParameters.MODE3)
        {
            cbd(r, buf);
        }
        else // MODE5
        {
            sp_cbd2(r, buf);
        }
    }

    private void sp_cbd1(short[] r, byte[] buf)
    {
        for (int i = 0; i < N / 8; ++i)
        {
            long t = load24_le(buf, 3 * i);
            long d = t & 0x00249249L;
            d &= (t >>> 1) & 0x00249249L;
            long s = (t >>> 2) & 0x00249249L;
            for (int j = 0; j < 8; ++j)
            {
                int a = (int)((d >>> (3 * j)) & 0x1);
                int sj = (int)((s >>> (3 * j)) & 0x1);
                // a * (((((s >> (3j)) & 0x1) - 1) ^ -2) | 1)
                int v = a * ((((sj - 1) ^ -2) | 1));
                r[8 * i + j] = (short)v;
            }
        }
    }

    private void cbd(short[] r, byte[] buf)
    {
        for (int i = 0; i < N / 16; ++i)
        {
            long t = load32_le(buf, 4 * i);
            for (int j = 0; j < 16; ++j)
            {
                int a = (int)((t >>> (2 * j)) & 0x01);
                int b = (int)((t >>> (2 * j + 1)) & 0x01);
                r[16 * i + j] = (short)(a - b);
            }
        }
    }

    private void sp_cbd2(short[] r, byte[] buf)
    {
        for (int i = 0; i < N / 8; ++i)
        {
            long t = load32_le(buf, 4 * i);
            long d = t & 0x11111111L;
            d |= (t >>> 1) & 0x11111111L;
            d &= (t >>> 2) & 0x11111111L;
            long s = (t >>> 3) & 0x11111111L;
            for (int j = 0; j < 8; ++j)
            {
                int a = (int)((d >>> (4 * j)) & 0x1);
                int sj = (int)((s >>> (4 * j)) & 0x1);
                int v = a * ((((sj - 1) ^ -2) | 1));
                r[8 * i + j] = (short)v;
            }
        }
    }

    private static long load24_le(byte[] x, int off)
    {
        return ((long)(x[off] & 0xFF))
            | ((long)(x[off + 1] & 0xFF) << 8)
            | ((long)(x[off + 2] & 0xFF) << 16);
    }

    private static long load32_le(byte[] x, int off)
    {
        return ((long)(x[off] & 0xFF))
            | ((long)(x[off + 1] & 0xFF) << 8)
            | ((long)(x[off + 2] & 0xFF) << 16)
            | ((long)(x[off + 3] & 0xFF) << 24);
    }

    // ============================================================
    // Discrete Gaussian
    // ============================================================

    private void d_gaussian(short[][] op, byte[] seed)
    {
        byte[] extseed = new byte[CRYPTO_BYTES + 1];
        System.arraycopy(seed, 0, extseed, 0, CRYPTO_BYTES);
        for (int i = 0; i < K; ++i)
        {
            extseed[CRYPTO_BYTES] = (byte)(K * i);
            d_gaussian_poly(op[i], extseed);
        }
    }

    private void d_gaussian_poly(short[] op, byte[] seed)
    {
        long[] seedTemp = new long[DG_SEED_LEN];
        byte[] buf = new byte[DG_SEED_LEN * 8];
        long[] s = new long[DG_SLEN];

        shake256(buf, DG_SEED_LEN * 8, seed, CRYPTO_BYTES + 1);
        load64_le_block(seedTemp, DG_SEED_LEN, buf);

        int j = 0;
        for (int i = 0; i < N; i += 64)
        {
            long x0 = seedTemp[j];
            long x1 = seedTemp[j + 1];
            long x2 = seedTemp[j + 2];
            long x3 = seedTemp[j + 3];
            long x4 = seedTemp[j + 4];
            long x5 = seedTemp[j + 5];
            long x6 = seedTemp[j + 6];
            long x7 = seedTemp[j + 7];
            long x8 = seedTemp[j + 8];
            long x9 = seedTemp[j + 9];

            s[0] = (x0 & x1 & x2 & x3 & x4 & x5 & x7 & ~x8) |
                (x0 & x3 & x4 & x5 & x6 & x8) |
                (x1 & x3 & x4 & x5 & x6 & x8) |
                (x2 & x3 & x4 & x5 & x6 & x8) |
                (~x2 & ~x3 & ~x6 & x8) | (~x1 & ~x3 & ~x6 & x8) |
                (x6 & x7 & ~x8) | (~x5 & ~x6 & x8) |
                (~x4 & ~x6 & x8) | (~x7 & x8);
            s[1] = (x1 & x2 & x4 & x5 & x7 & x8) |
                (x3 & x4 & x5 & x7 & x8) | (x6 & x7 & x8);

            for (int k = 0; k < 64; ++k)
            {
                int v = (int)(((s[0] >>> k) & 0x01) | (((s[1] >>> k) & 0x01) << 1));
                int sign = (int)((x9 >>> k) & 0x01);
                int signed = ((-sign) ^ v) + sign;
                op[i + k] = (short)(signed << MODULUS_16_LOG_Q);
            }
            j += DG_RAND_BITS;
        }
    }

    private static void load64_le_block(long[] out, int outlen, byte[] in)
    {
        int pos = 0;
        for (int i = 0; i < outlen / 10; ++i)
        {
            for (int jj = 0; jj < 10; ++jj)
            {
                out[10 * i + jj] =
                    ((long)(in[pos + jj] & 0xFF))
                        | ((long)(in[pos + 10 + jj] & 0xFF) << 8)
                        | ((long)(in[pos + 20 + jj] & 0xFF) << 16)
                        | ((long)(in[pos + 30 + jj] & 0xFF) << 24)
                        | ((long)(in[pos + 40 + jj] & 0xFF) << 32)
                        | ((long)(in[pos + 50 + jj] & 0xFF) << 40)
                        | ((long)(in[pos + 60 + jj] & 0xFF) << 48)
                        | ((long)(in[pos + 70 + jj] & 0xFF) << 56);
            }
            pos += 80;
        }
    }

    // ============================================================
    // poly / polyvec / matrix arithmetic
    // ============================================================

    private void vec_vec_mult_add(short[] r, short[][] a, short[][] b, int mod)
    {
        short[][] al = new short[K][N];
        for (int i = 0; i < K; ++i)
        {
            for (int j = 0; j < N; ++j)
            {
                al[i][j] = (short)((a[i][j] & 0xFFFF) >>> mod);
            }
        }
        short[] res = new short[N];
        vec_vec_mult(res, al, b);
        for (int j = 0; j < N; ++j)
        {
            res[j] = (short)(res[j] << mod);
        }
        for (int j = 0; j < N; ++j)
        {
            r[j] = (short)(r[j] + res[j]);
        }
    }

    private void matrix_vec_mult_add(short[][] r, short[][][] a, short[][] b)
    {
        for (int i = 0; i < K; ++i)
        {
            short[][] at = new short[K][N];
            for (int j = 0; j < K; ++j)
            {
                for (int k = 0; k < N; ++k)
                {
                    at[j][k] = (short)((a[j][i][k] & 0xFFFF) >>> MODULUS_16_LOG_Q);
                }
            }
            vec_vec_mult(r[i], at, b);
            for (int j = 0; j < N; ++j)
            {
                r[i][j] = (short)(r[i][j] << MODULUS_16_LOG_Q);
            }
        }
    }

    private void matrix_vec_mult_sub(short[][] r, short[][][] a, short[][] b)
    {
        for (int i = 0; i < K; ++i)
        {
            short[][] al = new short[K][N];
            for (int j = 0; j < K; ++j)
            {
                for (int k = 0; k < N; ++k)
                {
                    al[j][k] = (short)((a[i][j][k] & 0xFFFF) >>> MODULUS_16_LOG_Q);
                }
            }
            short[] res = new short[N];
            vec_vec_mult(res, al, b);
            for (int j = 0; j < N; ++j)
            {
                res[j] = (short)(res[j] << MODULUS_16_LOG_Q);
            }
            for (int j = 0; j < N; ++j)
            {
                r[i][j] = (short)(r[i][j] - res[j]);
            }
        }
    }

    private void vec_vec_mult(short[] r, short[][] a, short[][] b)
    {
        for (int i = 0; i < K; ++i)
        {
            poly_mul_acc(a[i], b[i], r);
        }
    }

    // ============================================================
    // Toom-Cook 4-way polynomial multiplication
    // ============================================================

    private static final int KARATSUBA_N = 64;
    private static final int N_SB = N >> 2;        // 64
    private static final int N_SB_RES = 2 * N_SB - 1; // 127

    static void poly_mul_acc(short[] a, short[] b, short[] res)
    {
        short[] c = new short[2 * N];
        toom_cook_4way(a, b, c);
        // res[i - N] += (c[i - N] - c[i])
        for (int i = N; i < 2 * N; ++i)
        {
            res[i - N] = (short)(res[i - N] + (c[i - N] - c[i]));
        }
    }

    private static void karatsuba_simple(short[] a1, short[] b1, short[] result_final)
    {
        // Q = KARATSUBA_N / 4 = 16. All operations below are +/-/* only (no
        // right shifts), so every value is correct modulo 2^16 regardless of
        // intermediate int overflow (2^16 divides 2^32) or sign-extension of
        // the 16-bit inputs. We therefore accumulate in int[], skip the
        // per-step (short) truncations and the redundant & 0xFFFF masks on
        // addition results, and truncate to 16 bits only when writing the
        // short[] output. The a-derived sums depend only on i and are hoisted
        // out of the inner loop. Byte-identical to the reference.
        final int Q = KARATSUBA_N / 4;

        int[] rf = new int[2 * KARATSUBA_N - 1];
        int[] rd = new int[KARATSUBA_N - 1];
        int[] d01 = new int[KARATSUBA_N / 2 - 1];
        int[] d0123 = new int[KARATSUBA_N / 2 - 1];
        int[] d23 = new int[KARATSUBA_N / 2 - 1];

        for (int i = 0; i < Q; ++i)
        {
            int a1v = a1[i] & 0xFFFF;
            int a2v = a1[i + Q] & 0xFFFF;
            int a3v = a1[i + 2 * Q] & 0xFFFF;
            int a4v = a1[i + 3 * Q] & 0xFFFF;
            // a-derived sums depend only on i: hoist out of the inner loop
            int a12 = a1v + a2v;
            int a34 = a3v + a4v;
            int a13 = a1v + a3v;
            int a24 = a2v + a4v;
            int a1234 = a13 + a24;
            for (int j = 0; j < Q; ++j)
            {
                int b5 = b1[j] & 0xFFFF;
                int b6 = b1[j + Q] & 0xFFFF;
                int b7 = b1[j + 2 * Q] & 0xFFFF;
                int b8 = b1[j + 3 * Q] & 0xFFFF;
                int b5c = b5 + b7;
                int b6c = b6 + b8;
                int idx = i + j;
                rf[idx] += a1v * b5;
                rf[idx + 2 * Q] += a2v * b6;
                d01[idx] += (b5 + b6) * a12;
                rf[idx + 4 * Q] += b7 * a3v;
                rf[idx + 6 * Q] += b8 * a4v;
                d23[idx] += a34 * (b7 + b8);
                rd[idx] += b5c * a13;
                rd[idx + 2 * Q] += b6c * a24;
                d0123[idx] += (b5c + b6c) * a1234;
            }
        }

        for (int i = 0; i < KARATSUBA_N / 2 - 1; ++i)
        {
            d0123[i] = d0123[i] - rd[i] - rd[i + 2 * Q];
            d01[i] = d01[i] - rf[i] - rf[i + 2 * Q];
            d23[i] = d23[i] - rf[i + 4 * Q] - rf[i + 6 * Q];
        }
        for (int i = 0; i < KARATSUBA_N / 2 - 1; ++i)
        {
            rd[i + Q] += d0123[i];
            rf[i + Q] += d01[i];
            rf[i + 5 * Q] += d23[i];
        }
        for (int i = 0; i < KARATSUBA_N - 1; ++i)
        {
            rd[i] = rd[i] - rf[i] - rf[i + KARATSUBA_N];
        }
        for (int i = 0; i < KARATSUBA_N - 1; ++i)
        {
            rf[i + KARATSUBA_N / 2] += rd[i];
        }

        for (int i = 0; i < 2 * KARATSUBA_N - 1; ++i)
        {
            result_final[i] = (short)rf[i];
        }
    }

    private static void toom_cook_4way(short[] a1, short[] b1, short[] C)
    {
        final int inv3 = 43691, inv9 = 36409, inv15 = 61167;

        short[] aw1 = new short[N_SB], aw2 = new short[N_SB], aw3 = new short[N_SB], aw4 = new short[N_SB];
        short[] aw5 = new short[N_SB], aw6 = new short[N_SB], aw7 = new short[N_SB];
        short[] bw1 = new short[N_SB], bw2 = new short[N_SB], bw3 = new short[N_SB], bw4 = new short[N_SB];
        short[] bw5 = new short[N_SB], bw6 = new short[N_SB], bw7 = new short[N_SB];
        short[] w1 = new short[N_SB_RES], w2 = new short[N_SB_RES], w3 = new short[N_SB_RES];
        short[] w4 = new short[N_SB_RES], w5 = new short[N_SB_RES], w6 = new short[N_SB_RES], w7 = new short[N_SB_RES];

        // EVALUATION (a)
        for (int j = 0; j < N_SB; ++j)
        {
            int r0 = a1[j] & 0xFFFF;
            int r1 = a1[N_SB + j] & 0xFFFF;
            int r2 = a1[2 * N_SB + j] & 0xFFFF;
            int r3 = a1[3 * N_SB + j] & 0xFFFF;
            int r4 = (r0 + r2) & 0xFFFF;
            int r5 = (r1 + r3) & 0xFFFF;
            int r6 = (r4 + r5) & 0xFFFF;
            int r7 = (r4 - r5) & 0xFFFF;
            aw3[j] = (short)r6;
            aw4[j] = (short)r7;
            int r4b = (((r0 << 2) + r2) << 1) & 0xFFFF;
            int r5b = ((r1 << 2) + r3) & 0xFFFF;
            int r6b = (r4b + r5b) & 0xFFFF;
            int r7b = (r4b - r5b) & 0xFFFF;
            aw5[j] = (short)r6b;
            aw6[j] = (short)r7b;
            int r4c = ((r3 << 3) + (r2 << 2) + (r1 << 1) + r0) & 0xFFFF;
            aw2[j] = (short)r4c;
            aw7[j] = (short)r0;
            aw1[j] = (short)r3;
        }
        // EVALUATION (b)
        for (int j = 0; j < N_SB; ++j)
        {
            int r0 = b1[j] & 0xFFFF;
            int r1 = b1[N_SB + j] & 0xFFFF;
            int r2 = b1[2 * N_SB + j] & 0xFFFF;
            int r3 = b1[3 * N_SB + j] & 0xFFFF;
            int r4 = (r0 + r2) & 0xFFFF;
            int r5 = (r1 + r3) & 0xFFFF;
            int r6 = (r4 + r5) & 0xFFFF;
            int r7 = (r4 - r5) & 0xFFFF;
            bw3[j] = (short)r6;
            bw4[j] = (short)r7;
            int r4b = (((r0 << 2) + r2) << 1) & 0xFFFF;
            int r5b = ((r1 << 2) + r3) & 0xFFFF;
            int r6b = (r4b + r5b) & 0xFFFF;
            int r7b = (r4b - r5b) & 0xFFFF;
            bw5[j] = (short)r6b;
            bw6[j] = (short)r7b;
            int r4c = ((r3 << 3) + (r2 << 2) + (r1 << 1) + r0) & 0xFFFF;
            bw2[j] = (short)r4c;
            bw7[j] = (short)r0;
            bw1[j] = (short)r3;
        }

        // MULTIPLICATION
        karatsuba_simple(aw1, bw1, w1);
        karatsuba_simple(aw2, bw2, w2);
        karatsuba_simple(aw3, bw3, w3);
        karatsuba_simple(aw4, bw4, w4);
        karatsuba_simple(aw5, bw5, w5);
        karatsuba_simple(aw6, bw6, w6);
        karatsuba_simple(aw7, bw7, w7);

        // INTERPOLATION
        for (int i = 0; i < N_SB_RES; ++i)
        {
            int r0 = w1[i] & 0xFFFF;
            int r1 = w2[i] & 0xFFFF;
            int r2 = w3[i] & 0xFFFF;
            int r3 = w4[i] & 0xFFFF;
            int r4 = w5[i] & 0xFFFF;
            int r5 = w6[i] & 0xFFFF;
            int r6 = w7[i] & 0xFFFF;

            r1 = (r1 + r4) & 0xFFFF;
            r5 = (r5 - r4) & 0xFFFF;
            // r3 = ((r3 - r2) >> 1)   -- shift of uint16
            r3 = (((r3 - r2) & 0xFFFF) >>> 1) & 0xFFFF;
            r4 = (r4 - r0) & 0xFFFF;
            r4 = (r4 - (r6 << 6)) & 0xFFFF;
            r4 = ((r4 << 1) + r5) & 0xFFFF;
            r2 = (r2 + r3) & 0xFFFF;
            r1 = (r1 - (r2 << 6) - r2) & 0xFFFF;
            r2 = (r2 - r6) & 0xFFFF;
            r2 = (r2 - r0) & 0xFFFF;
            r1 = (r1 + 45 * r2) & 0xFFFF;
            // r4 = (uint16_t)(((r4 - (r2 << 3)) * (uint32_t)inv3) >> 3);
            r4 = ((((r4 - (r2 << 3)) & 0xFFFF) * inv3) >>> 3) & 0xFFFF;
            r5 = (r5 + r1) & 0xFFFF;
            // r1 = (uint16_t)(((r1 + (r3 << 4)) * (uint32_t)inv9) >> 1);
            r1 = ((((r1 + (r3 << 4)) & 0xFFFF) * inv9) >>> 1) & 0xFFFF;
            r3 = (-(r3 + r1)) & 0xFFFF;
            // r5 = (uint16_t)(((30 * r1 - r5) * (uint32_t)inv15) >> 2);
            r5 = ((((30 * r1 - r5) & 0xFFFF) * inv15) >>> 2) & 0xFFFF;
            r2 = (r2 - r4) & 0xFFFF;
            r1 = (r1 - r5) & 0xFFFF;

            C[i] = (short)(C[i] + r6);
            C[i + 64] = (short)(C[i + 64] + r5);
            C[i + 128] = (short)(C[i + 128] + r4);
            C[i + 192] = (short)(C[i + 192] + r3);
            C[i + 256] = (short)(C[i + 256] + r2);
            C[i + 320] = (short)(C[i + 320] + r1);
            C[i + 384] = (short)(C[i + 384] + r0);
        }
    }

    // ============================================================
    // computeC1 / computeC2 / D2 encoding
    // ============================================================

    private void computeC1(short[][] c1, short[][][] A, short[][] r)
    {
        matrix_vec_mult_add(c1, A, r);
        // round1
        for (int i = 0; i < K; ++i)
        {
            for (int j = 0; j < N; ++j)
            {
                int v = ((c1[i][j] & 0xFFFF) + RD_ADD) & RD_AND;
                c1[i][j] = (short)((v & 0xFFFF) >>> MODULUS_16_LOG_P);
            }
        }
    }

    private void computeC2(short[] c2, byte[] delta, short[][] b, short[][] r)
    {
        if (mode == SmaugTParameters.MODET)
        {
            d2_ecd(c2, delta);
        }
        else
        {
            for (int i = 0; i < MSG_BYTES; ++i)
            {
                int by = delta[i] & 0xFF;
                for (int j = 0; j < 8; ++j)
                {
                    c2[8 * i + j] = (short)((((by >>> j) & 0x1) << MODULUS_16_LOG_T) & 0xFFFF);
                }
            }
        }
        vec_vec_mult_add(c2, b, r, MODULUS_16_LOG_Q);
        // round2
        for (int i = 0; i < N; ++i)
        {
            int v = ((c2[i] & 0xFFFF) + RD_ADD2) & RD_AND2;
            c2[i] = (short)((v & 0xFFFF) >>> MODULUS_16_LOG_P_PRIME);
        }
    }

    private static void d2_ecd(short[] r, byte[] msg)
    {
        for (int i = 0; i < 16; ++i)
        {
            int by = msg[i] & 0xFF;
            for (int j = 0; j < 8; ++j)
            {
                int mask = (by >>> j) & 1;
                mask = (mask * MODULUS_SCALED_Q_HALF) & MODULUS_SCALED_Q_HALF;
                r[8 * i + j] = (short)mask;
                r[8 * i + j + 128] = (short)mask;
            }
        }
    }

    private static void d2_dcd(byte[] msg, short[] x)
    {
        for (int i = 0; i < 16; ++i)
        {
            msg[i] = 0;
        }
        for (int i = 0; i < N / 2; ++i)
        {
            int t = flipabs(x[i]) & 0xFFFF;
            t = (t + flipabs(x[i + 128])) & 0xFFFF;
            t = (t - MODULUS_SCALED_Q_HALF) & 0xFFFF;
            t >>>= 15;
            msg[i >> 3] |= (byte)(t << (i & 7));
        }
    }

    private static int flipabs(short xs)
    {
        int x = xs & 0xFFFF;
        int r = (x - MODULUS_SCALED_Q_HALF);
        // C: int16_t r = x - Q/2; m = r >> 15; return (r + m) ^ m;
        // Use 16-bit arithmetic semantics
        short r16 = (short)r;
        int m = r16 >> 15; // arithmetic shift of signed 16-bit -> sign-extend (-1 or 0)
        return ((r16 + m) ^ m) & 0xFFFF;
    }

    // ============================================================
    // pack / unpack
    // ============================================================

    private void pack_enck(byte[] output, byte[] pkSeed, short[][] b)
    {
        System.arraycopy(pkSeed, 0, output, 0, PKSEED_BYTES);
        pack_ring_vec(output, PKSEED_BYTES, b);
    }

    private void pack_deck(byte[] output, short[][] sk)
    {
        for (int i = 0; i < K; ++i)
        {
            pack_s_poly(output, i * SKPOLY_BYTES, sk[i]);
        }
    }

    private void unpack_deck(short[][] sk, byte[] input, int off)
    {
        for (int i = 0; i < K; ++i)
        {
            unpack_s_poly(sk[i], input, off + i * SKPOLY_BYTES);
        }
    }

    private static void pack_s_poly(byte[] bytes, int off, short[] s)
    {
        for (int i = 0; i < N / 4; ++i)
        {
            int d = i * 4;
            int v = ((1 - s[d]) & 0x03)
                | (((1 - s[d + 1]) & 0x03) << 2)
                | (((1 - s[d + 2]) & 0x03) << 4)
                | (((1 - s[d + 3]) & 0x03) << 6);
            bytes[off + i] = (byte)v;
        }
    }

    private static void unpack_s_poly(short[] s, byte[] bytes, int off)
    {
        for (int i = 0; i < N / 4; ++i)
        {
            int d = i * 4;
            int b = bytes[off + i] & 0xFF;
            s[d] = (short)(1 - (b & 0x03));
            s[d + 1] = (short)(1 - ((b >>> 2) & 0x03));
            s[d + 2] = (short)(1 - ((b >>> 4) & 0x03));
            s[d + 3] = (short)(1 - ((b >>> 6) & 0x03));
        }
    }

    private void pack_ct(byte[] output, short[][] c1, short[] c2)
    {
        pack_ring_p_vec(output, 0, c1);
        pack_ring_p_prime(output, CTPOLYVEC_BYTES, c2);
    }

    private void unpack_ct(short[][] c1, short[] c2, byte[] input)
    {
        unpack_ring_p_vec(c1, input, 0);
        unpack_ring_p_prime(c2, input, CTPOLYVEC_BYTES);
    }

    private void pack_ring_vec(byte[] bytes, int off, short[][] data)
    {
        for (int i = 0; i < K; ++i)
        {
            pack_ring(bytes, off + i * PKPOLY_BYTES, data[i]);
        }
    }

    private void unpack_ring_vec(short[][] data, byte[] bytes, int off)
    {
        for (int i = 0; i < K; ++i)
        {
            unpack_ring(data[i], bytes, off + i * PKPOLY_BYTES);
        }
    }

    private void pack_ring_p_vec(byte[] bytes, int off, short[][] data)
    {
        for (int i = 0; i < K; ++i)
        {
            pack_ring_p(bytes, off + i * CTPOLY1_BYTES, data[i]);
        }
    }

    private void unpack_ring_p_vec(short[][] data, byte[] bytes, int off)
    {
        for (int i = 0; i < K; ++i)
        {
            unpack_ring_p(data[i], bytes, off + i * CTPOLY1_BYTES);
        }
    }

    private void pack_ring(byte[] bytes, int off, short[] data)
    {
        if (LOG_Q == 10)
        {
            pack_R2_10(bytes, off, data);
        }
        else
        {
            pack_R2_11(bytes, off, data);
        }
    }

    private void unpack_ring(short[] data, byte[] bytes, int off)
    {
        if (LOG_Q == 10)
        {
            unpack_R2_10(data, bytes, off);
        }
        else
        {
            unpack_R2_11(data, bytes, off);
        }
    }

    private void pack_ring_p(byte[] bytes, int off, short[] data)
    {
        if (LOG_P == 8)
        {
            pack_R2_8(bytes, off, data);
        }
        else
        {
            pack_R2_9(bytes, off, data);
        }
    }

    private void unpack_ring_p(short[] data, byte[] bytes, int off)
    {
        if (LOG_P == 8)
        {
            unpack_R2_8(data, bytes, off);
        }
        else
        {
            unpack_R2_9(data, bytes, off);
        }
    }

    private void pack_ring_p_prime(byte[] bytes, int off, short[] data)
    {
        switch (LOG_P_PRIME)
        {
        case 3:
            pack_R2_3(bytes, off, data);
            break;
        case 4:
            pack_R2_4(bytes, off, data);
            break;
        case 5:
            pack_R2_5(bytes, off, data);
            break;
        case 7:
            pack_R2_7(bytes, off, data);
            break;
        }
    }

    private void unpack_ring_p_prime(short[] data, byte[] bytes, int off)
    {
        switch (LOG_P_PRIME)
        {
        case 3:
            unpack_R2_3(data, bytes, off);
            break;
        case 4:
            unpack_R2_4(data, bytes, off);
            break;
        case 5:
            unpack_R2_5(data, bytes, off);
            break;
        case 7:
            unpack_R2_7(data, bytes, off);
            break;
        }
    }

    // --- mode-specific bit-packing routines (pack_R2_*) ---

    private static void pack_R2_3(byte[] bytes, int off, short[] data)
    {
        int b = off;
        for (int d = 0; d < N; d += 8)
        {
            int packed = 0;
            for (int i = 0; i < 8; ++i)
            {
                packed |= ((data[d + i] & 0x0007) << (3 * i));
            }
            bytes[b++] = (byte)(packed & 0xFF);
            bytes[b++] = (byte)((packed >>> 8) & 0xFF);
            bytes[b++] = (byte)((packed >>> 16) & 0xFF);
        }
    }

    private static void unpack_R2_3(short[] data, byte[] bytes, int off)
    {
        int b = off;
        for (int d = 0; d < N; d += 8)
        {
            int packed = (bytes[b++] & 0xFF)
                | ((bytes[b++] & 0xFF) << 8)
                | ((bytes[b++] & 0xFF) << 16);
            for (int i = 0; i < 8; ++i)
            {
                data[d + i] = (short)((packed >>> (3 * i)) & 0x07);
            }
        }
    }

    private static void pack_R2_4(byte[] bytes, int off, short[] data)
    {
        int b = off;
        for (int d = 0; d < N; d += 2)
        {
            int v = (data[d] & 0x0F) | ((data[d + 1] & 0x0F) << 4);
            bytes[b++] = (byte)v;
        }
    }

    private static void unpack_R2_4(short[] data, byte[] bytes, int off)
    {
        int b = off;
        for (int d = 0; d < N; d += 2)
        {
            int v = bytes[b++] & 0xFF;
            data[d] = (short)(v & 0x0F);
            data[d + 1] = (short)((v >>> 4) & 0x0F);
        }
    }

    private static void pack_R2_5(byte[] bytes, int off, short[] data)
    {
        int b = off;
        for (int d = 0; d < N; d += 8)
        {
            long packed = 0;
            for (int i = 0; i < 8; ++i)
            {
                packed |= ((long)(data[d + i] & 0x001F) << (5 * i));
            }
            bytes[b++] = (byte)(packed & 0xFF);
            bytes[b++] = (byte)((packed >>> 8) & 0xFF);
            bytes[b++] = (byte)((packed >>> 16) & 0xFF);
            bytes[b++] = (byte)((packed >>> 24) & 0xFF);
            bytes[b++] = (byte)((packed >>> 32) & 0xFF);
        }
    }

    private static void unpack_R2_5(short[] data, byte[] bytes, int off)
    {
        int b = off;
        for (int d = 0; d < N; d += 8)
        {
            long packed = (long)(bytes[b++] & 0xFF)
                | ((long)(bytes[b++] & 0xFF) << 8)
                | ((long)(bytes[b++] & 0xFF) << 16)
                | ((long)(bytes[b++] & 0xFF) << 24)
                | ((long)(bytes[b++] & 0xFF) << 32);
            for (int i = 0; i < 8; ++i)
            {
                data[d + i] = (short)((packed >>> (5 * i)) & 0x1F);
            }
        }
    }

    private static void pack_R2_7(byte[] bytes, int off, short[] data)
    {
        int b = off;
        for (int d = 0; d < N; d += 8)
        {
            long packed = 0;
            for (int i = 0; i < 8; ++i)
            {
                packed |= ((long)(data[d + i] & 0x007F) << (7 * i));
            }
            bytes[b++] = (byte)(packed & 0xFF);
            bytes[b++] = (byte)((packed >>> 8) & 0xFF);
            bytes[b++] = (byte)((packed >>> 16) & 0xFF);
            bytes[b++] = (byte)((packed >>> 24) & 0xFF);
            bytes[b++] = (byte)((packed >>> 32) & 0xFF);
            bytes[b++] = (byte)((packed >>> 40) & 0xFF);
            bytes[b++] = (byte)((packed >>> 48) & 0xFF);
        }
    }

    private static void unpack_R2_7(short[] data, byte[] bytes, int off)
    {
        int b = off;
        for (int d = 0; d < N; d += 8)
        {
            long packed = (long)(bytes[b++] & 0xFF)
                | ((long)(bytes[b++] & 0xFF) << 8)
                | ((long)(bytes[b++] & 0xFF) << 16)
                | ((long)(bytes[b++] & 0xFF) << 24)
                | ((long)(bytes[b++] & 0xFF) << 32)
                | ((long)(bytes[b++] & 0xFF) << 40)
                | ((long)(bytes[b++] & 0xFF) << 48);
            for (int i = 0; i < 8; ++i)
            {
                data[d + i] = (short)((packed >>> (7 * i)) & 0x7F);
            }
        }
    }

    private static void pack_R2_8(byte[] bytes, int off, short[] data)
    {
        for (int i = 0; i < N; ++i)
        {
            bytes[off + i] = (byte)(data[i] & 0xFF);
        }
    }

    private static void unpack_R2_8(short[] data, byte[] bytes, int off)
    {
        for (int i = 0; i < N; ++i)
        {
            data[i] = (short)(bytes[off + i] & 0xFF);
        }
    }

    private static void pack_R2_9(byte[] bytes, int off, short[] data)
    {
        int b = off;
        for (int d = 0; d < N; d += 8)
        {
            long packed = 0;
            for (int i = 0; i < 7; ++i)
            {
                packed |= ((long)(data[d + i] & 0x01FF) << (9 * i));
            }
            packed |= ((long)(data[d + 7] & 0x0001) << 63);
            int packed2 = ((data[d + 7] & 0xFFFF) >>> 1) & 0xFF;
            bytes[b++] = (byte)(packed & 0xFF);
            bytes[b++] = (byte)((packed >>> 8) & 0xFF);
            bytes[b++] = (byte)((packed >>> 16) & 0xFF);
            bytes[b++] = (byte)((packed >>> 24) & 0xFF);
            bytes[b++] = (byte)((packed >>> 32) & 0xFF);
            bytes[b++] = (byte)((packed >>> 40) & 0xFF);
            bytes[b++] = (byte)((packed >>> 48) & 0xFF);
            bytes[b++] = (byte)((packed >>> 56) & 0xFF);
            bytes[b++] = (byte)(packed2 & 0xFF);
        }
    }

    private static void unpack_R2_9(short[] data, byte[] bytes, int off)
    {
        int b = off;
        for (int d = 0; d < N; d += 8)
        {
            long packed = (long)(bytes[b++] & 0xFF)
                | ((long)(bytes[b++] & 0xFF) << 8)
                | ((long)(bytes[b++] & 0xFF) << 16)
                | ((long)(bytes[b++] & 0xFF) << 24)
                | ((long)(bytes[b++] & 0xFF) << 32)
                | ((long)(bytes[b++] & 0xFF) << 40)
                | ((long)(bytes[b++] & 0xFF) << 48)
                | ((long)(bytes[b++] & 0xFF) << 56);
            int packed2 = bytes[b++] & 0xFF;
            for (int i = 0; i < 7; ++i)
            {
                data[d + i] = (short)((packed >>> (9 * i)) & 0x01FF);
            }
            data[d + 7] = (short)((packed >>> 63) & 0x0001);
            data[d + 7] |= (short)((packed2 << 1) & 0x01FE);
        }
    }

    private static void pack_R2_10(byte[] bytes, int off, short[] data)
    {
        int b = off;
        for (int d = 0; d < N; d += 4)
        {
            long packed = 0;
            for (int i = 0; i < 4; ++i)
            {
                packed |= ((long)(((data[d + i] & 0xFFFF) >>> 6) & 0x03FF) << (10 * i));
            }
            bytes[b++] = (byte)(packed & 0xFF);
            bytes[b++] = (byte)((packed >>> 8) & 0xFF);
            bytes[b++] = (byte)((packed >>> 16) & 0xFF);
            bytes[b++] = (byte)((packed >>> 24) & 0xFF);
            bytes[b++] = (byte)((packed >>> 32) & 0xFF);
        }
    }

    private static void unpack_R2_10(short[] data, byte[] bytes, int off)
    {
        int b = off;
        for (int d = 0; d < N; d += 4)
        {
            long packed = (long)(bytes[b++] & 0xFF)
                | ((long)(bytes[b++] & 0xFF) << 8)
                | ((long)(bytes[b++] & 0xFF) << 16)
                | ((long)(bytes[b++] & 0xFF) << 24)
                | ((long)(bytes[b++] & 0xFF) << 32);
            for (int i = 0; i < 4; ++i)
            {
                data[d + i] = (short)(((packed >>> (10 * i)) & 0x03FF) << 6);
            }
        }
    }

    private static void pack_R2_11(byte[] bytes, int off, short[] data)
    {
        int b = off;
        for (int d = 0; d < N; d += 8)
        {
            long packed = 0;
            for (int i = 0; i < 5; ++i)
            {
                packed |= ((long)(((data[d + i] & 0xFFFF) >>> 5) & 0x07FF) << (11 * i));
            }
            packed |= ((long)(((data[d + 5] & 0xFFFF) >>> 5) & 0x0001) << 55);

            long packed2 = ((data[d + 5] & 0xFFFF) >>> 6) & 0x03FF;
            for (int i = 0; i < 2; ++i)
            {
                packed2 |= ((long)(((data[d + 6 + i] & 0xFFFF) >>> 5) & 0x07FF) << (10 + 11 * i));
            }
            bytes[b++] = (byte)(packed & 0xFF);
            bytes[b++] = (byte)((packed >>> 8) & 0xFF);
            bytes[b++] = (byte)((packed >>> 16) & 0xFF);
            bytes[b++] = (byte)((packed >>> 24) & 0xFF);
            bytes[b++] = (byte)((packed >>> 32) & 0xFF);
            bytes[b++] = (byte)((packed >>> 40) & 0xFF);
            bytes[b++] = (byte)((packed >>> 48) & 0xFF);
            bytes[b++] = (byte)(packed2 & 0xFF);
            bytes[b++] = (byte)((packed2 >>> 8) & 0xFF);
            bytes[b++] = (byte)((packed2 >>> 16) & 0xFF);
            bytes[b++] = (byte)((packed2 >>> 24) & 0xFF);
        }
    }

    private static void unpack_R2_11(short[] data, byte[] bytes, int off)
    {
        int b = off;
        for (int d = 0; d < N; d += 8)
        {
            long packed = (long)(bytes[b++] & 0xFF)
                | ((long)(bytes[b++] & 0xFF) << 8)
                | ((long)(bytes[b++] & 0xFF) << 16)
                | ((long)(bytes[b++] & 0xFF) << 24)
                | ((long)(bytes[b++] & 0xFF) << 32)
                | ((long)(bytes[b++] & 0xFF) << 40)
                | ((long)(bytes[b++] & 0xFF) << 48);
            long packed2 = (long)(bytes[b++] & 0xFF)
                | ((long)(bytes[b++] & 0xFF) << 8)
                | ((long)(bytes[b++] & 0xFF) << 16)
                | ((long)(bytes[b++] & 0xFF) << 24);
            for (int i = 0; i < 5; ++i)
            {
                data[d + i] = (short)(((packed >>> (11 * i)) & 0x07FF) << 5);
            }
            data[d + 5] = (short)(((packed >>> 55) & 0x0001) << 5);
            data[d + 5] |= (short)((packed2 & 0x03FF) << 6);
            for (int i = 0; i < 2; ++i)
            {
                data[d + 6 + i] = (short)(((packed2 >>> (10 + 11 * i)) & 0x07FF) << 5);
            }
        }
    }

    // ============================================================
    // verify / cmov / hashes
    // ============================================================

    private static int verify(byte[] a, int aOff, byte[] b, int bOff, int len)
    {
        int r = 0;
        for (int i = 0; i < len; ++i)
        {
            r |= (a[aOff + i] ^ b[bOff + i]) & 0xFF;
        }
        // return (-(uint64_t)r) >> 63;
        // r is 0 or non-zero; result is 1 if r != 0 else 0
        return (r | -r) >>> 31;
    }

    private static void cmov(byte[] r, int rOff, byte[] x, int xOff, int len, byte b)
    {
        int mask = -(b & 0xFF);
        for (int i = 0; i < len; ++i)
        {
            r[rOff + i] ^= (byte)(mask & ((r[rOff + i] ^ x[xOff + i]) & 0xFF));
        }
    }

    private static void sha3_256(byte[] out, int outOff, byte[] in, int inOff, int inLen)
    {
        SHA3Digest d = new SHA3Digest(256);
        d.update(in, inOff, inLen);
        d.doFinal(out, outOff);
    }

    private static void sha3_512(byte[] out, int outOff, byte[] in, int inOff, int inLen)
    {
        SHA3Digest d = new SHA3Digest(512);
        d.update(in, inOff, inLen);
        d.doFinal(out, outOff);
    }

    private static void shake256(byte[] out, int outLen, byte[] in, int inLen)
    {
        SHAKEDigest s = new SHAKEDigest(256);
        s.update(in, 0, inLen);
        s.doFinal(out, 0, outLen);
    }

    private static void shake128(byte[] out, int outLen, byte[] in, int inLen)
    {
        SHAKEDigest s = new SHAKEDigest(128);
        s.update(in, 0, inLen);
        s.doFinal(out, 0, outLen);
    }

    private static void shake256AbsorbTwiceSqueeze(byte[] out, int outLen,
                                                   byte[] in1, int in1Len,
                                                   byte[] in2, int in2Len)
    {
        SHAKEDigest s = new SHAKEDigest(256);
        s.update(in1, 0, in1Len);
        s.update(in2, 0, in2Len);
        s.doFinal(out, 0, outLen);
    }
}
