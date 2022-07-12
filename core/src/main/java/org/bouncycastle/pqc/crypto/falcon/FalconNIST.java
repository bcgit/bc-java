package org.bouncycastle.pqc.crypto.falcon;


import java.security.SecureRandom;

class FalconNIST
{

    int NONCELEN;
    int LOGN;
    private int N;
    private SecureRandom rand;
    private int CRYPTO_SECRETKEYBYTES;
    private int CRYPTO_PUBLICKEYBYTES;
    int CRYPTO_BYTES;

    private FalconCodec codec;

    FalconNIST(int logn, int noncelen, SecureRandom random)
    {
        codec = new FalconCodec();
        this.rand = random;
        this.LOGN = logn;
        this.NONCELEN = noncelen;
        this.N = 1 << logn;
        if (logn == 10)
        {
            this.CRYPTO_SECRETKEYBYTES = 2305;
            this.CRYPTO_PUBLICKEYBYTES = 1793;
            this.CRYPTO_BYTES = 1330;
        }
        else
        {
            this.CRYPTO_SECRETKEYBYTES = 1281;
            this.CRYPTO_PUBLICKEYBYTES = 897;
            this.CRYPTO_BYTES = 690;
        }
    }

    int crypto_sign_keypair(byte[] srcpk, int pk, byte[] srcsk, int sk)
    {
        byte[] f = new byte[N],
            g = new byte[N],
            F = new byte[N];
        short[] h = new short[N];
        byte[] seed = new byte[48];
        SHAKE256 rng = new SHAKE256();
        int u, v;
        FalconKeyGen keygen = new FalconKeyGen();

//        savcw = set_fpu_cw(2);

        /*
         * Generate key pair.
         */
//        randombytes(seed, sizeof seed);
        rand.nextBytes(seed);
//        inner_shake256_init(&rng);
//        inner_shake256_inject(&rng, seed, sizeof seed);
//        inner_shake256_flip(&rng);
        rng.inner_shake256_init();
        rng.inner_shake256_inject(seed, 0, seed.length);
        rng.i_shake256_flip();

//        Zf(keygen)(&rng, f, g, F, NULL, h, 10, tmp.b);
        keygen.keygen(rng, f, 0, g, 0, F, 0, null, 0, h, 0, LOGN);


//        set_fpu_cw(savcw);

        /*
         * Encode private key.
         */
        srcsk[sk + 0] = (byte)(0x50 + LOGN);
        u = 1;
        v = codec.trim_i8_encode(srcsk, sk + u, CRYPTO_SECRETKEYBYTES - u,
            f, 0, LOGN, codec.max_fg_bits[LOGN]);
        if (v == 0)
        {
            return -1;
        }
        u += v;
        v = codec.trim_i8_encode(srcsk, sk + u, CRYPTO_SECRETKEYBYTES - u,
            g, 0, LOGN, codec.max_fg_bits[LOGN]);
        if (v == 0)
        {
            return -1;
        }
        u += v;
        v = codec.trim_i8_encode(srcsk, sk + u, CRYPTO_SECRETKEYBYTES - u,
            F, 0, LOGN, codec.max_FG_bits[LOGN]);
        if (v == 0)
        {
            return -1;
        }
        u += v;
        if (u != CRYPTO_SECRETKEYBYTES)
        {
            return -1;
        }

        /*
         * Encode public key.
         */
        srcpk[pk + 0] = (byte)(0x00 + LOGN);
        v = codec.modq_encode(srcpk, pk + 1, CRYPTO_PUBLICKEYBYTES - 1, h, 0, LOGN);
        if (v != CRYPTO_PUBLICKEYBYTES - 1)
        {
            return -1;
        }

        return 0;
    }

    int crypto_sign(byte[] srcsm, int sm, int[] smlen, int[] siglen,
                    byte[] srcm, int m, int mlen,
                    byte[] srcsk, int sk)
    {
        byte[] b = new byte[72 * N];

        byte[] f = new byte[N],
            g = new byte[N],
            F = new byte[N],
            G = new byte[N];

        short[] sig = new short[N];
        short[] hm = new short[N];

        byte[] seed = new byte[48],
            nonce = new byte[NONCELEN];

        byte[] esig = new byte[CRYPTO_BYTES - 2 - NONCELEN];
        SHAKE256 sc = new SHAKE256();
        int u, v, sig_len;
        FalconSign sign = new FalconSign();
        FalconVrfy vrfy = new FalconVrfy();
        FalconCommon common = new FalconCommon();

        /*
         * Decode the private key.
         */
        if (srcsk[sk + 0] != (byte)(0x50 + LOGN))
        {
            return -1;
        }
        u = 1;
        v = codec.trim_i8_decode(f, 0, LOGN, codec.max_fg_bits[LOGN],
            srcsk, sk + u, CRYPTO_SECRETKEYBYTES - u);
        if (v == 0)
        {
            return -1;
        }
        u += v;
        v = codec.trim_i8_decode(g, 0, LOGN, codec.max_fg_bits[LOGN],
            srcsk, sk + u, CRYPTO_SECRETKEYBYTES - u);
        if (v == 0)
        {
            return -1;
        }
        u += v;
        v = codec.trim_i8_decode(F, 0, LOGN, codec.max_FG_bits[LOGN],
            srcsk, sk + u, CRYPTO_SECRETKEYBYTES - u);
        if (v == 0)
        {
            return -1;
        }
        u += v;
        if (u != CRYPTO_SECRETKEYBYTES)
        {
            return -1;
        }

        if (vrfy.complete_private(G, 0, f, 0, g, 0, F, 0, LOGN, new short[2 * N], 0) == 0)
        {
            return -1;
        }

        /*
         * Create a random nonce (40 bytes).
         */
//        randombytes(nonce, sizeof nonce);
        rand.nextBytes(nonce);

        /*
         * Hash message nonce + message into a vector.
         */
//        inner_shake256_init(&sc);
//        inner_shake256_inject(&sc, nonce, sizeof nonce);
//        inner_shake256_inject(&sc, m, mlen);
//        inner_shake256_flip(&sc);
        sc.inner_shake256_init();
        sc.inner_shake256_inject(nonce, 0, NONCELEN);
        sc.inner_shake256_inject(srcm, m, mlen);
        sc.i_shake256_flip();
//        Zf(hash_to_point_vartime)(&sc, r.hm, 10);
        common.hash_to_point_vartime(sc, hm, 0, LOGN); // TODO check if this needs to be ct
//        System.out.println(String.format("%x %x %x %x %x %x %x %x", hm[0], hm[1], hm[2], hm[3], hm[4], hm[5], hm[6], hm[7]));

        /*
         * Initialize a RNG.
         */
//        randombytes(seed, sizeof seed);
        rand.nextBytes(seed);
//        inner_shake256_init(&sc);
//        inner_shake256_inject(&sc, seed, sizeof seed);
//        inner_shake256_flip(&sc);
        sc.inner_shake256_init();
        sc.inner_shake256_inject(seed, 0, seed.length);
        sc.i_shake256_flip();

//        savcw = set_fpu_cw(2);

        /*
         * Compute the signature.
         */
//        Zf(sign_dyn)(r.sig, &sc, f, g, F, G, r.hm, 10, tmp.b);
        sign.sign_dyn(sig, 0, sc, f, 0, g, 0, F, 0, G, 0, hm, 0, LOGN, new FalconFPR[18 * N], 0);

//        set_fpu_cw(savcw);

        /*
         * Encode the signature and bundle it with the message. Format is:
         *   signature length     2 bytes, big-endian
         *   nonce                40 bytes
         *   message              mlen bytes
         *   signature            slen bytes
         */
        esig[0] = (byte)(0x20 + LOGN);
        sig_len = codec.comp_encode(esig, 1, esig.length - 1, sig, 0, LOGN);
        if (sig_len == 0)
        {
            return -1;
        }
        sig_len++;
//        memmove(sm + 2 + sizeof nonce, m, mlen);
        System.arraycopy(srcm, m, srcsm, sm + 2 + NONCELEN, mlen);
        srcsm[sm + 0] = (byte)(sig_len >>> 8);
        srcsm[sm + 1] = (byte)sig_len;
//        memcpy(sm + 2, nonce, sizeof nonce);
        System.arraycopy(nonce, 0, srcsm, sm + 2, NONCELEN);
//        memcpy(sm + 2 + (sizeof nonce) + mlen, esig, sig_len);
        System.arraycopy(esig, 0, srcsm, sm + 2 + NONCELEN + mlen, sig_len);
        smlen[0] = 2 + (NONCELEN) + mlen + sig_len;
        siglen[0] = sig_len;
        return 0;
    }

    int crypto_sign_open(byte[] srcm, int m, int[] mlen,
                         byte[] srcsm, int sm, int smlen,
                         byte[] srcpk, int pk)
    {
        int esig;
        short[] h = new short[N],
            hm = new short[N];
        short[] sig = new short[N];
        SHAKE256 sc = new SHAKE256();
        int sig_len, msg_len;
        FalconVrfy vrfy = new FalconVrfy();
        FalconCommon common = new FalconCommon();

        /*
         * Decode public key.
         */
        if (srcpk[pk + 0] != (byte)(0x00 + LOGN))
        {
            return -1;
        }
        if (codec.modq_decode(h, 0, LOGN, srcpk, pk + 1, CRYPTO_PUBLICKEYBYTES - 1)
            != CRYPTO_PUBLICKEYBYTES - 1)
        {
            return -1;
        }
        vrfy.to_ntt_monty(h, 0, LOGN);

        /*
         * Find nonce, signature, message length.
         */
        if (smlen < 2 + NONCELEN)
        {
            return -1;
        }
        sig_len = (Byte.toUnsignedInt(srcsm[sm + 0]) << 8) | Byte.toUnsignedInt(srcsm[sm + 1]);
        if (sig_len > (smlen - 2 - NONCELEN))
        {
            return -1;
        }
        msg_len = smlen - 2 - NONCELEN - sig_len;

        /*
         * Decode signature.
         */
        esig = sm + 2 + NONCELEN + msg_len;
        if (sig_len < 1 || srcsm[esig + 0] != (byte)(0x20 + LOGN))
        {
            return -1;
        }
        if (codec.comp_decode(sig, 0, LOGN,
            srcsm, esig + 1, sig_len - 1) != sig_len - 1)
        {
            return -1;
        }

        /*
         * Hash nonce + message into a vector.
         */
//        inner_shake256_init(&sc);
//        inner_shake256_inject(&sc, sm + 2, NONCELEN + msg_len);
//        inner_shake256_flip(&sc);
//        Zf(hash_to_point_vartime)(&sc, hm, 10);
        sc.inner_shake256_init();
        sc.inner_shake256_inject(srcsm, sm + 2, NONCELEN + msg_len);
        sc.i_shake256_flip();
        common.hash_to_point_vartime(sc, hm, 0, LOGN); // TODO check if this needs to become ct

//        System.out.println(String.format("%x %x %x %x %x %x %x %x", hm[0], hm[1], hm[2], hm[3], hm[4], hm[5], hm[6], hm[7]));

        /*
         * Verify signature.
         */
        if (vrfy.verify_raw(hm, 0, sig, 0, h, 0, LOGN, new short[N], 0) == 0)
        {
            return -1;
        }

        /*
         * Return plaintext.
         */
//        memmove(m, sm + 2 + NONCELEN, msg_len);
        System.arraycopy(srcsm, sm + 2 + NONCELEN, srcm, m, msg_len);
        mlen[0] = msg_len;
        return 0;
    }
}
