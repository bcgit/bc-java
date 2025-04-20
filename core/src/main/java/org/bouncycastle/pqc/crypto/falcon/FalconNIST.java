package org.bouncycastle.pqc.crypto.falcon;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

class FalconNIST
{
    final int NONCELEN;
    final int LOGN;
    private final int N;
    private final SecureRandom rand;
    private final int CRYPTO_SECRETKEYBYTES;
    private final int CRYPTO_PUBLICKEYBYTES;
    final int CRYPTO_BYTES;

//    private FalconCodec codec;

    FalconNIST(int logn, int noncelen, SecureRandom random)
    {
//        codec = new FalconCodec();
        this.rand = random;
        this.LOGN = logn;
        this.NONCELEN = noncelen;
        this.N = 1 << logn;
        this.CRYPTO_PUBLICKEYBYTES = 1 + (14 * this.N / 8);
        if (logn == 10)
        {
            this.CRYPTO_SECRETKEYBYTES = 2305;
            this.CRYPTO_BYTES = 1330;
        }
        else if (logn == 9 || logn == 8)
        {
            this.CRYPTO_SECRETKEYBYTES = 1 + (6 * this.N * 2 / 8) + this.N;
            this.CRYPTO_BYTES = 690; // TODO find what the byte length is here when not at degree 9 or 10
        }
        else if (logn == 7 || logn == 6)
        {
            this.CRYPTO_SECRETKEYBYTES = 1 + (7 * this.N * 2 / 8) + this.N;
            this.CRYPTO_BYTES = 690;
        }
        else
        {
            this.CRYPTO_SECRETKEYBYTES = 1 + (this.N * 2) + this.N;
            this.CRYPTO_BYTES = 690;
        }
    }

    byte[][] crypto_sign_keypair(byte[] srcpk, byte[] srcsk)
    {
        // TODO: clean up required
        byte[] f = new byte[N],
            g = new byte[N],
            F = new byte[N];
        short[] h = new short[N];
        byte[] seed = new byte[48];
        //SHAKE256 rng = new SHAKE256();
        SHAKEDigest rng = new SHAKEDigest(256);
        int u, v;
//        FalconKeyGen keygen = new FalconKeyGen();

//        savcw = set_fpu_cw(2);

        /*
         * Generate key pair.
         */
//        randombytes(seed, sizeof seed);
        rand.nextBytes(seed);
//        inner_shake256_init(&rng);
//        inner_shake256_inject(&rng, seed, sizeof seed);
//        inner_shake256_flip(&rng);
        //rng.inner_shake256_init();
        rng.update(seed, 0, seed.length);
        //rng.i_shake256_flip();

//        Zf(keygen)(&rng, f, g, F, NULL, h, 10, tmp.b);
        FalconKeyGen.keygen(rng, f, g, F, h, LOGN);


//        set_fpu_cw(savcw);

        /*
         * Encode private key.
         */
        srcsk[0] = (byte)(0x50 + LOGN);     // old python header
        u = 1;
        v = FalconCodec.trim_i8_encode(srcsk, u, CRYPTO_SECRETKEYBYTES - u,
            f, LOGN, FalconCodec.max_fg_bits[LOGN]);
        if (v == 0)
        {
            throw new IllegalStateException("f encode failed");
        }
        byte[] fEnc = Arrays.copyOfRange(srcsk, u, u + v);
        u += v;
        v = FalconCodec.trim_i8_encode(srcsk, u, CRYPTO_SECRETKEYBYTES - u,
            g, LOGN, FalconCodec.max_fg_bits[LOGN]);
        if (v == 0)
        {
            throw new IllegalStateException("g encode failed");
        }
        byte[] gEnc = Arrays.copyOfRange(srcsk, u, u + v);
        u += v;

        v = FalconCodec.trim_i8_encode(srcsk, u, CRYPTO_SECRETKEYBYTES - u,
            F, LOGN, FalconCodec.max_FG_bits[LOGN]);
        if (v == 0)
        {
            throw new IllegalStateException("F encode failed");
        }
        byte[] FEnc = Arrays.copyOfRange(srcsk, u, u + v);
        u += v;
        if (u != CRYPTO_SECRETKEYBYTES)
        {
            throw new IllegalStateException("secret key encoding failed");
        }

        /*
         * Encode public key.
         */
        srcpk[0] = (byte)(LOGN);
        v = FalconCodec.modq_encode(srcpk, CRYPTO_PUBLICKEYBYTES - 1, h, LOGN);
        if (v != CRYPTO_PUBLICKEYBYTES - 1)
        {
            throw new IllegalStateException("public key encoding failed");
        }

        return new byte[][]{Arrays.copyOfRange(srcpk, 1, srcpk.length), fEnc, gEnc, FEnc};
    }

    byte[] crypto_sign(byte[] srcsm,
                       byte[] srcm, int mlen,
                       byte[] srcsk)
    {
        byte[] f = new byte[N],
            g = new byte[N],
            F = new byte[N],
            G = new byte[N];

        short[] sig = new short[N];
        short[] hm = new short[N];

        byte[] seed = new byte[48],
            nonce = new byte[NONCELEN];


        SHAKEDigest sc = new SHAKEDigest(256);
        int u, v, sig_len;
        FalconSign sign = new FalconSign();
        //FalconVrfy vrfy = new FalconVrfy();
//        FalconCommon common = new FalconCommon();

        /*
         * Decode the private key.
         */
//        if (srcsk[sk + 0] != (byte)(0x50 + LOGN))
//        {
//            throw new IllegalArgumentException("private key header incorrect");
//        }
        u = 0;
        v = FalconCodec.trim_i8_decode(f, LOGN, FalconCodec.max_fg_bits[LOGN],
            srcsk, 0, CRYPTO_SECRETKEYBYTES - u);
        if (v == 0)
        {
            throw new IllegalStateException("f decode failed");
        }
        u += v;
        v = FalconCodec.trim_i8_decode(g, LOGN, FalconCodec.max_fg_bits[LOGN],
            srcsk, u, CRYPTO_SECRETKEYBYTES - u);
        if (v == 0)
        {
            throw new IllegalStateException("g decode failed");
        }
        u += v;
        v = FalconCodec.trim_i8_decode(F, LOGN, FalconCodec.max_FG_bits[LOGN],
            srcsk, u, CRYPTO_SECRETKEYBYTES - u);
        if (v == 0)
        {
            throw new IllegalArgumentException("F decode failed");
        }
        u += v;
        if (u != CRYPTO_SECRETKEYBYTES - 1)
        {
            throw new IllegalStateException("full key not used");
        }

        if (!FalconVrfy.complete_private(G, f, g, F, LOGN, new short[2 * N]))
        {
            throw new IllegalStateException("complete_private failed");
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
        //sc.inner_shake256_init();
        sc.update(nonce, 0, NONCELEN);
        sc.update(srcm, 0, mlen);
        //sc.i_shake256_flip();
//        Zf(hash_to_point_vartime)(&sc, r.hm, 10);
        FalconCommon.hash_to_point_vartime(sc, hm, LOGN); // TODO check if this needs to be ct
//        System.out.println(String.format("%x %x %x %x %x %x %x %x", hm[0], hm[1], hm[2], hm[3], hm[4], hm[5], hm[6], hm[7]));

        /*
         * Initialize a RNG.
         */
//        randombytes(seed, sizeof seed);
        rand.nextBytes(seed);
//        inner_shake256_init(&sc);
//        inner_shake256_inject(&sc, seed, sizeof seed);
//        inner_shake256_flip(&sc);
        sc.reset();
        //sc.inner_shake256_init();
        sc.update(seed, 0, seed.length);
        //sc.i_shake256_flip();

//        savcw = set_fpu_cw(2);

        /*
         * Compute the signature.
         */
//        Zf(sign_dyn)(r.sig, &sc, f, g, F, G, r.hm, 10, tmp.b);
        sign.sign_dyn(sig, sc, f, g, F, G, hm, LOGN, new double[10 * N]);

//        set_fpu_cw(savcw);

        byte[] esig = new byte[CRYPTO_BYTES - 2 - NONCELEN];
//        if (attached)
//        {
//            /*
//             * Encode the signature. Format is:
//             *   signature header     1 bytes
//             *   nonce                40 bytes
//             *   signature            slen bytes
//             */
//            esig[0] = (byte)(0x20 + LOGN);
//            sig_len = FalconCodec.comp_encode(esig, 1, esig.length - 1, sig, LOGN);
//            if (sig_len == 0)
//            {
//                throw new IllegalStateException("signature failed to generate");
//            }
//            sig_len++;
//        }
//        else
//        {
        sig_len = FalconCodec.comp_encode(esig, esig.length, sig, LOGN);
        if (sig_len == 0)
        {
            throw new IllegalStateException("signature failed to generate");
        }
//        }

        // header
        srcsm[0] = (byte)(0x30 + LOGN);
        // nonce
        System.arraycopy(nonce, 0, srcsm, 1, NONCELEN);

        // signature
        System.arraycopy(esig, 0, srcsm, 1 + NONCELEN, sig_len);

        return Arrays.copyOfRange(srcsm, 0, 1 + NONCELEN + sig_len);
    }

    int crypto_sign_open(byte[] sig_encoded, byte[] nonce, byte[] msg,
                         byte[] srcpk)
    {
        short[] h = new short[N],
            hm = new short[N];
        short[] sig = new short[N];
        //SHAKE256 sc = new SHAKE256();
        SHAKEDigest sc = new SHAKEDigest(256);
        int sig_len, msg_len;
        //FalconVrfy vrfy = new FalconVrfy();
//        FalconCommon common = new FalconCommon();

        /*
         * Decode public key.
         */
//        if (srcpk[pk + 0] != (byte)(0x00 + LOGN))
//        {
//            return -1;
//        }
        if (FalconCodec.modq_decode(h, LOGN, srcpk, CRYPTO_PUBLICKEYBYTES - 1)
            != CRYPTO_PUBLICKEYBYTES - 1)
        {
            return -1;
        }
        FalconVrfy.to_ntt_monty(h, LOGN);

        /*
         * Find nonce, signature, message length.
         */
//        if (smlen < 2 + NONCELEN)
//        {
//            return -1;
//        }
//        sig_len = (Byte.toUnsignedInt(srcsm[sm + 0]) << 8) | Byte.toUnsignedInt(srcsm[sm + 1]);
        sig_len = sig_encoded.length;
//        if (sig_len > (smlen - 2 - NONCELEN))
//        {
//            return -1;
//        }
        msg_len = msg.length;

        /*
         * Decode signature.
         */
        // Check only required for attached signatures - see 3.11.3 and 3.11.6 in the spec
//        if (attached)
//        {
//            if (sig_len < 1 || sig_encoded[0] != (byte)(0x20 + LOGN))
//            {
//                return -1;
//            }
//            if (FalconCodec.comp_decode(sig, LOGN,
//                sig_encoded, 1, sig_len - 1) != sig_len - 1)
//            {
//                return -1;
//            }
//        }
//        else
//        {
        if (sig_len < 1 || FalconCodec.comp_decode(sig, LOGN,
            sig_encoded, sig_len) != sig_len)
        {
            return -1;
        }
//        }

        /*
         * Hash nonce + message into a vector.
         */
        //sc.inner_shake256_init();
        sc.update(nonce, 0, NONCELEN);
        sc.update(msg, 0, msg_len);
        //sc.i_shake256_flip();
        FalconCommon.hash_to_point_vartime(sc, hm, LOGN); // TODO check if this needs to become ct

        /*
         * Verify signature.
         */
        if (FalconVrfy.verify_raw(hm, sig, h, LOGN, new short[N]) == 0)
        {
            return -1;
        }

        /*
         * Return plaintext.
         */
//        System.arraycopy(srcsm, sm + 2 + NONCELEN, srcm, m, msg_len);
//        mlen[0] = msg_len;
        return 0;
    }
}
