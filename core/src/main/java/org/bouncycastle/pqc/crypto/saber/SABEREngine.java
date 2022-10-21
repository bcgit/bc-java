package org.bouncycastle.pqc.crypto.saber;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

class SABEREngine
{
    // constant parameters
    public static final int SABER_EP = 10;
    public static final int SABER_N = 256;

    private static final int SABER_SEEDBYTES = 32;
    private static final int SABER_NOISE_SEEDBYTES = 32;
    private static final int SABER_KEYBYTES = 32;
    private static final int SABER_HASHBYTES = 32;


    // parameters for SABER{n}
    private final int SABER_L;
    private final int SABER_MU;
    private final int SABER_ET;

    private final int SABER_POLYCOINBYTES;
    private final int SABER_EQ;

    private final int SABER_POLYBYTES;
    private final int SABER_POLYVECBYTES;
    private final int SABER_POLYCOMPRESSEDBYTES;
    private final int SABER_POLYVECCOMPRESSEDBYTES;
    private final int SABER_SCALEBYTES_KEM;
    private final int SABER_INDCPA_PUBLICKEYBYTES;
    private final int SABER_INDCPA_SECRETKEYBYTES;
    private final int SABER_PUBLICKEYBYTES;
    private final int SABER_SECRETKEYBYTES;
    private final int SABER_BYTES_CCA_DEC;
    private final int defaultKeySize;

    //
    private final int h1;
    private final int h2;

    private final Utils utils;
    private final Poly poly;

    public int getSABER_N()
    {
        return SABER_N;
    }

    public int getSABER_EP()
    {
        return SABER_EP;
    }

    public int getSABER_KEYBYTES()
    {
        return SABER_KEYBYTES;
    }

    public int getSABER_L()
    {
        return SABER_L;
    }

    public int getSABER_ET()
    {
        return SABER_ET;
    }

    public int getSABER_POLYBYTES()
    {
        return SABER_POLYBYTES;
    }
    public int getSABER_POLYVECBYTES()
    {
        return SABER_POLYVECBYTES;
    }

    public int getSABER_SEEDBYTES()
    {
        return SABER_SEEDBYTES;
    }

    public int getSABER_POLYCOINBYTES()
    {
        return SABER_POLYCOINBYTES;
    }

    public int getSABER_NOISE_SEEDBYTES()
    {
        return SABER_NOISE_SEEDBYTES;
    }

    public int getSABER_MU()
    {
        return SABER_MU;
    }

    public Utils getUtils()
    {
        return utils;
    }

    public int getSessionKeySize()
    {
        return defaultKeySize / 8;
    }
    public int getCipherTextSize()
    {
        return SABER_BYTES_CCA_DEC;
    }
    public int getPublicKeySize()
    {
        return SABER_PUBLICKEYBYTES;
    }
    public int getPrivateKeySize()
    {
        return SABER_SECRETKEYBYTES;
    }

    private final boolean usingAES;
    protected final boolean usingEffectiveMasking;

    protected final Symmetric symmetric;

    public SABEREngine(int l, int defaultKeySize, boolean usingAES, boolean usingEffectiveMasking)
    {
        this.defaultKeySize = defaultKeySize;
        this.usingAES = usingAES;
        this.usingEffectiveMasking = usingEffectiveMasking;

        this.SABER_L = l;
        if (l == 2)
        {
            this.SABER_MU = 10;
            this.SABER_ET = 3;
        }
        else if(l == 3)
        {
            this.SABER_MU = 8;
            this.SABER_ET = 4;
        }
        else // l == 4
        {
            this.SABER_MU = 6;
            this.SABER_ET = 6;
        }

        if(usingAES)
        {
            symmetric = new Symmetric.AesSymmetric();
        }
        else
        {
            symmetric = new Symmetric.ShakeSymmetric();
        }

        if(usingEffectiveMasking)
        {
            this.SABER_EQ = 12;
            this.SABER_POLYCOINBYTES = (2 * SABER_N / 8);
        }
        else
        {
            this.SABER_EQ = 13;
            this.SABER_POLYCOINBYTES = (SABER_MU * SABER_N / 8);
        }

        this.SABER_POLYBYTES = (SABER_EQ * SABER_N / 8);
        this.SABER_POLYVECBYTES = (SABER_L * SABER_POLYBYTES);
        this.SABER_POLYCOMPRESSEDBYTES = (SABER_EP * SABER_N / 8);
        this.SABER_POLYVECCOMPRESSEDBYTES = (SABER_L * SABER_POLYCOMPRESSEDBYTES);
        this.SABER_SCALEBYTES_KEM = (SABER_ET * SABER_N / 8);
        this.SABER_INDCPA_PUBLICKEYBYTES = (SABER_POLYVECCOMPRESSEDBYTES + SABER_SEEDBYTES);
        this.SABER_INDCPA_SECRETKEYBYTES = (SABER_POLYVECBYTES);
        this.SABER_PUBLICKEYBYTES = (SABER_INDCPA_PUBLICKEYBYTES);
        this.SABER_SECRETKEYBYTES = (SABER_INDCPA_SECRETKEYBYTES + SABER_INDCPA_PUBLICKEYBYTES + SABER_HASHBYTES + SABER_KEYBYTES);
        this.SABER_BYTES_CCA_DEC = (SABER_POLYVECCOMPRESSEDBYTES + SABER_SCALEBYTES_KEM);

        this.h1 = (1 << (SABER_EQ - SABER_EP - 1));
        this.h2 = ((1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1)));
        utils = new Utils(this);
        poly = new Poly(this);
    }

    private void indcpa_kem_keypair(byte[] pk, byte[] sk, SecureRandom random)
    {
        short[][][] A = new short[SABER_L][SABER_L][SABER_N];
        short[][] s = new short[SABER_L][SABER_N];
        short[][] b = new short[SABER_L][SABER_N];

        byte[] seed_A = new byte[SABER_SEEDBYTES];
        byte[] seed_s = new byte[SABER_NOISE_SEEDBYTES];
        int i, j;

        random.nextBytes(seed_A);

        symmetric.prf(seed_A, seed_A, SABER_SEEDBYTES, SABER_SEEDBYTES);

        random.nextBytes(seed_s);

        poly.GenMatrix(A, seed_A);

        poly.GenSecret(s, seed_s);

        poly.MatrixVectorMul(A, s, b, 1);

        for (i = 0; i < SABER_L; i++)
        {
            for (j = 0; j < SABER_N; j++)
            {
                b[i][j] = (short) (((b[i][j] + h1)&0xffff) >>> (SABER_EQ - SABER_EP));
            }
        }

        utils.POLVECq2BS(sk, s);
        utils.POLVECp2BS(pk, b);
        System.arraycopy(seed_A, 0, pk, SABER_POLYVECCOMPRESSEDBYTES, seed_A.length);

    }

    public int crypto_kem_keypair(byte[] pk, byte[]sk, SecureRandom random)
    {
        int i;
        indcpa_kem_keypair(pk, sk, random); // sk[0:SABER_INDCPA_SECRETKEYBYTES-1] <-- sk
        for (i = 0; i < SABER_INDCPA_PUBLICKEYBYTES; i++)
        {
            sk[i + SABER_INDCPA_SECRETKEYBYTES] = pk[i]; // sk[SABER_INDCPA_SECRETKEYBYTES:SABER_INDCPA_SECRETKEYBYTES+SABER_INDCPA_SECRETKEYBYTES-1] <-- pk
         }

        // Then hash(pk) is appended.
        symmetric.hash_h(sk, pk, SABER_SECRETKEYBYTES - 64);

        // Remaining part of sk contains a pseudo-random number.
        byte[] nonce = new byte[SABER_KEYBYTES];
        random.nextBytes(nonce);
        System.arraycopy(nonce, 0, sk, SABER_SECRETKEYBYTES - SABER_KEYBYTES, nonce.length);

        // This is output when check in crypto_kem_dec() fails.
        return 0;
    }


    private void indcpa_kem_enc(byte[] m, byte[] seed_sp, byte[] pk, byte[] ciphertext)
    {
        short[][][] A = new short[SABER_L][SABER_L][SABER_N];
        short[][] sp = new short[SABER_L][SABER_N];
        short[][] bp = new short[SABER_L][SABER_N];
        short[][] b = new short[SABER_L][SABER_N];
        short[] mp = new short[SABER_N];
        short[] vp = new short[SABER_N];
        int i, j;
        byte[] seed_A = Arrays.copyOfRange(pk, SABER_POLYVECCOMPRESSEDBYTES, pk.length);

        poly.GenMatrix(A, seed_A);
        poly.GenSecret(sp, seed_sp);
        poly.MatrixVectorMul(A, sp, bp, 0);

        for (i = 0; i < SABER_L; i++)
        {
            for (j = 0; j < SABER_N; j++)
            {
                bp[i][j] = (short) (((bp[i][j] + h1)&0xffff) >>> (SABER_EQ - SABER_EP));
            }
        }

        utils.POLVECp2BS(ciphertext, bp);
        utils.BS2POLVECp(pk, b);
        poly.InnerProd(b, sp, vp);

        utils.BS2POLmsg(m, mp);

        for (j = 0; j < SABER_N; j++)
        {
            vp[j] = (short) (((vp[j] - (mp[j] << (SABER_EP - 1)) + h1)&0xffff) >>> (SABER_EP - SABER_ET));
        }

        utils.POLT2BS(ciphertext, SABER_POLYVECCOMPRESSEDBYTES, vp);
    }

    public int crypto_kem_enc(byte[] c, byte[] k, byte[] pk, SecureRandom random)
    {
        byte[] kr = new byte[64]; // Will contain key, coins
        byte[] buf = new byte[64];

        byte[] nonce = new byte[32];
        random.nextBytes(nonce);

        // BUF[0:31] <-- random message (will be used as the key for client) Note: hash doesnot release system RNG output
        symmetric.hash_h(nonce, nonce, 0);
        System.arraycopy(nonce, 0, buf, 0, 32);

        // BUF[32:63] <-- Hash(public key);  Multitarget countermeasure for coins + contributory KEM
        symmetric.hash_h(buf, pk, 32);

        // kr[0:63] <-- Hash(buf[0:63]);
        symmetric.hash_g(kr, buf);

        // K^ <-- kr[0:31]
        // noiseseed (r) <-- kr[32:63];
        // buf[0:31] contains message; kr[32:63] contains randomness r;
        indcpa_kem_enc(buf, Arrays.copyOfRange(kr, 32, kr.length), pk, c);

        symmetric.hash_h(kr, c, 32);

        // hash concatenation of pre-k and h(c) to k
        //todo support 128 and 192 bit keys
        byte[] temp_k = new byte[32];

        symmetric.hash_h(temp_k, kr, 0);
        System.arraycopy(temp_k,0, k, 0, defaultKeySize/8);

        return 0;
    }

    private void indcpa_kem_dec(byte[] sk, byte[] ciphertext, byte[] m)
    {
        short[][] s = new short[SABER_L][SABER_N];
        short[][] b = new short[SABER_L][SABER_N];
        short[] v = new short[SABER_N];
        short[] cm = new short[SABER_N];
        int i;

        utils.BS2POLVECq(sk,0, s);
        utils.BS2POLVECp(ciphertext, b);
        poly.InnerProd(b, s, v);
        utils.BS2POLT(ciphertext, SABER_POLYVECCOMPRESSEDBYTES, cm);

        for (i = 0; i < SABER_N; i++)
        {
            v[i] = (short) (((v[i] + h2 - (cm[i] << (SABER_EP - SABER_ET)))&0xffff) >> (SABER_EP - 1));
        }

        utils.POLmsg2BS(m, v);
    }

    public int crypto_kem_dec(byte[] k, byte[] c, byte[] sk)
    {
        int i, fail;
        byte[] cmp = new byte[SABER_BYTES_CCA_DEC];
        byte[] buf = new byte[64];
        byte[] kr = new byte[64]; // Will contain key, coins
        byte[] pk = Arrays.copyOfRange(sk, SABER_INDCPA_SECRETKEYBYTES, sk.length);

        indcpa_kem_dec(sk, c, buf); // buf[0:31] <-- message

        // Multitarget countermeasure for coins + contributory KEM
        for (i = 0; i < 32; i++) // Save hash by storing h(pk) in sk
        {
            buf[32 + i] = sk[SABER_SECRETKEYBYTES - 64 + i];
        }

        symmetric.hash_g(kr, buf);

        indcpa_kem_enc(buf, Arrays.copyOfRange(kr, 32, kr.length), pk, cmp);

        fail = verify(c, cmp, SABER_BYTES_CCA_DEC);

        // overwrite coins in kr with h(c)

        symmetric.hash_h(kr, c, 32);

        cmov(kr, sk, SABER_SECRETKEYBYTES - SABER_KEYBYTES, SABER_KEYBYTES, (byte) fail);

        // hash concatenation of pre-k and h(c) to k
        //todo support 128 and 192 bit keys
        byte[] temp_k = new byte[32];

        symmetric.hash_h(temp_k, kr, 0);

        System.arraycopy(temp_k,0, k, 0, defaultKeySize/8);
        return 0;

    }

    /* returns 0 for equal strings, 1 for non-equal strings */
    static int verify(byte[] a, byte[] b, int len)
    {
        long r;
        int i;
        r = 0;

        for (i = 0; i < len; i++)
            r |= a[i] ^ b[i];

        r = (-r) >>> 63;
        return (int) r;
    }

    /* b = 1 means mov, b = 0 means don't mov*/
    static void cmov(byte[] r, byte[] x, int x_offset, int len, byte b)
    {
        int i;

        b = (byte) -b;
        for (i = 0; i < len; i++)
            r[i] ^= b & (x[i + x_offset] ^ r[i]);
    }


}
