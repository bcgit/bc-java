package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class HQCEngine
{
    private int n;
    private int n1;
    private int n2;
    private int k;
    private int delta;
    private int w;
    private int wr;
    private int we;
    private int g;
    private int rejectionThreshold;
    private int fft;
    private int mulParam;

    private int SEED_SIZE = 40;
    private byte G_FCT_DOMAIN = 3;
    private byte K_FCT_DOMAIN = 4;

    private int N_BYTE;
    private int n1n2;
    private int N_BYTE_64;
    private int K_BYTE;
    private int K_BYTE_64;
    private int N1_BYTE_64;
    private int N1N2_BYTE_64;
    private int N1N2_BYTE;
    private int N1_BYTE;

    private int GF_POLY_WT  = 5;
    private int GF_POLY_M2 = 4;
    private int SALT_SIZE_BYTES = 16;
    private int SALT_SIZE_64 = 2;

    private int[] generatorPoly;
    private int SHA512_BYTES = 512 / 8;

    private long RED_MASK;

    private GF2PolynomialCalculator gfCalculator;

    public HQCEngine(int n, int n1, int n2, int k, int g, int delta, int w, int wr, int we, int rejectionThreshold, int fft, int[] generatorPoly)
    {
        this.n = n;
        this.k = k;
        this.delta = delta;
        this.w = w;
        this.wr = wr;
        this.we = we;
        this.n1 = n1;
        this.n2 = n2;
        this.n1n2 = n1 * n2;
        this.generatorPoly = generatorPoly;
        this.g = g;
        this.rejectionThreshold = rejectionThreshold;
        this.fft = fft;

        this.mulParam = (int)Math.ceil(n2 / 128);
        this.N_BYTE = Utils.getByteSizeFromBitSize(n);
        this.K_BYTE = k;
        this.N_BYTE_64 = Utils.getByte64SizeFromBitSize(n);
        this.K_BYTE_64 = Utils.getByteSizeFromBitSize(k);
        this.N1_BYTE_64 = Utils.getByteSizeFromBitSize(n1);
        this.N1N2_BYTE_64 = Utils.getByte64SizeFromBitSize(n1 * n2);
        this.N1N2_BYTE = Utils.getByteSizeFromBitSize(n1 * n2);
        this.N1_BYTE = Utils.getByteSizeFromBitSize(n1);

        this.RED_MASK = ((1L << ((long)n % 64)) - 1);

        this.gfCalculator = new GF2PolynomialCalculator(N_BYTE_64, n, RED_MASK);
    }

    /**
     * Generate key pairs
     * - Secret key : (x,y)
     * - Public key: (h,s)
     *
     * @param pk output pk = (publicSeed||s)
     **/
    public void genKeyPair(byte[] pk, byte[] sk, byte[] seed)
    {
        // Randomly generate seeds for secret keys and public keys
        byte[] secretKeySeed = new byte[SEED_SIZE];
        byte[] sigma = new byte[K_BYTE];

        KeccakRandomGenerator randomGenerator = new KeccakRandomGenerator(256);
        randomGenerator.randomGeneratorInit(seed, null, seed.length, 0);
        randomGenerator.squeeze(secretKeySeed, 40);
        randomGenerator.squeeze(sigma, K_BYTE);

        // 1. Randomly generate secret keys x, y
        KeccakRandomGenerator secretKeySeedExpander = new KeccakRandomGenerator(256);
        secretKeySeedExpander.seedExpanderInit(secretKeySeed, secretKeySeed.length);

        long[] xLongBytes = new long[N_BYTE_64];
        long[] yLongBytes = new long[N_BYTE_64];

        generateRandomFixedWeight(yLongBytes, secretKeySeedExpander, w);
        generateRandomFixedWeight(xLongBytes, secretKeySeedExpander, w);

        // 2. Randomly generate h
        byte[] publicKeySeed = new byte[SEED_SIZE];
        randomGenerator.squeeze(publicKeySeed, 40);

        KeccakRandomGenerator randomPublic = new KeccakRandomGenerator(256);
        randomPublic.seedExpanderInit(publicKeySeed, publicKeySeed.length);

        long[] hLongBytes = new long[N_BYTE_64];
        generatePublicKeyH(hLongBytes, randomPublic);

        // 3. Compute s
        long[] s = new long[N_BYTE_64];
        gfCalculator.multLongs(s, yLongBytes, hLongBytes);
        GF2PolynomialCalculator.addLongs(s, s, xLongBytes);
        byte[] sBytes = new byte[N_BYTE];
        Utils.fromLongArrayToByteArray(sBytes, s);

        byte[] tmpPk = Arrays.concatenate(publicKeySeed, sBytes);
        byte[] tmpSk = Arrays.concatenate(secretKeySeed, sigma, tmpPk);

        System.arraycopy(tmpPk, 0, pk, 0, tmpPk.length);
        System.arraycopy(tmpSk, 0, sk, 0, tmpSk.length);
    }

    /**
     * HQC Encapsulation
     * - Input: pk, seed
     * - Output: c = (u,v,d), K
     *
     * @param u    u
     * @param v    v
     * @param K    session key
     * @param pk   public key
     * @param seed seed
     **/
    public void encaps(byte[] u, byte[] v, byte[] K, byte[] pk, byte[] seed, byte[] salt)
    {
        // 1. Randomly generate m
        byte[] m = new byte[K_BYTE];

        byte[] secretKeySeed = new byte[SEED_SIZE];
        KeccakRandomGenerator randomGenerator = new KeccakRandomGenerator(256);
        randomGenerator.randomGeneratorInit(seed, null, seed.length, 0);
        randomGenerator.squeeze(secretKeySeed, 40);

        byte[] sigma = new byte[K_BYTE];
        randomGenerator.squeeze(sigma, K_BYTE);

        byte[] publicKeySeed = new byte[SEED_SIZE];
        randomGenerator.squeeze(publicKeySeed, 40);

        // gen m
        randomGenerator.squeeze(m, K_BYTE);

        // 2. Generate theta
        byte[] theta = new byte[SHA512_BYTES];
        byte[] tmp = new byte[K_BYTE + (SALT_SIZE_BYTES * 2) + SALT_SIZE_BYTES];
        randomGenerator.squeeze(salt, SALT_SIZE_BYTES);

        System.arraycopy(m, 0, tmp, 0, m.length);
        System.arraycopy(pk, 0, tmp, K_BYTE, SALT_SIZE_BYTES * 2);
        System.arraycopy(salt, 0, tmp, K_BYTE + (SALT_SIZE_BYTES * 2), SALT_SIZE_BYTES);
        KeccakRandomGenerator shakeDigest = new KeccakRandomGenerator(256);
        shakeDigest.SHAKE256_512_ds(theta, tmp, tmp.length, new byte[]{G_FCT_DOMAIN});

        // 3. Generate ciphertext c = (u,v)
        // Extract public keys
        long[] h = new long[N_BYTE_64];
        byte[] s = new byte[N_BYTE];
        extractPublicKeys(h, s, pk);

        long[] vTmp = new long[N1N2_BYTE_64];
        encrypt(u, vTmp, h, s, m, theta);

        Utils.fromLongArrayToByteArray(v, vTmp);

        // 5. Compute session key K
        byte[] hashInputK = Arrays.concatenate(m, u, v);
        shakeDigest.SHAKE256_512_ds(K, hashInputK, hashInputK.length, new byte[]{K_FCT_DOMAIN});
    }

    /**
     * HQC Decapsulation
     * - Input: ct, sk
     * - Output: ss
     *
     * @param ss session key
     * @param ct ciphertext
     * @param sk secret key
     * @return 0 if decapsulation is successful, -1 otherwise
     **/
    public int decaps(byte[] ss, byte[] ct, byte[] sk)
    {
        //Extract Y and Public Keys from sk
        long[] y = new long[N_BYTE_64];
        byte[] pk = new byte[40 + N_BYTE];
        byte[] sigma = new byte[K_BYTE];
        extractKeysFromSecretKeys(y, sigma, pk, sk);

        // Extract u, v, d from ciphertext
        byte[] u = new byte[N_BYTE];
        byte[] v = new byte[N1N2_BYTE];
        byte[] salt = new byte[SALT_SIZE_BYTES];
        extractCiphertexts(u, v, salt, ct);

        // 1. Decrypt -> m'
        byte[] mPrimeBytes = new byte[k];
        int result = decrypt(mPrimeBytes, mPrimeBytes, sigma, u, v, y);

        // 2. Compute theta'
        byte[] theta = new byte[SHA512_BYTES];
        byte[] tmp = new byte[K_BYTE + (SALT_SIZE_BYTES * 2) + SALT_SIZE_BYTES];
        System.arraycopy(mPrimeBytes, 0, tmp, 0, mPrimeBytes.length);
        System.arraycopy(pk, 0, tmp, K_BYTE, SALT_SIZE_BYTES * 2);
        System.arraycopy(salt, 0, tmp, K_BYTE + (SALT_SIZE_BYTES * 2), SALT_SIZE_BYTES);

        KeccakRandomGenerator shakeDigest = new KeccakRandomGenerator(256);
        shakeDigest.SHAKE256_512_ds(theta, tmp, tmp.length, new byte[]{G_FCT_DOMAIN});

        // 3. Compute c' = Enc(pk, m', theta')
        // Extract public keys
        long[] h = new long[N_BYTE_64];
        byte[] s = new byte[N_BYTE];
        extractPublicKeys(h, s, pk);

        byte[] u2Bytes = new byte[N_BYTE];
        byte[] v2Bytes = new byte[N1N2_BYTE];
        long[] vTmp = new long[N1N2_BYTE_64];
        encrypt(u2Bytes, vTmp, h, s, mPrimeBytes, theta);
        Utils.fromLongArrayToByteArray(v2Bytes, vTmp);

        // 5. Compute session key KPrime
        byte[] hashInputK = new byte[K_BYTE + N_BYTE + N1N2_BYTE];

        // Compare u, v, d
        if (!Arrays.constantTimeAreEqual(u, u2Bytes))
        {
            result = 1;
        }

        if (!Arrays.constantTimeAreEqual(v, v2Bytes))
        {
            result = 1;
        }

        result -= 1;

        for (int i = 0; i < K_BYTE; i++)
        {
            hashInputK[i] = (byte)(((mPrimeBytes[i] & result) ^ (sigma[i] & ~result)) & 0xff);
        }
        System.arraycopy(u, 0, hashInputK, K_BYTE, N_BYTE);
        System.arraycopy(v, 0, hashInputK, K_BYTE + N_BYTE, N1N2_BYTE);

        shakeDigest.SHAKE256_512_ds(ss, hashInputK, hashInputK.length, new byte[]{K_FCT_DOMAIN});

        return -result;
    }

    int getSessionKeySize()
    {
        return SHA512_BYTES;
    }

    /**
     * HQC Encryption
     * - Input: (h,s, m)
     * - Output: (u,v) = c
     *
     * @param h public key
     * @param s public key
     * @param m message
     * @param u ciphertext
     * @param v ciphertext
     **/
    private void encrypt(byte[] u, long[] v, long[] h, byte[] s, byte[] m, byte[] theta)
    {
        // Randomly generate e, r1, r2
        KeccakRandomGenerator randomGenerator = new KeccakRandomGenerator(256);
        randomGenerator.seedExpanderInit(theta, SEED_SIZE);
        long[] e = new long[N_BYTE_64];
        long[] r1 = new long[N_BYTE_64];
        long[] r2 = new long[N_BYTE_64];
        generateRandomFixedWeight(r2, randomGenerator, wr);
        generateRandomFixedWeight(e, randomGenerator, we);
        generateRandomFixedWeight(r1, randomGenerator, wr);

        // Calculate u
        long[] uLong = new long[N_BYTE_64];
        gfCalculator.multLongs(uLong, r2, h);
        GF2PolynomialCalculator.addLongs(uLong, uLong, r1);
        Utils.fromLongArrayToByteArray(u, uLong);

        // Calculate v
        // encode m
        byte[] res = new byte[n1];
        long[] vLong = new long[N1N2_BYTE_64];
        long[] tmpVLong = new long[N_BYTE_64];
        ReedSolomon.encode(res, m, K_BYTE * 8, n1, k, g, generatorPoly);
        ReedMuller.encode(vLong, res, n1, mulParam);
        System.arraycopy(vLong, 0, tmpVLong, 0, vLong.length);

        //Compute v
        long[] sLong = new long[N_BYTE_64];
        Utils.fromByteArrayToLongArray(sLong, s);

        long[] tmpLong = new long[N_BYTE_64];
        gfCalculator.multLongs(tmpLong, r2, sLong);
        GF2PolynomialCalculator.addLongs(tmpLong, tmpLong, tmpVLong);
        GF2PolynomialCalculator.addLongs(tmpLong, tmpLong, e);

        Utils.resizeArray(v, n1n2, tmpLong, n, N1N2_BYTE_64, N1N2_BYTE_64);
    }

    private int decrypt(byte[] output, byte[] m, byte[] sigma, byte[] u, byte[] v, long[] y)
    {
        long[] uLongs = new long[N_BYTE_64];
        Utils.fromByteArrayToLongArray(uLongs, u);

        long[] vLongs = new long[N1N2_BYTE_64];
        Utils.fromByteArrayToLongArray(vLongs, v);

        long[] tmpV = new long[N_BYTE_64];
        System.arraycopy(vLongs, 0, tmpV, 0, vLongs.length);

        long[] tmpLong = new long[N_BYTE_64];
        gfCalculator.multLongs(tmpLong, y, uLongs);
        GF2PolynomialCalculator.addLongs(tmpLong, tmpLong, tmpV);

        // Decode res
        byte[] tmp = new byte[n1];
        ReedMuller.decode(tmp, tmpLong, n1, mulParam);
        ReedSolomon.decode(m, tmp, n1, fft, delta, k, g);

        System.arraycopy(m, 0, output, 0, output.length);
        return 0;
    }

    private void generateRandomFixedWeight(long[] output, KeccakRandomGenerator random, int weight)
    {
        int[] rand_u32 = new int[this.wr];
        byte[] rand_bytes = new byte[this.wr * 4];
        int[] support = new int[this.wr];
        int[] index_tab = new int[this.wr];
        long[] bit_tab = new long[this.wr];

        random.expandSeed(rand_bytes, 4 * weight);
        Pack.littleEndianToInt(rand_bytes, 0, rand_u32, 0, rand_u32.length);

        for (int i = 0; i < weight; i++)
        {
            support[i] = (int) (i + ((rand_u32[i]&0xFFFFFFFFL) % (n - i)));
        }

        for (int i = (weight - 1); i >= 0; i--)
        {
            int found = 0;
            for (int j = i + 1; j < weight; j++)
            {
                if (support[j] == support[i])
                {
                    found |= 1;
                }
            }

            int mask = -found;
            support[i] = (mask & i) ^ (~mask & support[i]);
        }

        for (int i = 0; i < weight; i++)
        {
            index_tab[i] = support[i] >>> 6;
            int pos = support[i] & 0x3f;
            bit_tab[i] = (1L) << pos;
        }
        long val = 0;
        for (int i = 0; i < N_BYTE_64; i++)
        {
            val = 0;
            for (int j = 0; j < weight; j++)
            {
                int tmp = i - index_tab[j];
                int val1 = 1 ^ ((tmp | -tmp) >>> 31);
                long mask = -val1;
                val |= (bit_tab[j] & mask);
            }
            output[i] |= val;
        }
    }

    void generatePublicKeyH(long[] out, KeccakRandomGenerator random)
    {
        byte[] randBytes = new byte[N_BYTE];
        random.expandSeed(randBytes, N_BYTE);
        long[] tmp = new long[N_BYTE_64];
        Utils.fromByteArrayToLongArray(tmp, randBytes);
        tmp[N_BYTE_64 - 1] &= Utils.bitMask(n, 64);
        System.arraycopy(tmp, 0, out, 0, out.length);
    }

    private void extractPublicKeys(long[] h, byte[] s, byte[] pk)
    {
        byte[] publicKeySeed = new byte[SEED_SIZE];
        System.arraycopy(pk, 0, publicKeySeed, 0, publicKeySeed.length);

        KeccakRandomGenerator randomPublic = new KeccakRandomGenerator(256);
        randomPublic.seedExpanderInit(publicKeySeed, publicKeySeed.length);

        long[] hLongBytes = new long[N_BYTE_64];
        generatePublicKeyH(hLongBytes, randomPublic);

        System.arraycopy(hLongBytes, 0, h, 0, h.length);
        System.arraycopy(pk, 40, s, 0, s.length);
    }

    private void extractKeysFromSecretKeys(long[] y, byte[] sigma, byte[] pk, byte[] sk)
    {
        byte[] secretKeySeed = new byte[SEED_SIZE];
        System.arraycopy(sk, 0, secretKeySeed, 0, secretKeySeed.length);
        System.arraycopy(sk, SEED_SIZE, sigma, 0, K_BYTE);

        // Randomly generate secret keys x, y
        KeccakRandomGenerator secretKeySeedExpander = new KeccakRandomGenerator(256);
        secretKeySeedExpander.seedExpanderInit(secretKeySeed, secretKeySeed.length);

        generateRandomFixedWeight(y, secretKeySeedExpander, w);

        System.arraycopy(sk, SEED_SIZE + K_BYTE, pk, 0, pk.length);
    }

    private void extractCiphertexts(byte[] u, byte[] v, byte[] salt, byte[] ct)
    {
        System.arraycopy(ct, 0, u, 0, u.length);
        System.arraycopy(ct, u.length, v, 0, v.length);
        System.arraycopy(ct, u.length + v.length, salt, 0, salt.length);
    }
}
