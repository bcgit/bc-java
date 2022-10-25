package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Arrays;

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
    private byte H_FCT_DOMAIN = 4;
    private byte K_FCT_DOMAIN = 5;

    private int N_BYTE;
    private int n1n2;
    private int N_BYTE_64;
    private int K_BYTE;
    private int K_BYTE_64;
    private int N1_BYTE_64;
    private int N1N2_BYTE_64;
    private int N1N2_BYTE;
    private int N1_BYTE;

    private int[] generatorPoly;
    private int SHA512_BYTES = 512 / 8;

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

        KeccakRandomGenerator randomGenerator = new KeccakRandomGenerator(256);
        randomGenerator.randomGeneratorInit(seed, null, seed.length, 0);
        randomGenerator.squeeze(secretKeySeed, 40);

        // 1. Randomly generate secret keys x, y
        KeccakRandomGenerator secretKeySeedExpander = new KeccakRandomGenerator(256);
        secretKeySeedExpander.seedExpanderInit(secretKeySeed, secretKeySeed.length);

        long[] xLongBytes = new long[N_BYTE_64];
        int[] yPos = new int[this.w];

        generateSecretKey(xLongBytes, secretKeySeedExpander, w);
        generateSecretKeyByCoordinates(yPos, secretKeySeedExpander, w);

        // 2. Randomly generate h
        byte[] publicKeySeed = new byte[SEED_SIZE];
        randomGenerator.squeeze(publicKeySeed, 40);

        KeccakRandomGenerator randomPublic = new KeccakRandomGenerator(256);
        randomPublic.seedExpanderInit(publicKeySeed, publicKeySeed.length);

        long[] hLongBytes = new long[N_BYTE_64];
        generatePublicKeyH(hLongBytes, randomPublic);

        // 3. Compute s
        long[] s = new long[N_BYTE_64];
        GF2PolynomialCalculator.modMult(s, yPos, hLongBytes, w, n, N_BYTE_64, we, secretKeySeedExpander);
        GF2PolynomialCalculator.addLongs(s, s, xLongBytes);
        byte[] sBytes = new byte[N_BYTE];
        Utils.fromLongArrayToByteArray(sBytes, s);

        byte[] tmpPk = Arrays.concatenate(publicKeySeed, sBytes);
        byte[] tmpSk = Arrays.concatenate(secretKeySeed, tmpPk);

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
     * @param d    d
     * @param K    session key
     * @param pk   public key
     * @param seed seed
     **/
    public void encaps(byte[] u, byte[] v, byte[] K, byte[] d, byte[] pk, byte[] seed)
    {
        // 1. Randomly generate m
        byte[] m = new byte[K_BYTE];

        byte[] secretKeySeed = new byte[SEED_SIZE];
        KeccakRandomGenerator randomGenerator = new KeccakRandomGenerator(256);
        randomGenerator.randomGeneratorInit(seed, null, seed.length, 0);
        randomGenerator.squeeze(secretKeySeed, 40);

        byte[] publicKeySeed = new byte[SEED_SIZE];
        randomGenerator.squeeze(publicKeySeed, 40);

        // gen m
        randomGenerator.squeeze(m, K_BYTE);

        // 2. Generate theta
        byte[] theta = new byte[SHA512_BYTES];
        KeccakRandomGenerator shakeDigest = new KeccakRandomGenerator(256);
        shakeDigest.SHAKE256_512_ds(theta, m, m.length, new byte[]{G_FCT_DOMAIN});

        // 3. Generate ciphertext c = (u,v)
        // Extract public keys
        long[] h = new long[N_BYTE_64];
        byte[] s = new byte[N_BYTE];
        extractPublicKeys(h, s, pk);

        long[] vTmp = new long[N1N2_BYTE_64];
        encrypt(u, vTmp, h, s, m, theta);
        Utils.fromLongArrayToByteArray(v, vTmp);

        // 4. Compute d
        shakeDigest.SHAKE256_512_ds(d, m, m.length, new byte[]{H_FCT_DOMAIN});

        // 5. Compute session key K
        byte[] hashInputK = new byte[K_BYTE + N_BYTE + N1N2_BYTE];
        hashInputK = Arrays.concatenate(m, u);
        hashInputK = Arrays.concatenate(hashInputK, v);
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
     **/
    public void decaps(byte[] ss, byte[] ct, byte[] sk)
    {
        //Extract Y and Public Keys from sk
        int[] yPos = new int[w];
        byte[] pk = new byte[40 + N_BYTE];
        extractKeysFromSecretKeys(yPos, pk, sk);

        // Extract u, v, d from ciphertext
        byte[] u = new byte[N_BYTE];
        byte[] v = new byte[N1N2_BYTE];
        byte[] d = new byte[SHA512_BYTES];
        extractCiphertexts(u, v, d, ct);

        // 1. Decrypt -> m'
        byte[] mPrimeBytes = new byte[k];
        decrypt(mPrimeBytes, mPrimeBytes, u, v, yPos);

        // 2. Compute theta'
        byte[] theta = new byte[SHA512_BYTES];
        KeccakRandomGenerator shakeDigest = new KeccakRandomGenerator(256);
        shakeDigest.SHAKE256_512_ds(theta, mPrimeBytes, mPrimeBytes.length, new byte[]{G_FCT_DOMAIN});

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

        // 4. Compute d' = H(m')
        byte[] dPrime = new byte[SHA512_BYTES];
        shakeDigest.SHAKE256_512_ds(dPrime, mPrimeBytes, mPrimeBytes.length, new byte[]{H_FCT_DOMAIN});

        // 5. Compute session key KPrime
        byte[] hashInputK = new byte[K_BYTE + N_BYTE + N1N2_BYTE];
        hashInputK = Arrays.concatenate(mPrimeBytes, u);
        hashInputK = Arrays.concatenate(hashInputK, v);
        shakeDigest.SHAKE256_512_ds(ss, hashInputK, hashInputK.length, new byte[]{K_FCT_DOMAIN});

        int result = 1;
        // Compare u, v, d
        if (!Arrays.areEqual(u, u2Bytes))
        {
            result = 0;
        }

        if (!Arrays.areEqual(v, v2Bytes))
        {
            result = 0;
        }

        if (!Arrays.areEqual(d, dPrime))
        {
            result = 0;
        }

        if (result == 0)
        { //abort
            for (int i = 0; i < getSessionKeySize(); i++)
            {
                ss[i] = 0;
            }
        }
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
        int[] r2 = new int[wr];
        generateSecretKey(r1, randomGenerator, wr);
        generateSecretKeyByCoordinates(r2, randomGenerator, wr);
        generateSecretKey(e, randomGenerator, we);

        // Calculate u
        long[] uLong = new long[N_BYTE_64];
        GF2PolynomialCalculator.modMult(uLong, r2, h, wr, n, N_BYTE_64, we, randomGenerator);
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
        GF2PolynomialCalculator.modMult(tmpLong, r2, sLong, wr, n, N_BYTE_64, we, randomGenerator);
        GF2PolynomialCalculator.addLongs(tmpLong, tmpLong, tmpVLong);
        GF2PolynomialCalculator.addLongs(tmpLong, tmpLong, e);

        Utils.resizeArray(v, n1n2, tmpLong, n, N1N2_BYTE_64, N1N2_BYTE_64);
    }

    private void decrypt(byte[] output, byte[] m, byte[] u, byte[] v, int[] y)
    {
        byte[] tmpSeed = new byte[SEED_SIZE];
        KeccakRandomGenerator randomGenerator = new KeccakRandomGenerator(256);
        randomGenerator.seedExpanderInit(tmpSeed, SEED_SIZE);

        long[] uLongs = new long[N_BYTE_64];
        Utils.fromByteArrayToLongArray(uLongs, u);

        long[] vLongs = new long[N1N2_BYTE_64];
        Utils.fromByteArrayToLongArray(vLongs, v);

        long[] tmpV = new long[N_BYTE_64];
        System.arraycopy(vLongs, 0, tmpV, 0, vLongs.length);

        long[] tmpLong = new long[N_BYTE_64];
        GF2PolynomialCalculator.modMult(tmpLong, y, uLongs, w, n, N_BYTE_64, we, randomGenerator);
        GF2PolynomialCalculator.addLongs(tmpLong, tmpLong, tmpV);

        // Decode res
        byte[] tmp = new byte[n1];
        ReedMuller.decode(tmp, tmpLong, n1, mulParam);
        ReedSolomon.decode(m, tmp, n1, fft, delta, k, g);

        System.arraycopy(m, 0, output, 0, output.length);
    }

    private void generateSecretKey(long[] output, KeccakRandomGenerator random, int w)
    {
        int[] tmp = new int[w];

        generateSecretKeyByCoordinates(tmp, random, w);

        for (int i = 0; i < w; ++i)
        {
            int index = tmp[i] / 64;
            int pos = tmp[i] % 64;
            long t = ((1L) << pos);
            output[index] |= t;
        }
    }

    private void generateSecretKeyByCoordinates(int[] output, KeccakRandomGenerator random, int w)
    {
        int randomByteSize = 3 * w;
        byte randomBytes[] = new byte[3 * this.wr];
        int inc;

        int i = 0;
        int j = randomByteSize;
        while (i < w)
        {
            do
            {
                if (j == randomByteSize)
                {
                    random.expandSeed(randomBytes, randomByteSize);

                    j = 0;
                }

                output[i] = (randomBytes[j++] & 0xff) << 16;
                output[i] |= (randomBytes[j++] & 0xff) << 8;
                output[i] |= (randomBytes[j++] & 0xff);

            }
            while (output[i] >= this.rejectionThreshold);

            output[i] = output[i] % this.n;
            inc = 1;
            for (int k = 0; k < i; k++)
            {
                if (output[k] == output[i])
                {
                    inc = 0;
                }
            }
            i += inc;
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

    private void extractKeysFromSecretKeys(int[] y, byte[] pk, byte[] sk)
    {
        byte[] secretKeySeed = new byte[SEED_SIZE];
        System.arraycopy(sk, 0, secretKeySeed, 0, secretKeySeed.length);

        // Randomly generate secret keys x, y
        KeccakRandomGenerator secretKeySeedExpander = new KeccakRandomGenerator(256);
        secretKeySeedExpander.seedExpanderInit(secretKeySeed, secretKeySeed.length);

        long[] xLongBytes = new long[N_BYTE_64];
        int[] yPos = new int[this.w];

        generateSecretKey(xLongBytes, secretKeySeedExpander, w);
        generateSecretKeyByCoordinates(yPos, secretKeySeedExpander, w);

        System.arraycopy(yPos, 0, y, 0, y.length);
        System.arraycopy(sk, SEED_SIZE, pk, 0, pk.length);
    }

    private void extractCiphertexts(byte[] u, byte[] v, byte[] d, byte[] ct)
    {
        System.arraycopy(ct, 0, u, 0, u.length);
        System.arraycopy(ct, u.length, v, 0, v.length);
        System.arraycopy(ct, u.length + v.length, d, 0, d.length);
    }
}
