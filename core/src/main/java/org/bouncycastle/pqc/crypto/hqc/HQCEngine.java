package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
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

    private GF2mField field;

    private PolynomialGF2mSmallM reductionPoly;

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

        // finite field GF(2)
        GF2mField field = new GF2mField(1);
        this.field = field;

        // generate reductionPoly (X^r + 1)
        PolynomialGF2mSmallM poly = new PolynomialGF2mSmallM(field, n);
        this.reductionPoly = poly.addMonomial(0);
    }

    /**
     * Generate key pairs
     * - Secret key : (x,y)
     * - Public key: (h,s)
     *  @param pk     output pk = (publicSeed||s)
     *
     **/
    public void genKeyPair(byte[] pk, byte[] sk, byte[] seed)
    {
        // Randomly generate seeds for secret keys and public keys
        byte[] secretKeySeed = new byte[SEED_SIZE];

        HQCKeccakRandomGenerator randomGenerator = new HQCKeccakRandomGenerator(256);
        randomGenerator.randomGeneratorInit(seed, null, seed.length, 0);
        randomGenerator.squeeze(secretKeySeed, 40);

        // 1. Randomly generate secret keys x, y
        HQCKeccakRandomGenerator secretKeySeedExpander = new HQCKeccakRandomGenerator(256);
        secretKeySeedExpander.seedExpanderInit(secretKeySeed, secretKeySeed.length);

        long[] xLongBytes = new long[N_BYTE_64];
        int[] yPos = new int[this.w];

        generateSecretKey(xLongBytes, secretKeySeedExpander, w);
        generateSecretKeyByCoordinates(yPos, secretKeySeedExpander, w);

        // convert to bit array
        byte[] yBits = Utils.fromListOfPos1ToBitArray(yPos, this.n);
        byte[] xBits = new byte[this.n];
        Utils.fromLongArrayToBitArray(xBits, xLongBytes);

        // 2. Randomly generate h
        byte[] publicKeySeed = new byte[SEED_SIZE];
        randomGenerator.squeeze(publicKeySeed, 40);

        HQCKeccakRandomGenerator randomPublic = new HQCKeccakRandomGenerator(256);
        randomPublic.seedExpanderInit(publicKeySeed, publicKeySeed.length);

        long[] hLongBytes = new long[N_BYTE_64];
        generatePublicKeyH(hLongBytes, randomPublic);

        byte[] hBits = new byte[this.n];
        Utils.fromLongArrayToBitArray(hBits, hLongBytes);

        // 3. Compute s
        PolynomialGF2mSmallM xPoly = new PolynomialGF2mSmallM(this.field, Utils.removeLast0Bits(xBits));
        PolynomialGF2mSmallM yPoly = new PolynomialGF2mSmallM(this.field, Utils.removeLast0Bits(yBits));
        PolynomialGF2mSmallM hPoly = new PolynomialGF2mSmallM(this.field, Utils.removeLast0Bits(hBits));
        PolynomialGF2mSmallM sPoly = xPoly.add(hPoly.modKaratsubaMultiplyBigDeg(yPoly, reductionPoly));

        byte[] sBits = sPoly.getEncoded();
        byte[] sBytes = new byte[N_BYTE];
        Utils.fromBitArrayToByteArray(sBytes, sBits);

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

        // TODO: no way to gen m without seed and gen skseed, pkseed. In reference implementation they use the same
        byte[] secretKeySeed = new byte[SEED_SIZE];
        HQCKeccakRandomGenerator randomGenerator = new HQCKeccakRandomGenerator(256);
        randomGenerator.randomGeneratorInit(seed, null, seed.length, 0);
        randomGenerator.squeeze(secretKeySeed, 40);

        byte[] publicKeySeed = new byte[SEED_SIZE];
        randomGenerator.squeeze(publicKeySeed, 40);

        // gen m
        randomGenerator.squeeze(m, K_BYTE);
        long[] mLongBytes = new long[K_BYTE_64];
        Utils.fromByteArrayToLongArray(mLongBytes, m);

        // 2. Generate theta
        byte[] theta = new byte[SHA512_BYTES];
        HQCKeccakRandomGenerator shakeDigest = new HQCKeccakRandomGenerator(256);
        shakeDigest.SHAKE256_512_ds(theta, m, m.length, new byte[]{G_FCT_DOMAIN});

        // 3. Generate ciphertext c = (u,v)
        // Extract public keys
        long[] h = new long[N_BYTE_64];
        byte[] s = new byte[N_BYTE];
        extractPublicKeys(h, s, pk);

        long[] uTmp = new long[N_BYTE_64];
        long[] vTmp = new long[N1N2_BYTE_64];
        encrypt(uTmp, vTmp, h, s, mLongBytes, theta);
        Utils.fromLongArrayToByteArray(v, vTmp, n1n2);
        Utils.fromLongArrayToByteArray(u, uTmp, n);

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
        byte[] yBits = new byte[n];
        byte[] pk = new byte[40 + N_BYTE];
        extractKeysFromSecretKeys(yBits, pk, sk);

        // Extract u, v, d from ciphertext
        byte[] u = new byte[N_BYTE];
        byte[] v = new byte[N1N2_BYTE];
        byte[] d = new byte[SHA512_BYTES];
        extractCiphertexts(u, v, d, ct);

        // 1. Decrypt -> m'
        long[] mPrime = new long[K_BYTE_64];
        decrypt(mPrime, mPrime, u, v, yBits);

        byte[] mPrimeBytes = new byte[k];
        Utils.fromLongArrayToByteArray(mPrimeBytes, mPrime, k * 8);

        // 2. Compute theta'
        byte[] theta = new byte[SHA512_BYTES];
        HQCKeccakRandomGenerator shakeDigest = new HQCKeccakRandomGenerator(256);
        shakeDigest.SHAKE256_512_ds(theta, mPrimeBytes, mPrimeBytes.length, new byte[]{G_FCT_DOMAIN});

        // 3. Compute c' = Enc(pk, m', theta')
        // Extract public keys
        long[] h = new long[N_BYTE_64];
        byte[] s = new byte[N_BYTE];
        extractPublicKeys(h, s, pk);

        long[] uTmp = new long[N_BYTE_64];
        long[] vTmp = new long[N1N2_BYTE_64];
        encrypt(uTmp, vTmp, h, s, mPrime, theta);

        byte[] u2Bytes = new byte[N_BYTE];
        byte[] v2Bytes = new byte[N1N2_BYTE];

        Utils.fromLongArrayToByteArray(u2Bytes, uTmp, n);
        Utils.fromLongArrayToByteArray(v2Bytes, vTmp, n1n2);

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
    private void encrypt(long[] u, long[] v, long[] h, byte[] s, long[] m, byte[] theta)
    {
        // Randomly generate e, r1, r2
        HQCKeccakRandomGenerator randomGenerator = new HQCKeccakRandomGenerator(256);
        randomGenerator.seedExpanderInit(theta, SEED_SIZE);
        long[] e = new long[N_BYTE_64];
        long[] r1 = new long[N_BYTE_64];
        int[] r2 = new int[wr];
        generateSecretKey(r1, randomGenerator, wr);
        generateSecretKeyByCoordinates(r2, randomGenerator, wr);
        generateSecretKey(e, randomGenerator, we);

        // parsing to bits
        byte[] hBits = new byte[n];
        Utils.fromLongArrayToBitArray(hBits, h);

        byte[] r1Bits = new byte[n];
        Utils.fromLongArrayToBitArray(r1Bits, r1);

        byte[] r2Bits = new byte[n];
        r2Bits = Utils.fromListOfPos1ToBitArray(r2, r2Bits.length);

        byte[] eBits = new byte[n];
        Utils.fromLongArrayToBitArray(eBits, e);

        byte[] sBits = new byte[n];
        Utils.fromByteArrayToBitArray(sBits, s);

        // Calculate u
        PolynomialGF2mSmallM r1Poly = new PolynomialGF2mSmallM(field, Utils.removeLast0Bits(r1Bits));
        PolynomialGF2mSmallM r2Poly = new PolynomialGF2mSmallM(field, Utils.removeLast0Bits(r2Bits));
        PolynomialGF2mSmallM hPoly = new PolynomialGF2mSmallM(field, Utils.removeLast0Bits(hBits));
        PolynomialGF2mSmallM uPoly = r1Poly.add(r2Poly.modKaratsubaMultiplyBigDeg(hPoly, reductionPoly));
        Utils.fromBitArrayToLongArray(u, uPoly.getEncoded());

        // Calculate v
        PolynomialGF2mSmallM sPoly = new PolynomialGF2mSmallM(field, Utils.removeLast0Bits(sBits));
        PolynomialGF2mSmallM ePoly = new PolynomialGF2mSmallM(field, Utils.removeLast0Bits(eBits));

        // encode m
        long[] res = new long[N1_BYTE_64];
        ReedSolomon.encode(res, m, K_BYTE * 8, n1, k, g, generatorPoly);
        ReedMuller.encode(v, res, n1, mulParam);

        byte[] vBits = new byte[n1n2];
        Utils.fromLongArrayToBitArray(vBits, v);

        //Compute v
        PolynomialGF2mSmallM vPoly = new PolynomialGF2mSmallM(field, Utils.removeLast0Bits(vBits));
        vPoly = vPoly.add(sPoly.modKaratsubaMultiplyBigDeg(r2Poly, reductionPoly));
        vPoly = vPoly.add(ePoly);

        long[] vLongTmp = new long[N_BYTE_64];
        Utils.fromBitArrayToLongArray(vLongTmp, vPoly.getEncoded());
        Utils.resizeArray(v, n1n2, vLongTmp, n, N1N2_BYTE_64, N1N2_BYTE_64);
    }

    private void decrypt(long[] output, long[] m, byte[] u, byte[] v, byte[] yBits)
    {
        byte[] uBits = new byte[n];
        Utils.fromByteArrayToBitArray(uBits, u);

        byte[] vBits = new byte[n1n2];
        Utils.fromByteArrayToBitArray(vBits, v);

        long[] uLong = new long[N_BYTE_64];
        Utils.fromBitArrayToLongArray(uLong, uBits);

        long[] vLong = new long[N1N2_BYTE_64];
        Utils.fromBitArrayToLongArray(vLong, vBits);

        PolynomialGF2mSmallM uPoly = new PolynomialGF2mSmallM(field, Utils.removeLast0Bits(uBits));
        PolynomialGF2mSmallM vPoly = new PolynomialGF2mSmallM(field, Utils.removeLast0Bits(vBits));
        PolynomialGF2mSmallM yPoly = new PolynomialGF2mSmallM(field, Utils.removeLast0Bits(yBits));

        PolynomialGF2mSmallM res = vPoly.add(uPoly.modKaratsubaMultiplyBigDeg(yPoly, reductionPoly));

        long[] resLong = new long[N_BYTE_64];
        Utils.fromBitArrayToLongArray(resLong, res.getEncoded());

        // Decode res
        long[] tmp = new long[N1_BYTE_64];
        ReedMuller.decode(tmp, resLong, n1, mulParam);
        ReedSolomon.decode(m, tmp, n1, fft, delta, k, g);

        System.arraycopy(m, 0, output, 0, output.length);
    }

    private void generateSecretKey(long[] output, HQCKeccakRandomGenerator random, int w)
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

    private void generateSecretKeyByCoordinates(int[] output, HQCKeccakRandomGenerator random, int w)
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

    void generatePublicKeyH(long[] out, HQCKeccakRandomGenerator random)
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

        HQCKeccakRandomGenerator randomPublic = new HQCKeccakRandomGenerator(256);
        randomPublic.seedExpanderInit(publicKeySeed, publicKeySeed.length);

        long[] hLongBytes = new long[N_BYTE_64];
        generatePublicKeyH(hLongBytes, randomPublic);

        System.arraycopy(hLongBytes, 0, h, 0, h.length);
        System.arraycopy(pk, 40, s, 0, s.length);
    }

    private void extractKeysFromSecretKeys(byte[] y, byte[] pk, byte[] sk)
    {
        byte[] secretKeySeed = new byte[SEED_SIZE];
        System.arraycopy(sk, 0, secretKeySeed, 0, secretKeySeed.length);

        // Randomly generate secret keys x, y
        HQCKeccakRandomGenerator secretKeySeedExpander = new HQCKeccakRandomGenerator(256);
        secretKeySeedExpander.seedExpanderInit(secretKeySeed, secretKeySeed.length);

        long[] xLongBytes = new long[N_BYTE_64];
        int[] yPos = new int[this.w];

        generateSecretKey(xLongBytes, secretKeySeedExpander, w);
        generateSecretKeyByCoordinates(yPos, secretKeySeedExpander, w);

        // convert to bit array
        byte[] yBits = Utils.fromListOfPos1ToBitArray(yPos, this.n);

        System.arraycopy(yBits, 0, y, 0, y.length);
        System.arraycopy(sk, SEED_SIZE, pk, 0, pk.length);
    }

    private void extractCiphertexts(byte[] u, byte[] v, byte[] d, byte[] ct)
    {
        System.arraycopy(ct, 0, u, 0, u.length);
        System.arraycopy(ct, u.length, v, 0, v.length);
        System.arraycopy(ct, u.length + v.length, d, 0, d.length);
    }
}
