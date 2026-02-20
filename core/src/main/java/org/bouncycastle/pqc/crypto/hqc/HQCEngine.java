package org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class HQCEngine
{
    private static final int SALT_BYTES = 16;
    private static final int SEED_BYTES = 32;

    private final int n;
    private final int n1;
    private final int k;
    private final int delta;
    private final int w;
    private final int wr;
    private final int g;
    private final int fft;
    private final int mulParam;
    private final int N_BYTE;
    private final int K_BYTE;
    private final int N1N2_BYTE_64;
    private final int N1N2_BYTE;
    private final int[] generatorPoly;
    private final int N_MU;
    private final int pkSize;
    private final GF2PolynomialCalculator gf;
    private final int rejectionThreshold;
    private final int cipherTextBytes;

    HQCEngine(int n, int n1, int n2, int k, int g, int delta, int w, int wr, int fft, int nmu, int pkSize,
        int[] generatorPoly)
    {
        this.n = n;
        this.k = k;
        this.delta = delta;
        this.w = w;
        this.wr = wr;
        this.n1 = n1;
        this.generatorPoly = generatorPoly;
        this.g = g;
        this.fft = fft;
        this.N_MU = nmu;
        this.pkSize = pkSize;
        this.mulParam = n2 >> 7;
        this.N_BYTE = Utils.getByteSizeFromBitSize(n);
        this.K_BYTE = k;
        this.N1N2_BYTE_64 = Utils.getByte64SizeFromBitSize(n1 * n2);
        this.N1N2_BYTE = Utils.getByteSizeFromBitSize(n1 * n2);
        this.gf = new GF2PolynomialCalculator(n);
        this.rejectionThreshold = ((1 << 24) / n) * n;
        this.cipherTextBytes = N_BYTE + N1N2_BYTE + 16;
    }

    int getCipherTextBytes()
    {
        return cipherTextBytes;
    }

    /**
     * Generate key pairs - Secret key : (x,y) - Public key: (h,s)
     *
     * @param pk output pk = (publicSeed||s)
     **/
    void genKeyPair(byte[] pk, byte[] sk, SecureRandom secureRandom)
    {
        // Randomly generate seeds for secret keys and public keys
        byte[] seedKem = new byte[SEED_BYTES]; // seedKem
        byte[] keypairSeed = new byte[SEED_BYTES << 1];
        long[] xLongBytes = gf.create();
        long[] yLongBytes = gf.create();
        long[] h = gf.create(); // s

        secureRandom.nextBytes(seedKem);
        Shake256RandomGenerator ctxKem = new Shake256RandomGenerator(seedKem, (byte)1);
        System.arraycopy(seedKem, 0, sk, pkSize + SEED_BYTES + K_BYTE, SEED_BYTES);

        ctxKem.nextBytes(seedKem);
        ctxKem.nextBytes(sk, pkSize + SEED_BYTES, K_BYTE);

        hashHI(keypairSeed, 512, seedKem, seedKem.length, (byte)2);
        ctxKem.init(keypairSeed, 0, SEED_BYTES, (byte)1);

        vectSampleFixedWeight1(yLongBytes, ctxKem, w);
        vectSampleFixedWeight1(xLongBytes, ctxKem, w);
        System.arraycopy(keypairSeed, SEED_BYTES, pk, 0, SEED_BYTES);
        ctxKem.init(keypairSeed, SEED_BYTES, SEED_BYTES, (byte)1);
        gf.random(ctxKem, h);
        gf.mul(h, yLongBytes, h); // h is s as the output
        gf.addTo(xLongBytes, h); // h is s
        Utils.fromLongArrayToByteArray(pk, SEED_BYTES, pk.length - SEED_BYTES, h);
        System.arraycopy(keypairSeed, 0, sk, pkSize, SEED_BYTES);
        System.arraycopy(pk, 0, sk, 0, pkSize);
        Arrays.clear(keypairSeed);
        Arrays.clear(xLongBytes);
        Arrays.clear(yLongBytes);
        Arrays.clear(h);
    }

    /**
     * HQC Encapsulation - Input: pk, seed - Output: c = (u,v,d), K
     *
     * @param u u
     * @param v v
     * @param kTheta session key
     * @param pk public key
     **/
    void encaps(byte[] u, byte[] v, byte[] kTheta, byte[] pk, byte[] salt, SecureRandom secureRandom)
    {
        // 1. Randomly generate m
        byte[] m = new byte[K_BYTE];
        byte[] hashEkKem = new byte[SEED_BYTES];
        long[] u64 = gf.create();
        long[] v64 = new long[N1N2_BYTE_64];

        secureRandom.nextBytes(m);
        secureRandom.nextBytes(salt);

        hashHI(hashEkKem, 256, pk, pk.length, (byte)1);
        hashGJ(kTheta, 512, hashEkKem, m, 0, m.length, salt, 0, SALT_BYTES, (byte)0);
        pkeEncrypt(u64, v64, pk, m, kTheta, SEED_BYTES);
        Utils.fromLongArrayToByteArray(u, 0, u.length, u64);
        Utils.fromLongArrayToByteArray(v, 0, v.length, v64);
        Arrays.clear(u64);
        Arrays.clear(v64);
        Arrays.clear(m);
        Arrays.clear(hashEkKem);
    }

    /**
     * HQC Decapsulation - Input: ct, sk - Output: ss
     *
     * @param ss session key
     * @param ct ciphertext
     * @param sk secret key
     * @return 0 if decapsulation is successful, -1 otherwise
     **/
    int decaps(byte[] ss, byte[] ct, byte[] sk)
    {
        // Extract Y and Public Keys from sk
        long[] u64 = gf.create();
        long[] v64 = gf.create();
        long[] cKemPrimeU64 = gf.create(); // tmpLong
        long[] cKemPrimeV64 = gf.create(); // y
        byte[] hashEkKem = new byte[SEED_BYTES];
        byte[] kThetaPrime = new byte[32 + SEED_BYTES];
        byte[] mPrime = new byte[k];
        byte[] kBar = new byte[32];
        byte[] tmp = new byte[n1];

        Shake256RandomGenerator generator = new Shake256RandomGenerator(sk, pkSize, SEED_BYTES, (byte)1);
        vectSampleFixedWeight1(cKemPrimeV64, generator, w); // cKemPrimeV64 is y

        // Extract u, v, d from ciphertext
        Utils.fromByteArrayToLongArray(u64, ct, 0, N_BYTE);
        Utils.fromByteArrayToLongArray(v64, ct, N_BYTE, N1N2_BYTE);

        // cKemPrimeU64 is tmpLong
        gf.mul(cKemPrimeV64, u64, cKemPrimeU64);
        vectTruncate(cKemPrimeU64);
        gf.addTo(v64, cKemPrimeU64);

        ReedMuller.decode(tmp, cKemPrimeU64, n1, mulParam);
        ReedSolomon.decode(mPrime, tmp, n1, fft, delta, k, g);

        // Compute shared key K_prime and ciphertext cKemPrime
        hashHI(hashEkKem, 256, sk, pkSize, (byte)1);
        hashGJ(kThetaPrime, 512, hashEkKem, mPrime, 0, mPrime.length, ct, N_BYTE + N1N2_BYTE, SALT_BYTES, (byte)0);
        System.arraycopy(kThetaPrime, 0, ss, 0, 32);
        Arrays.fill(cKemPrimeV64, 0L);
        pkeEncrypt(cKemPrimeU64, cKemPrimeV64, sk, mPrime, kThetaPrime, 32);
        hashGJ(kBar, 256, hashEkKem, sk, pkSize + SEED_BYTES, K_BYTE, ct, 0, ct.length, (byte)3);

        int result = (int)(gf.equalTo(u64, cKemPrimeU64) & gf.equalTo(v64, cKemPrimeV64));

        for (int i = 0; i < K_BYTE; i++)
        {
            ss[i] = (byte)(((ss[i] & result) ^ (kBar[i] & ~result)) & 0xff);
        }

        Arrays.clear(u64);
        Arrays.clear(v64);
        Arrays.clear(cKemPrimeU64);
        Arrays.clear(cKemPrimeV64);
        Arrays.clear(hashEkKem);
        Arrays.clear(kThetaPrime);
        Arrays.clear(mPrime);
        Arrays.clear(kBar);
        Arrays.clear(tmp);
        return -result;
    }

    private void pkeEncrypt(long[] u, long[] v, byte[] ekPke, byte[] m, byte[] theta, int thetaOff)
    {
        long[] e = gf.create(); // r2
        long[] tmp = gf.create(); // s, h1, h
        byte[] res = new byte[n1];

        ReedSolomon.encode(res, m, n1, k, g, generatorPoly);
        ReedMuller.encode(v, res, n1, mulParam);

        Shake256RandomGenerator randomGenerator = new Shake256RandomGenerator(ekPke, 0, SEED_BYTES, (byte)1);
        gf.random(randomGenerator, tmp);

        randomGenerator.init(theta, thetaOff, SEED_BYTES, (byte)1);
        vectSampleFixedWeights2(randomGenerator, e, wr); // e is r2
        gf.mul(tmp, e, u); // e is r2
        Utils.fromByteArrayToLongArray(tmp, ekPke, SEED_BYTES, pkSize - SEED_BYTES);
        gf.mul(tmp, e, tmp);
        vectSampleFixedWeights2(randomGenerator, e, wr);
        gf.addTo(e, tmp);
        vectTruncate(tmp);
        Nat.xorTo64(N1N2_BYTE_64, tmp, v);

        vectSampleFixedWeights2(randomGenerator, tmp, wr);// tmp is r1
        gf.addTo(tmp, u);
        Arrays.clear(e);
        Arrays.clear(tmp);
        Arrays.clear(res);
    }

    private int barrettReduce(int x)
    {
        long q = ((long) x * N_MU) >>> 32;
        int r = x - (int) (q * n);
        r -= (-(((r - n) >>> 31) ^ 1)) & n;
        return r;
    }

    private void generateRandomSupport(int[] support, int weight, Shake256RandomGenerator random)
    {
        int randomBytesSize = 3 * weight;
        byte[] randBytes = new byte[randomBytesSize];
        int j = randomBytesSize;

        int count = 0;
        while (count < weight)
        {
            if (j == randomBytesSize)
            {
                random.xofGetBytes(randBytes, randomBytesSize);
                j = 0;
            }
            int candidate = ((randBytes[j++] & 0xFF) << 16) | ((randBytes[j++] & 0xFF) << 8) | randBytes[j++] & 0xFF;
            if (candidate >= rejectionThreshold)
            {
                continue;
            }
            candidate = barrettReduce(candidate);
            boolean duplicate = false;

            for (int k = 0; k < count; k++)
            {
                if (support[k] == candidate)
                {
                    duplicate = true;
                    break;
                }
            }

            if (!duplicate)
            {
                support[count++] = candidate;
            }
        }
    }

    private void writeSupportToVector(long[] v, int[] support, int weight)
    {
        int[] indexTab = new int[wr];
        long[] bitTab = new long[wr];
        for (int i = 0; i < weight; i++)
        {
            indexTab[i] = support[i] >>> 6;
            bitTab[i] = 1L << (support[i] & 0x3F);
        }
        for (int i = 0; i < v.length; i++)
        {
            long val = 0;
            for (int j = 0; j < weight; j++)
            {
                int tmp = i - indexTab[j];
                val |= (bitTab[j] & -(1 ^ ((tmp | -tmp) >>> 31)));
            }
            v[i] = val;
        }
    }

    public void vectSampleFixedWeight1(long[] output, Shake256RandomGenerator random, int weight)
    {
        int[] support = new int[wr];
        generateRandomSupport(support, weight, random);
        writeSupportToVector(output, support, weight);
    }

    private static void hashHI(byte[] output, int bitLength, byte[] in, int inLen, byte domain)
    {
        SHA3Digest digest = new SHA3Digest(bitLength);
        digest.update(in, 0, inLen);
        digest.update(domain);
        digest.doFinal(output, 0);
    }

    private void hashGJ(byte[] output, int bitLength, byte[] hashEkKem, byte[] mOrSigma, int mOrSigmaOff,
        int mOrSigmaLen, byte[] saltOrCt, int saltOrCtOff, int saltOrCtOffLen, byte domain)
    {
        SHA3Digest digest = new SHA3Digest(bitLength);
        digest.update(hashEkKem, 0, hashEkKem.length);
        digest.update(mOrSigma, mOrSigmaOff, mOrSigmaLen);
        digest.update(saltOrCt, saltOrCtOff, saltOrCtOffLen);
        digest.update(domain);
        digest.doFinal(output, 0);
    }

    private void vectSampleFixedWeights2(Shake256RandomGenerator generator, long[] v, int weight)
    {
        int[] support = new int[wr];
        byte[] rand = new byte[wr << 2];
        generator.xofGetBytes(rand, rand.length);
        Pack.littleEndianToInt(rand, 0, support);
        for (int i = 0; i < weight; ++i)
        {
            support[i] = i + (int) (((support[i] & 0xFFFFFFFFL) * (n - i)) >> 32);
        }

        for (int i = weight - 1; i-- > 0;)
        {
            int found = 0;
            for (int j = i + 1; j < weight; ++j)
            {
                found |= compareU32(support[j], support[i]);
            }
            found = -found;
            support[i] = (found & i) ^ (~found & support[i]);
        }
        writeSupportToVector(v, support, weight);
    }

    private static int compareU32(int v1, int v2)
    {
        return 1 ^ (((v1 - v2) | (v2 - v1)) >>> 31);
    }

    private void vectTruncate(long[] v)
    {
        Arrays.fill(v, N1N2_BYTE_64, (n + 63) >> 6, 0L);
    }
}
