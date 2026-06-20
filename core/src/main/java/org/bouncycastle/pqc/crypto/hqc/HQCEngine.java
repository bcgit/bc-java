package org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class HQCEngine
{
    static final int SHARED_SECRET_BYTES = 32;
    private static final int SALT_BYTES = 16;
    private static final int SEED_BYTES = 32;

    private final int n;
    private final int n1;
    private final int k;
    private final int delta;
    private final int w;
    private final int wr;
    private final int fft;
    private final int mulParam;
    private final int N_BYTE;
    private final int N1N2_BYTE_64;
    private final int N1N2_BYTE;
    private final int[] generatorPoly;
    private final int nMu;
    private final int pkSize;
    private final GF2x gf2x;
    private final int rejectionThreshold;
    private final int cipherTextBytes;

    HQCEngine(int n, int n1, int n2, int k, int delta, int w, int wr, int fft, int nMu, int pkSize,
        int[] generatorPoly)
    {
        this.n = n;
        this.k = k;
        this.delta = delta;
        this.w = w;
        this.wr = wr;
        this.n1 = n1;
        this.generatorPoly = generatorPoly;
        this.fft = fft;
        this.nMu = nMu;
        this.pkSize = pkSize;
        this.mulParam = n2 >> 7;
        this.N_BYTE = Utils.getByteSizeFromBitSize(n);
        this.N1N2_BYTE_64 = Utils.getByte64SizeFromBitSize(n1 * n2);
        this.N1N2_BYTE = Utils.getByteSizeFromBitSize(n1 * n2);
        this.gf2x = new GF2x(n);
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
        long[] yLongBytes = gf2x.create();
        long[] h = gf2x.create(); // s

        secureRandom.nextBytes(seedKem);
        Shake256RandomGenerator ctxKem = new Shake256RandomGenerator(seedKem, (byte)1);
        System.arraycopy(seedKem, 0, sk, pkSize + SEED_BYTES + k, SEED_BYTES);

        ctxKem.nextBytes(seedKem);
        ctxKem.nextBytes(sk, pkSize + SEED_BYTES, k);

        hashHI(keypairSeed, 512, seedKem, seedKem.length, (byte)2);
        ctxKem.init(keypairSeed, 0, SEED_BYTES, (byte)1);

        int[] ySupport = sampleSupport1(ctxKem, w);
        int[] xSupport = sampleSupport1(ctxKem, w);
        writeSupportToVector(yLongBytes, ySupport, w);
        System.arraycopy(keypairSeed, SEED_BYTES, pk, 0, SEED_BYTES);
        ctxKem.init(keypairSeed, SEED_BYTES, SEED_BYTES, (byte)1);
        gf2x.random(ctxKem, h);
        gf2x.mul(h, yLongBytes, h); // h is s as the output
        addSupportTo(h, xSupport, w); // h ^= x
        Utils.fromLongArrayToByteArray(pk, SEED_BYTES, pk.length - SEED_BYTES, h);
        System.arraycopy(keypairSeed, 0, sk, pkSize, SEED_BYTES);
        System.arraycopy(pk, 0, sk, 0, pkSize);
        Arrays.clear(keypairSeed);
        Arrays.clear(ySupport);
        Arrays.clear(xSupport);
        gf2x.clear(yLongBytes);
        gf2x.clear(h);
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
        byte[] m = new byte[k];
        byte[] hashEkKem = new byte[SEED_BYTES];
        long[] u64 = gf2x.create();
        long[] v64 = new long[N1N2_BYTE_64];

        secureRandom.nextBytes(m);
        secureRandom.nextBytes(salt);

        hashHI(hashEkKem, 256, pk, pk.length, (byte)1);
        hashGJ(kTheta, 512, hashEkKem, m, 0, m.length, salt, 0, SALT_BYTES, (byte)0);
        pkeEncrypt(u64, v64, pk, m, kTheta, SEED_BYTES);
        Utils.fromLongArrayToByteArray(u, 0, u.length, u64);
        Utils.fromLongArrayToByteArray(v, 0, v.length, v64);
        gf2x.clear(u64);
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
        long[] u64 = gf2x.create();
        long[] v64 = new long[N1N2_BYTE_64]; // ciphertext v: an n1*n2-bit codeword, not a ring element
        long[] cKemPrimeU64 = gf2x.create(); // tmpLong
        long[] cKemPrimeV64 = gf2x.create(); // re-encryption v scratch
        byte[] hashEkKem = new byte[SEED_BYTES];
        byte[] kThetaPrime = new byte[32 + SEED_BYTES];
        byte[] mPrime = new byte[k];
        byte[] kBar = new byte[32];
        byte[] tmp = new byte[n1];

        Shake256RandomGenerator generator = new Shake256RandomGenerator(sk, pkSize, SEED_BYTES, (byte)1);
        int[] ySupport = sampleSupport1(generator, w);
        writeSupportToVector(cKemPrimeV64, ySupport, w); // cKemPrimeV64 holds dense y for the multiply

        // Extract u, v, d from ciphertext
        Utils.fromByteArrayToLongArray(u64, ct, 0, N_BYTE);
        Utils.fromByteArrayToLongArray(v64, ct, N_BYTE, N1N2_BYTE);

        // cKemPrimeU64 is tmpLong
        gf2x.mul(cKemPrimeV64, u64, cKemPrimeU64);
        vectTruncate(cKemPrimeU64);
        Nat.xorTo64(N1N2_BYTE_64, v64, cKemPrimeU64); // cKemPrimeU64 ^= v over the codeword limbs

        ReedMuller.decode(tmp, cKemPrimeU64, n1, mulParam);
        ReedSolomon.decode(mPrime, tmp, n1, fft, delta, k, generatorPoly.length);

        // Compute shared key K_prime and ciphertext cKemPrime
        hashHI(hashEkKem, 256, sk, pkSize, (byte)1);
        hashGJ(kThetaPrime, 512, hashEkKem, mPrime, 0, mPrime.length, ct, N_BYTE + N1N2_BYTE, SALT_BYTES, (byte)0);
        System.arraycopy(kThetaPrime, 0, ss, 0, 32);
        Arrays.fill(cKemPrimeV64, 0L); // clear y before reusing cKemPrimeV64 for the re-encryption v
        pkeEncrypt(cKemPrimeU64, cKemPrimeV64, sk, mPrime, kThetaPrime, 32);
        hashGJ(kBar, 256, hashEkKem, sk, pkSize + SEED_BYTES, k, ct, 0, ct.length, (byte)3);

        // u is a full ring element; v is an n1*n2-bit codeword, so compare it over just the codeword
        // limbs (cKemPrimeV64's higher limbs are unused re-encryption scratch).
        int result = (int)(gf2x.equalTo(u64, cKemPrimeU64) & Nat.equalTo64(N1N2_BYTE_64, v64, cKemPrimeV64));

        // On re-encryption failure the implicit-rejection secret kBar must replace the *entire*
        // shared secret. Bounding this by k would leave ss[k..] holding K' = G(H(pk)||m'||salt),
        // which depends on the decrypted m' - an FO/IND-CCA break for the parameter sets with
        // k < SHARED_SECRET_BYTES (HQC-128: 16, HQC-192: 24).
        for (int i = 0; i < SHARED_SECRET_BYTES; i++)
        {
            ss[i] = (byte)(((ss[i] & result) ^ (kBar[i] & ~result)) & 0xff);
        }

        gf2x.clear(u64);
        Nat.zero64(v64.length, v64);
        gf2x.clear(cKemPrimeU64);
        gf2x.clear(cKemPrimeV64);
        Arrays.clear(ySupport);
        Arrays.clear(hashEkKem);
        Arrays.clear(kThetaPrime);
        Arrays.clear(mPrime);
        Arrays.clear(kBar);
        Arrays.clear(tmp);
        return -result;
    }

    private void pkeEncrypt(long[] u, long[] v, byte[] ekPke, byte[] m, byte[] theta, int thetaOff)
    {
        long[] r2Dense = gf2x.create();
        long[] tmp = gf2x.create(); // s, h1, h
        byte[] res = new byte[n1];

        ReedSolomon.encode(res, m, n1, k, generatorPoly);
        ReedMuller.encode(v, res, n1, mulParam);

        Shake256RandomGenerator randomGenerator = new Shake256RandomGenerator(ekPke, 0, SEED_BYTES, (byte)1);
        gf2x.random(randomGenerator, tmp);

        randomGenerator.init(theta, thetaOff, SEED_BYTES, (byte)1);
        int[] r2Support = sampleSupport2(randomGenerator, wr);
        writeSupportToVector(r2Dense, r2Support, wr);
        gf2x.mul(tmp, r2Dense, u);
        Utils.fromByteArrayToLongArray(tmp, ekPke, SEED_BYTES, pkSize - SEED_BYTES);
        gf2x.mul(tmp, r2Dense, tmp);
        int[] eSupport = sampleSupport2(randomGenerator, wr);
        addSupportTo(tmp, eSupport, wr); // tmp ^= e
        vectTruncate(tmp);
        Nat.xorTo64(N1N2_BYTE_64, tmp, v);

        int[] r1Support = sampleSupport2(randomGenerator, wr);
        addSupportTo(u, r1Support, wr); // u ^= r1
        Arrays.clear(r2Support);
        Arrays.clear(eSupport);
        Arrays.clear(r1Support);
        gf2x.clear(r2Dense);
        gf2x.clear(tmp);
        Arrays.clear(res);
    }

    private int barrettReduce(int x)
    {
        int q = (int)(((long)x * nMu) >>> 32);
        int r = x - n - q * n;
        return r + ((r >> 31) & n);
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
            if (duplicate)
            {
                continue;
            }

            support[count++] = candidate;
        }
    }

    /**
     * Constant-time materialisation of a fixed-weight sparse vector (given as its support
     * indices) into a freshly-zeroed dense long[] target. Branchless mask-OR over every
     * (i, j) pair, so neither timing nor cache-access patterns leak the secret support.
     */
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
                val |= bitTab[j] & ~((tmp | -tmp) >> 31);
            }
            v[i] = val;
        }
    }

    /**
     * Constant-time XOR of a fixed-weight sparse vector (given as its support indices) into a
     * dense long[] target. Equivalent to materialising the sparse vector to a dense long[] and
     * then XORing it into {@code out}, but in a single pass without the dense intermediate.
     * The (i, j) iteration pattern matches {@link #writeSupportToVector}'s constant-time
     * branchless mask-OR, so timing and cache-access do not leak the secret support indices.
     */
    private void addSupportTo(long[] out, int[] support, int weight)
    {
        int[] indexTab = new int[wr];
        long[] bitTab = new long[wr];
        for (int i = 0; i < weight; i++)
        {
            indexTab[i] = support[i] >>> 6;
            bitTab[i] = 1L << (support[i] & 0x3F);
        }
        for (int i = 0; i < out.length; i++)
        {
            long val = out[i];
            for (int j = 0; j < weight; j++)
            {
                int tmp = i - indexTab[j];
                val ^= bitTab[j] & ~((tmp | -tmp) >> 31);
            }
            out[i] = val;
        }
    }

    private int[] sampleSupport1(Shake256RandomGenerator random, int weight)
    {
        int[] support = new int[wr];
        generateRandomSupport(support, weight, random);
        return support;
    }

    private int[] sampleSupport2(Shake256RandomGenerator generator, int weight)
    {
        byte[] rand = new byte[wr << 2];
        generator.xofGetBytes(rand, rand.length);

        int[] support = new int[wr];
        Pack.littleEndianToInt(rand, 0, support);

        int i = weight;
        while (--i >= 0)
        {
            int support_i = i + (int)(((support[i] & 0xFFFFFFFFL) * (n - i)) >> 32);
            int notFound = -1;
            for (int j = i + 1; j < weight; ++j)
            {
                notFound &= cdiff(support_i, support[j]);
            }
            support[i] = (~notFound & i) ^ (notFound & support_i);
        }
        return support;
    }

    private void vectTruncate(long[] v)
    {
        Arrays.fill(v, N1N2_BYTE_64, (n + 63) >> 6, 0L);
    }

    private static int cdiff(int v1, int v2)
    {
        return ((v1 - v2) | (v2 - v1)) >> 31;
    }

    private static void hashGJ(byte[] output, int bitLength, byte[] hashEkKem, byte[] mOrSigma, int mOrSigmaOff,
        int mOrSigmaLen, byte[] saltOrCt, int saltOrCtOff, int saltOrCtOffLen, byte domain)
    {
        SHA3Digest digest = new SHA3Digest(bitLength);
        digest.update(hashEkKem, 0, hashEkKem.length);
        digest.update(mOrSigma, mOrSigmaOff, mOrSigmaLen);
        digest.update(saltOrCt, saltOrCtOff, saltOrCtOffLen);
        digest.update(domain);
        digest.doFinal(output, 0);
    }

    private static void hashHI(byte[] output, int bitLength, byte[] in, int inLen, byte domain)
    {
        SHA3Digest digest = new SHA3Digest(bitLength);
        digest.update(in, 0, inLen);
        digest.update(domain);
        digest.doFinal(output, 0);
    }
}
