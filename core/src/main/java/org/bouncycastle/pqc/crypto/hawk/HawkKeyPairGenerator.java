package org.bouncycastle.pqc.crypto.hawk;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Lightweight Hawk key pair generator. Initialised with a
 * {@link HawkKeyGenerationParameters} containing the parameter set and a
 * {@link SecureRandom}; produces a {@link HawkPublicKeyParameters} /
 * {@link HawkPrivateKeyParameters} pair.
 */
public class HawkKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private HawkParameters p;
    private SecureRandom random;
    static final byte[] lowBitsQ00 = {0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 6};
    static final byte[] lowBitsQ01 = {0, 0, 0, 0, 0, 0, 0, 0, 8, 9, 10};

    public void init(KeyGenerationParameters param)
    {
        this.p = ((HawkKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        int logn = p.logn;
        int[] tmp = new int[(26 << logn) + 7];

        int n = 1 << logn;

        // Align to 8-byte boundary (simplified for Java)
        int alignedOffset = 0;

        // Allocate arrays within the tmp buffer
        int fOffset = 7;
        int gOffset = fOffset + n;
        int tt8Offset = 0;//gOffset + n;

        // F and G will be stored in the same location as tt8 (they overlap)
        int FOffset = tt8Offset;
        int GOffset = FOffset + n;

        // Calculate positions for q00, q01, q11 (using int array for mixed types)
        int q00Offset = (GOffset + n) >> 1;
        int q01Offset = q00Offset + n;
        int q11Offset = (q01Offset + n) >> 1;

        int seedLen = 8 + (1 << (logn - 5));
        int seedOffset = ((q11Offset + n) << 2) + ((((q01Offset + n) >> 1) & 1) << 1) + (((GOffset + n) >> 1) & 1);

        // Calculate private and public key sizes
        int privLen = p.getPrivateKeySize();
        int pubLen = p.getPublicKeySize();

        int tprivOffset = seedOffset + seedLen;
        int tpubOffset = tprivOffset + privLen;

        // Convert tmp buffer to different types for easier access
        // We'll use separate arrays for different types
        byte[] f = new byte[n];
        byte[] g = new byte[n];
        byte[] F = new byte[n];
        byte[] G = new byte[n];
        short[] q00 = new short[n];
        short[] q01 = new short[n];
        int[] q11 = new int[n];
        byte[] seed = new byte[seedLen];
        byte[] tmpBytes = null;
        while (true)
        {
            // Call Hawk_keygen to generate the key material
            int result = Hawk_keygen(logn,
                f, 0, g, 0,
                F, 0, G, 0,
                q00, 0, q01, 0, q11, 0,
                seed, 0,
                tmp, 0, tmp.length - (0 - alignedOffset));

            tmpBytes = Pack.intToLittleEndian(tmp); //tt8

            // Encode public key
            if (encodePublic(logn, tmpBytes, tpubOffset, pubLen, q00, 0, q01, 0))
            {
                // Encode private key (ignore return value as in C code)
                encodePrivate(logn, tmpBytes, tprivOffset, seed, 0, F, 0, G, 0, tmpBytes, tpubOffset, pubLen);
                break;
            }
        }
        HawkPrivateKeyParameters priv = new HawkPrivateKeyParameters(p, tmpBytes, tprivOffset, privLen);
        HawkPublicKeyParameters pub = new HawkPublicKeyParameters(p, tmpBytes, tpubOffset, pubLen);

        return new AsymmetricCipherKeyPair(pub, priv);
    }

    // Encode public key
    public static boolean encodePublic(int logn, byte[] dst, int dstOffset, int dstLen,
                                       short[] q00, int q00Offset, short[] q01, int q01Offset)
    {
        /*
         * General format:
         *   q00
         *   q01
         *   padding
         * q00 and q01 both use Golomb-Rice coding.
         *
         * Special handling of q00[0]: since it has a larger possible
         * range than the rest of the coefficients, it is temporarily
         * downscaled (q00[0] is modified, but the original value is put
         * back afterwards). The extra bits are appended at the end of the
         * encoding of q00.
         */

        int low00 = lowBitsQ00[logn];
        int low01 = lowBitsQ01[logn];
        int eb00Len = 16 - (low00 + 4);

        int bufOffset = dstOffset;
        int remainingLen = dstLen;

        /* q00 */
        int[] numIgnored = new int[1];
        short savedQ00 = q00[q00Offset];  // Save original q00[0]
        q00[q00Offset] = (short)(q00[q00Offset] >> eb00Len);  // Temporarily scale down

        int len00 = encodeGR(logn - 1, dst, bufOffset, remainingLen, q00, q00Offset, low00, numIgnored);

        q00[q00Offset] = savedQ00;  // Restore original value

        if (len00 == 0)
        {
            return false;
        }

        /* Extra bits of q00[0] */
        int eb00 = savedQ00 & ((1 << eb00Len) - 1);
        int ni = numIgnored[0];

        if (eb00Len <= ni)
        {
            dst[bufOffset + len00 - 1] |= (byte)(eb00 << (8 - ni));
        }
        else
        {
            if (len00 >= remainingLen)
            {
                return false;
            }
            dst[bufOffset + len00 - 1] |= (byte)(eb00 << (8 - ni));
            dst[bufOffset + len00] = (byte)(eb00 >> ni);
            len00++;
        }

        bufOffset += len00;
        remainingLen -= len00;

        /* q01 */
        int len01 = encodeGR(logn, dst, bufOffset, remainingLen,
            q01, q01Offset, low01, null);
        if (len01 == 0)
        {
            return false;
        }

        bufOffset += len01;
        remainingLen -= len01;

        /* Padding to the requested length. */
        Arrays.fill(dst, bufOffset, bufOffset + remainingLen, (byte)0);
        return true;
    }

    /*
     * Golomb-Rice encoding, with part segregation (sign bits, fixed-size
     * parts, variable-size parts). The fixed-size part has size 'low' bits.
     * The ignored bits in the last byte are set to 0, and their number is
     * written in *num_ignored (0 to 7). The total number of written bytes
     * is returned.
     *
     * If the encoded size would exceed dst_len, then the process fails
     * and the function returns 0.
     */
    private static int encodeGR(int logn, byte[] dst, int dstOffset, int dstLen,
                                short[] a, int aOffset, int low, int[] numIgnored)
    {
        int n = 1 << logn;
        int bufOffset = dstOffset;
        int remainingLen = dstLen;

        // Check minimum buffer size
        int minSize = (low + 1) << (logn - 3);
        if (remainingLen < minSize)
        {
            return 0;
        }

        /* Sign bits */
        for (int u = 0; u < n; u += 8)
        {
            int x = 0;
            for (int v = 0; v < 8; v++)
            {
                int signBit = ((a[aOffset + u + v] & 0xFFFF) >>> 15) & 1;
                x |= signBit << v;
            }
            dst[bufOffset + (u >> 3)] = (byte)x;
        }

        bufOffset += (n >> 3);
        remainingLen -= (n >> 3);

        /* Fixed-size parts */
        int lowMask = (1 << low) - 1;

        if (low <= 8)
        {
            for (int u = 0; u < n; u += 8)
            {
                long x = 0;
                for (int v = 0, shift = 0; v < 8; v++, shift += low)
                {
                    int w = a[aOffset + u + v];
                    int mask = HawkEngine.tbmask(w);
                    w ^= mask;
                    x |= (long)(w & lowMask) << shift;
                }

                // Write bytes (little-endian)
                for (int i = 0; i < low; i++)
                {
                    dst[bufOffset++] = (byte)(x & 0xFF);
                    x >>>= 8;
                }
            }
        }
        else
        {
            for (int u = 0; u < n; u += 8)
            {
                long x0 = 0;
                for (int v = 0, shift = 0; v < 4; v++, shift += low)
                {
                    int w = a[aOffset + u + v];
                    int mask = HawkEngine.tbmask(w);
                    w ^= mask;
                    x0 |= (long)(w & lowMask) << shift;
                }

                long x1 = 0;
                for (int v = 4, shift = 0; v < 8; v++, shift += low)
                {
                    int w = a[aOffset + u + v];
                    int mask = HawkEngine.tbmask(w);
                    w ^= mask;
                    x1 |= (long)(w & lowMask) << shift;
                }

                int shiftAmount = low * 4;
                x0 |= x1 << shiftAmount;
                x1 >>>= (64 - shiftAmount);

                // Write first 8 bytes from x0
                for (int i = 0; i < 8; i++)
                {
                    dst[bufOffset++] = (byte)(x0 & 0xFF);
                    x0 >>>= 8;
                }

                // Write remaining bytes from x1
                int remainingBytes = low - 8;
                for (int i = 0; i < remainingBytes; i++)
                {
                    dst[bufOffset++] = (byte)(x1 & 0xFF);
                    x1 >>>= 8;
                }
            }
        }

        remainingLen -= low << (logn - 3);

        /* Variable-size parts */
        int acc = 0;
        int accLen = 0;

        for (int u = 0; u < n; u++)
        {
            int w = a[aOffset + u];
            int mask = HawkEngine.tbmask(w);
            int k = (w ^ mask) >>> low;

            acc |= 1 << (accLen + k);
            accLen += 1 + k;

            while (accLen >= 8)
            {
                if (remainingLen == 0)
                {
                    return 0;
                }
                dst[bufOffset++] = (byte)(acc & 0xFF);
                remainingLen--;
                acc >>>= 8;
                accLen -= 8;
            }
        }

        // Flush remaining bits
        if (accLen > 0)
        {
            if (remainingLen == 0)
            {
                return 0;
            }
            dst[bufOffset++] = (byte)(acc & 0xFF);
            remainingLen--;
        }

        // Set ignored bits count
        if (numIgnored != null)
        {
            numIgnored[0] = (-accLen) & 7;
        }

        return bufOffset - dstOffset;
    }

    // Extract least significant bits
    public static void extractLowBit(int logn, byte[] dst, int dstOffset, byte[] f)
    {
        int n = 1 << logn;
        for (int u = 0; u < n; u += 8)
        {
            dst[dstOffset + (u >>> 3)] = (byte)(
                (f[u] & 1) |
                    ((f[u + 1] & 1) << 1) |
                    ((f[u + 2] & 1) << 2) |
                    ((f[u + 3] & 1) << 3) |
                    ((f[u + 4] & 1) << 4) |
                    ((f[u + 5] & 1) << 5) |
                    ((f[u + 6] & 1) << 6) |
                    ((f[u + 7] & 1) << 7)
            );
        }
    }

    public int Hawk_keygen(int logn,
                           byte[] f, int fOffset,
                           byte[] g, int gOffset,
                           byte[] F, int FOffset,
                           byte[] G, int GOffset,
                           short[] q00, int q00Offset,
                           short[] q01, int q01Offset,
                           int[] q11, int q11Offset,
                           byte[] seed, int seedOffset,
                           int[] tmp, int tmpOffset, int tmpLen)
    {

        // Validate parameters
        if (tmpLen < 7)
        {
            return -1;
        }
        if (logn < 2 || logn > 10)
        {
            return -1;
        }

        // Align to 8-byte boundary (simplified for Java)
        int alignedTmpOffset = tmpOffset;
        int alignedTmpLen = tmpLen;

        // Check if we have enough space (24 << logn)
        if (alignedTmpLen < (24 << logn))
        {
            return -1;
        }

        // Profile selection based on logn
        int l2low;
        long d0high;
        HawkParameters prof;

        switch (logn)
        {
        case 8:
            l2low = 556;
            d0high = 17179869; // 1/250
            prof = HawkParameters.Hawk_256;
            break;
        case 9:
            l2low = 2080;
            d0high = 4294967; // 1/1000
            prof = HawkParameters.Hawk_512;
            break;
        case 10:
            l2low = 7981;
            d0high = 1431655; // 1/3000
            prof = HawkParameters.Hawk_1024;
            break;
        default:
            return -1;
        }

        // Get limits from precomputed arrays
        int lim00 = 1 << HawkEngine.BITS_LIM00[logn];
        int lim01 = 1 << HawkEngine.BITS_LIM01[logn];
        int lim11 = 1 << HawkEngine.BITS_LIM11[logn];

        int n = 1 << logn;
        int hn = n >> 1;
        int seedLen = 8 + (1 << (logn - 5));
        byte[] seedBuf = new byte[seedLen];
        // Main key generation loop
        while (true)
        {
            // Generate f and g
            random.nextBytes(seedBuf);
            HawkEngine.Hawk_regen_fg(logn, f, fOffset, g, gOffset, seedBuf);

            // Check if f and g are both odd
            if (HawkEngine.parity(logn, f, fOffset) != 1 || HawkEngine.parity(logn, g, gOffset) != 1)
            {
                continue;
            }

            // Check norm bounds
            int norm2_fg = HawkEngine.polySqNorm(logn, f, fOffset) + HawkEngine.polySqNorm(logn, g, gOffset);
            if (norm2_fg < l2low)
            {
                continue;
            }

            // Check invertibility modulo first prime
            int t1 = alignedTmpOffset;
            int t2 = t1 + n;
            int t3 = t2 + n;
            int t4 = t3 + n;

            SmallPrime prime0 = HawkEngine.PRIMES[0];
            int p = (int)prime0.p;
            int p0i = (int)prime0.p0i;
            int R2 = (int)prime0.R2;

            boolean invertible = true;
            HawkEngine.mpMkgmigm(logn, tmp, t1, tmp, t2, (int)prime0.g, (int)prime0.ig, p, p0i);

            // Convert f and g to modular representation
            for (int u = 0; u < n; u++)
            {
                tmp[t3 + u] = HawkEngine.mp_set(f[fOffset + u], p);
                tmp[t4 + u] = HawkEngine.mp_set(g[gOffset + u], p);
            }

            HawkEngine.mpNTT(logn, tmp, t3, tmp, t1, p, p0i);
            HawkEngine.mpNTT(logn, tmp, t4, tmp, t1, p, p0i);

            // Compute f*adj(f) + g*adj(g)
            for (int u = 0; u < n; u++)
            {
                int adjF = tmp[t3 + (n - 1) - u];
                int adjG = tmp[t4 + (n - 1) - u];
                int term1 = HawkEngine.mpMontyMul(tmp[t3 + u], adjF, p, p0i);
                int term2 = HawkEngine.mpMontyMul(tmp[t4 + u], adjG, p, p0i);
                int x = HawkEngine.mpAdd(term1, term2, p);

                if (x == 0)
                {
                    invertible = false;
                    break;
                }
                x = HawkEngine.mpMontyMul(R2, x, p, p0i);
                tmp[t1 + u] = x;
            }

            if (!invertible)
            {
                continue;
            }

            // Convert back to plain representation
            HawkEngine.mpINTT(logn, tmp, t1, tmp, t2, p, p0i);
            for (int u = 0; u < n; u++)
            {
                tmp[t1 + u] = HawkEngine.mpNorm(tmp[t1 + u], p);
            }

            // Check invertibility modulo second prime
            SmallPrime prime1 = HawkEngine.PRIMES[1];
            p = (int)prime1.p;
            p0i = (int)prime1.p0i;

            for (int u = 0; u < n; u++)
            {
                tmp[t2 + u] = HawkEngine.mp_set(tmp[t1 + u], p);
            }

            HawkEngine.mpMkgm(logn, tmp, t3, (int)prime1.g, p, p0i);
            HawkEngine.mpNTT(logn, tmp, t2, tmp, t3, p, p0i);

            for (int u = 0; u < n; u++)
            {
                if (tmp[t2 + u] == 0)
                {
                    invertible = false;
                    break;
                }
            }

            if (!invertible)
            {
                continue;
            }

            int rt1Pos = t2;

            // Check constant term bound using FFT
            long[] rt1 = new long[n];
            for (int u = 0; u < n; u++)
            {
                rt1[u] = HawkEngine.fxrOf(tmp[t1 + u]);
            }

            HawkEngine.vectFFT(logn, rt1, 0);

            // Invert in frequency domain (only first half due to symmetry)
            for (int u = 0; u < hn; u++)
            {
                rt1[u] = HawkEngine.fxrInv(rt1[u]);
            }

            // Normally the values are already zero, or close to zero in case of loss of precision. We force them to zero
            Arrays.fill(rt1, hn, n, 0L);

            HawkEngine.vectIFFT(logn, rt1, 0);
            boolean result = HawkEngine.fxrLt(d0high, rt1[0]);
            HawkEngine.fromLongArrayToByte32Array(tmp, rt1Pos, rt1);
            if (result)
            {
                continue;
            }

            // Solve the NTRU equation
            int err = HawkEngine.solve_NTRU(prof, logn, f, fOffset, g, gOffset, tmp, alignedTmpOffset);
            if (err != HawkEngine.SOLVE_OK)
            {
                continue;
            }

            // F and G are at the start of tmp[] after solving
            int tF = alignedTmpOffset;
            int tG = tF + n;

            // Compute q00, q01, q11
            int qTempOffset = (tG + n) >> 2;
            byte[] tmpBytes = Pack.intToLittleEndian(tmp);
            boolean make_q001Result = HawkEngine.make_q001(logn, lim00, lim01, lim11,
                f, fOffset, g, gOffset, tmpBytes, tF, tmpBytes, tG, tmp, qTempOffset);
            if (!make_q001Result)
            {
                continue;
            }
            short[] tmpShorts = new short[tmp.length << 1];
            HawkEngine.fromByte32ArrayToShortArray(tmpShorts, 0, tmp, 0, tmp.length);
            int tq00 = qTempOffset << 1;
            int tq01 = tq00 + n;
            int tq11 = (tq01 + n) >> 1;
            int tseed = (tq11 + n) << 1;

            // Copy seed to temporary buffer
            System.arraycopy(seedBuf, 0, seed, seedOffset, seedLen);

            // Copy results to output arrays
            if (F != null)
            {
                Pack.intToLittleEndian(tmp, tF, n >> 2, F, FOffset);
            }

            if (G != null)
            {
                Pack.intToLittleEndian(tmp, tG >> 2, n >> 2, G, GOffset);
            }

            if (q00 != null)
            {
                System.arraycopy(tmpShorts, tq00, q00, q00Offset, n);
            }

            if (q01 != null)
            {
                System.arraycopy(tmpShorts, tq01, q01, q01Offset, n);
            }

            if (q11 != null)
            {
                for (int u = 0; u < n; u++)
                {
                    q11[q11Offset + u] = tmp[tq11 + u];
                }
            }

            return 0; // Success
        }
    }

    public static int encodePrivate(int logn, byte[] dst, int dstOffset,
                                    byte[] seed, int seedOffset,
                                    byte[] F, int fOffset,
                                    byte[] G, int gOffset,
                                    byte[] pub, int pubOffset, int pubLen)
    {
        int n = 1 << logn;
        int currentOffset = dstOffset;

        // Calculate lengths
        int seedLen = 8 + (1 << (logn - 5));
        int hpubLen = 1 << (logn - 4);

        // 1. Copy seed
        System.arraycopy(seed, seedOffset, dst, currentOffset, seedLen);
        currentOffset += seedLen;

        // 2. F mod 2 and G mod 2
        extractLowBit(logn, dst, currentOffset, F, fOffset);
        currentOffset += (n >> 3);

        extractLowBit(logn, dst, currentOffset, G, gOffset);
        currentOffset += (n >> 3);

        // 3. Public key hash (SHAKE256)
        byte[] publicKeyHash = computeShake256Hash(
            Arrays.copyOfRange(pub, pubOffset, pubOffset + pubLen), hpubLen);
        System.arraycopy(publicKeyHash, 0, dst, currentOffset, hpubLen);
        currentOffset += hpubLen;

        return currentOffset - dstOffset;
    }

    private static void extractLowBit(int logn, byte[] dest, int destOffset,
                                      byte[] src, int srcOffset)
    {
        int n = 1 << logn;
        for (int u = 0; u < n; u += 8)
        {
            byte packedBits = (byte)(
                (src[srcOffset + u] & 1) |
                    ((src[srcOffset + u + 1] & 1) << 1) |
                    ((src[srcOffset + u + 2] & 1) << 2) |
                    ((src[srcOffset + u + 3] & 1) << 3) |
                    ((src[srcOffset + u + 4] & 1) << 4) |
                    ((src[srcOffset + u + 5] & 1) << 5) |
                    ((src[srcOffset + u + 6] & 1) << 6) |
                    ((src[srcOffset + u + 7] & 1) << 7)
            );
            dest[destOffset + (u >> 3)] = packedBits;
        }
    }

    private static byte[] computeShake256Hash(byte[] input, int outputLength)
    {
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(input, 0, input.length);
        byte[] hash = new byte[outputLength];
        shake.doOutput(hash, 0, outputLength);
        return hash;
    }
}
