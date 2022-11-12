package org.bouncycastle.pqc.crypto.bike;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

class BIKEEngine
{
    // degree of R
    private int r;

    // the row weight
    private int w;

    // Hamming weight of h0, h1
    private int hw;

    // the error weight
    private int t;

    //the shared secret size
//    private int l;

    // number of iterations in BGF decoder
    private int nbIter;

    // tau
    private int tau;

    private final BIKERing bikeRing;
    private int L_BYTE;
    private int R_BYTE;

    public BIKEEngine(int r, int w, int t, int l, int nbIter, int tau)
    {
        this.r = r;
        this.w = w;
        this.t = t;
//        this.l = l;
        this.nbIter = nbIter;
        this.tau = tau;
        this.hw = this.w / 2;
        this.L_BYTE = l / 8;
        this.R_BYTE = (r + 7) / 8;
        this.bikeRing = new BIKERing(r);
    }

    public int getSessionKeySize()
    {
        return L_BYTE;
    }

    private byte[] functionH(byte[] seed)
    {
        byte[] res = new byte[r * 2];
        Xof digest = new SHAKEDigest(256);
        digest.update(seed, 0, seed.length);
        BIKEUtils.generateRandomByteArray(res,r * 2, t, digest);
        return res;
    }

    private void functionL(byte[] e0, byte[] e1, byte[] result)
    {
        byte[] hashRes = new byte[48];

        SHA3Digest digest = new SHA3Digest(384);
        digest.update(e0, 0, e0.length);
        digest.update(e1, 0, e1.length);
        digest.doFinal(hashRes, 0);

        System.arraycopy(hashRes, 0, result, 0, L_BYTE);
    }

    private void functionK(byte[] m, byte[] c0, byte[] c1, byte[] result)
    {
        byte[] hashRes = new byte[48];

        SHA3Digest digest = new SHA3Digest(384);
        digest.update(m, 0, m.length);
        digest.update(c0, 0, c0.length);
        digest.update(c1, 0, c1.length);
        digest.doFinal(hashRes, 0);

        System.arraycopy(hashRes, 0, result, 0, L_BYTE);
    }

    /**
     * Generate key pairs
     * - Secret key : (h0, h1, sigma)
     * - Public key: h
     *
     * @param h0     h0
     * @param h1     h1
     * @param sigma  sigma
     * @param h      h
     * @param random Secure Random
     **/
    public void genKeyPair(byte[] h0, byte[] h1, byte[] sigma, byte[] h, SecureRandom random)
    {
//         Randomly generate seeds
        byte[] seeds = new byte[64];
        random.nextBytes(seeds);

        Xof digest = new SHAKEDigest(256);
        digest.update(seeds, 0, L_BYTE);

//      1. Randomly generate h0, h1
        BIKEUtils.generateRandomByteArray(h0, r, hw, digest);
        BIKEUtils.generateRandomByteArray(h1, r, hw, digest);

        long[] h0Element = bikeRing.create();
        long[] h1Element = bikeRing.create();
        bikeRing.decodeBytes(h0, h0Element);
        bikeRing.decodeBytes(h1, h1Element);

        // 2. Compute h
        long[] hElement = bikeRing.create();
        bikeRing.inv(h0Element, hElement);
        bikeRing.multiply(hElement, h1Element, hElement);
        bikeRing.encodeBytes(hElement, h);

        //3. Parse seed2 as sigma
        System.arraycopy(seeds, L_BYTE, sigma, 0, sigma.length);
    }

    /**
     * KEM Encapsulation
     * - Input: h
     * - Output: (c0,c1,k)
     *
     * @param c0     ciphertext
     * @param c1     ciphertext
     * @param k      session key
     * @param h      public key
     * @param random Secure Random
     **/
    public void encaps(byte[] c0, byte[] c1, byte[] k, byte[] h, SecureRandom random)
    {
        // 1. Randomly generate m by using seed1
        byte[] m = new byte[L_BYTE];
        random.nextBytes(m);

        // 2. Calculate e0, e1
        byte[] eBytes = functionH(m);

        byte[] eBits = new byte[2 * r];
        BIKEUtils.fromByteArrayToBitArray(eBits, eBytes);

        byte[] e0Bytes = new byte[R_BYTE];
        BIKEUtils.fromBitArrayToByteArray(e0Bytes, eBits, 0, r);

        byte[] e1Bytes = new byte[R_BYTE];
        BIKEUtils.fromBitArrayToByteArray(e1Bytes, eBits, r, r);

        long[] e0Element = bikeRing.create();
        long[] e1Element = bikeRing.create();

        bikeRing.decodeBytes(e0Bytes, e0Element);
        bikeRing.decodeBytes(e1Bytes, e1Element);

        long[] hElement = bikeRing.create();
        bikeRing.decodeBytes(h, hElement);

        // 3. Calculate c
        // calculate c0
        long[] c0Element = bikeRing.create();
        bikeRing.multiply(e1Element, hElement, c0Element);
        bikeRing.add(c0Element, e0Element, c0Element);
        bikeRing.encodeBytes(c0Element, c0);

        //calculate c1
        functionL(e0Bytes, e1Bytes, c1);
        BIKEUtils.xorTo(m, c1, L_BYTE);

        // 4. Calculate K
        functionK(m, c0, c1, k);
    }

    /**
     * KEM Decapsulation
     * - Input: (h0, h1, sigma), (c0, c1)
     * - Output: k
     *
     * @param h0    private key
     * @param h1    private key
     * @param sigma private key
     * @param c0    ciphertext
     * @param c1    ciphertext
     * @param k     session key
     **/
    public void decaps(byte[] k, byte[] h0, byte[] h1, byte[] sigma, byte[] c0, byte[] c1)
    {
        // Get compact version of h0, h1
        int[] h0Compact = new int[hw];
        int[] h1Compact = new int[hw];
        convertToCompact(h0Compact, h0);
        convertToCompact(h1Compact, h1);

        // Compute syndrome
        byte[] syndrome = computeSyndrome(c0, h0);

        // 1. Compute e'
        byte[] ePrimeBits = BGFDecoder(syndrome, h0Compact, h1Compact);
        byte[] ePrimeBytes = new byte[2 * R_BYTE];
        BIKEUtils.fromBitArrayToByteArray(ePrimeBytes, ePrimeBits, 0, 2 * r);

        byte[] e0Bytes = new byte[R_BYTE];
        BIKEUtils.fromBitArrayToByteArray(e0Bytes, ePrimeBits, 0, r);
        byte[] e1Bytes = new byte[R_BYTE];
        BIKEUtils.fromBitArrayToByteArray(e1Bytes, ePrimeBits, r, r);

        // 2. Compute m'
        byte[] mPrime = new byte[L_BYTE];
        functionL(e0Bytes, e1Bytes, mPrime);
        BIKEUtils.xorTo(c1, mPrime, L_BYTE);

        // 3. Compute K
        byte[] wlist = functionH(mPrime);
        if (Arrays.areEqual(ePrimeBytes, 0, ePrimeBytes.length, wlist, 0, ePrimeBytes.length))
        {
            functionK(mPrime, c0, c1, k);
        }
        else
        {
            functionK(sigma, c0, c1, k);
        }
    }

    private byte[] computeSyndrome(byte[] c0, byte[] h0)
    {
        long[] c0Element = bikeRing.create();
        long[] h0Element = bikeRing.create();
        bikeRing.decodeBytes(c0, c0Element);
        bikeRing.decodeBytes(h0, h0Element);
        long[] sElement = bikeRing.create();
        bikeRing.multiply(c0Element, h0Element, sElement);
        return transpose(bikeRing.encodeBits(sElement));
    }

    private byte[] BGFDecoder(byte[] s, int[] h0Compact, int[] h1Compact)
    {
        byte[] e = new byte[2 * r];

        // Get compact column version
        int[] h0CompactCol = getColumnFromCompactVersion(h0Compact);
        int[] h1CompactCol = getColumnFromCompactVersion(h1Compact);

        byte[] black = new byte[2 * r];
        byte[] ctrs = new byte[r];

        {
            byte[] gray = new byte[2 * r];

            int T = threshold(BIKEUtils.getHammingWeight(s), r);

            BFIter(s, e, T, h0Compact, h1Compact, h0CompactCol, h1CompactCol, black, gray, ctrs);
            BFMaskedIter(s, e, black, (hw + 1) / 2 + 1, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
            BFMaskedIter(s, e, gray, (hw + 1) / 2 + 1, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
        }
        for (int i = 1; i < nbIter; i++)
        {
            Arrays.fill(black, (byte)0);

            int T = threshold(BIKEUtils.getHammingWeight(s), r);

            BFIter2(s, e, T, h0Compact, h1Compact, h0CompactCol, h1CompactCol, ctrs);
        }
        if (BIKEUtils.getHammingWeight(s) == 0)
        {
            return e;
        }
        else
        {
            return null;
        }
    }

    private byte[] transpose(byte[] in)
    {
        byte[] output = new byte[r];
        output[0] = in[0];
        for (int i = 1; i < r; i++)
        {
            output[i] = in[r - i];
        }
        return output;
    }

    private void BFIter(byte[] s, byte[] e, int T, int[] h0Compact, int[] h1Compact, int[] h0CompactCol,
        int[] h1CompactCol, byte[] black, byte[] gray, byte[] ctrs)
    {
        // calculate for h0compact
        {
            ctrAll(h0CompactCol, s, ctrs);

            {
                int count = ctrs[0] & 0xFF;
                int ctrBit1 = ((count - T) >> 31) + 1;
                int ctrBit2 = ((count - (T - tau)) >> 31) + 1;
                e[0] ^= (byte)ctrBit1;
                black[0] = (byte)ctrBit1;
                gray[0] = (byte)ctrBit2;
            }
            for (int j = 1; j < r; j++)
            {
                int count = ctrs[j] & 0xFF;
                int ctrBit1 = ((count - T) >> 31) + 1;
                int ctrBit2 = ((count - (T - tau)) >> 31) + 1;
                e[r - j] ^= (byte)ctrBit1;
                black[j] = (byte)ctrBit1;
                gray[j] = (byte)ctrBit2;
            }
        }

        // calculate for h1Compact
        {
            ctrAll(h1CompactCol, s, ctrs);

            {
                int count = ctrs[0] & 0xFF;
                int ctrBit1 = ((count - T) >> 31) + 1;
                int ctrBit2 = ((count - (T - tau)) >> 31) + 1;
                e[r] ^= (byte)ctrBit1;
                black[r] = (byte)ctrBit1;
                gray[r] = (byte)ctrBit2;
            }
            for (int j = 1; j < r; j++)
            {
                int count = ctrs[j] & 0xFF;
                int ctrBit1 = ((count - T) >> 31) + 1;
                int ctrBit2 = ((count - (T - tau)) >> 31) + 1;
                e[r + r - j] ^= (byte)ctrBit1;
                black[r + j] = (byte)ctrBit1;
                gray[r + j] = (byte)ctrBit2;
            }
        }

        // recompute syndrome
        for (int i = 0; i < 2 * r; i++)
        {
            if (black[i] != 0)
            {
                recomputeSyndrome(s, i, h0Compact, h1Compact);
            }
        }
    }

    private void BFIter2(byte[] s, byte[] e, int T, int[] h0Compact, int[] h1Compact, int[] h0CompactCol, int[] h1CompactCol, byte[] ctrs)
    {
        int[] updatedIndices = new int[2 * r];

        // calculate for h0compact
        {
            ctrAll(h0CompactCol, s, ctrs);

            {
                int count = ctrs[0] & 0xFF;
                int ctrBit1 = ((count - T) >> 31) + 1;
                e[0] ^= (byte)ctrBit1;
                updatedIndices[0] = ctrBit1;
            }
            for (int j = 1; j < r; j++)
            {
                int count = ctrs[j] & 0xFF;
                int ctrBit1 = ((count - T) >> 31) + 1;
                e[r - j] ^= (byte)ctrBit1;
                updatedIndices[j] = ctrBit1;
            }
        }

        // calculate for h1Compact
        {
            ctrAll(h1CompactCol, s, ctrs);

            {
                int count = ctrs[0] & 0xFF;
                int ctrBit1 = ((count - T) >> 31) + 1;
                e[r] ^= (byte)ctrBit1;
                updatedIndices[r] = ctrBit1;
            }
            for (int j = 1; j < r; j++)
            {
                int count = ctrs[j] & 0xFF;
                int ctrBit1 = ((count - T) >> 31) + 1;
                e[r + r - j] ^= (byte)ctrBit1;
                updatedIndices[r + j] = ctrBit1;
            }
        }

        // recompute syndrome
        for (int i = 0; i < 2 * r; i++)
        {
            if (updatedIndices[i] == 1)
            {
                recomputeSyndrome(s, i, h0Compact, h1Compact);
            }
        }
    }

    private void BFMaskedIter(byte[] s, byte[] e, byte[] mask, int T, int[] h0Compact, int[] h1Compact, int[] h0CompactCol, int[] h1CompactCol)
    {
        int[] updatedIndices = new int[2 * r];

        for (int j = 0; j < r; j++)
        {
            if (mask[j] == 1)
            {
                if (ctr(h0CompactCol, s, j) >= T)
                {
                    updateNewErrorIndex(e, j);
                    updatedIndices[j] = 1;
                }
            }
        }

        for (int j = 0; j < r; j++)
        {
            if (mask[r + j] == 1)
            {
                if (ctr(h1CompactCol, s, j) >= T)
                {
                    updateNewErrorIndex(e, r + j);
                    updatedIndices[r + j] = 1;
                }
            }
        }

        // recompute syndrome
        for (int i = 0; i < 2 * r; i++)
        {
            if (updatedIndices[i] == 1)
            {
                recomputeSyndrome(s, i, h0Compact, h1Compact);
            }
        }
    }

    private int threshold(int hammingWeight, int r)
    {
        switch (r)
        {
        case 12323: return thresholdFromParameters(hammingWeight, 0.0069722, 13.530, 36);
        case 24659: return thresholdFromParameters(hammingWeight, 0.005265, 15.2588, 52);
        case 40973: return thresholdFromParameters(hammingWeight, 0.00402312, 17.8785, 69);
        default:    throw new IllegalArgumentException();
        }
//        return res;
    }

    private static int thresholdFromParameters(int hammingWeight, double dm, double da, int min)
    {
        return Math.max(min, (int)Math.floor(dm * hammingWeight + da));
    }

    private int ctr(int[] hCompactCol, byte[] s, int j)
    {
//        assert 0 <= j && j < r;

        int count = 0;

        int i = 0, limit = hw - 4;
        while (i <= limit)
        {
            int sPos0 = hCompactCol[i + 0] + j - r;
            int sPos1 = hCompactCol[i + 1] + j - r;
            int sPos2 = hCompactCol[i + 2] + j - r;
            int sPos3 = hCompactCol[i + 3] + j - r;

            sPos0 += (sPos0 >> 31) & r;
            sPos1 += (sPos1 >> 31) & r;
            sPos2 += (sPos2 >> 31) & r;
            sPos3 += (sPos3 >> 31) & r;

            count += s[sPos0] & 0xFF;
            count += s[sPos1] & 0xFF;
            count += s[sPos2] & 0xFF;
            count += s[sPos3] & 0xFF;

            i += 4;
        }
        while (i < hw)
        {
            int sPos = hCompactCol[i] + j - r;
            sPos += (sPos >> 31) & r;
            count += s[sPos] & 0xFF;
            ++i;
        }
        return count;
    }

    private void ctrAll(int[] hCompactCol, byte[] s, byte[] ctrs)
    {
        {
            int col = hCompactCol[0], neg = r - col;
            System.arraycopy(s, col, ctrs, 0, neg);
            System.arraycopy(s, 0, ctrs, neg, col);
        }
        for (int i = 1; i < hw; ++i)
        {
            int col = hCompactCol[i], neg = r - col;

            int j = 0;
            // TODO Vectorization when available
            {
                int jLimit = neg - 4;
                while (j <= jLimit)
                {
                    ctrs[j + 0] += s[col + j + 0] & 0xFF;
                    ctrs[j + 1] += s[col + j + 1] & 0xFF;
                    ctrs[j + 2] += s[col + j + 2] & 0xFF;
                    ctrs[j + 3] += s[col + j + 3] & 0xFF;
                    j += 4;
                }
            }
            {
                while (j < neg)
                {
                    ctrs[j] += s[col + j] & 0xFF;
                    ++j;
                }
            }

            int k = neg;
            // TODO Vectorization when available
            {
                int kLimit = r - 4;
                while (k <= kLimit)
                {
                    ctrs[k + 0] += s[k + 0 - neg] & 0xFF;
                    ctrs[k + 1] += s[k + 1 - neg] & 0xFF;
                    ctrs[k + 2] += s[k + 2 - neg] & 0xFF;
                    ctrs[k + 3] += s[k + 3 - neg] & 0xFF;
                    k += 4;
                }
            }
            {
                while (k < r)
                {
                    ctrs[k] += s[k - neg] & 0xFF;
                    ++k;
                }
            }
        }
    }

    // Convert a polynomial in GF2 to an array of positions of which the coefficients of the polynomial are equals to 1
    private void convertToCompact(int[] compactVersion, byte[] h)
    {
        // maximum size of this array is the Hamming weight of the polynomial
        int count = 0;
        for (int i = 0; i < R_BYTE; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                if ((i * 8 + j) == this.r)
                {
                    break;
                }

                if (((h[i] >> j) & 1) == 1)
                {
                    compactVersion[count++] = i * 8 + j;
                }
            }
        }
    }

    private int[] getColumnFromCompactVersion(int[] hCompact)
    {
        int[] hCompactColumn = new int[hw];
        if (hCompact[0] == 0)
        {
            hCompactColumn[0] = 0;
            for (int i = 1; i < hw; i++)
            {
                hCompactColumn[i] = r - hCompact[hw - i];
            }
        }
        else
        {
            for (int i = 0; i < hw; i++)
            {
                hCompactColumn[i] = r - hCompact[hw - 1 - i];
            }
        }
        return hCompactColumn;
    }

    private void recomputeSyndrome(byte[] syndrome, int index, int[] h0Compact, int[] h1Compact)
    {
        if (index < r)
        {
            for (int i = 0; i < hw; i++)
            {
                if (h0Compact[i] <= index)
                {
                    syndrome[index - h0Compact[i]] ^= 1;
                }
                else
                {
                    syndrome[r + index - h0Compact[i]] ^= 1;
                }
            }
        }
        else
        {
            for (int i = 0; i < hw; i++)
            {
                if (h1Compact[i] <= (index - r))
                {
                    syndrome[(index - r) - h1Compact[i]] ^= 1;
                }
                else
                {
                    syndrome[r - h1Compact[i] + (index - r)] ^= 1;
                }
            }
        }
    }

    private void updateNewErrorIndex(byte[] e, int index)
    {
        int newIndex = index;
        if (index != 0 && index != r)
        {
            if (index > r)
            {
                newIndex = 2 * r - index + r;
            }
            else
            {
                newIndex = r - index;
            }
        }
        e[newIndex] ^= 1;
    }
}
