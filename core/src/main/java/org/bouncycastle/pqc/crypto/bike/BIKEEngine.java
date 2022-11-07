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

        byte[] seed1 = new byte[L_BYTE];
        byte[] seed2 = new byte[L_BYTE];
        System.arraycopy(seeds, 0, seed1, 0, seed1.length);
        System.arraycopy(seeds, seed1.length, seed2, 0, seed2.length);

        Xof digest = new SHAKEDigest(256);
        digest.update(seed1, 0, seed1.length);

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
        System.arraycopy(seed2, 0, sigma, 0, sigma.length);
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
        byte[] seeds = new byte[64];
        random.nextBytes(seeds);

        // 1. Randomly generate m by using seed1
        byte[] m = new byte[L_BYTE];
        System.arraycopy(seeds, 0, m, 0, m.length);

        // 2. Calculate e0, e1
        byte[] eBytes = functionH(m);

        byte[] eBits = new byte[2 * r];
        BIKEUtils.fromByteArrayToBitArray(eBits, eBytes);

        byte[] e0Bits = Arrays.copyOfRange(eBits, 0, r);
        byte[] e0Bytes = new byte[R_BYTE];
        BIKEUtils.fromBitArrayToByteArray(e0Bytes, e0Bits);
        
        byte[] e1Bits = Arrays.copyOfRange(eBits, r, eBits.length);
        byte[] e1Bytes = new byte[R_BYTE];
        BIKEUtils.fromBitArrayToByteArray(e1Bytes, e1Bits);

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
        BIKEUtils.fromBitArrayToByteArray(ePrimeBytes, ePrimeBits);

        byte[] e0Bits = Arrays.copyOfRange(ePrimeBits, 0, r);
        byte[] e1Bits = Arrays.copyOfRange(ePrimeBits, r, ePrimeBits.length);

        byte[] e0Bytes = new byte[R_BYTE];
        BIKEUtils.fromBitArrayToByteArray(e0Bytes, e0Bits);
        byte[] e1Bytes = new byte[R_BYTE];
        BIKEUtils.fromBitArrayToByteArray(e1Bytes, e1Bits);

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

        for (int i = 1; i <= nbIter; i++)
        {
            byte[] black = new byte[2 * r];
            byte[] gray = new byte[2 * r];

            int T = threshold(BIKEUtils.getHammingWeight(s), i, r);

            BFIter(s, e, T, h0Compact, h1Compact, h0CompactCol, h1CompactCol, black, gray);

            if (i == 1)
            {
                BFMaskedIter(s, e, black, (hw + 1) / 2 + 1, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
                BFMaskedIter(s, e, gray, (hw + 1) / 2 + 1, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
            }
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

    private void BFIter(byte[] s, byte[] e, int T, int[] h0Compact, int[] h1Compact, int[] h0CompactCol, int[] h1CompactCol, byte[] black, byte[] gray)
    {
        int[] updatedIndices = new int[2 * r];

        // calculate for h0compact
        for (int j = 0; j < r; j++)
        {
            if (ctr(h0CompactCol, s, j) >= T)
            {
                updateNewErrorIndex(e, j);
                updatedIndices[j] = 1;
                black[j] = 1;
            }
            else if (ctr(h0CompactCol, s, j) >= T - tau)
            {
                gray[j] = 1;
            }
        }

        // calculate for h1Compact
        for (int j = 0; j < r; j++)
        {
            if (ctr(h1CompactCol, s, j) >= T)
            {
                updateNewErrorIndex(e, r + j);
                updatedIndices[r + j] = 1;
                black[r + j] = 1;
            }
            else if (ctr(h1CompactCol, s, j) >= T - tau)
            {
                gray[r + j] = 1;
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
            if (ctr(h0CompactCol, s, j) >= T && mask[j] == 1)
            {
                updateNewErrorIndex(e, j);
                updatedIndices[j] = 1;
            }
        }

        for (int j = 0; j < r; j++)
        {
            if (ctr(h1CompactCol, s, j) >= T && mask[r + j] == 1)
            {
                updateNewErrorIndex(e, r + j);
                updatedIndices[r + j] = 1;
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

    private int threshold(int hammingWeight, int i, int r)
    {
        double d = 0;
        int floorD = 0;
        int res = 0;
        switch (r)
        {
        case 12323:
            d = 0.0069722 * hammingWeight + 13.530;
            floorD = (int)Math.floor(d);
            res = floorD > 36 ? floorD : 36;
            break;
        case 24659:
            d = 0.005265 * hammingWeight + 15.2588;
            floorD = (int)Math.floor(d);
            res = floorD > 52 ? floorD : 52;
            break;
        case 40973:
            d = 0.00402312 * hammingWeight + 17.8785;
            floorD = (int)Math.floor(d);
            res = floorD > 69 ? floorD : 69;
            break;
        }
        return res;
    }

    private int ctr(int[] hCompactCol, byte[] s, int j)
    {
        int count = 0;
        for (int i = 0; i < hw; i++)
        {
            if (s[(hCompactCol[i] + j) % r] == 1)
            {
                count += 1;
            }
        }
        return count;
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
