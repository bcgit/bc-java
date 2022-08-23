package org.bouncycastle.pqc.crypto.bike;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
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
    private int l;

    // number of iterations in BGF decoder
    private int nbIter;

    // tau
    private int tau;

    private GF2mField field;
    private final PolynomialGF2mSmallM reductionPoly;
    private int L_BYTE;
    private int R_BYTE;

    public BIKEEngine(int r, int w, int t, int l, int nbIter, int tau)
    {
        this.r = r;
        this.w = w;
        this.t = t;
        this.l = l;
        this.nbIter = nbIter;
        this.tau = tau;
        this.hw = this.w / 2;
        this.L_BYTE = l / 8;
        this.R_BYTE = (r + 7) / 8;

        // finite field GF(2)
        GF2mField field = new GF2mField(1);
        this.field = field;

        // generate reductionPoly (X^r + 1)
        PolynomialGF2mSmallM poly = new PolynomialGF2mSmallM(field, r);
        this.reductionPoly = poly.addMonomial(0);
    }

    public int getSessionKeySize()
    {
        return L_BYTE;
    }

    private byte[] functionH(byte[] seed)
    {
        Xof digest = new SHAKEDigest(256);
        digest.update(seed, 0, seed.length);
        byte[] wlist = BIKERandomGenerator.generateRandomByteArray(r * 2, 2 * R_BYTE, t, digest);
        return wlist;
    }

    private byte[] functionL(byte[] e0, byte[] e1)
    {
        byte[] hashRes = new byte[48];
        byte[] res = new byte[L_BYTE];

        SHA3Digest digest = new SHA3Digest(384);
        digest.update(e0, 0, e0.length);
        digest.update(e1, 0, e1.length);
        digest.doFinal(hashRes, 0);

        System.arraycopy(hashRes, 0, res, 0, L_BYTE);
        return res;
    }

    private byte[] functionK(byte[] m, byte[] c0, byte[] c1)
    {
        byte[] hashRes = new byte[48];
        byte[] res = new byte[L_BYTE];

        SHA3Digest digest = new SHA3Digest(384);
        digest.update(m, 0, m.length);
        digest.update(c0, 0, c0.length);
        digest.update(c1, 0, c1.length);
        digest.doFinal(hashRes, 0);

        System.arraycopy(hashRes, 0, res, 0, L_BYTE);
        return res;
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
        byte[] h0Tmp = BIKERandomGenerator.generateRandomByteArray(r, R_BYTE, hw, digest);
        byte[] h1Tmp = BIKERandomGenerator.generateRandomByteArray(r, R_BYTE, hw, digest);

        System.arraycopy(h0Tmp, 0, h0, 0, h0.length);
        System.arraycopy(h1Tmp, 0, h1, 0, h1.length);

        byte[] h1Bits = new byte[r];
        byte[] h0Bits = new byte[r];

        Utils.fromByteArrayToBitArray(h0Bits, h0Tmp);
        Utils.fromByteArrayToBitArray(h1Bits, h1Tmp);

        // remove last 0 bits (most significant bits with 0 mean non-sense)
        byte[] h0Cut = Utils.removeLast0Bits(h0Bits);
        byte[] h1Cut = Utils.removeLast0Bits(h1Bits);

        // 2. Compute h
        PolynomialGF2mSmallM h0Poly = new PolynomialGF2mSmallM(this.field, h0Cut);
        PolynomialGF2mSmallM h1Poly = new PolynomialGF2mSmallM(this.field, h1Cut);

        PolynomialGF2mSmallM h0Inv = h0Poly.modInverseBigDeg(reductionPoly);
        PolynomialGF2mSmallM hPoly = h1Poly.modKaratsubaMultiplyBigDeg(h0Inv, reductionPoly);

        // Get coefficients of hPoly
        byte[] hTmp = hPoly.getEncoded();
        byte[] hByte = new byte[R_BYTE];
        Utils.fromBitArrayToByteArray(hByte, hTmp);
        System.arraycopy(hByte, 0, h, 0, h.length);

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
        Utils.fromByteArrayToBitArray(eBits, eBytes);

        byte[] e0Bits = Arrays.copyOfRange(eBits, 0, r);
        byte[] e1Bits = Arrays.copyOfRange(eBits, r, eBits.length);

        // remove last 0 bits (most significant bits with 0 mean no sense)
        byte[] e0Cut = Utils.removeLast0Bits(e0Bits);
        byte[] e1Cut = Utils.removeLast0Bits(e1Bits);

        PolynomialGF2mSmallM e0 = new PolynomialGF2mSmallM(field, e0Cut);
        PolynomialGF2mSmallM e1 = new PolynomialGF2mSmallM(field, e1Cut);

        // 3. Calculate c
        // calculate c0
        byte[] h0Bits = new byte[r];
        Utils.fromByteArrayToBitArray(h0Bits, h);
        PolynomialGF2mSmallM hPoly = new PolynomialGF2mSmallM(field, Utils.removeLast0Bits(h0Bits));
        PolynomialGF2mSmallM c0Poly = e0.add(e1.modKaratsubaMultiplyBigDeg(hPoly, reductionPoly));

        byte[] c0Bits = c0Poly.getEncoded();
        byte[] c0Bytes = new byte[R_BYTE];
        Utils.fromBitArrayToByteArray(c0Bytes, c0Bits);
        System.arraycopy(c0Bytes, 0, c0, 0, c0.length);

        //calculate c1
        byte[] e0Bytes = new byte[R_BYTE];
        Utils.fromBitArrayToByteArray(e0Bytes, e0Bits);
        byte[] e1Bytes = new byte[R_BYTE];
        Utils.fromBitArrayToByteArray(e1Bytes, e1Bits);

        byte[] tmp = functionL(e0Bytes, e1Bytes);
        byte[] c1Tmp = Utils.xorBytes(m, tmp, L_BYTE);
        System.arraycopy(c1Tmp, 0, c1, 0, c1.length);

        // 4. Calculate K
        byte[] kTmp = functionK(m, c0, c1);
        System.arraycopy(kTmp, 0, k, 0, kTmp.length);
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
        //convert to bits
        byte[] c0Bits = new byte[this.r];
        byte[] h0Bits = new byte[this.r];
        byte[] sigmaBits = new byte[this.l];

        Utils.fromByteArrayToBitArray(c0Bits, c0);
        Utils.fromByteArrayToBitArray(h0Bits, h0);
        Utils.fromByteArrayToBitArray(sigmaBits, sigma);

        byte[] c0Cut = Utils.removeLast0Bits(c0Bits);
        byte[] h0Cut = Utils.removeLast0Bits(h0Bits);

        // Get compact version of h0, h1
        int[] h0Compact = new int[hw];
        int[] h1Compact = new int[hw];
        convertToCompact(h0Compact, h0);
        convertToCompact(h1Compact, h1);

        // Compute syndrome
        byte[] syndrome = computeSyndrome(c0Cut, h0Cut);

        // 1. Compute e'
        byte[] ePrimeBits = BGFDecoder(syndrome, h0Compact, h1Compact);
        byte[] ePrimeBytes = new byte[2 * R_BYTE];
        Utils.fromBitArrayToByteArray(ePrimeBytes, ePrimeBits);

        byte[] e0Bits = Arrays.copyOfRange(ePrimeBits, 0, r);
        byte[] e1Bits = Arrays.copyOfRange(ePrimeBits, r, ePrimeBits.length);

        byte[] e0Bytes = new byte[R_BYTE];
        Utils.fromBitArrayToByteArray(e0Bytes, e0Bits);
        byte[] e1Bytes = new byte[R_BYTE];
        Utils.fromBitArrayToByteArray(e1Bytes, e1Bits);

        // 2. Compute m'
        byte[] mPrime = Utils.xorBytes(c1, functionL(e0Bytes, e1Bytes), L_BYTE);

        // 3. Compute K
        byte[] tmpK = new byte[l];
        byte[] wlist = functionH(mPrime);
        if (Arrays.areEqual(ePrimeBytes, wlist))
        {
            tmpK = functionK(mPrime, c0, c1);
        }
        else
        {
            tmpK = functionK(sigma, c0, c1);
        }
        System.arraycopy(tmpK, 0, k, 0, tmpK.length);
    }

    private byte[] computeSyndrome(byte[] h0, byte[] c0)
    {
        PolynomialGF2mSmallM coPoly = new PolynomialGF2mSmallM(field, c0);
        PolynomialGF2mSmallM h0Poly = new PolynomialGF2mSmallM(field, h0);

        PolynomialGF2mSmallM s = coPoly.modKaratsubaMultiplyBigDeg(h0Poly, reductionPoly);
        byte[] transposedS = transpose(s.getEncoded());
        return transposedS;
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

            int T = threshold(Utils.getHammingWeight(s), i, r);

            BFIter(s, e, T, h0Compact, h1Compact, h0CompactCol, h1CompactCol, black, gray);

            if (i == 1)
            {
                BFMaskedIter(s, e, black, (hw + 1) / 2 + 1, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
                BFMaskedIter(s, e, gray, (hw + 1) / 2 + 1, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
            }
        }
        if (Utils.getHammingWeight(s) == 0)
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
        byte[] tmp = Utils.append0s(in, r); // append zeros to s
        byte[] out = new byte[r];
        out[0] = tmp[0];
        for (int i = 1; i < r; i++)
        {
            out[i] = tmp[r - i];
        }
        return out;
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
