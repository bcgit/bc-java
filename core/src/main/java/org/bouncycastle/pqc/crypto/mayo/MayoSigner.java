package org.bouncycastle.pqc.crypto.mayo;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;

public class MayoSigner
    implements MessageSigner
{
    private SecureRandom random;
    MayoParameters params;
    private MayoPublicKeyParameter pubKey;
    private MayoPrivateKeyParameter privKey;

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {

        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (MayoPrivateKeyParameter)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (MayoPrivateKeyParameter)param;
                random = null;
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (MayoPublicKeyParameter)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        byte[] tenc = new byte[params.getMBytes()];
        byte[] t = new byte[params.getM()];
        byte[] y = new byte[params.getM()];
        byte[] salt = new byte[params.getSaltBytes()];
        byte[] V = new byte[params.getK() * params.getVBytes() + params.getRBytes()];
        byte[] Vdec = new byte[params.getV() * params.getK()];
        byte[] A = new byte[((params.getM() + 7) / 8 * 8) * (params.getK() * params.getO() + 1)];
        byte[] x = new byte[params.getK() * params.getN()];
        byte[] r = new byte[params.getK() * params.getO() + 1];
        byte[] s = new byte[params.getK() * params.getN()];
        byte[] tmp = new byte[params.getDigestBytes() + params.getSaltBytes() + params.getSkSeedBytes() + 1];
        byte[] sig = new byte[params.getSigBytes()];
        long[] P = new long[params.getP1Limbs() + params.getP2Limbs()];
        byte[] O = new byte[params.getV() * params.getO()];

        try
        {
            // Expand secret key
            MayoEngine.mayoExpandSk(params, privKey.getSeedSk(), P, O);

            // Hash message
            SHAKEDigest shake = new SHAKEDigest(256);
            shake.update(message, 0, message.length);
            shake.doFinal(tmp, 0, params.getDigestBytes());

            // Generate random salt
            random.nextBytes(salt);

            System.arraycopy(salt, 0, tmp, params.getDigestBytes(), salt.length);

            // Hash to salt
            System.arraycopy(privKey.getSeedSk(), 0, tmp, params.getDigestBytes() + params.getSaltBytes(),
                params.getSkSeedBytes());

            shake.update(tmp, 0, params.getDigestBytes() + params.getSaltBytes() +
                params.getSkSeedBytes());
            shake.doFinal(salt, 0, params.getSaltBytes());

            // Hash to t
            System.arraycopy(salt, 0, tmp, params.getDigestBytes(), params.getSaltBytes());
            shake.update(tmp, 0, params.getDigestBytes() + params.getSaltBytes());
            shake.doFinal(tenc, 0, params.getMBytes());
            Utils.decode(tenc, t, params.getM());

            for (int ctr = 0; ctr <= 255; ctr++)
            {
                tmp[tmp.length - 1] = (byte)ctr;

                // Generate V
                shake.update(tmp, 0, tmp.length);
                shake.doFinal(V, 0, V.length);

                // Decode vectors
                for (int i = 0; i < params.getK(); i++)
                {
                    Utils.decode(V, i * params.getVBytes(), Vdec, i * params.getV(), params.getV());
                }

                // Compute matrices
                long[] Mtmp = new long[params.getK() * params.getO() * params.getMVecLimbs()];
                long[] vPv = new long[params.getK() * params.getK() * params.getMVecLimbs()];
                computeMandVPV(params, Vdec, P, params.getP1Limbs(), P, Mtmp, vPv);

                computeRHS(params, vPv, t, y);
                computeA(params, Mtmp, A);

                // Clear trailing bytes
                for (int i = 0; i < params.getM(); ++i)
                {
                    A[(i + 1) * (params.getK() * params.getO() + 1) - 1] = 0;
                }

                Utils.decode(V, params.getK() * params.getVBytes(), r, 0,
                    params.getK() * params.getO());

                if (sampleSolution(params, A, y, r, x) != 0)
                {
                    break;
                }
                else
                {
                    Arrays.fill(Mtmp, 0L);
                    Arrays.fill(vPv, 0L);
                }
            }

            // Compute final signature components
            byte[] Ox = new byte[params.getV()];
            for (int i = 0; i < params.getK(); i++)
            {
                byte[] vi = Arrays.copyOfRange(Vdec, i * params.getV(),
                    (i + 1) * params.getV());
                GF16Utils.matMul(O, 0, x, i * params.getO(), Ox, 0,
                    params.getO(), params.getN() - params.getO(), 1);
                GF16Utils.matAdd(vi, 0, Ox, 0, s, i * params.getN(), params.getV(), 1);
                System.arraycopy(x, i * params.getO(), s,
                    i * params.getN() + params.getN() - params.getO(), params.getO());
            }

            // Encode and add salt
            Utils.encode(s, sig, params.getN() * params.getK());
            System.arraycopy(salt, 0, sig, sig.length - params.getSaltBytes(),
                params.getSaltBytes());

            return Arrays.concatenate(sig, message);
        }
        finally
        {
            // Secure cleanup
            Arrays.fill(tenc, (byte)0);
            Arrays.fill(t, (byte)0);
            Arrays.fill(y, (byte)0);
            Arrays.fill(salt, (byte)0);
            Arrays.fill(V, (byte)0);
            Arrays.fill(Vdec, (byte)0);
            Arrays.fill(A, (byte)0);
            Arrays.fill(x, (byte)0);
            Arrays.fill(r, (byte)0);
            Arrays.fill(s, (byte)0);
            Arrays.fill(tmp, (byte)0);
        }
    }


    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        final int paramM = params.getM();
        final int paramN = params.getN();
        final int paramK = params.getK();
        final int paramMBytes = params.getMBytes();
        final int paramSigBytes = params.getSigBytes();
        final int paramDigestBytes = params.getDigestBytes();
        final int paramSaltBytes = params.getSaltBytes();

        byte[] tEnc = new byte[params.getMBytes()];
        byte[] t = new byte[params.getM()];
        byte[] y = new byte[2 * params.getM()];
        byte[] s = new byte[params.getK() * params.getN()];
        long[] pk = new long[params.getP1Limbs() + params.getP2Limbs() + params.getP3Limbs()];
        byte[] tmp = new byte[params.getDigestBytes() + params.getSaltBytes()];
        byte[] cpk = pubKey.getEncoded();

        // Expand public key
        // mayo_expand_pk
        MayoEngine.expandP1P2(params, pk, cpk);
        Utils.unpackMVecs(cpk, params.getPkSeedBytes(), pk, params.getP1Limbs() + params.getP2Limbs(), params.getP3Limbs() / params.getMVecLimbs(), params.getM());

        // Split pk into P1, P2, P3
        int p1Limbs = params.getP1Limbs();
        int p2Limbs = params.getP2Limbs();
        int p3Limbs = params.getP3Limbs();

        long[] P1 = new long[p1Limbs];
        long[] P2 = new long[p2Limbs];
        long[] P3 = new long[p3Limbs];
        System.arraycopy(pk, 0, P1, 0, p1Limbs);
        System.arraycopy(pk, p1Limbs, P2, 0, p2Limbs);
        System.arraycopy(pk, p1Limbs + p2Limbs, P3, 0, p3Limbs);

        // Hash message
        Utils.shake256(tmp, paramDigestBytes, message, message.length);

        // Compute t
        System.arraycopy(signature, paramSigBytes - paramSaltBytes, tmp, paramDigestBytes, paramSaltBytes);
        Utils.shake256(tEnc, paramMBytes, tmp, paramDigestBytes + paramSaltBytes);
        Utils.decode(tEnc, t, paramM);

        // Decode signature
        Utils.decode(signature, s, paramK * paramN);

        // Evaluate public map
        evalPublicMap(params, s, P1, P2, P3, y);

        // Compare results
        return Arrays.constantTimeAreEqual(paramM, y, 0, t, 0);
    }


    /**
     * Computes the product of the matrix P1 (bit-sliced) with the transpose of matrix V and adds the result to acc.
     *
     * @param p   the parameters object
     * @param P1  the bit-sliced matrix P1 as a long array
     * @param V   the matrix V as a byte array
     * @param acc the accumulator array where the result is added
     */
    public static void P1TimesVt(MayoParameters p, long[] P1, byte[] V, long[] acc)
    {
        int mVecLimbs = p.getMVecLimbs();
        int paramV = p.getV();
        int paramK = p.getK();
        // triangular parameter is set to 1
        GF16Utils.mulAddMUpperTriangularMatXMatTrans(mVecLimbs, P1, V, acc, paramV, paramV, paramK, 1);
    }

    /**
     * Computes the matrices M and VP1V from the given input matrices.
     *
     * @param p    the parameters object
     * @param Vdec the decoded V matrix as a byte array
     * @param L    the matrix L as a long array
     * @param P1   the bit-sliced matrix P1 as a long array
     * @param VL   the output accumulator for VL
     * @param VP1V the output accumulator for VP1V
     */
    public static void computeMandVPV(MayoParameters p, byte[] Vdec, long[] L, int Loff, long[] P1, long[] VL, long[] VP1V)
    {
        int paramK = p.getK();
        int paramV = p.getV();
        int paramO = p.getO();
        int mVecLimbs = p.getMVecLimbs();

        // Compute VL: VL = Vdec * L
        GF16Utils.mulAddMatXMMat(mVecLimbs, Vdec, L, Loff, VL, paramK, paramV, paramO);

        // Compute VP1V:
        // Allocate temporary array for Pv. Its length is V_MAX * K_MAX * M_VEC_LIMBS_MAX.
        int size = p.getV() * p.getK() * p.getMVecLimbs();
        long[] Pv = new long[size]; // automatically initialized to zero in Java

        // Compute Pv = P1 * V^T (using upper triangular multiplication)
        P1TimesVt(p, P1, Vdec, Pv);

        // Compute VP1V = Vdec * Pv
        GF16Utils.mulAddMatXMMat(mVecLimbs, Vdec, Pv, VP1V, paramK, paramV, paramK);
    }

    public static void computeRHS(MayoParameters p, long[] vPv, byte[] t, byte[] y)
    {
        final int m = p.getM();
        final int mVecLimbs = p.getMVecLimbs();
        final int k = p.getK();
        final int[] fTail = p.getFTail();

        final int topPos = ((m - 1) % 16) * 4;

        // Zero out tails of m_vecs if necessary
        if (m % 16 != 0)
        {
            long mask = 1L;
            mask <<= ((m % 16) * 4);
            mask -= 1;
            final int kSquared = k * k;

            for (int i = 0; i < kSquared; i++)
            {
                int index = i * mVecLimbs + mVecLimbs - 1;
                vPv[index] &= mask;
            }
        }

        long[] temp = new long[mVecLimbs];
        byte[] tempBytes = new byte[mVecLimbs << 3];

        for (int i = k - 1; i >= 0; i--)
        {
            for (int j = i; j < k; j++)
            {
                // Multiply by X (shift up 4 bits)
                int top = (int)((temp[mVecLimbs - 1] >>> topPos) & 0xF);
                temp[mVecLimbs - 1] <<= 4;

                for (int limb = mVecLimbs - 2; limb >= 0; limb--)
                {
                    temp[limb + 1] ^= temp[limb] >>> 60;
                    temp[limb] <<= 4;
                }
                Pack.longToLittleEndian(temp, tempBytes, 0);

                // Reduce mod f(X)
                for (int jj = 0; jj < 4; jj++)
                {
                    int ft = fTail[jj];
                    if (ft == 0)
                    {
                        continue;
                    }

                    long product = GF16Utils.mulF(top, ft);
                    if (jj % 2 == 0)
                    {
                        tempBytes[jj / 2] ^= (byte)(product & 0xF);
                    }
                    else
                    {
                        tempBytes[jj / 2] ^= (byte)((product & 0xF) << 4);
                    }
                }
                Pack.littleEndianToLong(tempBytes, 0, temp);

                // Extract from vPv and add
                int matrixIndex = i * k + j;
                int symmetricIndex = j * k + i;
                boolean isDiagonal = (i == j);

                for (int limb = 0; limb < mVecLimbs; limb++)
                {
                    long value = vPv[matrixIndex * mVecLimbs + limb];
                    if (!isDiagonal)
                    {
                        value ^= vPv[symmetricIndex * mVecLimbs + limb];
                    }
                    temp[limb] ^= value;
                }
            }
        }
        Pack.longToLittleEndian(temp, tempBytes, 0);
        // Compute y
        for (int i = 0; i < m; i += 2)
        {
            int bytePos = i / 2;
            y[i] = (byte)(t[i] ^ (tempBytes[bytePos] & 0xF));
            y[i + 1] = (byte)(t[i + 1] ^ ((tempBytes[bytePos] >>> 4) & 0xF));
        }
    }


    private static final int F_TAIL_LEN = 4;
    private static final long EVEN_NIBBLES = 0x0F0F0F0F0F0F0F0FL;
    private static final long EVEN_BYTES = 0x00FF00FF00FF00FFL;
    private static final long EVEN_2BYTES = 0x0000FFFF0000FFFFL;
    private static final long EVEN_HALF = 0x00000000FFFFFFFFL;
    private static final long LOW_BIT_IN_NIBBLE = 0x1111111111111111L;

    public static void computeA(MayoParameters p, long[] VtL, byte[] AOut)
    {
        final int k = p.getK();
        final int o = p.getO();
        final int m = p.getM();
        final int mVecLimbs = p.getMVecLimbs();
        final int ACols = p.getACols();
        final byte[] fTailArr = p.getFTailArr();

        int bitsToShift = 0;
        int wordsToShift = 0;
        final int MAYO_M_OVER_8 = (m + 7) / 8;
        final int AWidth = ((o * k + 15) / 16) * 16;
        long[] A = new long[AWidth * MAYO_M_OVER_8 * 16];

        // Zero out tails of m_vecs if necessary
        if (m % 16 != 0)
        {
            long mask = 1L << ((m % 16) * 4);
            mask -= 1;
            for (int i = 0; i < o * k; i++)
            {
                int idx = i * mVecLimbs + mVecLimbs - 1;
                VtL[idx] &= mask;
            }
        }

        for (int i = 0; i < k; i++)
        {
            for (int j = k - 1; j >= i; j--)
            {
                // Process Mj
                int mjOffset = j * mVecLimbs * o;
                for (int c = 0; c < o; c++)
                {
                    for (int limb = 0; limb < mVecLimbs; limb++)
                    {
                        int idx = mjOffset + limb + c * mVecLimbs;
                        long value = VtL[idx];

                        int aIndex = o * i + c + (limb + wordsToShift) * AWidth;
                        A[aIndex] ^= value << bitsToShift;

                        if (bitsToShift > 0)
                        {
                            A[aIndex + AWidth] ^= value >>> (64 - bitsToShift);
                        }
                    }
                }

                if (i != j)
                {
                    // Process Mi
                    int miOffset = i * mVecLimbs * o;
                    for (int c = 0; c < o; c++)
                    {
                        for (int limb = 0; limb < mVecLimbs; limb++)
                        {
                            int idx = miOffset + limb + c * mVecLimbs;
                            long value = VtL[idx];

                            int aIndex = o * j + c + (limb + wordsToShift) * AWidth;
                            A[aIndex] ^= value << bitsToShift;

                            if (bitsToShift > 0)
                            {
                                A[aIndex + AWidth] ^= value >>> (64 - bitsToShift);
                            }
                        }
                    }
                }

                bitsToShift += 4;
                if (bitsToShift == 64)
                {
                    wordsToShift++;
                    bitsToShift = 0;
                }
            }
        }

        // Transpose blocks
        for (int c = 0; c < AWidth * ((m + (k + 1) * k / 2 + 15) / 16); c += 16)
        {
            transpose16x16Nibbles(A, c);
        }

        // Generate tab array
        byte[] tab = new byte[F_TAIL_LEN * 4];
        for (int i = 0; i < F_TAIL_LEN; i++)
        {
            byte ft = fTailArr[i];
            tab[4 * i] = (byte)GF16Utils.mulF(ft, 1);
            tab[4 * i + 1] = (byte)GF16Utils.mulF(ft, 2);
            tab[4 * i + 2] = (byte)GF16Utils.mulF(ft, 4);
            tab[4 * i + 3] = (byte)GF16Utils.mulF(ft, 8);
        }

        // Final processing
        for (int c = 0; c < AWidth; c += 16)
        {
            for (int r = m; r < m + (k + 1) * k / 2; r++)
            {
                int pos = (r / 16) * AWidth + c + (r % 16);
                long t0 = A[pos] & LOW_BIT_IN_NIBBLE;
                long t1 = (A[pos] >>> 1) & LOW_BIT_IN_NIBBLE;
                long t2 = (A[pos] >>> 2) & LOW_BIT_IN_NIBBLE;
                long t3 = (A[pos] >>> 3) & LOW_BIT_IN_NIBBLE;

                for (int t = 0; t < F_TAIL_LEN; t++)
                {
                    int targetRow = r + t - m;
                    int targetPos = (targetRow / 16) * AWidth + c + (targetRow % 16);
                    long xorValue = (t0 * tab[4 * t]) ^ (t1 * tab[4 * t + 1])
                        ^ (t2 * tab[4 * t + 2]) ^ (t3 * tab[4 * t + 3]);
                    A[targetPos] ^= xorValue;
                }
            }
        }

        byte[] Abytes = Pack.longToLittleEndian(A);
        // Decode to output
        for (int r = 0; r < m; r += 16)
        {
            for (int c = 0; c < ACols - 1; c += 16)
            {
                for (int i = 0; i + r < m; i++)
                {
                    Utils.decode(Abytes, (r * AWidth / 16 + c + i) * 8,
                        AOut, (r + i) * ACols + c,
                        Math.min(16, ACols - 1 - c));
                }
            }
        }
    }

    private static void transpose16x16Nibbles(long[] M, int offset)
    {
        for (int i = 0; i < 16; i += 2)
        {
            int idx1 = offset + i;
            int idx2 = offset + i + 1;
            long t = ((M[idx1] >>> 4) ^ M[idx2]) & EVEN_NIBBLES;
            M[idx1] ^= t << 4;
            M[idx2] ^= t;
        }

        for (int i = 0; i < 16; i += 4)
        {
            int base = offset + i;
            long t0 = ((M[base] >>> 8) ^ M[base + 2]) & EVEN_BYTES;
            long t1 = ((M[base + 1] >>> 8) ^ M[base + 3]) & EVEN_BYTES;
            M[base] ^= t0 << 8;
            M[base + 1] ^= t1 << 8;
            M[base + 2] ^= t0;
            M[base + 3] ^= t1;
        }

        for (int i = 0; i < 4; i++)
        {
            int base = offset + i;
            long t0 = ((M[base] >>> 16) ^ M[base + 4]) & EVEN_2BYTES;
            long t1 = ((M[base + 8] >>> 16) ^ M[base + 12]) & EVEN_2BYTES;
            M[base] ^= t0 << 16;
            M[base + 8] ^= t1 << 16;
            M[base + 4] ^= t0;
            M[base + 12] ^= t1;
        }

        for (int i = 0; i < 8; i++)
        {
            int base = offset + i;
            long t = ((M[base] >>> 32) ^ M[base + 8]) & EVEN_HALF;
            M[base] ^= t << 32;
            M[base + 8] ^= t;
        }
    }

    public int sampleSolution(MayoParameters params, byte[] A, byte[] y,
                              byte[] r, byte[] x)
    {
        final int k = params.getK();
        final int o = params.getO();
        final int m = params.getM();
        final int aCols = params.getACols();

        // Initialize x with r values
        System.arraycopy(r, 0, x, 0, k * o);

        // Compute Ar matrix product
        byte[] Ar = new byte[m];
//        Arrays.fill(Ar, (byte)0);

        // Clear last column of A
        for (int i = 0; i < m; i++)
        {
            A[k * o + i * (k * o + 1)] = 0;
        }
        GF16Utils.matMul(A, r, Ar, k * o + 1, m, 1);

        // Update last column of A with y - Ar
        for (int i = 0; i < m; i++)
        {
            A[k * o + i * (k * o + 1)] = (byte)(y[i] ^ Ar[i]);
        }

        // Perform row echelon form transformation
        ef(A, m, aCols);

        // Check matrix rank
        boolean fullRank = false;
        for (int i = 0; i < aCols - 1; i++)
        {
            fullRank |= (A[(m - 1) * aCols + i] != 0);
        }
        if (!fullRank)
        {
            return 0;
        }

        // Constant-time back substitution
        for (int row = m - 1; row >= 0; row--)
        {
            byte finished = 0;
            int colUpperBound = Math.min(row + (32 / (m - row)), k * o);

            for (int col = row; col <= colUpperBound; col++)
            {
                byte correctCol = GF16Utils.ctCompare8(A[row * aCols + col], (byte)0);
                byte mask = (byte)(correctCol & ~finished);

                // Update x[col] using constant-time mask
                byte u = (byte)(mask & A[row * aCols + aCols - 1]);
                //System.out.println("x[col]: " + x[col] + ", u: " + u);
                x[col] ^= u;


                // Update matrix entries
                for (int i = 0; i < row; i += 8)
                {
                    long tmp = 0;
                    // Pack 8 GF(16) elements into long
                    for (int j = 0; j < 8; j++)
                    {
                        tmp ^= (long)(A[(i + j) * aCols + col] & 0xFF) << (j * 8);
                    }

                    // GF(16) multiplication
                    tmp = GF16Utils.mulFx8(u, tmp);

                    // Unpack and update
                    for (int j = 0; j < 8; j++)
                    {
                        A[(i + j) * aCols + aCols - 1] ^= (byte)((tmp >> (j * 8)) & 0x0F);
                    }
                }
                finished |= correctCol;
            }
        }
        return 1;
    }

    // Adjust these as needed. In our translation we compute rowLen from ncols.
    // These blockers are used in the C code for constant-time masking.
    private static final long UINT64_BLOCKER = 0L;
    private static final int UNSIGNED_CHAR_BLOCKER = 0; // Not used in our Java version.

    /**
     * Converts a matrix A (given as a flat array of GF(16) elements, one per byte)
     * into row echelon form (with ones on the first nonzero entries) in constant time.
     *
     * @param A     the input matrix, stored rowwise; each element is in [0,15]
     * @param nrows the number of rows
     * @param ncols the number of columns (GF(16) elements per row)
     */
    public void ef(byte[] A, int nrows, int ncols)
    {
        // Each 64-bit long can hold 16 nibbles (16 GF(16) elements).
        int rowLen = (ncols + 15) / 16;

        // Allocate temporary arrays.
        long[] pivotRow = new long[rowLen];
        long[] pivotRow2 = new long[rowLen];
        // The packed matrix: one contiguous array storing nrows rows, each rowLen longs long.
        long[] packedA = new long[nrows * rowLen];

        // Pack the matrix rows.
        for (int i = 0; i < nrows; i++)
        {
            long[] packedRow = packRow(A, i, ncols);
            System.arraycopy(packedRow, 0, packedA, i * rowLen, rowLen);
        }

        int pivotRowIndex = 0;
        // Loop over each pivot column (each column corresponds to one GF(16) element)
        for (int pivotCol = 0; pivotCol < ncols; pivotCol++)
        {
            int lowerBound = Math.max(0, pivotCol + nrows - ncols);
            int upperBound = Math.min(nrows - 1, pivotCol);

            // Zero out pivot row buffers.
            for (int i = 0; i < rowLen; i++)
            {
                pivotRow[i] = 0;
                pivotRow2[i] = 0;
            }

            // Try to select a pivot row in constant time.
            int pivot = 0;
            long pivotIsZero = -1L; // all bits set (0xFFFFFFFFFFFFFFFF)
            int searchUpper = Math.min(nrows - 1, upperBound + 32);
            for (int row = lowerBound; row <= searchUpper; row++)
            {
                long isPivotRow = ~ctCompare64(row, pivotRowIndex);
                long belowPivotRow = ct64IsGreaterThan(row, pivotRowIndex);
                for (int j = 0; j < rowLen; j++)
                {
                    // The expression below accumulates (in constant time) the candidate pivot row.
                    pivotRow[j] ^= (isPivotRow | (belowPivotRow & pivotIsZero))
                        & packedA[row * rowLen + j];
                }
                // Extract candidate pivot element from the packed row.
                pivot = mExtractElement(pivotRow, pivotCol);
                pivotIsZero = ~ctCompare64(pivot, 0);
            }

            // Multiply the pivot row by the inverse of the pivot element.
            int inv = inverseF(pivot);
            vecMulAddU64(rowLen, pivotRow, (byte)inv, pivotRow2);

            // Conditionally write the pivot row back into the correct row (if pivot is nonzero).
            for (int row = lowerBound; row <= upperBound; row++)
            {
                long doCopy = ~ctCompare64(row, pivotRowIndex) & ~pivotIsZero;
                long doNotCopy = ~doCopy;
                for (int col = 0; col < rowLen; col++)
                {
                    // Since the masks are disjoint, addition is equivalent to OR.
                    packedA[row * rowLen + col] =
                        (doNotCopy & packedA[row * rowLen + col]) |
                            (doCopy & pivotRow2[col]);
                }
            }

            // Eliminate entries below the pivot.
            for (int row = lowerBound; row < nrows; row++)
            {
                int belowPivot = (row > pivotRowIndex) ? 1 : 0;
                int eltToElim = mExtractElementFromPacked(packedA, row, rowLen, pivotCol);
                vecMulAddU64(rowLen, pivotRow2, (byte)(belowPivot * eltToElim), packedA, row * rowLen);
            }

            // If pivot is nonzero, increment pivotRowIndex.
            if (pivot != 0)
            {
                pivotRowIndex++;
            }
        }

        byte[] temp = new byte[params.getO() * params.getK() + 1 + 15];
        // At this point, packedA holds the row-echelon form of the original matrix.
        // (Depending on your application you might want to unpack it back to A.)
        for (int i = 0; i < nrows; i++)
        {
            GF16Utils.efUnpackMVector(rowLen, packedA, i * rowLen, temp);
            for (int j = 0; j < ncols; j++)
            {
                A[i * ncols + j] = temp[j];
            }
        }
    }

    /**
     * Packs one row of GF(16) elements (stored in A) into a long[].
     * Each long holds 16 GF(16) elements (4 bits each).
     *
     * @param A     the flat input matrix (row-major)
     * @param row   the row index to pack
     * @param ncols the number of columns (GF(16) elements) in a row
     * @return an array of longs representing the packed row.
     */
    private static long[] packRow(byte[] A, int row, int ncols)
    {
        int rowLen = (ncols + 15) / 16; // number of longs needed for this row
        long[] packed = new long[rowLen];
        // Process each 64-bit word (each holds 16 nibbles).
        for (int word = 0; word < rowLen; word++)
        {
            long wordVal = 0;
            for (int nibble = 0; nibble < 16; nibble++)
            {
                int col = word * 16 + nibble;
                if (col < ncols)
                {
                    int element = A[row * ncols + col] & 0xF;
                    wordVal |= ((long)element) << (4 * nibble);
                }
            }
            packed[word] = wordVal;
        }
        return packed;
    }

    /**
     * Constant-time comparison: returns 0 if a==b, else returns all 1s (0xFFFFFFFFFFFFFFFF).
     */
    private static long ctCompare64(int a, int b)
    {
        // Compute (-(a XOR b)) >> 63 then XOR with UINT64_BLOCKER.
        long diff = -(long)(a ^ b);
        long shift = diff >> 63;  // arithmetic shift; results in 0 or -1.
        return shift ^ UINT64_BLOCKER;
    }

    /**
     * Returns 0xFFFFFFFFFFFFFFFF if a > b, 0 otherwise.
     */
    private static long ct64IsGreaterThan(int a, int b)
    {
        long diff = (long)b - (long)a;
        long shift = diff >> 63;
        return shift ^ UINT64_BLOCKER;
    }

    /**
     * Extracts the GF(16) element at a given column index from a packed row.
     *
     * @param in    the packed row (array of longs)
     * @param index the column index (0-indexed)
     * @return the GF(16) element (an int in 0..15)
     */
    private static int mExtractElement(long[] in, int index)
    {
        int leg = index / 16;
        int offset = index % 16;
        return (int)((in[leg] >>> (4 * offset)) & 0xF);
    }

    /**
     * Extracts an element from the packed matrix for a given row and column.
     *
     * @param packedA the packed matrix stored in row-major order
     * @param row     the row index
     * @param rowLen  the number of longs per row
     * @param index   the column index
     * @return the GF(16) element at that position.
     */
    private static int mExtractElementFromPacked(long[] packedA, int row, int rowLen, int index)
    {
        int leg = index / 16;
        int offset = index % 16;
        return (int)((packedA[row * rowLen + leg] >>> (4 * offset)) & 0xF);
    }

    /**
     * Computes the multiplicative inverse in GF(16) for a GF(16) element.
     */
    private static int inverseF(int a)
    {
        // In GF(16), the inverse can be computed via exponentiation.
        int a2 = mulF(a, a);
        int a4 = mulF(a2, a2);
        int a8 = mulF(a4, a4);
        int a6 = mulF(a2, a4);
        int a14 = mulF(a8, a6);
        return a14;
    }

    /**
     * GF(16) multiplication mod (x^4 + x + 1).
     * <p>
     * Multiplies two GF(16) elements (only the lower 4 bits are used).
     */
    public static int mulF(int a, int b)
    {
        // Carryless multiply: multiply b by each bit of a and XOR.
        int p = ((a & 1) * b) ^
            ((a & 2) * b) ^
            ((a & 4) * b) ^
            ((a & 8) * b);
        // Reduce modulo f(X) = x^4 + x + 1.
        int topP = p & 0xF0;
        int out = (p ^ (topP >> 4) ^ (topP >> 3)) & 0x0F;
        return out;
    }

    /**
     * Multiplies each word of the input vector (in) by a GF(16) scalar (a),
     * then XORs the result into the accumulator vector (acc).
     * <p>
     * This version updates the acc array starting at index 0.
     *
     * @param legs the number of 64-bit words in the vector.
     * @param in   the input vector.
     * @param a    the GF(16) scalar (as a byte; only low 4 bits used).
     * @param acc  the accumulator vector which is updated.
     */
    private static void vecMulAddU64(int legs, long[] in, byte a, long[] acc)
    {
        int tab = mulTable(a & 0xFF);
        long lsbAsk = 0x1111111111111111L;
        for (int i = 0; i < legs; i++)
        {
            long val = ((in[i] & lsbAsk) * (tab & 0xFF))
                ^ (((in[i] >>> 1) & lsbAsk) * ((tab >>> 8) & 0xF))
                ^ (((in[i] >>> 2) & lsbAsk) * ((tab >>> 16) & 0xF))
                ^ (((in[i] >>> 3) & lsbAsk) * ((tab >>> 24) & 0xF));
            acc[i] ^= val;
        }
    }

    /**
     * Overloaded version of vecMulAddU64 that writes to acc starting at accOffset.
     *
     * @param legs      the number of 64-bit words.
     * @param in        the input vector.
     * @param a         the GF(16) scalar.
     * @param acc       the accumulator vector.
     * @param accOffset the starting index in acc.
     */
    private static void vecMulAddU64(int legs, long[] in, byte a, long[] acc, int accOffset)
    {
        int tab = mulTable(a & 0xFF);
        long lsbAsk = 0x1111111111111111L;
        for (int i = 0; i < legs; i++)
        {
            long val = ((in[i] & lsbAsk) * (tab & 0xFF))
                ^ (((in[i] >>> 1) & lsbAsk) * ((tab >>> 8) & 0xF))
                ^ (((in[i] >>> 2) & lsbAsk) * ((tab >>> 16) & 0xF))
                ^ (((in[i] >>> 3) & lsbAsk) * ((tab >>> 24) & 0xF));
            acc[accOffset + i] ^= val;
        }
    }

    /**
     * Computes a multiplication table for nibble-packed vectors.
     * <p>
     * Implements arithmetic for GF(16) elements modulo (x^4 + x + 1).
     *
     * @param b a GF(16) element (only lower 4 bits are used)
     * @return a 32-bit integer representing the multiplication table.
     */
    private static int mulTable(int b)
    {
        int x = b * 0x08040201;
        int highNibbleMask = 0xf0f0f0f0;
        int highHalf = x & highNibbleMask;
        return x ^ (highHalf >>> 4) ^ (highHalf >>> 3);
    }

    private static void evalPublicMap(MayoParameters p, byte[] s, long[] P1, long[] P2, long[] P3, byte[] eval)
    {
        int mVecLimbs = (p.getM() + 15) / 16;
        long[] SPS = new long[p.getK() * p.getK() * mVecLimbs];
        mCalculatePsSps(p, P1, P2, P3, s, SPS);
        byte[] zero = new byte[p.getM()];
        computeRHS(p, SPS, zero, eval);
    }

    private static void mCalculatePsSps(MayoParameters p, long[] P1, long[] P2, long[] P3, byte[] s, long[] SPS)
    {
        int m = p.getM();
        int v = p.getV();
        int o = p.getO();
        int k = p.getK();
        int mVecLimbs = (m + 15) / 16;

        long[] PS = new long[p.getN() * p.getK() * mVecLimbs];
        mayoGenericMCalculatePS(p, P1, P2, P3, s, m, v, o, k, PS);
        mayoGenericMCalculateSPS(PS, s, m, k, p.getN(), SPS);
    }

    private static void mayoGenericMCalculatePS(MayoParameters p, long[] P1, long[] P2, long[] P3, byte[] S,
                                                int m, int v, int o, int k, long[] PS)
    {
        int n = o + v;
        int mVecLimbs = (m + 15) / 16;
        long[] accumulator = new long[16 * ((p.getM() + 15) / 16 * p.getK() * p.getN() * mVecLimbs)];

        int p1Used = 0;
        for (int row = 0; row < v; row++)
        {
            for (int j = row; j < v; j++)
            {
                for (int col = 0; col < k; col++)
                {
                    Longs.xorTo(mVecLimbs, P1, p1Used * mVecLimbs,
                        accumulator, ((row * k + col) * 16 + (S[col * n + j] & 0xFF)) * mVecLimbs);
                }
                p1Used++;
            }

            for (int j = 0; j < o; j++)
            {
                for (int col = 0; col < k; col++)
                {
                    Longs.xorTo(mVecLimbs, P2, (row * o + j) * mVecLimbs,
                        accumulator, ((row * k + col) * 16 + (S[(col * n) + j + v] & 0xFF)) * mVecLimbs);
                }
            }
        }

        int p3Used = 0;
        for (int row = v; row < n; row++)
        {
            for (int j = row; j < n; j++)
            {
                for (int col = 0; col < k; col++)
                {
                    Longs.xorTo(mVecLimbs, P3, p3Used * mVecLimbs,
                        accumulator, ((row * k + col) * 16 + (S[col * n + j] & 0xFF)) * mVecLimbs);
                }
                p3Used++;
            }
        }

        for (int i = 0; i < n * k; i++)
        {
            mVecMultiplyBins(mVecLimbs, accumulator, i * 16 * mVecLimbs, PS, i * mVecLimbs);
        }
    }

    private static void mayoGenericMCalculateSPS(long[] PS, byte[] S, int m, int k, int n, long[] SPS)
    {
        final int mVecLimbs = (m + 15) / 16;
        final int accumulatorSize = 16 * mVecLimbs * k * k;
        final long[] accumulator = new long[accumulatorSize];

        // Accumulation phase
        for (int row = 0; row < k; row++)
        {
            for (int j = 0; j < n; j++)
            {
                final int sVal = S[row * n + j] & 0xFF; // Unsigned byte value
                for (int col = 0; col < k; col++)
                {
                    final int psOffset = (j * k + col) * mVecLimbs;
                    final int accOffset = ((row * k + col) * 16 + sVal) * mVecLimbs;
                    mVecAdd(mVecLimbs, PS, psOffset, accumulator, accOffset);
                }
            }
        }

        // Processing phase
        for (int i = 0; i < k * k; i++)
        {
            mVecMultiplyBins(mVecLimbs, accumulator, i * 16 * mVecLimbs, SPS, i * mVecLimbs);
        }
    }

    // Helper method for vector addition (XOR)
    private static void mVecAdd(int limbs, long[] src, int srcOffset, long[] dest, int destOffset)
    {
        for (int i = 0; i < limbs; i++)
        {
            dest[destOffset + i] ^= src[srcOffset + i];
        }
    }

    // Main bin processing method
    private static void mVecMultiplyBins(int mVecLimbs, long[] bins, int binOffset, long[] ps, int psOff)
    {
        // Series of modular operations as per original C code
        mVecMulAddXInv(mVecLimbs, bins, binOffset + 5 * mVecLimbs, bins, binOffset + 10 * mVecLimbs);
        mVecMulAddX(mVecLimbs, bins, binOffset + 11 * mVecLimbs, bins, binOffset + 12 * mVecLimbs);
        mVecMulAddXInv(mVecLimbs, bins, binOffset + 10 * mVecLimbs, bins, binOffset + 7 * mVecLimbs);
        mVecMulAddX(mVecLimbs, bins, binOffset + 12 * mVecLimbs, bins, binOffset + 6 * mVecLimbs);
        mVecMulAddXInv(mVecLimbs, bins, binOffset + 7 * mVecLimbs, bins, binOffset + 14 * mVecLimbs);
        mVecMulAddX(mVecLimbs, bins, binOffset + 6 * mVecLimbs, bins, binOffset + 3 * mVecLimbs);
        mVecMulAddXInv(mVecLimbs, bins, binOffset + 14 * mVecLimbs, bins, binOffset + 15 * mVecLimbs);
        mVecMulAddX(mVecLimbs, bins, binOffset + 3 * mVecLimbs, bins, binOffset + 8 * mVecLimbs);
        mVecMulAddXInv(mVecLimbs, bins, binOffset + 15 * mVecLimbs, bins, binOffset + 13 * mVecLimbs);
        mVecMulAddX(mVecLimbs, bins, binOffset + 8 * mVecLimbs, bins, binOffset + 4 * mVecLimbs);
        mVecMulAddXInv(mVecLimbs, bins, binOffset + 13 * mVecLimbs, bins, binOffset + 9 * mVecLimbs);
        mVecMulAddX(mVecLimbs, bins, binOffset + 4 * mVecLimbs, bins, binOffset + 2 * mVecLimbs);
        mVecMulAddXInv(mVecLimbs, bins, binOffset + 9 * mVecLimbs, bins, binOffset + 1 * mVecLimbs);
        mVecMulAddX(mVecLimbs, bins, binOffset + 2 * mVecLimbs, bins, binOffset + 1 * mVecLimbs);
        System.arraycopy(bins, mVecLimbs + binOffset, ps, psOff, mVecLimbs);
    }

    // Modular arithmetic operations
    private static void mVecMulAddXInv(int limbs, long[] in, int inOffset,
                                       long[] acc, int accOffset)
    {
        final long maskLsb = 0x1111111111111111L;
        for (int i = 0; i < limbs; i++)
        {
            final long t = in[inOffset + i] & maskLsb;
            acc[accOffset + i] ^= ((in[inOffset + i] ^ t) >>> 1) ^ (t * 9);
        }
    }

    private static void mVecMulAddX(int limbs, long[] in, int inOffset,
                                    long[] acc, int accOffset)
    {
        final long maskMsb = 0x8888888888888888L;
        for (int i = 0; i < limbs; i++)
        {
            final long t = in[inOffset + i] & maskMsb;
            acc[accOffset + i] ^= ((in[inOffset + i] ^ t) << 1) ^ ((t >>> 3) * 3);
        }
    }


}
