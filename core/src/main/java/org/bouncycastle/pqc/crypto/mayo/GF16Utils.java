package org.bouncycastle.pqc.crypto.mayo;

public class GF16Utils
{

    /**
     * Multiplies a 64-bit limb by a GF(16) element (represented as an int, 0–255).
     * This emulates gf16v_mul_u64 from C.
     *
     * @param a a 64-bit limb
     * @param b an 8-bit GF(16) element (only the low 4 bits are used)
     * @return the product as a 64-bit limb
     */
    public static long gf16vMulU64(long a, int b)
    {
        long maskMsb = 0x8888888888888888L;
        long a64 = a;
        // In the original code there is a conditional XOR with unsigned_char_blocker;
        // here we simply use b directly.
        long b32 = b & 0x00000000FFFFFFFFL;
        long r64 = a64 * (b32 & 1);

        long a_msb = a64 & maskMsb;
        a64 ^= a_msb;
        a64 = (a64 << 1) ^ ((a_msb >>> 3) * 3);
        r64 ^= a64 * ((b32 >> 1) & 1);

        a_msb = a64 & maskMsb;
        a64 ^= a_msb;
        a64 = (a64 << 1) ^ ((a_msb >>> 3) * 3);
        r64 ^= a64 * ((b32 >>> 2) & 1);

        a_msb = a64 & maskMsb;
        a64 ^= a_msb;
        a64 = (a64 << 1) ^ ((a_msb >>> 3) * 3);
        r64 ^= a64 * ((b32 >> 3) & 1);

        return r64;
    }

    /**
     * Multiplies each limb of a GF(16) vector (subarray of 'in') by the GF(16) element 'a'
     * and XORs the result into the corresponding subarray of acc.
     * <p>
     * This version uses explicit array offsets.
     *
     * @param mVecLimbs the number of limbs in the vector
     * @param in        the input long array containing the vector; the vector starts at index inOffset
     * @param inOffset  the starting index in 'in'
     * @param a         the GF(16) element (0–255) to multiply by
     * @param acc       the accumulator long array; the target vector starts at index accOffset
     * @param accOffset the starting index in 'acc'
     */
    public static void mVecMulAdd(int mVecLimbs, long[] in, int inOffset, int a, long[] acc, int accOffset)
    {
        for (int i = 0; i < mVecLimbs; i++)
        {
            acc[accOffset + i] ^= gf16vMulU64(in[inOffset + i], a);
        }
    }

    /**
     * Convenience overload of mVecMulAdd that assumes zero offsets.
     *
     * @param mVecLimbs the number of limbs
     * @param in        the input vector
     * @param a         the GF(16) element to multiply by
     * @param acc       the accumulator vector
     */
    public static void mVecMulAdd(int mVecLimbs, long[] in, int a, long[] acc)
    {
        mVecMulAdd(mVecLimbs, in, 0, a, acc, 0);
    }

    /**
     * Performs the multiplication and accumulation of a block of an upper‐triangular matrix
     * times a second matrix.
     *
     * @param mVecLimbs  number of limbs per m-vector.
     * @param bsMat      the “basis” matrix (as a flat long[] array); each entry occupies mVecLimbs elements.
     * @param mat        the second matrix (as a flat byte[] array) stored row‐major,
     *                   with dimensions (bsMatCols x matCols).
     * @param acc        the accumulator (as a flat long[] array) with dimensions (bsMatRows x matCols);
     *                   each “entry” is an m‐vector (length mVecLimbs).
     * @param bsMatRows  number of rows in the bsMat (the “triangular” matrix’s row count).
     * @param bsMatCols  number of columns in bsMat.
     * @param matCols    number of columns in the matrix “mat.”
     * @param triangular if 1, start column index for each row is (r * triangular); otherwise use 0.
     */
    public static void mulAddMUpperTriangularMatXMat(int mVecLimbs, long[] bsMat, byte[] mat, long[] acc,
                                                     int bsMatRows, int bsMatCols, int matCols, int triangular)
    {
        int bsMatEntriesUsed = 0;
        for (int r = 0; r < bsMatRows; r++)
        {
            // For each row r, the inner loop goes from column triangular*r to bsMatCols-1.
            for (int c = triangular * r; c < bsMatCols; c++)
            {
                for (int k = 0; k < matCols; k++)
                {
                    // Calculate the offsets:
                    // For bsMat: the m-vector starting at index bsMatEntriesUsed * mVecLimbs.
                    int bsMatOffset = bsMatEntriesUsed * mVecLimbs;
                    // For mat: element at row c, column k (row-major layout).
                    int a = mat[c * matCols + k] & 0xFF;
                    // For acc: add into the m-vector at row r, column k.
                    int accOffset = (r * matCols + k) * mVecLimbs;
                    GF16Utils.mVecMulAdd(mVecLimbs, bsMat, bsMatOffset, a, acc, accOffset);
                }
                bsMatEntriesUsed++;
            }
        }
    }

    /**
     * Computes P1_times_O.
     * <p>
     * In C:
     * P1_times_O(p, P1, O, acc) calls:
     * mul_add_m_upper_triangular_mat_x_mat(PARAM_m_vec_limbs(p), P1, O, acc, PARAM_v(p), PARAM_v(p), PARAM_o(p), 1);
     *
     * @param p   the parameter object.
     * @param P1  the P1 matrix as a long[] array.
     * @param O   the O matrix as a byte[] array.
     * @param acc the output accumulator (long[] array).
     */
    public static void P1TimesO(MayoParameters p, long[] P1, byte[] O, long[] acc)
    {
        int mVecLimbs = p.getMVecLimbs();
        int paramV = p.getV();
        int paramO = p.getO();
        // Here, bsMatRows and bsMatCols are both paramV, and matCols is paramO, triangular=1.
        mulAddMUpperTriangularMatXMat(mVecLimbs, P1, O, acc, paramV, paramV, paramO, 1);
    }

    /**
     * Multiplies the transpose of a single matrix with m matrices and adds the result into acc.
     *
     * @param mVecLimbs number of limbs per m-vector.
     * @param mat       the matrix to be transposed (as a flat byte[] array), dimensions: (matRows x matCols).
     * @param bsMat     the m-matrix (as a flat long[] array), with each entry of length mVecLimbs.
     *                  Its logical dimensions: (matRows x bsMatCols).
     * @param acc       the accumulator (as a flat long[] array) with dimensions (matCols x bsMatCols);
     *                  each entry is an m-vector.
     * @param matRows   number of rows in the matrix “mat.”
     * @param matCols   number of columns in “mat.”
     * @param bsMatCols number of columns in the bsMat matrix.
     */
    public static void mulAddMatTransXMMat(int mVecLimbs, byte[] mat, long[] bsMat, long[] acc,
                                           int matRows, int matCols, int bsMatCols)
    {
        // Loop over each column r of mat (which becomes row of mat^T)
        for (int r = 0; r < matCols; r++)
        {
            for (int c = 0; c < matRows; c++)
            {
                for (int k = 0; k < bsMatCols; k++)
                {
                    // For bsMat: the m-vector at index (c * bsMatCols + k)
                    int bsMatOffset = (c * bsMatCols + k) * mVecLimbs;
                    // For mat: element at row c, column r.
                    int a = mat[c * matCols + r] & 0xFF;
                    // For acc: add into the m-vector at index (r * bsMatCols + k)
                    int accOffset = (r * bsMatCols + k) * mVecLimbs;
                    GF16Utils.mVecMulAdd(mVecLimbs, bsMat, bsMatOffset, a, acc, accOffset);
                }
            }
        }
    }


    /**
     * Adds (bitwise XOR) mVecLimbs elements from the source array (starting at srcOffset)
     * into the destination array (starting at destOffset).
     */
    public static void mVecAdd(int mVecLimbs, long[] src, int srcOffset, long[] dest, int destOffset)
    {
        for (int i = 0; i < mVecLimbs; i++)
        {
            dest[destOffset + i] ^= src[srcOffset + i];
        }
    }

}

