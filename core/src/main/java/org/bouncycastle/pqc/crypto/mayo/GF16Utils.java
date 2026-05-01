package org.bouncycastle.pqc.crypto.mayo;

import org.bouncycastle.util.GF16;

class GF16Utils
{
    static final long NIBBLE_MASK_MSB = 0x7777777777777777L;
    static final long MASK_MSB = 0x8888888888888888L;
    static final long MASK_LSB = 0x1111111111111111L;
    static final long NIBBLE_MASK_LSB = ~MASK_LSB;

    /**
     * Multiplies each limb of a GF(16) vector (subarray of 'in') by the GF(16) element 'a'
     * and XORs the result into the corresponding subarray of acc.
     * <p>
     * This version uses explicit array offsets.
     *
     * @param mVecLimbs the number of limbs in the vector
     * @param in        the input long array containing the vector; the vector starts at index inOffset
     * @param inOffset  the starting index in 'in'
     * @param b         the GF(16) element (0–255) to multiply by
     * @param acc       the accumulator long array; the target vector starts at index accOffset
     * @param accOffset the starting index in 'acc'
     */
    static void mVecMulAdd(int mVecLimbs, long[] in, int inOffset, int b, long[] acc, int accOffset)
    {
        long a, r64, a_msb, a_msb3;
        long b32 = b & 0x00000000FFFFFFFFL;
        long b32and1 = b32 & 1;
        long b32_1_1 = ((b32 >>> 1) & 1);
        long b32_2_1 = ((b32 >>> 2) & 1);
        long b32_3_1 = ((b32 >>> 3) & 1);
        for (int i = 0; i < mVecLimbs; i++)
        {
            // In the original code there is a conditional XOR with unsigned_char_blocker;
            // here we simply use b directly.
            a = in[inOffset++];
            r64 = a & -b32and1;

            a_msb = a & MASK_MSB;
            a &= NIBBLE_MASK_MSB;
            a_msb3 = a_msb >>> 3;
            a = (a << 1) ^ (a_msb3 + (a_msb3 << 1));
            r64 ^= a & -b32_1_1;

            a_msb = a & MASK_MSB;
            a &= NIBBLE_MASK_MSB;
            a_msb3 = a_msb >>> 3;
            a = (a << 1) ^ (a_msb3 + (a_msb3 << 1));
            r64 ^= a & -b32_2_1;

            a_msb = a & MASK_MSB;
            a &= NIBBLE_MASK_MSB;
            a_msb3 = a_msb >>> 3;
            a = (a << 1) ^ (a_msb3 + (a_msb3 << 1));
            acc[accOffset++] ^= r64 ^ (a & -b32_3_1);
        }
    }


    /**
     * Performs the multiplication and accumulation of a block of an upper‐triangular matrix
     * times a second matrix.
     *
     * @param mVecLimbs number of limbs per m-vector.
     * @param bsMat     the “basis” matrix (as a flat long[] array); each entry occupies mVecLimbs elements.
     * @param mat       the second matrix (as a flat byte[] array) stored row‐major,
     *                  with dimensions (bsMatCols x matCols).
     * @param acc       the accumulator (as a flat long[] array) with dimensions (bsMatRows x matCols);
     *                  each “entry” is an m‐vector (length mVecLimbs).
     * @param bsMatRows number of rows in the bsMat (the “triangular” matrix’s row count).
     * @param matCols   number of columns in the matrix “mat.”
     */
    static void mulAddMUpperTriangularMatXMat(int mVecLimbs, long[] bsMat, byte[] mat, long[] acc, int accOff,
                                              int bsMatRows, int matCols)
    {
        int bsMatEntriesUsed = 0;
        int matColsmVecLimbs = matCols * mVecLimbs;
        for (int r = 0, rmatCols = 0, rmatColsmVecLimbs = 0; r < bsMatRows; r++, rmatCols += matCols, rmatColsmVecLimbs += matColsmVecLimbs)
        {
            // For each row r, the inner loop goes from column triangular*r to bsMatCols-1.
            for (int c = r, cmatCols = rmatCols; c < bsMatRows; c++, cmatCols += matCols)
            {
                for (int k = 0, kmVecLimbs = 0; k < matCols; k++, kmVecLimbs += mVecLimbs)
                {
                    // For acc: add into the m-vector at row r, column k.
                    mVecMulAdd(mVecLimbs, bsMat, bsMatEntriesUsed, mat[cmatCols + k], acc, accOff + rmatColsmVecLimbs + kmVecLimbs);
                }
                bsMatEntriesUsed += mVecLimbs;
            }
        }
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
     */
    static void mulAddMatTransXMMat(int mVecLimbs, byte[] mat, long[] bsMat, int bsMatOff, long[] acc,
                                    int matRows, int matCols)
    {
        int multiply = matCols * mVecLimbs;
        for (int r = 0, rmultiply = 0; r < matCols; r++, rmultiply += multiply)
        {
            for (int c = 0, cmatCols = 0, cmultiply = 0; c < matRows; c++, cmatCols += matCols, cmultiply += multiply)
            {
                byte matVal = mat[cmatCols + r];
                for (int k = 0, kmVecLimbs = 0; k < matCols; k++, kmVecLimbs += mVecLimbs)
                {
                    mVecMulAdd(mVecLimbs, bsMat, bsMatOff + cmultiply + kmVecLimbs, matVal, acc, rmultiply + kmVecLimbs);
                }
            }
        }
    }

    /**
     * Multiplies a matrix (given as a byte array) with a bit‐sliced matrix (given as a long array)
     * and accumulates the result into the acc array.
     *
     * <p>
     * The operation iterates over the rows and columns of the matrix. For each element in the matrix,
     * it multiplies a corresponding vector (from bsMat) by the scalar value (from mat) and adds the
     * result to the accumulator vector in acc.
     * </p>
     *
     * @param mVecLimbs the number of limbs (elements) in each vector
     * @param mat       the matrix as a byte array with dimensions [matRows x matCols]
     * @param bsMat     the bit‐sliced matrix as a long array
     * @param acc       the accumulator array (long[]) where results are accumulated
     * @param matRows   the number of rows in the matrix
     * @param matCols   the number of columns in the matrix
     */
    static void mulAddMatXMMat(int mVecLimbs, byte[] mat, long[] bsMat, long[] acc, int matRows, int matCols)
    {
        int multiply = mVecLimbs * matRows;
        for (int r = 0, rmatCols = 0, rmultiply = 0; r < matRows; r++, rmatCols += matCols, rmultiply += multiply)
        {
            for (int c = 0, cmultiply = 0; c < matCols; c++, cmultiply += multiply)
            {
                // Retrieve the scalar from the matrix for row r and column c.
                byte matVal = mat[rmatCols + c];
                for (int k = 0, kmVecLimbs = 0; k < matRows; k++, kmVecLimbs += mVecLimbs)
                {
                    mVecMulAdd(mVecLimbs, bsMat, cmultiply + kmVecLimbs, matVal, acc, rmultiply + kmVecLimbs);
                }
            }
        }
    }

    static void mulAddMatXMMat(int mVecLimbs, byte[] mat, long[] bsMat, int bsMatOff, long[] acc,
                               int matRows, int matCols, int bsMatCols)
    {
        int multiply = mVecLimbs * bsMatCols;
        for (int r = 0, rmultiply = 0, rmatCols = 0; r < matRows; r++, rmultiply += multiply, rmatCols += matCols)
        {
            for (int c = 0, cmultiply = 0; c < matCols; c++, cmultiply += multiply)
            {
                // Retrieve the scalar from the matrix for row r and column c.
                byte matVal = mat[rmatCols + c];
                for (int k = 0, kmVecLimbs = 0; k < bsMatCols; k++, kmVecLimbs += mVecLimbs)
                {
                    mVecMulAdd(mVecLimbs, bsMat, cmultiply + kmVecLimbs + bsMatOff, matVal, acc, rmultiply + kmVecLimbs);
                }
            }
        }
    }

    /**
     * Multiplies m (possibly upper triangular) matrices with the transpose of a single matrix
     * and adds the result to the accumulator.
     *
     * <p>
     * For each row {@code r} in the bit‑sliced matrix and for each column {@code c} (starting from
     * {@code triangular * r}) in the bit‑sliced matrix, this method iterates over all rows {@code k}
     * of the single matrix, and for each element, it multiplies the vector (from {@code bsMat})
     * by the scalar (from {@code mat}) and adds the result to the corresponding vector in {@code acc}.
     * </p>
     *
     * @param mVecLimbs the number of limbs (elements) in each vector.
     * @param bsMat     the bit‑sliced matrix stored as a long array.
     * @param mat       the matrix stored as a byte array.
     * @param acc       the accumulator array where the results are added.
     * @param bsMatRows the number of rows in the bit‑sliced matrix.
     * @param matRows   the number of rows in the matrix.
     */
    static void mulAddMUpperTriangularMatXMatTrans(int mVecLimbs, long[] bsMat, byte[] mat, long[] acc, int bsMatRows, int matRows)
    {
        int bsMatEntriesUsed = 0;
        int multiply = mVecLimbs * matRows;
        for (int r = 0, rmultiply = 0; r < bsMatRows; r++, rmultiply += multiply)
        {
            // For upper triangular, start c at triangular * r; otherwise, triangular is zero.
            for (int c = r; c < bsMatRows; c++)
            {
                for (int k = 0, kbsMatRows = 0, kmVecLimbs = 0; k < matRows; k++, kbsMatRows += bsMatRows, kmVecLimbs += mVecLimbs)
                {
                    mVecMulAdd(mVecLimbs, bsMat, bsMatEntriesUsed, mat[kbsMatRows + c], acc, rmultiply + kmVecLimbs);
                }
                bsMatEntriesUsed += mVecLimbs;
            }
        }
    }

    /**
     * Performs a GF(16) carryless multiplication of a nibble (lower 4 bits of a)
     * with a 64-bit word b, then reduces modulo the polynomial x⁴ + x + 1 on each byte.
     *
     * @param a a GF(16) element (only the low 4 bits are used)
     * @param b a 64-bit word representing 16 GF(16) elements (packed 4 bits per element)
     * @return the reduced 64-bit word after multiplication
     */
    static long mulFx8(byte a, long b)
    {
        // Convert 'a' to an unsigned int so that bit operations work as expected.
        int aa = a & 0xFF;
        // Carryless multiplication: for each bit in 'aa' (considering only the lower 4 bits),
        // if that bit is set, multiply 'b' (by 1, 2, 4, or 8) and XOR the result.
        long p = (-(aa & 1) & b) ^ (-((aa >> 1) & 1) & (b << 1)) ^ (-((aa >> 2) & 1) & (b << 2)) ^ (-((aa >> 3) & 1) & (b << 3));

        // Reduction mod (x^4 + x + 1): process each byte in parallel.
        long topP = p & 0xf0f0f0f0f0f0f0f0L;
        return (p ^ (topP >>> 4) ^ (topP >>> 3)) & 0x0f0f0f0f0f0f0f0fL;
    }

    static void matMul(byte[] a, byte[] b, int bOff, byte[] c, int colrowAB, int rowA)
    {
        for (int i = 0, aRowStart = 0, cOff = 0; i < rowA; i++)
        {
            byte result = 0;
            for (int k = 0; k < colrowAB; k++)
            {
                result ^= GF16.mul(a[aRowStart++], b[bOff + k]);
            }
            c[cOff++] = result;
        }
    }
}

