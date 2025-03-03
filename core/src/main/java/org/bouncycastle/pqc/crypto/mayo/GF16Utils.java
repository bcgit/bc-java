package org.bouncycastle.pqc.crypto.mayo;

import org.bouncycastle.util.Pack;

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
        // In the original code there is a conditional XOR with unsigned_char_blocker;
        // here we simply use b directly.
        long b32 = b & 0x00000000FFFFFFFFL;
        long r64 = a * (b32 & 1);

        long a_msb = a & maskMsb;
        a ^= a_msb;
        a = (a << 1) ^ ((a_msb >>> 3) * 3);
        r64 ^= a * ((b32 >> 1) & 1);

        a_msb = a & maskMsb;
        a ^= a_msb;
        a = (a << 1) ^ ((a_msb >>> 3) * 3);
        r64 ^= a * ((b32 >>> 2) & 1);

        a_msb = a & maskMsb;
        a ^= a_msb;
        a = (a << 1) ^ ((a_msb >>> 3) * 3);
        r64 ^= a * ((b32 >> 3) & 1);

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
                    mVecMulAdd(mVecLimbs, bsMat, bsMatOffset, a, acc, accOffset);
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
                byte matVal = mat[c * matCols + r];
                for (int k = 0; k < bsMatCols; k++)
                {
                    int bsMatOffset = (c * bsMatCols + k) * mVecLimbs;
                    // For acc: add into the m-vector at index (r * bsMatCols + k)
                    int accOffset = (r * bsMatCols + k) * mVecLimbs;
                    mVecMulAdd(mVecLimbs, bsMat, bsMatOffset, matVal, acc, accOffset);
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
     * @param bsMatCols the number of columns in the bit‐sliced matrix (per block)
     */
    public static void mulAddMatXMMat(int mVecLimbs, byte[] mat, long[] bsMat, long[] acc,
                                      int matRows, int matCols, int bsMatCols)
    {
        for (int r = 0; r < matRows; r++)
        {
            for (int c = 0; c < matCols; c++)
            {
                // Retrieve the scalar from the matrix for row r and column c.
                byte matVal = mat[r * matCols + c];
                for (int k = 0; k < bsMatCols; k++)
                {
                    // Compute the starting index for the vector in bsMat.
                    int bsMatOffset = mVecLimbs * (c * bsMatCols + k);
                    // Compute the starting index for the accumulator vector in acc.
                    int accOffset = mVecLimbs * (r * bsMatCols + k);
                    // Multiply the vector by the scalar and add the result to the accumulator.
                    mVecMulAdd(mVecLimbs, bsMat, bsMatOffset, matVal, acc, accOffset);
                }
            }
        }
    }

    public static void mulAddMatXMMat(int mVecLimbs, byte[] mat, long[] bsMat, int bsMatOff, long[] acc,
                                      int matRows, int matCols, int bsMatCols)
    {
        for (int r = 0; r < matRows; r++)
        {
            for (int c = 0; c < matCols; c++)
            {
                // Retrieve the scalar from the matrix for row r and column c.
                byte matVal = mat[r * matCols + c];
                for (int k = 0; k < bsMatCols; k++)
                {
                    // Compute the starting index for the vector in bsMat.
                    int bsMatOffset = mVecLimbs * (c * bsMatCols + k) + bsMatOff;
                    // Compute the starting index for the accumulator vector in acc.
                    int accOffset = mVecLimbs * (r * bsMatCols + k);
                    // Multiply the vector by the scalar and add the result to the accumulator.
                    mVecMulAdd(mVecLimbs, bsMat, bsMatOffset, matVal, acc, accOffset);
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
     * @param mVecLimbs  the number of limbs (elements) in each vector.
     * @param bsMat      the bit‑sliced matrix stored as a long array.
     * @param mat        the matrix stored as a byte array.
     * @param acc        the accumulator array where the results are added.
     * @param bsMatRows  the number of rows in the bit‑sliced matrix.
     * @param bsMatCols  the number of columns in the bit‑sliced matrix.
     * @param matRows    the number of rows in the matrix.
     * @param triangular if non‑zero, indicates that the matrix is upper triangular (i.e. the loop for {@code c}
     *                   starts at {@code triangular * r}).
     */
    public static void mulAddMUpperTriangularMatXMatTrans(int mVecLimbs, long[] bsMat, byte[] mat, long[] acc,
                                                          int bsMatRows, int bsMatCols, int matRows, int triangular)
    {
        int bsMatEntriesUsed = 0;
        for (int r = 0; r < bsMatRows; r++)
        {
            // For upper triangular, start c at triangular * r; otherwise, triangular is zero.
            for (int c = triangular * r; c < bsMatCols; c++)
            {
                for (int k = 0; k < matRows; k++)
                {
                    int bsMatOffset = mVecLimbs * bsMatEntriesUsed;
                    int accOffset = mVecLimbs * (r * matRows + k);
                    // Get the matrix element at row k and column c
                    byte matVal = mat[k * bsMatCols + c];
                    mVecMulAdd(mVecLimbs, bsMat, bsMatOffset, matVal, acc, accOffset);
                }
                bsMatEntriesUsed++;
            }
        }
    }

    /**
     * GF(16) multiplication mod x^4 + x + 1.
     * <p>
     * This method multiplies two elements in GF(16) (represented as integers 0–15)
     * using carryless multiplication followed by reduction modulo x^4 + x + 1.
     *
     * @param a an element in GF(16) (only the lower 4 bits are used)
     * @param b an element in GF(16) (only the lower 4 bits are used)
     * @return the product a * b in GF(16)
     */
    public static int mulF(int a, int b)
    {
        // In C there is a conditional XOR with unsigned_char_blocker to work around
        // compiler-specific behavior. In Java we can omit it (or define it as needed).
        // a ^= unsignedCharBlocker;  // Omitted in Java

        // Perform carryless multiplication:
        // Multiply b by each bit of a and XOR the results.
        int p = ((a & 1) * b) ^
            ((a & 2) * b) ^
            ((a & 4) * b) ^
            ((a & 8) * b);

        // Reduce modulo f(X) = x^4 + x + 1.
        // Extract the upper nibble (bits 4 to 7).
        int topP = p & 0xF0;
        // The reduction: XOR p with (topP shifted right by 4 and by 3) and mask to 4 bits.
        return (p ^ (topP >> 4) ^ (topP >> 3)) & 0x0F;
    }

    /**
     * Performs a GF(16) carryless multiplication of a nibble (lower 4 bits of a)
     * with a 64-bit word b, then reduces modulo the polynomial x⁴ + x + 1 on each byte.
     *
     * @param a a GF(16) element (only the low 4 bits are used)
     * @param b a 64-bit word representing 16 GF(16) elements (packed 4 bits per element)
     * @return the reduced 64-bit word after multiplication
     */
    public static long mulFx8(byte a, long b)
    {
        // Convert 'a' to an unsigned int so that bit operations work as expected.
        int aa = a & 0xFF;
        // Carryless multiplication: for each bit in 'aa' (considering only the lower 4 bits),
        // if that bit is set, multiply 'b' (by 1, 2, 4, or 8) and XOR the result.
        long p = ((aa & 1) * b)
            ^ ((aa & 2) * b)
            ^ ((aa & 4) * b)
            ^ ((aa & 8) * b);

        // Reduction mod (x^4 + x + 1): process each byte in parallel.
        long topP = p & 0xf0f0f0f0f0f0f0f0L;
        return (p ^ (topP >> 4) ^ (topP >> 3)) & 0x0f0f0f0f0f0f0f0fL;
    }

    public static void matMul(byte[] a, byte[] b, byte[] c,
                              int colrowAB, int rowA, int colB)
    {
        int cIndex = 0;
        for (int i = 0; i < rowA; i++)
        {
            int aRowStart = i * colrowAB;
            for (int j = 0; j < colB; j++)
            {
                c[cIndex++] = lincomb(a, aRowStart, b, j, colrowAB, colB);
            }
        }
    }

    public static void matMul(byte[] a, int aOff, byte[] b, int bOff, byte[] c, int cOff,
                              int colrowAB, int rowA, int colB)
    {
        int cIndex = 0;
        for (int i = 0; i < rowA; i++)
        {
            int aRowStart = i * colrowAB;
            for (int j = 0; j < colB; j++)
            {
                c[cOff + cIndex++] = lincomb(a, aOff + aRowStart, b, bOff + j, colrowAB, colB);
            }
        }
    }


    private static byte lincomb(byte[] a, int aStart, byte[] b, int bStart,
                                int colrowAB, int colB)
    {
        byte result = 0;
        for (int k = 0; k < colrowAB; k++)
        {
            result ^= mulF(a[aStart + k], b[bStart + k * colB]);
        }
        return result;
    }

    public static void matAdd(byte[] a, int aOff, byte[] b, int bOff, byte[] c, int cOff, int m, int n)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < n; j++)
            {
                int idx = i * n + j;
                c[idx + cOff] = (byte)(a[idx + aOff] ^ b[idx + bOff]);
            }
        }
    }

    /**
     * Returns 0x00 if a equals b, otherwise returns 0xFF.
     * This operation is performed in constant time.
     *
     * @param a an 8-bit value
     * @param b an 8-bit value
     * @return 0x00 if a == b, 0xFF if a != b
     */
    public static byte ctCompare8(byte a, byte b)
    {
        // Compute the difference between a and b using XOR.
        // Masking with 0xFF ensures we work with values in 0..255.
        int diff = (a ^ b) & 0xFF;
        // Negate the difference.
        int negDiff = -diff;
        // Right shift by 31 bits (since 8*sizeof(uint32_t)-1 equals 31 for 32-bit integers).
        // If diff is 0, then -diff is 0, and shifting yields 0.
        // If diff is nonzero, -diff is negative, so the arithmetic shift yields -1 (0xFFFFFFFF),
        // which when cast to a byte becomes 0xFF.
        return (byte) (negDiff >> 31);
    }

    public static void efUnpackMVector(int legs, long[] packedRow, int packedRowOff, byte[] out)
    {
        int outIndex = 0;
        byte[] bytes = new byte[out.length >> 1];
        Pack.longToLittleEndian(packedRow, packedRowOff, out.length >> 4, bytes, 0);
        for (int i = 0; i < legs * 16; i += 2)
        {
            out[outIndex++] = (byte)(bytes[i / 2] & 0x0F);       // Lower nibble
            out[outIndex++] = (byte)((bytes[i / 2] >> 4) & 0x0F); // Upper nibble
        }
    }
}

