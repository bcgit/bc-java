package org.bouncycastle.pqc.crypto.mirath;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

class MirathEngine
{
    // Define constants based on your specific parameters
    public final int securityBytes; // Example value
    public final int saltBytes; // Adjust as per your needs
    public final int m; // Set appropriate value
    public final int r; // Set appropriate value
    public final int n; // Set appropriate value
    public final int k;
    private final boolean isA;
    public final int ffYBytes;
    private final int offEA;
    private final int offEB;
    // GF(16) multiplication table (replace with actual implementation if different)
    private static final byte[] MIRATH_FF_MULT_TABLE = new byte[]{
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
        (byte)0x00, (byte)0x02, (byte)0x04, (byte)0x06, (byte)0x08, (byte)0x0a, (byte)0x0c, (byte)0x0e, (byte)0x03, (byte)0x01, (byte)0x07, (byte)0x05, (byte)0x0b, (byte)0x09, (byte)0x0f, (byte)0x0d,
        (byte)0x00, (byte)0x03, (byte)0x06, (byte)0x05, (byte)0x0c, (byte)0x0f, (byte)0x0a, (byte)0x09, (byte)0x0b, (byte)0x08, (byte)0x0d, (byte)0x0e, (byte)0x07, (byte)0x04, (byte)0x01, (byte)0x02,
        (byte)0x00, (byte)0x04, (byte)0x08, (byte)0x0c, (byte)0x03, (byte)0x07, (byte)0x0b, (byte)0x0f, (byte)0x06, (byte)0x02, (byte)0x0e, (byte)0x0a, (byte)0x05, (byte)0x01, (byte)0x0d, (byte)0x09,
        (byte)0x00, (byte)0x05, (byte)0x0a, (byte)0x0f, (byte)0x07, (byte)0x02, (byte)0x0d, (byte)0x08, (byte)0x0e, (byte)0x0b, (byte)0x04, (byte)0x01, (byte)0x09, (byte)0x0c, (byte)0x03, (byte)0x06,
        (byte)0x00, (byte)0x06, (byte)0x0c, (byte)0x0a, (byte)0x0b, (byte)0x0d, (byte)0x07, (byte)0x01, (byte)0x05, (byte)0x03, (byte)0x09, (byte)0x0f, (byte)0x0e, (byte)0x08, (byte)0x02, (byte)0x04,
        (byte)0x00, (byte)0x07, (byte)0x0e, (byte)0x09, (byte)0x0f, (byte)0x08, (byte)0x01, (byte)0x06, (byte)0x0d, (byte)0x0a, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x05, (byte)0x0c, (byte)0x0b,
        (byte)0x00, (byte)0x08, (byte)0x03, (byte)0x0b, (byte)0x06, (byte)0x0e, (byte)0x05, (byte)0x0d, (byte)0x0c, (byte)0x04, (byte)0x0f, (byte)0x07, (byte)0x0a, (byte)0x02, (byte)0x09, (byte)0x01,
        (byte)0x00, (byte)0x09, (byte)0x01, (byte)0x08, (byte)0x02, (byte)0x0b, (byte)0x03, (byte)0x0a, (byte)0x04, (byte)0x0d, (byte)0x05, (byte)0x0c, (byte)0x06, (byte)0x0f, (byte)0x07, (byte)0x0e,
        (byte)0x00, (byte)0x0a, (byte)0x07, (byte)0x0d, (byte)0x0e, (byte)0x04, (byte)0x09, (byte)0x03, (byte)0x0f, (byte)0x05, (byte)0x08, (byte)0x02, (byte)0x01, (byte)0x0b, (byte)0x06, (byte)0x0c,
        (byte)0x00, (byte)0x0b, (byte)0x05, (byte)0x0e, (byte)0x0a, (byte)0x01, (byte)0x0f, (byte)0x04, (byte)0x07, (byte)0x0c, (byte)0x02, (byte)0x09, (byte)0x0d, (byte)0x06, (byte)0x08, (byte)0x03,
        (byte)0x00, (byte)0x0c, (byte)0x0b, (byte)0x07, (byte)0x05, (byte)0x09, (byte)0x0e, (byte)0x02, (byte)0x0a, (byte)0x06, (byte)0x01, (byte)0x0d, (byte)0x0f, (byte)0x03, (byte)0x04, (byte)0x08,
        (byte)0x00, (byte)0x0d, (byte)0x09, (byte)0x04, (byte)0x01, (byte)0x0c, (byte)0x08, (byte)0x05, (byte)0x02, (byte)0x0f, (byte)0x0b, (byte)0x06, (byte)0x03, (byte)0x0e, (byte)0x0a, (byte)0x07,
        (byte)0x00, (byte)0x0e, (byte)0x0f, (byte)0x01, (byte)0x0d, (byte)0x03, (byte)0x02, (byte)0x0c, (byte)0x09, (byte)0x07, (byte)0x06, (byte)0x08, (byte)0x04, (byte)0x0a, (byte)0x0b, (byte)0x05,
        (byte)0x00, (byte)0x0f, (byte)0x0d, (byte)0x02, (byte)0x09, (byte)0x06, (byte)0x04, (byte)0x0b, (byte)0x01, (byte)0x0e, (byte)0x0c, (byte)0x03, (byte)0x08, (byte)0x07, (byte)0x05, (byte)0x0a,
    };

    public MirathEngine(MirathParameters parameters)
    {
        securityBytes = parameters.getSecurityLevelBytes();
        saltBytes = parameters.getSaltBytes();
        m = parameters.getM();
        r = parameters.getR();
        n = parameters.getN();
        k = parameters.getK();
        isA = parameters.isA();
        ffYBytes = calculateMatrixBytes(m * n - k, 1);
        offEA = (8 * ffYBytes) - (isA ? 4 : 1) * (m * n - k);
        offEB = (8 * calculateMatrixBytes(k, 1)) - (isA ? 4 : 1) * k;
    }

    public void mirathMatrixExpandSeedSecretMatrix(byte[] S, byte[] C, byte[] seedSk)
    {
        SHAKEDigest prng = new SHAKEDigest(128);
        mirathPrngInit(prng, null, seedSk, securityBytes);

        // Generate all bytes for S and C in one go
        byte[] T = new byte[S.length + C.length];
        prng.doFinal(T, 0, T.length);

        System.arraycopy(T, 0, S, 0, S.length);
        System.arraycopy(T, S.length, C, 0, C.length);

        mirathMatrixSetToFF(S, m, r);
        mirathMatrixSetToFF(C, r, n - r);
    }

    public void mirathMatrixExpandSeedPublicMatrix(byte[] H, byte[] seedPk)
    {
        SHAKEDigest prng = new SHAKEDigest(128);
        mirathPrngInit(prng, null, seedPk, securityBytes);

        int rows = m * m - k;
        int cols = k;
        int hBytes = calculateMatrixBytes(rows, cols);

        prng.doFinal(H, 0, hBytes);
        mirathMatrixSetToFF(H, rows, cols);
    }

    public void mirathMatrixComputeY(byte[] y, byte[] S, byte[] C, byte[] H)
    {
        int eASize = ffYBytes;
        int eBSize = calculateMatrixBytes(k, 1);
        byte[] eA = new byte[eASize];
        byte[] eB = new byte[eBSize];

        // Calculate intermediate matrices
        byte[] T = new byte[calculateMatrixBytes(m, n - r)];
        byte[] E = new byte[isA ? calculateMatrixBytes(m, n) : calculateMatrixBytes(m * n, 1)];

        matrixProduct(T, S, C, m, r, n - r);
        horizontalConcat(E, S, T, m, r, n - r);

        // Process eA and eB
        System.arraycopy(E, 0, eA, 0, eA.length);
        if (offEA > 0)
        {
            byte mask = (byte)((1 << (8 - offEA)) - 1);
            eA[eASize - 1] = (byte)(E[eASize - 1] & mask);

            for (int i = 0; i < eBSize - 1; i++)
            {
                byte part1 = (byte)((E[eASize - 1 + i] & 0xFF) >>> (8 - offEA));
                byte part2 = (byte)((E[eASize + i] & 0xFF) << offEA);
                eB[i] = (byte)(part1 ^ part2);
            }

            if ((offEA + offEB) >= 8)
            {
                eB[eBSize - 1] = (byte)((E[E.length - 1] & 0xFF) >>> (8 - offEA));
            }
            else
            {
                byte part1 = (byte)((E[E.length - 2] & 0xFF) >>> (8 - offEA));
                byte part2 = (byte)((E[E.length - 1] & 0xFF) << offEA);
                eB[eBSize - 1] = (byte)(part1 ^ part2);
            }
        }
        else
        {
            System.arraycopy(E, eASize, eB, 0, eBSize);
        }

        // Compute final y
        Arrays.fill(y, (byte)0);
        matrixProduct(y, H, eB, m * n - k, k, 1);
        vectorAdd(y, y, eA);
    }

    private void matrixProduct(byte[] result, byte[] matrix1, byte[] matrix2,
                               int nRows1, int nCols1, int nCols2)
    {
        int matrixHeight = mirathMatrixFfBytesPerColumn(nRows1);

        for (int i = 0; i < nRows1; i++)
        {
            for (int j = 0; j < nCols2; j++)
            {
                byte entry = 0;

                for (int k = 0; k < nCols1; k++)
                {
                    byte a = getMatrixEntry(matrix1, nRows1, i, k);
                    byte b = getMatrixEntry(matrix2, nCols1, k, j);
                    entry ^= ffMultiply(a, b);
                }

                setMatrixEntry(result, nRows1, i, j, entry);
            }
        }

        if ((nRows1 & 1) != 0)
        {
            int matrixHeightX = matrixHeight - 1;
            for (int i = 0; i < nCols2; i++)
            {
                result[i * matrixHeight + matrixHeightX] &= 0x0F;
            }
        }
    }

    private byte getMatrixEntry(byte[] matrix, int nRows, int i, int j)
    {
        int bytesPerCol = mirathMatrixFfBytesPerColumn(nRows);
        if (isA)
        {
            int pos = j * bytesPerCol + (i >>> 1);
            return (byte)((i & 1) != 0 ?
                (matrix[pos] & 0xFF) >>> 4 :
                matrix[pos] & 0x0F);
        }
        else
        {
            int idxLine = i >>> 3;
            int bitLine = i & 7;
            return (byte)((matrix[bytesPerCol * j + idxLine] >>> bitLine) & 0x01);
        }
    }

    private void setMatrixEntry(byte[] matrix, int nRows, int i, int j, byte value)
    {
        int bytesPerCol = mirathMatrixFfBytesPerColumn(nRows);
        int pos = j * bytesPerCol + (i >>> 1);
        if (isA)
        {
            if ((i & 1) != 0)
            {
                matrix[pos] = (byte)((matrix[pos] & 0x0F) | ((value & 0x0F) << 4));
            }
            else
            {
                matrix[pos] = (byte)((matrix[pos] & 0xF0) | (value & 0x0F));
            }
        }
        else
        {
            int idxLine = i >>> 3;
            int bitLine = i & 7;
            byte mask = (byte)(0xff ^ (1 << bitLine));
            matrix[bytesPerCol * j + idxLine] = (byte)((matrix[bytesPerCol * j + idxLine] & mask) ^ (value << bitLine));
        }
    }

//    private void horizontalConcat(byte[] result, byte[] matrix1, byte[] matrix2,
//                                         int nRows, int nCols1, int nCols2)
//    {
//        int bytesPerCol = bytesPerColumn(nRows);
//        int onCol = 8 - ((8 * bytesPerCol) - (4 * nRows));
//
//        int ptr = 0;
//        int offPtr = 8;  // Tracks bits remaining in current byte (starts empty)
//
//        // Process matrix1 columns
//        for (int j = 0; j < nCols1; j++)
//        {
//            int colStart = j * bytesPerCol;
//            for (int i = 0; i < bytesPerCol; i++)
//            {
//                byte current = matrix1[colStart + i];
//
//                // Process upper nibble (4 bits)
//                byte nibble = (byte)((current & 0xF0) >>> 4);
//                processNibble(result, nibble, ref ptr, ref offPtr, onCol);
//
//                // Process lower nibble (4 bits) if not last byte or if there's space
//                if (i < bytesPerCol - 1 || (nRows % 2 == 0))
//                {
//                    nibble = (byte)(current & 0x0F);
//                    processNibble(result, nibble, ref ptr, ref offPtr, onCol);
//                }
//            }
//        }
//
//        // Process matrix2 columns
//        for (int j = 0; j < nCols2; j++)
//        {
//            int colStart = j * bytesPerCol;
//            for (int i = 0; i < bytesPerCol; i++)
//            {
//                byte current = matrix2[colStart + i];
//
//                // Process upper nibble
//                byte nibble = (byte)((current & 0xF0) >>> 4);
//                processNibble(result, nibble, ref ptr, ref offPtr, onCol);
//
//                // Process lower nibble
//                if (i < bytesPerCol - 1 || (nRows % 2 == 0))
//                {
//                    nibble = (byte)(current & 0x0F);
//                    processNibble(result, nibble, ref ptr, ref offPtr, onCol);
//                }
//            }
//        }
//    }

    private void processNibble(byte[] result, byte nibble,
                               int[] ptrHolder, int[] offPtrHolder, int onCol)
    {
        int ptr = ptrHolder[0];
        int offPtr = offPtrHolder[0];

        if (offPtr == 8)
        {  // Start new byte
            //result[ptr] = 0;
            offPtr = 0;
        }

        // Calculate available space in current byte
        int shift = 4 - offPtr;
        if (shift >= 0)
        {
            // Fits in current byte
            result[ptr] |= (byte)((nibble & 0x0F) << (4 - offPtr));
            offPtr += 4;
        }
        else
        {
            // Split across bytes
            result[ptr] |= (byte)((nibble & 0x0F) >>> (-shift));
            ptr++;
            result[ptr] = (byte)((nibble & 0x0F) << (8 + shift));
            offPtr = 4 + shift;
        }

        // Check if byte is full
        if (offPtr >= 8)
        {
            ptr++;
            offPtr %= 8;
        }

        // Handle special column alignment
        if (offPtr > onCol)
        {
            ptr++;
            offPtr = 8 - (onCol - (offPtr - 8));
        }

        // Update holder arrays
        ptrHolder[0] = ptr;
        offPtrHolder[0] = offPtr;
    }

    // Modified horizontalConcat caller
    private void horizontalConcat(byte[] result, byte[] matrix1, byte[] matrix2,
                                  int nRows, int nCols1, int nCols2)
    {
//        int bytesPerCol = mirathMatrixFfBytesPerColumn(nRows);
//        int onCol = 8 - ((8 * bytesPerCol) - ((isA ? 4 : 1) * nRows));
//
//        // Use arrays to simulate ref parameters
//        int[] ptrHolder = new int[1];
//        int[] offPtrHolder = new int[]{8};  //8// Start with empty byte
//
//        // Process matrix1
//        processColumns(result, matrix1, nCols1, bytesPerCol, nRows, ptrHolder, offPtrHolder, onCol);
//
//        // Process matrix2
//        processColumns(result, matrix2, nCols2, bytesPerCol, nRows, ptrHolder, offPtrHolder, onCol);
        int ptrIndex = 0;
        int offPtr = 8;

        int nRowsBytes = mirathMatrixFfBytesPerColumn(nRows);
        int onCol = 8 - ((8 * nRowsBytes) - nRows);

        int colIndex;

        // Process matrix1
        colIndex = 0;
        for (int j = 0; j < nCols1; j++)
        {
            result[ptrIndex] |= (matrix1[colIndex] << (8 - offPtr));

            for (int i = 0; i < nRowsBytes - 1; i++)
            {
                ptrIndex++;
                result[ptrIndex] = (byte)((matrix1[colIndex] & 0xFF) >>> offPtr);
                colIndex++;
                result[ptrIndex] |= (matrix1[colIndex] << (8 - offPtr));
            }

            if (offPtr <= onCol)
            {
                ptrIndex++;
                result[ptrIndex] = (byte)((matrix1[colIndex] & 0xFF) >>> offPtr);
            }
            colIndex++;
            offPtr = (8 - ((onCol - offPtr) % 8));
            if (offPtr > 8)
            {
                offPtr -= 8;
            }
        }

        // Process matrix2
        colIndex = 0;
        for (int j = 0; j < nCols2; j++)
        {
            result[ptrIndex] |= (matrix2[colIndex] << (8 - offPtr));

            for (int i = 0; i < nRowsBytes - 1; i++)
            {
                ptrIndex++;
                result[ptrIndex] = (byte)((matrix2[colIndex] & 0xFF) >>> offPtr);
                colIndex++;
                result[ptrIndex] |= (matrix2[colIndex] << (8 - offPtr));
            }

            if (offPtr <= onCol)
            {
                ptrIndex++;
                if (offPtr < onCol)
                {
                    result[ptrIndex] = (byte)((matrix2[colIndex] & 0xFF) >>> offPtr);
                }
            }
            colIndex++;
            offPtr = (8 - ((onCol - offPtr) % 8));
            if (offPtr > 8)
            {
                offPtr -= 8;
            }
        }
    }


//    private void processColumns(byte[] result, byte[] matrix, int colCount,
//                                int bytesPerCol, int nRows, int[] ptrHolder,
//                                int[] offPtrHolder, int onCol)
//    {
//        for (int j = 0; j < colCount; j++)
//        {
//            int colStart = j * bytesPerCol;
//            byte[] column = Arrays.copyOfRange(matrix, colStart, colStart + bytesPerCol);
//
//            // Convert column to bit array (1 bit per element)
//            boolean[] bits = new boolean[nRows];
//            for (int i = 0; i < nRows; i++)
//            {
//                int byteIdx = i / 8;
//                int bitIdx = 7 - (i % 8);  // MSB first
//                bits[i] = ((column[byteIdx] >> bitIdx) & 1) != 0;
//            }
//
//            // Store bits in result with proper bit packing
//            int ptr = ptrHolder[0];
//            int offPtr = offPtrHolder[0];
//
//            for (boolean bit : bits)
//            {
//                if (offPtr == 8)
//                {
//                    ptr++;
//                    offPtr = 0;
//                    if (ptr >= result.length)
//                    {
//                        result = Arrays.copyOf(result, result.length + 1);
//                    }
//                    result[ptr] = 0;
//                }
//
//                if (bit)
//                {
//                    result[ptr] |= (1 << (7 - offPtr));
//                }
//                offPtr++;
//            }
//
//            // Handle column alignment
//            if (offPtr > onCol)
//            {
//                ptr++;
//                offPtr = 8 - (onCol - (offPtr - 8));
//            }
//
//            ptrHolder[0] = ptr;
//            offPtrHolder[0] = offPtr;
//        }
//    }

    private void processColumns(byte[] result, byte[] matrix, int colCount,
                                int bytesPerCol, int nRows, int[] ptrHolder,
                                int[] offPtrHolder, int onCol)
    {
        for (int j = 0; j < colCount; j++)
        {
            int colStart = j * bytesPerCol;
            for (int i = 0; i < bytesPerCol; i++)
            {
                byte current = matrix[colStart + i];

                // Process upper nibble
                byte nibble = (byte)((current & 0xF0) >>> 4);
                processNibble(result, nibble, ptrHolder, offPtrHolder, onCol);

                // Process lower nibble if needed
                if (i < bytesPerCol - 1 || (nRows % 2 == 0))
                {
                    nibble = (byte)(current & 0x0F);
                    processNibble(result, nibble, ptrHolder, offPtrHolder, onCol);
                }
            }
        }
    }

    private static void vectorAdd(byte[] result, byte[] a, byte[] b)
    {
        for (int i = 0; i < result.length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }
    }

    private static byte ffMultiply(byte a, byte b)
    {
        return MIRATH_FF_MULT_TABLE[(a & 0x0F) + 16 * (b & 0x0F)];
    }

    private void mirathPrngInit(SHAKEDigest prng, byte[] salt, byte[] seedSk, int seedSizeBytes)
    {
        int saltLength = (salt != null) ? salt.length : 0;
        byte[] input = new byte[saltBytes + seedSizeBytes];
        Arrays.fill(input, (byte)0);

        int position = 0;
        if (salt != null && salt.length >= saltBytes)
        {
            System.arraycopy(salt, 0, input, 0, saltBytes);
            position += saltBytes;
        }

        if (seedSk != null && seedSk.length >= seedSizeBytes)
        {
            System.arraycopy(seedSk, 0, input, position, seedSizeBytes);
            position += seedSizeBytes;
        }

        prng.update(input, 0, position);
    }

    private void mirathMatrixSetToFF(byte[] matrix, int nRows, int nCols)
    {
        if (isA)
        {
            if ((nRows & 1) != 0)
            {
                int matrixHeight = mirathMatrixFfBytesPerColumn(nRows);
                int matrixHeightX = matrixHeight - 1;

                for (int i = 0; i < nCols; i++)
                {
                    int index = i * matrixHeight + matrixHeightX;
                    matrix[index] &= 0x0F; // Clear upper 4 bits
                }
            }
        }
        else
        {
            if ((nRows & 7) != 0)
            {
                int matrixHeight = mirathMatrixFfBytesPerColumn(nRows);
                int matrixHeightX = matrixHeight - 1;

                byte mask = (byte)(0xff >>> (8 - (nRows % 8)));

                for (int i = 0; i < nCols; i++)
                {
                    int index = i * matrixHeight + matrixHeightX;
                    matrix[index] &= mask; // Clear upper 4 bits
                }
            }
        }
    }

    private int mirathMatrixFfBytesPerColumn(int nRows)
    {
        if (isA)
        {
            return (nRows + 1) >> 1;
        }
        else
        {
            return (nRows + 7) >> 3;
        }
    }

    int calculateMatrixBytes(int rows, int cols)
    {
        return cols * mirathMatrixFfBytesPerColumn(rows);
    }

}
