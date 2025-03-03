package org.bouncycastle.pqc.crypto.mayo;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Pack;

public class Utils
{
    /**
     * Decodes an encoded byte array.
     * Each byte in the input contains two nibbles (4-bit values); the lower nibble is stored first,
     * followed by the upper nibble.
     *
     * @param m       the input byte array (each byte holds two 4-bit values)
     * @param mdec    the output array that will hold the decoded nibbles (one per byte)
     * @param mdecLen the total number of nibbles to decode
     */
    public static void decode(byte[] m, byte[] mdec, int mdecLen)
    {
        int i;
        int decIndex = 0;
        // Process pairs of nibbles from each byte
        for (i = 0; i < mdecLen / 2; i++)
        {
            // Extract the lower nibble
            mdec[decIndex++] = (byte)((m[i] & 0xFF) & 0x0F);
            // Extract the upper nibble (shift right 4 bits)
            mdec[decIndex++] = (byte)(((m[i] & 0xFF) >> 4) & 0x0F);
        }
        // If there is an extra nibble (odd number of nibbles), decode only the lower nibble
        if (mdecLen % 2 == 1)
        {
            mdec[decIndex] = (byte)((m[i] & 0xFF) & 0x0F);
        }
    }

    public static void decode(byte[] m, int mOff, byte[] mdec, int decIndex, int mdecLen)
    {
        int i;
        // Process pairs of nibbles from each byte
        for (i = 0; i < mdecLen / 2; i++)
        {
            // Extract the lower nibble
            mdec[decIndex++] = (byte)((m[i + mOff] & 0xFF) & 0x0F);
            // Extract the upper nibble (shift right 4 bits)
            mdec[decIndex++] = (byte)(((m[i + mOff] & 0xFF) >> 4) & 0x0F);
        }
        // If there is an extra nibble (odd number of nibbles), decode only the lower nibble
        if (mdecLen % 2 == 1)
        {
            mdec[decIndex] = (byte)((m[i + mOff] & 0xFF) & 0x0F);
        }
    }

    /**
     * Decodes a nibble-packed byte array into an output array.
     *
     * @param input       the input byte array.
     * @param inputOffset the offset in input from which to start decoding.
     * @param output      the output byte array to hold the decoded nibbles.
     * @param mdecLen     the total number of nibbles to decode.
     */
    public static void decode(byte[] input, int inputOffset, byte[] output, int mdecLen)
    {
        int decIndex = 0;
        int blocks = mdecLen / 2;
        for (int i = 0; i < blocks; i++)
        {
            output[decIndex++] = (byte)(input[inputOffset + i] & 0x0F);
            output[decIndex++] = (byte)((input[inputOffset + i] >> 4) & 0x0F);
        }
        if (mdecLen % 2 == 1)
        {
            output[decIndex] = (byte)(input[inputOffset + blocks] & 0x0F);
        }
    }

    /**
     * Encodes an array of 4-bit values into a byte array.
     * Two 4-bit values are packed into one byte, with the first nibble stored in the lower 4 bits
     * and the second nibble stored in the upper 4 bits.
     *
     * @param m    the input array of 4-bit values (stored as bytes, only lower 4 bits used)
     * @param menc the output byte array that will hold the encoded bytes
     * @param mlen the number of nibbles in the input array
     */
    public static void encode(byte[] m, byte[] menc, int mlen)
    {
        int i;
        int srcIndex = 0;
        // Process pairs of 4-bit values
        for (i = 0; i < mlen / 2; i++)
        {
            int lowerNibble = m[srcIndex] & 0x0F;
            int upperNibble = (m[srcIndex + 1] & 0x0F) << 4;
            menc[i] = (byte)(lowerNibble | upperNibble);
            srcIndex += 2;
        }
        // If there is an extra nibble (odd number of nibbles), store it directly in lower 4 bits.
        if (mlen % 2 == 1)
        {
            menc[i] = (byte)(m[srcIndex] & 0x0F);
        }
    }

    /**
     * Unpacks m-vectors from a packed byte array into an array of 64-bit limbs.
     *
     * @param in   the input byte array containing packed data
     * @param out  the output long array where unpacked limbs are stored
     * @param vecs the number of vectors
     * @param m    the m parameter (used to compute m_vec_limbs and copy lengths)
     */
    public static void unpackMVecs(byte[] in, long[] out, int vecs, int m)
    {
        int mVecLimbs = (m + 15) / 16;
        int bytesToCopy = m / 2; // Number of bytes to copy per vector

        // Process vectors in reverse order
        for (int i = vecs - 1; i >= 0; i--)
        {
            // Temporary buffer to hold mVecLimbs longs (each long is 8 bytes)
            byte[] tmp = new byte[mVecLimbs * 8];
            // Copy m/2 bytes from the input into tmp. The rest remains zero.
            System.arraycopy(in, i * bytesToCopy, tmp, 0, bytesToCopy);

            // Convert each 8-byte block in tmp into a long using Pack
            for (int j = 0; j < mVecLimbs; j++)
            {
                out[i * mVecLimbs + j] = Pack.littleEndianToLong(tmp, j * 8);
            }
        }
    }

    public static void unpackMVecs(byte[] in, int inOff, long[] out, int outOff, int vecs, int m)
    {
        int mVecLimbs = (m + 15) / 16;
        int bytesToCopy = m / 2; // Number of bytes to copy per vector

        // Process vectors in reverse order
        for (int i = vecs - 1; i >= 0; i--)
        {
            // Temporary buffer to hold mVecLimbs longs (each long is 8 bytes)
            byte[] tmp = new byte[mVecLimbs * 8];
            // Copy m/2 bytes from the input into tmp. The rest remains zero.
            System.arraycopy(in, inOff + i * bytesToCopy, tmp, 0, bytesToCopy);

            // Convert each 8-byte block in tmp into a long using Pack
            for (int j = 0; j < mVecLimbs; j++)
            {
                out[outOff + i * mVecLimbs + j] = Pack.littleEndianToLong(tmp, j * 8);
            }
        }
    }

    /**
     * Packs m-vectors from an array of 64-bit limbs into a packed byte array.
     *
     * @param in   the input long array containing the m-vectors
     * @param out  the output byte array that will contain the packed data
     * @param vecs the number of vectors
     * @param m    the m parameter (used to compute m_vec_limbs and copy lengths)
     */
    public static void packMVecs(long[] in, byte[] out, int outOff, int vecs, int m)
    {
        int mVecLimbs = (m + 15) / 16;
        int bytesToCopy = m / 2; // Number of bytes per vector to write

        // Process each vector in order
        for (int i = 0; i < vecs; i++)
        {
            // Temporary buffer to hold the bytes for this vector
            byte[] tmp = new byte[mVecLimbs * 8];

            // Convert each long into 8 bytes using Pack
            for (int j = 0; j < mVecLimbs; j++)
            {
                Pack.longToLittleEndian(in[i * mVecLimbs + j], tmp, j * 8);
            }

            // Copy the first m/2 bytes from tmp to the output array
            System.arraycopy(tmp, 0, out, i * bytesToCopy + outOff, bytesToCopy);
        }
    }

    /**
     * Computes the SHAKE256 XOF on the given input.
     *
     * @param output the output buffer that will be filled with the result.
     * @param outlen the number of bytes to produce.
     * @param input  the input byte array.
     * @param inlen  the number of input bytes.
     * @return the number of output bytes produced (equals outlen).
     */
    public static int shake256(byte[] output, int outlen, byte[] input, int inlen)
    {
        // Create a new SHAKE256 digest instance.
        SHAKEDigest shake = new SHAKEDigest(256);

        // Absorb the input.
        shake.update(input, 0, inlen);

        // Squeeze out outlen bytes into the output array.
        shake.doFinal(output, 0, outlen);

        return outlen;
    }

}
