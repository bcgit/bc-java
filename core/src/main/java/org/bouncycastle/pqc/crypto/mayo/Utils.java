package org.bouncycastle.pqc.crypto.mayo;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class Utils
{
    public static void unpackMVecs(byte[] in, int inOff, long[] out, int outOff, int vecs, int m)
    {
        int mVecLimbs = (m + 15) >> 4;
        int bytesToCopy = m >> 1; // Number of bytes to copy per vector
        // Temporary buffer to hold mVecLimbs longs (each long is 8 bytes)
        int lastblockLen = 8 - (mVecLimbs << 3) + bytesToCopy;
        int i, j;
        // Process vectors in reverse order
        for (i = vecs - 1, outOff += i * mVecLimbs, inOff += i * bytesToCopy; i >= 0; i--, outOff -= mVecLimbs, inOff -= bytesToCopy)
        {
            // Convert each 8-byte block in tmp into a long using Pack
            for (j = 0; j < mVecLimbs - 1; j++)
            {
                out[outOff + j] = Pack.littleEndianToLong(in, inOff + (j << 3));
            }
            out[outOff + j] = Pack.littleEndianToLong(in, inOff + (j << 3), lastblockLen);
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
        int mVecLimbs = (m + 15) >> 4;
        int bytesToCopy = m >> 1; // Number of bytes per vector to write
        int lastBlockLen = 8 - (mVecLimbs << 3) + bytesToCopy;
        int j;
        // Process each vector in order
        for (int i = 0, inOff = 0; i < vecs; i++, outOff += bytesToCopy, inOff += mVecLimbs)
        {
            // Convert each long into 8 bytes using Pack
            for (j = 0; j < mVecLimbs - 1; j++)
            {
                Pack.longToLittleEndian(in[inOff + j], out, outOff + (j << 3));
            }
            Pack.longToLittleEndian(in[inOff + j], out, outOff + (j << 3), lastBlockLen);
        }
    }

    /**
     * Expands P1 and P2 using AES_128_CTR as a PRF and then unpacks the resulting bytes
     * into an array of 64-bit limbs.
     *
     * @param p       Mayo parameters
     * @param P       The output long array which will hold the unpacked limbs.
     *                Its length should be at least ((P1_bytes + P2_bytes) / 8) limbs.
     * @param seed_pk The seed (used as the key) for the PRF.
     */
    public static void expandP1P2(MayoParameters p, long[] P, byte[] seed_pk)
    {
        // Compute total number of bytes to generate: P1_bytes + P2_bytes.
        int outLen = p.getP1Bytes() + p.getP2Bytes();
        // Temporary byte array to hold the PRF output.
        byte[] temp = new byte[outLen];

        //AES_128_CTR(temp, outLen, seed_pk, p.getPkSeedBytes());
        // Create a 16-byte IV (all zeros)
        byte[] iv = new byte[16]; // automatically zero-initialized

        // Set up AES engine in CTR (SIC) mode.
        BlockCipher aesEngine = AESEngine.newInstance();
        // SICBlockCipher implements CTR mode for AES.
        CTRModeCipher ctrCipher = SICBlockCipher.newInstance(aesEngine);
        // Wrap the key with the IV.
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(Arrays.copyOf(seed_pk, p.getPkSeedBytes())), iv);
        ctrCipher.init(true, params);

        // CTR mode is a stream cipher: encrypting zero bytes produces the keystream.
        int blockSize = ctrCipher.getBlockSize(); // typically 16 bytes
        byte[] zeroBlock = new byte[blockSize];     // block of zeros
        byte[] blockOut = new byte[blockSize];

        int offset = 0;
        // Process full blocks
        while (offset + blockSize <= outLen)
        {
            ctrCipher.processBlock(zeroBlock, 0, blockOut, 0);
            System.arraycopy(blockOut, 0, temp, offset, blockSize);
            offset += blockSize;
        }
        // Process any remaining partial block.
        if (offset < outLen)
        {
            ctrCipher.processBlock(zeroBlock, 0, blockOut, 0);
            int remaining = outLen - offset;
            System.arraycopy(blockOut, 0, temp, offset, remaining);
        }

        // The number of vectors is the total limbs divided by mVecLimbs.
        int numVectors = (p.getP1Limbs() + p.getP2Limbs()) / p.getMVecLimbs();

        // Unpack the byte array 'temp' into the long array 'P'
        // using our previously defined unpackMVecs method.
        unpackMVecs(temp, 0, P, 0, numVectors, p.getM());
    }
}
