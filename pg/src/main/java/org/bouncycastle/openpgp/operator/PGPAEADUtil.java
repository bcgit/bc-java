package org.bouncycastle.openpgp.operator;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

public class PGPAEADUtil
{
    protected PGPAEADUtil()
    {

    }

    /**
     * Generate a nonce by xor-ing the given iv with the chunk index.
     *
     * @param iv         initialization vector
     * @param chunkIndex chunk index
     * @return nonce
     */
    protected static byte[] getNonce(byte[] iv, long chunkIndex)
    {
        byte[] nonce = Arrays.clone(iv);

        xorChunkId(nonce, chunkIndex);

        return nonce;
    }

    /**
     * XOR the byte array with the chunk index in-place.
     *
     * @param nonce      byte array
     * @param chunkIndex chunk index
     */
    protected static void xorChunkId(byte[] nonce, long chunkIndex)
    {
        int index = nonce.length - 8;

        nonce[index++] ^= (byte)(chunkIndex >> 56);
        nonce[index++] ^= (byte)(chunkIndex >> 48);
        nonce[index++] ^= (byte)(chunkIndex >> 40);
        nonce[index++] ^= (byte)(chunkIndex >> 32);
        nonce[index++] ^= (byte)(chunkIndex >> 24);
        nonce[index++] ^= (byte)(chunkIndex >> 16);
        nonce[index++] ^= (byte)(chunkIndex >> 8);
        nonce[index] ^= (byte)(chunkIndex);
    }

    /**
     * Calculate an actual chunk length from the encoded chunk size.
     *
     * @param chunkSize encoded chunk size
     * @return decoded length
     */
    protected static long getChunkLength(int chunkSize)
    {
        // RFC 9580 - 5.13.2
        if (chunkSize < 0 || chunkSize > 16)
        {
            throw new IllegalStateException("chunkSize out of range");
        }
        return 1L << (chunkSize + 6);
    }
}
