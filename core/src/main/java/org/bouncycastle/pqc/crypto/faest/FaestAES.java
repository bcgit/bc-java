package org.bouncycastle.pqc.crypto.faest;

/**
 * Compute-S-box AES / Rijndael for FAEST v2.0.
 * <p>
 * Handles three block sizes:
 * <ul>
 *   <li>4 words (16 bytes): standard AES &mdash; key sizes 128, 192, 256 bits.</li>
 *   <li>6 words (24 bytes): Rijndael-192 &mdash; FAEST-EM-192 OWF.</li>
 *   <li>8 words (32 bytes): Rijndael-256 &mdash; FAEST-EM-256 OWF.</li>
 * </ul>
 * The number of rounds follows the spec: 10 for 128-bit, 12 for 192-bit,
 * 14 for 256-bit (where the parameter is the larger of key bits and block bits).
 * <p>
 * Implementation is bit-serial constant-time: the S-box uses {@link BF8#inv}
 * plus an affine combination of {@link BF8#parity} terms rather than a
 * lookup table. The MixColumns multiplies use {@link BF8#mul} for the
 * {@code ×02} / {@code ×03} fixed constants. No data-dependent
 * memory access on any secret-influenced value.
 * <p>
 * State layout (matching the C reference): byte array of length
 * {@code blockWords * 4}, indexed as {@code state[c * 4 + r]} (column-major,
 * each AES column is four consecutive bytes).
 * <p>
 * faest-ref source of truth: {@code aes.c}.
 */
final class FaestAES
{
    /** AES round constants. faest-ref: aes.c:32. */
    private static final int[] ROUND_CONSTANTS =
        {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
        };

    /** Bytes per AES word (one column). */
    static final int AES_NR = 4;

    static final int AES_BLOCK_WORDS = 4;
    static final int RIJNDAEL_BLOCK_WORDS_192 = 6;
    static final int RIJNDAEL_BLOCK_WORDS_256 = 8;

    static final int KEY_WORDS_128 = 4;
    static final int KEY_WORDS_192 = 6;
    static final int KEY_WORDS_256 = 8;

    static final int ROUNDS_128 = 10;
    static final int ROUNDS_192 = 12;
    static final int ROUNDS_256 = 14;

    static final int MAX_ROUNDS = 14;

    private FaestAES()
    {
    }

    /**
     * Compute one AES S-box value: {@code SubBytes(x) = A * inv(x) + b}.
     * faest-ref: {@code compute_sbox}, aes.c:37.
     */
    static int sbox(int in)
    {
        int t = BF8.inv(in);
        int t0 = 0;
        t0 ^= BF8.parity(t & 0xF1) << 0;   // bits 0,4,5,6,7
        t0 ^= BF8.parity(t & 0xE3) << 1;   // bits 0,1,5,6,7
        t0 ^= BF8.parity(t & 0xC7) << 2;   // bits 0,1,2,6,7
        t0 ^= BF8.parity(t & 0x8F) << 3;   // bits 0,1,2,3,7
        t0 ^= BF8.parity(t & 0x1F) << 4;   // bits 0,1,2,3,4
        t0 ^= BF8.parity(t & 0x3E) << 5;   // bits 1,2,3,4,5
        t0 ^= BF8.parity(t & 0x7C) << 6;   // bits 2,3,4,5,6
        t0 ^= BF8.parity(t & 0xF8) << 7;   // bits 3,4,5,6,7
        return (t0 ^ 0x63) & 0xff;
    }

    /**
     * Expand {@code key[keyOff..keyOff + keyWords*4]} into {@code (numRounds+1)*blockWords*4}
     * round-key bytes. {@code roundKeys[r*blockWords*4 + c*4 + i]} is byte {@code i}
     * of column {@code c} in round {@code r}'s key.
     * faest-ref: {@code expand_key}, aes.c:139.
     */
    static void expandKey(byte[] roundKeys, byte[] key, int keyOff,
                          int keyWords, int blockWords, int numRounds)
    {
        // Step 1: copy the key into the first keyWords columns of the schedule.
        for (int k = 0; k < keyWords; k++)
        {
            int rkIdx = (k / blockWords) * blockWords * 4 + (k % blockWords) * 4;
            roundKeys[rkIdx]     = key[keyOff + 4 * k];
            roundKeys[rkIdx + 1] = key[keyOff + 4 * k + 1];
            roundKeys[rkIdx + 2] = key[keyOff + 4 * k + 2];
            roundKeys[rkIdx + 3] = key[keyOff + 4 * k + 3];
        }

        // Step 2: extend.
        int totalWords = blockWords * (numRounds + 1);
        int[] tmp = new int[4];
        for (int k = keyWords; k < totalWords; k++)
        {
            int prevIdx = ((k - 1) / blockWords) * blockWords * 4 + ((k - 1) % blockWords) * 4;
            tmp[0] = roundKeys[prevIdx]     & 0xff;
            tmp[1] = roundKeys[prevIdx + 1] & 0xff;
            tmp[2] = roundKeys[prevIdx + 2] & 0xff;
            tmp[3] = roundKeys[prevIdx + 3] & 0xff;

            if (k % keyWords == 0)
            {
                // rot_word
                int t = tmp[0];
                tmp[0] = tmp[1];
                tmp[1] = tmp[2];
                tmp[2] = tmp[3];
                tmp[3] = t;
                // sub_words
                tmp[0] = sbox(tmp[0]);
                tmp[1] = sbox(tmp[1]);
                tmp[2] = sbox(tmp[2]);
                tmp[3] = sbox(tmp[3]);
                tmp[0] ^= ROUND_CONSTANTS[(k / keyWords) - 1];
            }

            if (keyWords > 6 && (k % keyWords) == 4)
            {
                tmp[0] = sbox(tmp[0]);
                tmp[1] = sbox(tmp[1]);
                tmp[2] = sbox(tmp[2]);
                tmp[3] = sbox(tmp[3]);
            }

            int m = k - keyWords;
            int mIdx = (m / blockWords) * blockWords * 4 + (m % blockWords) * 4;
            int kIdx = (k / blockWords) * blockWords * 4 + (k % blockWords) * 4;

            roundKeys[kIdx]     = (byte)((roundKeys[mIdx]     & 0xff) ^ tmp[0]);
            roundKeys[kIdx + 1] = (byte)((roundKeys[mIdx + 1] & 0xff) ^ tmp[1]);
            roundKeys[kIdx + 2] = (byte)((roundKeys[mIdx + 2] & 0xff) ^ tmp[2]);
            roundKeys[kIdx + 3] = (byte)((roundKeys[mIdx + 3] & 0xff) ^ tmp[3]);
        }
    }

    /** AES round: SubBytes + ShiftRows + MixColumns + AddRoundKey for rounds 1..numRounds-1,
     *  then SubBytes + ShiftRows + AddRoundKey for the final round.
     *  faest-ref: {@code aes_encrypt}, aes.c:242. */
    static void encrypt(byte[] state, byte[] roundKeys, int blockWords, int numRounds)
    {
        addRoundKey(state, roundKeys, 0, blockWords);
        for (int round = 1; round < numRounds; ++round)
        {
            subBytes(state, blockWords);
            shiftRow(state, blockWords);
            mixColumn(state, blockWords);
            addRoundKey(state, roundKeys, round, blockWords);
        }
        subBytes(state, blockWords);
        shiftRow(state, blockWords);
        addRoundKey(state, roundKeys, numRounds, blockWords);
    }

    static void addRoundKey(byte[] state, byte[] roundKeys, int round, int blockWords)
    {
        int base = round * blockWords * 4;
        for (int i = 0; i < blockWords * 4; i++)
        {
            state[i] = (byte)((state[i] & 0xff) ^ (roundKeys[base + i] & 0xff));
        }
    }

    static void subBytes(byte[] state, int blockWords)
    {
        for (int i = 0; i < blockWords * 4; i++)
        {
            state[i] = (byte)sbox(state[i] & 0xff);
        }
    }

    /**
     * ShiftRows with the block-size-dependent offsets per Rijndael spec.
     * faest-ref: {@code shift_row}, aes.c:79.
     */
    static void shiftRow(byte[] state, int blockWords)
    {
        byte[] next = new byte[blockWords * 4];
        if (blockWords == 4 || blockWords == 6)
        {
            for (int i = 0; i < blockWords; ++i)
            {
                next[i * 4]     = state[i * 4];
                next[i * 4 + 1] = state[((i + 1) % blockWords) * 4 + 1];
                next[i * 4 + 2] = state[((i + 2) % blockWords) * 4 + 2];
                next[i * 4 + 3] = state[((i + 3) % blockWords) * 4 + 3];
            }
        }
        else // blockWords == 8
        {
            for (int i = 0; i < blockWords; ++i)
            {
                next[i * 4]     = state[i * 4];
                next[i * 4 + 1] = state[((i + 1) % 8) * 4 + 1];
                next[i * 4 + 2] = state[((i + 3) % 8) * 4 + 2];
                next[i * 4 + 3] = state[((i + 4) % 8) * 4 + 3];
            }
        }
        System.arraycopy(next, 0, state, 0, blockWords * 4);
    }

    /** MixColumns. faest-ref: {@code mix_column}, aes.c:106. */
    static void mixColumn(byte[] state, int blockWords)
    {
        for (int c = 0; c < blockWords; c++)
        {
            int s0 = state[c * 4]     & 0xff;
            int s1 = state[c * 4 + 1] & 0xff;
            int s2 = state[c * 4 + 2] & 0xff;
            int s3 = state[c * 4 + 3] & 0xff;
            int t0 = BF8.mul(s0, 0x02) ^ BF8.mul(s1, 0x03) ^ s2                ^ s3;
            int t1 = s0                ^ BF8.mul(s1, 0x02) ^ BF8.mul(s2, 0x03) ^ s3;
            int t2 = s0                ^ s1                ^ BF8.mul(s2, 0x02) ^ BF8.mul(s3, 0x03);
            int t3 = BF8.mul(s0, 0x03) ^ s1                ^ s2                ^ BF8.mul(s3, 0x02);
            state[c * 4]     = (byte)t0;
            state[c * 4 + 1] = (byte)t1;
            state[c * 4 + 2] = (byte)t2;
            state[c * 4 + 3] = (byte)t3;
        }
    }

    /**
     * Compute the FAEST {@code invnorm} of one byte: extract bits 0, 6, 7, 2 of
     * {@code inv(x)^17} and pack them into a 4-bit nibble. Used by the witness
     * extension's odd-round saves. faest-ref: {@code invnorm}, aes.c:207.
     */
    static int invnorm(int in)
    {
        int xInv = BF8.inv(in);
        int x17 = xInv;
        for (int i = 0; i < 4; i++)
        {
            x17 = BF8.square(x17);
        }
        x17 = BF8.mul(x17, xInv);
        int y = 0;
        y |= ((x17 >>> 0) & 1) << 0;
        y |= ((x17 >>> 6) & 1) << 1;
        y |= ((x17 >>> 7) & 1) << 2;
        y |= ((x17 >>> 2) & 1) << 3;
        return y;
    }

    /**
     * Pack {@code invnorm} nibbles of consecutive byte pairs of {@code state}
     * into {@code dst}, returning the byte count written ({@code blockWords * 2}).
     * faest-ref: {@code store_invnorm_state}, aes.c:226.
     */
    static int storeInvnormState(byte[] dst, int dstOff, byte[] state, int blockWords)
    {
        int written = 0;
        for (int i = 0; i < blockWords * 4; i += 2, ++written)
        {
            int lo = invnorm(state[i] & 0xff);
            int hi = invnorm(state[i + 1] & 0xff);
            dst[dstOff + written] = (byte)((hi << 4) | lo);
        }
        return written;
    }

    /** Copy the raw state bytes into {@code dst}, returning bytes written. */
    static int storeState(byte[] dst, int dstOff, byte[] state, int blockWords)
    {
        int len = blockWords * 4;
        System.arraycopy(state, 0, dst, dstOff, len);
        return len;
    }

    // ----- Convenience wrappers matching the upstream aesX_encrypt_block / rijndaelX_encrypt_block. -----

    /** Encrypt a 16-byte block under an AES-128 key. */
    static void aes128EncryptBlock(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        byte[] rk = new byte[(ROUNDS_128 + 1) * AES_BLOCK_WORDS * 4];
        expandKey(rk, key, keyOff, KEY_WORDS_128, AES_BLOCK_WORDS, ROUNDS_128);
        byte[] state = new byte[AES_BLOCK_WORDS * 4];
        System.arraycopy(in, inOff, state, 0, AES_BLOCK_WORDS * 4);
        encrypt(state, rk, AES_BLOCK_WORDS, ROUNDS_128);
        System.arraycopy(state, 0, out, outOff, AES_BLOCK_WORDS * 4);
    }

    /** Encrypt a 16-byte block under an AES-192 key. */
    static void aes192EncryptBlock(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        byte[] rk = new byte[(ROUNDS_192 + 1) * AES_BLOCK_WORDS * 4];
        expandKey(rk, key, keyOff, KEY_WORDS_192, AES_BLOCK_WORDS, ROUNDS_192);
        byte[] state = new byte[AES_BLOCK_WORDS * 4];
        System.arraycopy(in, inOff, state, 0, AES_BLOCK_WORDS * 4);
        encrypt(state, rk, AES_BLOCK_WORDS, ROUNDS_192);
        System.arraycopy(state, 0, out, outOff, AES_BLOCK_WORDS * 4);
    }

    /** Encrypt a 16-byte block under an AES-256 key. */
    static void aes256EncryptBlock(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        byte[] rk = new byte[(ROUNDS_256 + 1) * AES_BLOCK_WORDS * 4];
        expandKey(rk, key, keyOff, KEY_WORDS_256, AES_BLOCK_WORDS, ROUNDS_256);
        byte[] state = new byte[AES_BLOCK_WORDS * 4];
        System.arraycopy(in, inOff, state, 0, AES_BLOCK_WORDS * 4);
        encrypt(state, rk, AES_BLOCK_WORDS, ROUNDS_256);
        System.arraycopy(state, 0, out, outOff, AES_BLOCK_WORDS * 4);
    }

    /** Encrypt a 24-byte Rijndael-192 block under a 192-bit key. */
    static void rijndael192EncryptBlock(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        byte[] rk = new byte[(ROUNDS_192 + 1) * RIJNDAEL_BLOCK_WORDS_192 * 4];
        expandKey(rk, key, keyOff, KEY_WORDS_192, RIJNDAEL_BLOCK_WORDS_192, ROUNDS_192);
        byte[] state = new byte[RIJNDAEL_BLOCK_WORDS_192 * 4];
        System.arraycopy(in, inOff, state, 0, RIJNDAEL_BLOCK_WORDS_192 * 4);
        encrypt(state, rk, RIJNDAEL_BLOCK_WORDS_192, ROUNDS_192);
        System.arraycopy(state, 0, out, outOff, RIJNDAEL_BLOCK_WORDS_192 * 4);
    }

    /** Encrypt a 32-byte Rijndael-256 block under a 256-bit key. */
    static void rijndael256EncryptBlock(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        byte[] rk = new byte[(ROUNDS_256 + 1) * RIJNDAEL_BLOCK_WORDS_256 * 4];
        expandKey(rk, key, keyOff, KEY_WORDS_256, RIJNDAEL_BLOCK_WORDS_256, ROUNDS_256);
        byte[] state = new byte[RIJNDAEL_BLOCK_WORDS_256 * 4];
        System.arraycopy(in, inOff, state, 0, RIJNDAEL_BLOCK_WORDS_256 * 4);
        encrypt(state, rk, RIJNDAEL_BLOCK_WORDS_256, ROUNDS_256);
        System.arraycopy(state, 0, out, outOff, RIJNDAEL_BLOCK_WORDS_256 * 4);
    }
}
