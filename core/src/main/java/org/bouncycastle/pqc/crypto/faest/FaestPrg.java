package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * AES-CTR pseudo-random generator matching {@code faest-ref/aes.c} {@code prg()}.
 * <p>
 * Layout of the 16-byte counter block:
 * <pre>
 *   [counter (4 LE bytes)][middle (8 bytes)][tweak base (4 LE bytes)]
 * </pre>
 * On entry the IV is copied verbatim, then {@code tweak} is added as a 32-bit
 * little-endian value to the last 4 bytes ({@code add_to_upper_word}). Each
 * AES output block then increments the first 4 bytes ({@code aes_increment_iv})
 * &mdash; the lower 32-bit counter &mdash; while the rest of the block stays
 * fixed. AES key length is selected by {@code lambda}: 128 / 192 / 256 bit.
 * <p>
 * <b>Side-channel note:</b> uses BC's {@link AESEngine}. Each {@code init()}
 * call clones the S-box into a fresh array, which BC documents
 * ({@code AESEngine.java:460}) as introducing enough cache-line noise to
 * defeat standard cache-monitoring attacks on the secret seed material.
 * Replacing this with the in-package bit-serial {@link FaestAES#encrypt} was
 * measured at &gt;700&times; slower because the PRG is called thousands of
 * times during BAVC/VOLE tree expansion; the cache-clone mitigation is
 * preferred.
 * <p>
 * faest-ref source of truth: {@code prg}, aes.c:307.
 */
final class FaestPrg
{
    private FaestPrg()
    {
    }

    /**
     * Run AES-CTR with key {@code key[keyOff..keyOff+lambda/8]} starting at
     * counter {@code iv + tweak (in upper word)}, producing {@code outLen}
     * bytes into {@code out[outOff..]}.
     */
    static void prg(byte[] key, int keyOff,
                    byte[] iv, int ivOff, long tweak, int lambda,
                    byte[] out, int outOff, int outLen)
    {
        byte[] ctr = new byte[FaestParameters.IV_SIZE];
        System.arraycopy(iv, ivOff, ctr, 0, FaestParameters.IV_SIZE);
        addToUpperWord(ctr, tweak);

        byte[] aesKey = new byte[lambda / 8];
        System.arraycopy(key, keyOff, aesKey, 0, lambda / 8);

        AESEngine aes = new AESEngine();
        aes.init(true, new KeyParameter(aesKey));

        byte[] block = new byte[16];
        int produced = 0;
        while (produced + 16 <= outLen)
        {
            aes.processBlock(ctr, 0, out, outOff + produced);
            produced += 16;
            incrementLow32(ctr);
        }
        if (produced < outLen)
        {
            aes.processBlock(ctr, 0, block, 0);
            System.arraycopy(block, 0, out, outOff + produced, outLen - produced);
        }
    }

    /**
     * Add {@code tweak} (treated as unsigned 32-bit) to the last 4 bytes of
     * {@code iv} interpreted little-endian. faest-ref: aes.c:300.
     */
    private static void addToUpperWord(byte[] iv, long tweak)
    {
        int off = FaestParameters.IV_SIZE - 4;
        int v = (iv[off] & 0xff)
              | ((iv[off + 1] & 0xff) << 8)
              | ((iv[off + 2] & 0xff) << 16)
              | ((iv[off + 3] & 0xff) << 24);
        v = (int)(v + tweak);
        iv[off]     = (byte)v;
        iv[off + 1] = (byte)(v >>> 8);
        iv[off + 2] = (byte)(v >>> 16);
        iv[off + 3] = (byte)(v >>> 24);
    }

    /**
     * Increment the first 4 bytes of {@code iv} treated as a little-endian
     * 32-bit counter. faest-ref: aes.c:51.
     */
    private static void incrementLow32(byte[] iv)
    {
        int v = (iv[0] & 0xff)
              | ((iv[1] & 0xff) << 8)
              | ((iv[2] & 0xff) << 16)
              | ((iv[3] & 0xff) << 24);
        v++;
        iv[0] = (byte)v;
        iv[1] = (byte)(v >>> 8);
        iv[2] = (byte)(v >>> 16);
        iv[3] = (byte)(v >>> 24);
    }
}
