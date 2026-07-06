package org.bouncycastle.pqc.crypto.faest;

/**
 * One-way functions for FAEST v2.0.
 * <p>
 * In FAEST keygen, the public key is {@code (input, output)} where
 * {@code output = OWF(key, input)}. The signer proves knowledge of {@code key}
 * via the VOLE-AES proof system without revealing it; the verifier checks the
 * proof against the published {@code (input, output)} pair.
 * <p>
 * Two flavours, six concrete OWFs:
 * <ul>
 *   <li><b>FAEST</b> (key-keyed AES): {@code output = AES<lambda>(key).encrypt(input)}.
 *       For 192- and 256-bit security, two blocks are produced &mdash; the second uses
 *       {@code input XOR (0x01 at byte 0)} as plaintext &mdash; so the output absorbs
 *       the full {@code lambda} bits.</li>
 *   <li><b>FAEST-EM</b> (Even-Mansour): {@code output = AES<lambda>(input).encrypt(key) XOR key}.
 *       The roles of key and plaintext are swapped, and the output is XORed with
 *       the input key &mdash; the canonical EM construction. For lambda=192,256
 *       Rijndael with matching block size is used.</li>
 * </ul>
 * <p>
 * faest-ref source of truth: {@code owf.c}.
 */
final class Owf
{
    private Owf()
    {
    }

    /** {@code output[0..16] = AES-128(key).encrypt(input)}. */
    static void owf128(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        FaestAES.aes128EncryptBlock(key, keyOff, in, inOff, out, outOff);
    }

    /**
     * {@code output[0..16] = AES-192(key).encrypt(input)};
     * {@code output[16..32] = AES-192(key).encrypt(input XOR 0x01-at-byte-0)}.
     * Two blocks to fit the 192-bit OWF output width.
     */
    static void owf192(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        FaestAES.aes192EncryptBlock(key, keyOff, in, inOff, out, outOff);
        byte[] buf = new byte[16];
        System.arraycopy(in, inOff, buf, 0, 16);
        buf[0] ^= 0x01;
        FaestAES.aes192EncryptBlock(key, keyOff, buf, 0, out, outOff + 16);
    }

    /** Same shape as {@link #owf192} but with AES-256. */
    static void owf256(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        FaestAES.aes256EncryptBlock(key, keyOff, in, inOff, out, outOff);
        byte[] buf = new byte[16];
        System.arraycopy(in, inOff, buf, 0, 16);
        buf[0] ^= 0x01;
        FaestAES.aes256EncryptBlock(key, keyOff, buf, 0, out, outOff + 16);
    }

    /** EM-128: {@code output = AES-128(input).encrypt(key) XOR key} (16 bytes). */
    static void owfEm128(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        FaestAES.aes128EncryptBlock(in, inOff, key, keyOff, out, outOff);
        for (int i = 0; i < 16; i++)
        {
            out[outOff + i] = (byte)((out[outOff + i] & 0xff) ^ (key[keyOff + i] & 0xff));
        }
    }

    /** EM-192: {@code output = Rijndael-192(input).encrypt(key) XOR key} (24 bytes). */
    static void owfEm192(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        FaestAES.rijndael192EncryptBlock(in, inOff, key, keyOff, out, outOff);
        for (int i = 0; i < 24; i++)
        {
            out[outOff + i] = (byte)((out[outOff + i] & 0xff) ^ (key[keyOff + i] & 0xff));
        }
    }

    /** EM-256: {@code output = Rijndael-256(input).encrypt(key) XOR key} (32 bytes). */
    static void owfEm256(byte[] key, int keyOff, byte[] in, int inOff, byte[] out, int outOff)
    {
        FaestAES.rijndael256EncryptBlock(in, inOff, key, keyOff, out, outOff);
        for (int i = 0; i < 32; i++)
        {
            out[outOff + i] = (byte)((out[outOff + i] & 0xff) ^ (key[keyOff + i] & 0xff));
        }
    }
}
