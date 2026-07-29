package org.bouncycastle.crypto.generators;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.Arrays;

/**
 * The shared SM3-based auxiliary functions of SM9 (GM/T 0044-2016): the
 * cryptographic functions H1 and H2 that map a byte string to an integer in
 * [1, n-1] (GM/T 0044.2, 5.4), and the key derivation function KDF
 * (GM/T 0044.3/0044.4). H_v is SM3 (256-bit output).
 */
public class SM9Sm3
{
    /**
     * H1(Z, n): hash-to-range with the 0x01 domain prefix (GM/T 0044.2 5.4.2.2).
     */
    public static BigInteger h1(byte[] z, BigInteger n)
    {
        return hash((byte)0x01, z, n);
    }

    /**
     * H2(Z, n): hash-to-range with the 0x02 domain prefix (GM/T 0044.2 5.4.2.3).
     */
    public static BigInteger h2(byte[] z, BigInteger n)
    {
        return hash((byte)0x02, z, n);
    }

    /**
     * The SM9 key derivation function KDF(Z, klen) (GM/T 0044.3/0044.4), a
     * counter-mode construction over SM3 with a 32-bit big-endian counter
     * starting at 1. {@code klenBits} is the requested output length in bits.
     */
    public static byte[] kdf(byte[] z, int klenBits)
    {
        int klenBytes = (klenBits + 7) / 8;
        SM3Digest sm3 = new SM3Digest();
        byte[] out = new byte[((klenBytes + 31) / 32) * 32];
        byte[] block = new byte[32];
        int ct = 1;
        for (int off = 0; off < out.length; off += 32)
        {
            sm3.update(z, 0, z.length);
            sm3.update((byte)(ct >>> 24));
            sm3.update((byte)(ct >>> 16));
            sm3.update((byte)(ct >>> 8));
            sm3.update((byte)ct);
            sm3.doFinal(block, 0);
            System.arraycopy(block, 0, out, off, 32);
            ++ct;
        }
        return Arrays.copyOf(out, klenBytes);
    }

    private static BigInteger hash(byte prefix, byte[] z, BigInteger n)
    {
        // hlen = 8 * ceil(5 * ceil(log2 n) / 32) bits; n prime => ceil(log2 n) = bitLength
        int hlenBits = 8 * ((5 * n.bitLength() + 31) / 32);
        int hlenBytes = hlenBits / 8;

        SM3Digest sm3 = new SM3Digest();
        byte[] ha = new byte[((hlenBytes + 31) / 32) * 32];
        byte[] block = new byte[32];
        int ct = 1;
        for (int off = 0; off < ha.length; off += 32)
        {
            sm3.update(prefix);
            sm3.update(z, 0, z.length);
            sm3.update((byte)(ct >>> 24));
            sm3.update((byte)(ct >>> 16));
            sm3.update((byte)(ct >>> 8));
            sm3.update((byte)ct);
            sm3.doFinal(block, 0);
            System.arraycopy(block, 0, ha, off, 32);
            ++ct;
        }

        // leftmost hlenBytes of Ha, interpreted big-endian
        BigInteger h = new BigInteger(1, Arrays.copyOf(ha, hlenBytes));
        return h.mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    private SM9Sm3()
    {
    }
}
