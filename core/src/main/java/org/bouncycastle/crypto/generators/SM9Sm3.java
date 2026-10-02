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
     * The result is in [1, n-1], so n must be at least 2.
     */
    public static BigInteger h1(byte[] z, BigInteger n)
    {
        return hash((byte)0x01, z, n);
    }

    /**
     * H2(Z, n): hash-to-range with the 0x02 domain prefix (GM/T 0044.2 5.4.2.3).
     * The result is in [1, n-1], so n must be at least 2.
     *
     * @deprecated H2 is used only in signing and verification, which
     * {@link org.bouncycastle.crypto.signers.SM9Signer} now does without this method, hashing the
     * message as it is given rather than taking M || w in one array.
     */
    @Deprecated
    public static BigInteger h2(byte[] z, BigInteger n)
    {
        return hash((byte)0x02, z, n);
    }

    /**
     * The SM9 key derivation function KDF(Z, klen) (GM/T 0044.3/0044.4), a
     * counter-mode construction over SM3 with a 32-bit big-endian counter
     * starting at 1. {@code klenBits} is the requested output length in bits, and must be a
     * positive whole number of bytes.
     * <p>
     * The standard defines the function for any klen, but the output here is a byte array, so a
     * request that is not a whole number of bytes could only be answered by rounding - and
     * rounding up hands back more bits than were asked for while rounding down hands back fewer,
     * silently. A non-positive length has no output at all and used to raise
     * NegativeArraySizeException from the buffer sizing for some negative values. Every in-tree
     * caller passes a positive whole number of bytes.
     */
    public static byte[] kdf(byte[] z, int klenBits)
    {
        if (klenBits <= 0 || (klenBits % 8) != 0)
        {
            throw new IllegalArgumentException("klenBits must be a positive whole number of bytes");
        }
        int klenBytes = klenBits / 8;
        SM3Digest sm3 = new SM3Digest();
        sm3.update(z, 0, z.length);
        byte[] result = new byte[klenBytes];
        counterHash(sm3, result);
        return result;
    }

    private static BigInteger hash(byte prefix, byte[] z, BigInteger n)
    {
        if (n.compareTo(BigInteger.valueOf(2)) < 0)
        {
            // the final step reduces mod n-1 and adds 1, so n < 2 divides by zero or by a negative
            // modulus - a raw ArithmeticException from BigInteger rather than a statement of what
            // was wrong. SM9Curve.N is the only argument any in-tree caller passes.
            throw new IllegalArgumentException("n must be at least 2");
        }
        // hlen = 8 * ceil(5 * log2(n) / 32) bits, with log2 n the logarithm itself rather than n's
        // bit length, which differs from it for some n. The smallest k with 5 * log2(n) <= 32k is
        // the smallest with n^5 <= 2^(32k), and 2^e >= n^5 holds exactly when e is at least the bit
        // length of n^5 - 1; hlen is then 8k bits, which is k bytes.
        int hlenBytes = (n.pow(5).subtract(BigInteger.ONE).bitLength() + 31) / 32;

        SM3Digest sm3 = new SM3Digest();
        sm3.update(prefix);
        sm3.update(z, 0, z.length);
        byte[] ha = new byte[hlenBytes];
        counterHash(sm3, ha);

        // Ha, exactly hlen bits long, interpreted big-endian
        BigInteger h = new BigInteger(1, ha);
        return h.mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    /**
     * Fill out with the first out.length bytes of SM3(X || 1) || SM3(X || 2) || ..., the counter
     * 32 bits big-endian, where X is what sm3 has been given so far. An out that ends part way
     * through an output takes that output's leftmost bytes, as the KDF and H1/H2 take the
     * leftmost bits of their last output.
     * <p>
     * X is the same for every counter, so rather than hash it again for each output, every
     * counter starts from a copy of the state X leaves: an X of many blocks then costs one or two
     * compressions per output instead of one per block of X.
     */
    private static void counterHash(SM3Digest sm3, byte[] out)
    {
        SM3Digest afterX = new SM3Digest(sm3);
        int ct = 1;
        for (int off = 0; off < out.length; off += 32)
        {
            sm3.reset(afterX);
            sm3.update((byte)(ct >>> 24));
            sm3.update((byte)(ct >>> 16));
            sm3.update((byte)(ct >>> 8));
            sm3.update((byte)ct);
            if (out.length - off >= 32)
            {
                sm3.doFinal(out, off);
            }
            else
            {
                // doFinal always writes 32 bytes, so an output wanted only in part goes through a
                // block of its own, erased once the wanted bytes are copied out - the rest of it is
                // output too, and key material in the KDF. Which branch runs depends on the
                // requested length alone, never on X or the output.
                byte[] last = new byte[32];
                sm3.doFinal(last, 0);
                System.arraycopy(last, 0, out, off, out.length - off);
                Arrays.clear(last);
            }
            ++ct;
        }
        // X can be secret, as the KDF's is. The copy holds the chaining value X produced and, in
        // its word buffer, the last words of X; reset() would return the chaining value to the IV
        // but leave the words, so the copy is overwritten from a fresh digest instead. Nothing of
        // X reaches the copy's message schedule, as the copy compresses nothing.
        afterX.reset(new SM3Digest());
    }

    private SM9Sm3()
    {
    }
}
