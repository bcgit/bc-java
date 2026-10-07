package org.bouncycastle.util;

/**
 * Utility methods for converting byte arrays into ints and longs, and back again.
 * <p>
 * This is the JDK 23+ copy (META-INF/versions/23) of src/main/java's Pack and differs from it only in
 * longToLittleEndian(long, byte[], int), which here writes the eight bytes of the long directly: C2 merges those
 * stores into one from JDK 23 (JDK-8318446), while on earlier JDKs the form costs more than the base class's two
 * intToLittleEndian() calls. Keep the two copies in step.
 */
public abstract class Pack
{
    public static short bigEndianToShort(byte[] bs, int off)
    {
        int n = (bs[off] & 0xff) << 8;
        n |= (bs[++off] & 0xff);
        return (short)n;
    }

    public static int bigEndianToInt(byte[] bs, int off)
    {
        int n = bs[off] << 24;
        n |= (bs[++off] & 0xff) << 16;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff);
        return n;
    }

    public static void bigEndianToInt(byte[] bs, int off, int[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = bigEndianToInt(bs, off);
            off += 4;
        }
    }

    public static void bigEndianToInt(byte[] bs, int off, int[] ns, int nsOff, int nsLen)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            ns[nsOff + i] = bigEndianToInt(bs, off);
            off += 4;
        }
    }

    public static int bigEndianToInt_High(byte[] bs, int off, int len)
    {
        return bigEndianToInt_Low(bs, off, len) << ((4 - len) << 3);
    }

    public static int bigEndianToInt_Low(byte[] bs, int off, int len)
    {
//        assert 1 <= len && len <= 4;

        int result = bs[off] & 0xFF;
        for (int i = 1; i < len; ++i)
        {
            result <<= 8;
            result |= bs[off + i] & 0xFF;
        }
        return result;
    }

    public static byte[] intToBigEndian(int n)
    {
        byte[] bs = new byte[4];
        intToBigEndian(n, bs, 0);
        return bs;
    }

    public static void intToBigEndian(int n, byte[] bs)
    {
        bs[0] = (byte)(n >>> 24);
        bs[1] = (byte)(n >>> 16);
        bs[2] = (byte)(n >>> 8);
        bs[3] = (byte)(n);
    }

    public static void intToBigEndian(int n, byte[] bs, int off)
    {
        bs[off] = (byte)(n >>> 24);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n);
    }

    public static byte[] intToBigEndian(int[] ns)
    {
        byte[] bs = new byte[4 * ns.length];
        intToBigEndian(ns, bs, 0);
        return bs;
    }

    public static void intToBigEndian(int[] ns, byte[] bs, int off)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            intToBigEndian(ns[i], bs, off);
            off += 4;
        }
    }

    public static void intToBigEndian(int[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            intToBigEndian(ns[nsOff + i], bs, bsOff);
            bsOff += 4;
        }
    }

    public static void intToBigEndian_High(int n, byte[] bs, int off, int len)
    {
//        assert 1 <= len && len <= 4;

        int pos = 24;
        bs[off] = (byte)(n >>> pos);
        for (int i = 1; i < len; ++i)
        {
            pos -= 8;
            bs[off + i] = (byte)(n >>> pos);
        }
    }

    public static void intToBigEndian_Low(int n, byte[] bs, int off, int len)
    {
        intToBigEndian_High(n << ((4 - len) << 3), bs, off, len);
    }

    public static long bigEndianToLong(byte[] bs, int off)
    {
        int hi = bigEndianToInt(bs, off);
        int lo = bigEndianToInt(bs, off + 4);
        return ((long)(hi & 0xffffffffL) << 32) | (long)(lo & 0xffffffffL);
    }

    public static void bigEndianToLong(byte[] bs, int off, long[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = bigEndianToLong(bs, off);
            off += 8;
        }
    }

    public static void bigEndianToLong(byte[] bs, int bsOff, long[] ns, int nsOff, int nsLen)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            ns[nsOff + i] = bigEndianToLong(bs, bsOff);
            bsOff += 8;
        }
    }

    public static long bigEndianToLong_High(byte[] bs, int off, int len)
    {
        return bigEndianToLong_Low(bs, off, len) << ((8 - len) << 3);
    }

    /**
     * Reads the <code>len</code> bytes at <code>bs[off]</code> as a big-endian value and returns it
     * in the low <code>len</code> bytes of the result: a <code>len</code> of 3 returns what
     * {@link #bigEndianToLong(byte[], int)} would return for those three bytes preceded by five
     * zero ones.
     * <p>
     * It is the read side of {@link #longToBigEndian_Low(long, byte[], int, int)} and carries the
     * same unenforced 1..8 bound, for a related reason: the first byte is read ahead of the loop,
     * so a <code>len</code> of 0 reads one byte anyway and returns it rather than returning zero,
     * and a <code>len</code> above 8 goes on shifting and so yields the last eight bytes read
     * rather than the first. The callers here are the XMSS ones reading back RFC 8391's
     * toByte(x, y): the index field of a stored private key, in {@code XMSSPrivateKeyCodec}, which
     * is the one codec both families' keys are decoded through, and the index field of an XMSS^MT
     * signature in {@code XMSSMTSignature}. Each passes the constant 4 or ceil(h/8) for a height
     * its parameter class holds to 2..62, so both are inside the bound already, as are the reads
     * the package's own tests make with the same two lengths.
     */
    public static long bigEndianToLong_Low(byte[] bs, int off, int len)
    {
//        assert 1 <= len && len <= 8;

        long result = bs[off] & 0xFFL;
        for (int i = 1; i < len; ++i)
        {
            result <<= 8;
            result |= bs[off + i] & 0xFFL;
        }
        return result;
    }

    public static byte[] longToBigEndian(long n)
    {
        byte[] bs = new byte[8];
        longToBigEndian(n, bs, 0);
        return bs;
    }

    public static void longToBigEndian(long n, byte[] bs, int off)
    {
        // eight stores of the one long, which C2 merges into a single byte-swapped store on JDK 25 (JDK 23 does not)
        bs[off] = (byte)(n >>> 56);
        bs[++off] = (byte)(n >>> 48);
        bs[++off] = (byte)(n >>> 40);
        bs[++off] = (byte)(n >>> 32);
        bs[++off] = (byte)(n >>> 24);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n);
    }

    public static byte[] longToBigEndian(long[] ns)
    {
        byte[] bs = new byte[8 * ns.length];
        longToBigEndian(ns, bs, 0);
        return bs;
    }

    public static void longToBigEndian(long[] ns, byte[] bs, int off)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            longToBigEndian(ns[i], bs, off);
            off += 8;
        }
    }

    public static void longToBigEndian(long[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            longToBigEndian(ns[nsOff + i], bs, bsOff);
            bsOff += 8;
        }
    }

    /**
     * Writes the most significant <code>len</code> bytes of <code>n</code> to <code>bs</code> at
     * <code>off</code>, in big-endian order: a <code>len</code> of 3 writes the three bytes
     * {@link #longToBigEndian(long, byte[], int)} would put at <code>bs[off]</code> to
     * <code>bs[off + 2]</code>, and drops the other five.
     * <p>
     * It is the write side of {@link #bigEndianToLong_High(byte[], int, int)}. The pair is shaped
     * for the short final block of a big-endian sponge, where the bytes the block has occupy the
     * top of the rate word and the remainder of that word is padding - so both conversions work
     * against the high end of the word rather than the low one. The callers are the Ascon v1.2
     * classes ({@link org.bouncycastle.crypto.engines.AsconEngine},
     * {@link org.bouncycastle.crypto.digests.AsconDigest},
     * {@link org.bouncycastle.crypto.digests.AsconXof}), all three now deprecated: final Ascon is
     * little-endian and goes through {@link #longToLittleEndian_Low(long, byte[], int, int)}.
     * <p>
     * <code>len</code> must be 1..8, and nothing enforces it. The first store sits ahead of the
     * loop, so a <code>len</code> of 0 writes one byte anyway - <code>n</code>'s top one - and
     * throws <code>ArrayIndexOutOfBoundsException</code> where the array has no room for it; and
     * because Java takes a shift distance mod 64, a <code>len</code> above 8 wraps round and
     * repeats <code>n</code>'s bytes rather than running to zero. Callers whose length can reach 0
     * guard the call themselves.
     */
    public static void longToBigEndian_High(long n, byte[] bs, int off, int len)
    {
//        assert 1 <= len && len <= 8;

        int pos = 56;
        bs[off] = (byte)(n >>> pos);
        for (int i = 1; i < len; ++i)
        {
            pos -= 8;
            bs[off + i] = (byte)(n >>> pos);
        }
    }

    /**
     * Writes the least significant <code>len</code> bytes of <code>n</code> to <code>bs</code> at
     * <code>off</code>, in big-endian order: a <code>len</code> of 3 writes the three bytes
     * {@link #longToBigEndian(long, byte[], int)} would put at <code>bs[off + 5]</code> to
     * <code>bs[off + 7]</code>, and drops the other five.
     * <p>
     * It is {@link #longToBigEndian_High(long, byte[], int, int)} applied to <code>n</code>
     * shifted up past the bytes being dropped, the write side of
     * {@link #bigEndianToLong_Low(byte[], int, int)}, and it carries the same unenforced 1..8
     * bound for the same reason. It is the low-end counterpart of the _High pair the Ascon v1.2
     * classes use; its callers here are the XMSS ones building RFC 8391's toByte(x, y), which pads
     * left of the eight bytes rather than absorbing into the top of a word, so it wants the low
     * end. Two of the five pass a length that is not a constant, and both are inside the bound
     * because they say so: {@code XMSSUtil.toBytesBigEndian}, whose size is its caller's argument,
     * and {@code XMSSEngine}'s H_msg key, whose length is the security parameter, each taking a
     * min() with 8. The other three are inside it by construction - the index field of a stored
     * private key in {@code XMSSPrivateKeyCodec} and of an XMSS^MT signature in
     * {@code XMSSMTSignature}, both 4 or ceil(h/8), and {@code WOTSPlus}'s PRF index at the
     * constant 8.
     */
    public static void longToBigEndian_Low(long n, byte[] bs, int off, int len)
    {
        longToBigEndian_High(n << ((8 - len) << 3), bs, off, len);
    }

    public static short littleEndianToShort(byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        return (short)n;
    }

    public static void littleEndianToShort(byte[] bs, int bOff, short[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = littleEndianToShort(bs, bOff);
            bOff += 2;
        }
    }

    public static void littleEndianToShort(byte[] bs, int bOff, short[] ns, int nOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            ns[nOff + i] = littleEndianToShort(bs, bOff);
            bOff += 2;
        }
    }

    public static short[] littleEndianToShort(byte[] bs, int off, int count)
    {
        short[] ns = new short[count];
        littleEndianToShort(bs, off, ns, 0, count);
        return ns;
    }

    public static int littleEndianToInt24(byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        return n;
    }

    public static int littleEndianToInt(byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    public static int littleEndianToInt_High(byte[] bs, int off, int len)
    {
        return littleEndianToInt_Low(bs, off, len) << ((4 - len) << 3);
    }

    public static int littleEndianToInt_Low(byte[] bs, int off, int len)
    {
//        assert 1 <= len && len <= 4;

        int result = bs[off] & 0xff;
        int pos = 0;
        for (int i = 1; i < len; ++i)
        {
            pos += 8;
            result |= (bs[off + i] & 0xff) << pos;
        }
        return result;
    }

    public static void littleEndianToInt(byte[] bs, int off, int[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = littleEndianToInt(bs, off);
            off += 4;
        }
    }

    public static void littleEndianToInt(byte[] bs, int bOff, int[] ns, int nOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            ns[nOff + i] = littleEndianToInt(bs, bOff);
            bOff += 4;
        }
    }

    public static int[] littleEndianToInt(byte[] bs, int off, int count)
    {
        int[] ns = new int[count];
        littleEndianToInt(bs, off, ns);
        return ns;
    }

    public static byte[] shortToLittleEndian(short n)
    {
        byte[] bs = new byte[2];
        shortToLittleEndian(n, bs, 0);
        return bs;
    }

    public static void shortToLittleEndian(short n, byte[] bs, int off)
    {
        bs[off] = (byte)(n);
        bs[++off] = (byte)(n >>> 8);
    }

    public static void shortToLittleEndian(short[] ns, byte[] bs, int bsOff)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            shortToLittleEndian(ns[i], bs, bsOff);
            bsOff += 2;
        }
    }

    public static void shortToLittleEndian(short[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            shortToLittleEndian(ns[nsOff + i], bs, bsOff);
            bsOff += 2;
        }
    }

    public static byte[] shortToLittleEndian(short[] ns)
    {
        byte[] bs = new byte[ns.length<<1];
        int bsOff = 0;
        for (int i = 0; i < ns.length; ++i)
        {
            shortToLittleEndian(ns[i], bs, bsOff);
            bsOff += 2;
        }
        return bs;
    }

    public static byte[] shortToBigEndian(short n)
    {
        byte[] r = new byte[2];
        shortToBigEndian(n, r, 0);
        return r;
    }

    public static void shortToBigEndian(short n, byte[] bs, int off)
    {
        bs[off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n);
    }

    public static byte[] intToLittleEndian(int n)
    {
        byte[] bs = new byte[4];
        intToLittleEndian(n, bs, 0);
        return bs;
    }

    public static void intToLittleEndian(int n, byte[] bs, int off)
    {
        bs[off] = (byte)(n);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
    }

    public static byte[] intToLittleEndian(int[] ns)
    {
        byte[] bs = new byte[4 * ns.length];
        intToLittleEndian(ns, bs, 0);
        return bs;
    }

    public static void intToLittleEndian(int[] ns, byte[] bs, int off)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            intToLittleEndian(ns[i], bs, off);
            off += 4;
        }
    }

    public static void intToLittleEndian(int[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            intToLittleEndian(ns[nsOff + i], bs, bsOff);
            bsOff += 4;
        }
    }

    public static void intToLittleEndian_High(int n, byte[] bs, int off, int len)
    {
        intToLittleEndian_Low(n >> ((4 - len) << 3), bs, off, len);
    }

    public static void intToLittleEndian_Low(int n, byte[] bs, int off, int len)
    {
//        assert 1 <= len && len <= 4;

        bs[off] = (byte)n;
        for (int i = 1; i < len; ++i)
        {
            n >>>= 8;
            bs[off + i] = (byte)n;
        }
    }

    public static long littleEndianToLong(byte[] bs, int off)
    {
        int lo = littleEndianToInt(bs, off);
        int hi = littleEndianToInt(bs, off + 4);
        return ((long)(hi & 0xffffffffL) << 32) | (long)(lo & 0xffffffffL);
    }

    public static void littleEndianToLong(byte[] bs, int off, long[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = littleEndianToLong(bs, off);
            off += 8;
        }
    }

    public static void littleEndianToLong(byte[] bs, int bsOff, long[] ns, int nsOff, int nsLen)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            ns[nsOff + i] = littleEndianToLong(bs, bsOff);
            bsOff += 8;
        }
    }

    public static long[] littleEndianToLong(byte[] bs, int off, int count)
    {
        long[] ns = new long[count];
        littleEndianToLong(bs, off, ns);
        return ns;
    }

    public static long littleEndianToLong_High(byte[] bs, int off, int len)
    {
        return littleEndianToLong_Low(bs, off, len) << ((8 - len) << 3);
    }

    public static long littleEndianToLong_Low(byte[] bs, int off, int len)
    {
//        assert 1 <= len && len <= 8;

        long result = bs[off] & 0xFFL;
        int pos = 0;
        for (int i = 1; i < len; ++i)
        {
            pos += 8;
            result |= (bs[off + i] & 0xFFL) << pos;
        }
        return result;
    }

    public static byte[] longToLittleEndian(long n)
    {
        byte[] bs = new byte[8];
        longToLittleEndian(n, bs, 0);
        return bs;
    }

    public static void longToLittleEndian(long n, byte[] bs, int off)
    {
        bs[off] = (byte)(n);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
        bs[++off] = (byte)(n >>> 32);
        bs[++off] = (byte)(n >>> 40);
        bs[++off] = (byte)(n >>> 48);
        bs[++off] = (byte)(n >>> 56);
    }

    public static byte[] longToLittleEndian(long[] ns)
    {
        byte[] bs = new byte[8 * ns.length];
        longToLittleEndian(ns, bs, 0);
        return bs;
    }

    public static void longToLittleEndian(long[] ns, byte[] bs, int off)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            longToLittleEndian(ns[i], bs, off);
            off += 8;
        }
    }

    public static void longToLittleEndian(long[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            longToLittleEndian(ns[nsOff + i], bs, bsOff);
            bsOff += 8;
        }
    }

    public static void longToLittleEndian_High(long n, byte[] bs, int off, int len)
    {
        longToLittleEndian_Low(n >>> ((8 - len) << 3), bs, off, len);
    }

    public static void longToLittleEndian_Low(long n, byte[] bs, int off, int len)
    {
//        assert 1 <= len && len <= 8;

        bs[off] = (byte)n;
        for (int i = 1; i < len; ++i)
        {
            n >>>= 8;
            bs[off + i] = (byte)n;
        }
    }
}
