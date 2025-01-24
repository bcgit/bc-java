package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * ISAP Hash v2, https://isap.iaik.tugraz.at/
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
 * <p>
 * ISAP Hash v2 with reference to C Reference Impl from: https://github.com/isap-lwc/isap-code-package
 * </p>
 */

public class ISAPDigest
    extends BufferBaseDigest
{
    private long x0, x1, x2, x3, x4;
    private long t0, t1, t2, t3, t4;

    public ISAPDigest()
    {
        super(ProcessingBufferType.Immediate, 8);
        DigestSize = 32;
        algorithmName = "ISAP Hash";
        reset();
    }

    private void ROUND(long C)
    {
        t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
        t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
        t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
        t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
        t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
        x0 = t0 ^ ROTR(t0, 19) ^ ROTR(t0, 28);
        x1 = t1 ^ ROTR(t1, 39) ^ ROTR(t1, 61);
        x2 = ~(t2 ^ ROTR(t2, 1) ^ ROTR(t2, 6));
        x3 = t3 ^ ROTR(t3, 10) ^ ROTR(t3, 17);
        x4 = t4 ^ ROTR(t4, 7) ^ ROTR(t4, 41);
    }

    private void P12()
    {
        ROUND(0xf0);
        ROUND(0xe1);
        ROUND(0xd2);
        ROUND(0xc3);
        ROUND(0xb4);
        ROUND(0xa5);
        ROUND(0x96);
        ROUND(0x87);
        ROUND(0x78);
        ROUND(0x69);
        ROUND(0x5a);
        ROUND(0x4b);
    }

    private long ROTR(long x, long n)
    {
        return (x >>> n) | (x << (64 - n));
    }

    protected long U64BIG(long x)
    {
        return ((ROTR(x, 8) & (0xFF000000FF000000L)) | (ROTR(x, 24) & (0x00FF000000FF0000L)) |
            (ROTR(x, 40) & (0x0000FF000000FF00L)) | (ROTR(x, 56) & (0x000000FF000000FFL)));
    }

    @Override
    protected void processBytes(byte[] input, int inOff)
    {
        /* absorb */
        x0 ^= Pack.bigEndianToLong(input, inOff);
        P12();
    }

    @Override
    protected void finish(byte[] output, int outOff)
    {
        /* absorb final input block */
        int idx;
        x0 ^= 0x80L << ((7 - m_bufPos) << 3);
        while (m_bufPos > 0)
        {
            x0 ^= (m_buf[--m_bufPos] & 0xFFL) << ((7 - m_bufPos) << 3);
        }
        P12();
        // squeeze
        long[] out64 = new long[4];
        for (idx = 0; idx < 3; ++idx)
        {
            out64[idx] = U64BIG(x0);
            P12();
        }
        /* squeeze final output block */
        out64[idx] = U64BIG(x0);
        Pack.longToLittleEndian(out64, output, outOff);
    }

    @Override
    public void reset()
    {
        t0 = t1 = t2 = t3 = t4 = 0;
        /* init state */
        x0 = -1255492011513352131L;
        x1 = -8380609354527731710L;
        x2 = -5437372128236807582L;
        x3 = 4834782570098516968L;
        x4 = 3787428097924915520L;
        Arrays.clear(m_buf);
        m_bufPos = 0;
    }
}
