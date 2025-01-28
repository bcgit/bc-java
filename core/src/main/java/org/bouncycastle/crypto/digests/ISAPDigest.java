package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.engines.AsconPermutationFriend;
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
    public static class Friend
    {
        private static final Friend INSTANCE = new Friend();

        private Friend()
        {
        }

        static Friend getFriend(AsconBaseDigest.Friend friend)
        {
            if (null == friend)
            {
                throw new NullPointerException("This method is only for use by AsconBaseDigest");
            }
            return INSTANCE;
        }
    }

    private final AsconPermutationFriend.AsconPermutation p;

    public ISAPDigest()
    {
        super(ProcessingBufferType.Immediate, 8);
        p = AsconPermutationFriend.getAsconPermutation(Friend.INSTANCE);
        DigestSize = 32;
        algorithmName = "ISAP Hash";
        reset();
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
        p.x0 ^= Pack.bigEndianToLong(input, inOff);
        p.p(12);
    }

    @Override
    protected void finish(byte[] output, int outOff)
    {
        /* absorb final input block */
        int idx;
        p.x0 ^= 0x80L << ((7 - m_bufPos) << 3);
        while (m_bufPos > 0)
        {
            p.x0 ^= (m_buf[--m_bufPos] & 0xFFL) << ((7 - m_bufPos) << 3);
        }
        p.p(12);
        // squeeze
        long[] out64 = new long[4];
        for (idx = 0; idx < 3; ++idx)
        {
            out64[idx] = U64BIG(p.x0);
            p.p(12);
        }
        /* squeeze final output block */
        out64[idx] = U64BIG(p.x0);
        Pack.longToLittleEndian(out64, output, outOff);
    }

    @Override
    public void reset()
    {
        super.reset();
        /* init state */
        p.x0 = -1255492011513352131L;
        p.x1 = -8380609354527731710L;
        p.x2 = -5437372128236807582L;
        p.x3 = 4834782570098516968L;
        p.x4 = 3787428097924915520L;
    }
}
