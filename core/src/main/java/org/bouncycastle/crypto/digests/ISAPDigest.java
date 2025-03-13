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
        p.x0 ^= 0x80L << ((7 - m_bufPos) << 3);
        while (m_bufPos > 0)
        {
            p.x0 ^= (m_buf[--m_bufPos] & 0xFFL) << ((7 - m_bufPos) << 3);
        }
        // squeeze
        for (int i = 0; i < 4; ++i)
        {
            p.p(12);
            Pack.longToBigEndian(p.x0, output, outOff);
            outOff += 8;
        }
    }

    @Override
    public void reset()
    {
        super.reset();
        /* init state */
        p.set(-1255492011513352131L, -8380609354527731710L, -5437372128236807582L, 4834782570098516968L, 3787428097924915520L);
    }
}
