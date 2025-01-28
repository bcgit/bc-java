package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.engines.XoodyakEngine;
import org.bouncycastle.util.Arrays;

/**
 * Xoodyak v1, https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
 * <p>
 * Xoodyak with reference to C Reference Impl from: https://github.com/XKCP/XKCP
 * </p>
 */

public class XoodyakDigest
    extends BufferBaseDigest
{
    public static class Friend
    {
        private static final Friend INSTANCE = new Friend();

        private Friend()
        {
        }
    }

    private final byte[] state;
    private int phase;
    private static final int mode = 1; // set as ModeHash
    private static final int PhaseUp = 2;
    private static final int TAGLEN = 16;
    private int Cd;

    public XoodyakDigest()
    {
        super(ProcessingBufferType.Immediate, 16);
        DigestSize = 32;
        state = new byte[48];
        algorithmName = "Xoodyak Hash";
        reset();
    }

    @Override
    protected void processBytes(byte[] input, int inOff)
    {
        if (phase != PhaseUp)
        {
            phase = XoodyakEngine.up(Friend.INSTANCE, mode, state, null, 0, 0, 0);
        }
        phase = XoodyakEngine.down(Friend.INSTANCE, mode, state, input, inOff, BlockSize, Cd);
        Cd = 0;
    }

    @Override
    protected void finish(byte[] output, int outOff)
    {
        if (m_bufPos != 0)
        {
            if (phase != PhaseUp)
            {
                phase = XoodyakEngine.up(Friend.INSTANCE, mode, state, null, 0, 0, 0);
            }
            phase = XoodyakEngine.down(Friend.INSTANCE, mode, state, m_buf, 0, m_bufPos, Cd);
        }
        phase = XoodyakEngine.up(Friend.INSTANCE, mode, state, output, outOff, TAGLEN, 0x40);
        phase = XoodyakEngine.down(Friend.INSTANCE, mode, state, null, 0, 0, 0);
        phase = XoodyakEngine.up(Friend.INSTANCE, mode, state, output, outOff + TAGLEN, TAGLEN, 0);
    }

    @Override
    public void reset()
    {
        super.reset();
        Arrays.fill(state, (byte)0);
        phase = PhaseUp;
        Cd = 0x03;
    }
}
