package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.engines.PhotonBeetleEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

/**
 * Photon-Beetle, https://www.isical.ac.in/~lightweight/beetle/
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
 * <p>
 * Photon-Beetle with reference to C Reference Impl from: https://github.com/PHOTON-Beetle/Software
 * </p>
 */
public class PhotonBeetleDigest
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
    private static final int SQUEEZE_RATE_INBYTES = 16;
    private static final int D = 8;
    private int blockCount;

    public PhotonBeetleDigest()
    {
        super(ProcessingBufferType.Buffered, 4);
        DigestSize = 32;
        state = new byte[DigestSize];
        algorithmName = "Photon-Beetle Hash";
        blockCount = 0;
    }

    @Override
    protected void processBytes(byte[] input, int inOff)
    {
        if (blockCount < 4)
        {
            System.arraycopy(input, inOff, state, blockCount << 2, BlockSize);
        }
        else
        {
            PhotonBeetleEngine.photonPermutation(Friend.INSTANCE, state);
            Bytes.xorTo(BlockSize, input, inOff, state);
        }
        blockCount++;
    }

    @Override
    protected void finish(byte[] output, int outOff)
    {
        int LAST_THREE_BITS_OFFSET = 5;
        if (m_bufPos == 0 && blockCount == 0)
        {
            state[DigestSize - 1] ^= 1 << LAST_THREE_BITS_OFFSET;
        }
        else if (blockCount < 4)
        {
            System.arraycopy(m_buf, 0, state, blockCount << 2, m_bufPos);
            state[(blockCount << 2) + m_bufPos] ^= 0x01; // ozs
            state[DigestSize - 1] ^= (byte)1 << LAST_THREE_BITS_OFFSET;
        }
        else if (blockCount == 4 && m_bufPos == 0)
        {
            state[DigestSize - 1] ^= (byte)2 << LAST_THREE_BITS_OFFSET;
        }
        else
        {
            PhotonBeetleEngine.photonPermutation(Friend.INSTANCE, state);
            Bytes.xorTo(m_bufPos, m_buf, state);
            if (m_bufPos < BlockSize)
            {
                state[m_bufPos] ^= 0x01; // ozs
            }
            state[DigestSize - 1] ^= (m_bufPos % BlockSize == 0 ? (byte)1 : (byte)2) << LAST_THREE_BITS_OFFSET;
        }
        PhotonBeetleEngine.photonPermutation(Friend.INSTANCE, state);
        System.arraycopy(state, 0, output, outOff, SQUEEZE_RATE_INBYTES);
        PhotonBeetleEngine.photonPermutation(Friend.INSTANCE, state);
        System.arraycopy(state, 0, output, outOff + SQUEEZE_RATE_INBYTES, SQUEEZE_RATE_INBYTES);
    }

    @Override
    public void reset()
    {
        super.reset();
        Arrays.fill(state, (byte)0);
        blockCount = 0;
    }
}