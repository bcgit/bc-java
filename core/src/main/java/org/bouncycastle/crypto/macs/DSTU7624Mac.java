package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * Implementation of DSTU7624 MAC mode.
 * <p>
 * This is a CBC-MAC variant (a CBC chain whose final block is masked with kDelta = E(0) before the
 * last encryption) and, like raw CBC-MAC, it is defined only for input that is a whole number of
 * blocks: {@link #doFinal} rejects a trailing partial block with "input must be a multiple of
 * blocksize". The restriction is deliberate and is <b>not</b> relaxed by zero-padding the final
 * block. The MAC binds no message length, so zero-padding a partial block would make the tag of an
 * N-byte message collide with that of a longer message sharing the same final block once padded
 * (the documented ambiguity of ISO/IEC 9797-1 padding method 1). DSTU 7624:2014 specifies no
 * partial-block padding for this MAC and publishes no vector for one, so any padding scheme BC chose
 * (zero-pad, or the unambiguous 10* / ISO 9797-1 method 2 that CMAC uses) would be non-conformant
 * and non-interoperable. Callers needing to authenticate arbitrary-length input should pad to a
 * block boundary with an agreed scheme before calling update, or use a length-binding MAC such as
 * KGMac. See github #287.
 * </p>
 */
public class DSTU7624Mac
    implements Mac
{
    private final static int BITS_IN_BYTE = 8;

    private byte[]              buf;
    private int                 bufOff;

    private int macSize;
    private int blockSize;
    private DSTU7624Engine engine;

    private byte[] c, cTemp, kDelta;

    private boolean initCalled = false;

    public DSTU7624Mac(int blockBitLength, int q)
    {
        this.engine = new DSTU7624Engine(blockBitLength);
        this.blockSize = blockBitLength / BITS_IN_BYTE;
        this.macSize = q / BITS_IN_BYTE;
        this.c = new byte[blockSize];
        this.kDelta = new byte[blockSize];
        this.cTemp = new byte[blockSize];
        this.buf = new byte[blockSize];
    }

    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof KeyParameter)
        {
            engine.init(true, params);
            initCalled = true;
            reset();
        }
        else
        {
            throw new IllegalArgumentException("Invalid parameter passed to DSTU7624Mac");
        }
    }

    public String getAlgorithmName()
    {
        return "DSTU7624Mac";
    }

    public int getMacSize()
    {
        return macSize;
    }

    public void update(byte in)
    {
        if (bufOff == buf.length)
        {
            processBlock(buf, 0);
            bufOff = 0;
        }

        buf[bufOff++] = in;
    }

    public void update(byte[] in, int inOff, int len)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException(
                "can't have a negative input length!");
        }

        int blockSize = engine.getBlockSize();
        int gapLen = blockSize - bufOff;

        if (len > gapLen)
        {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);

            processBlock(buf, 0);

            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            while (len > blockSize)
            {
                processBlock(in, inOff);

                len -= blockSize;
                inOff += blockSize;
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);

        bufOff += len;
    }

    private void processBlock(byte[] in, int inOff)
    {
        xor(c, 0, in, inOff, cTemp);

        engine.processBlock(cTemp, 0, c, 0);
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (bufOff % buf.length != 0)
        {
            // Deliberately strict: see the class javadoc for why partial blocks are not zero-padded
            // here (no DSTU 7624 padding spec, no vector, and this MAC binds no length). github #287.
            throw new DataLengthException("input must be a multiple of blocksize");
        }

        //Last block
        xor(c, 0, buf, 0, cTemp);
        xor(cTemp, 0, kDelta, 0, c);
        engine.processBlock(c, 0, c, 0);

        if (macSize + outOff > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        System.arraycopy(c, 0, out, outOff, macSize);

        reset();
        
        return macSize;
    }

    public void reset()
    {
        Arrays.fill(c, (byte)0x00);
        Arrays.fill(cTemp, (byte)0x00);
        Arrays.fill(kDelta, (byte)0x00);
        Arrays.fill(buf, (byte)0x00);
        engine.reset();
        
        if (initCalled)
        {
            engine.processBlock(kDelta, 0, kDelta, 0);
        }

        bufOff = 0;
    }

    private void xor(byte[] x, int xOff, byte[] y, int yOff, byte[] x_xor_y)
    {

        if (x.length - xOff < blockSize || y.length - yOff < blockSize || x_xor_y.length < blockSize)
        {
            throw new IllegalArgumentException("some of input buffers too short");
        }
        for (int byteIndex = 0; byteIndex < blockSize; byteIndex++)
        {
            x_xor_y[byteIndex] = (byte)(x[byteIndex + xOff] ^ y[byteIndex + yOff]);
        }
    }

}
