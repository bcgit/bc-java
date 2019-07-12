package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * Implementation of DSTU7624 MAC mode
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
