package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/**
 * Implementation of DSTU7624 MAC mode
 */
public class DSTU7624Mac
    implements Mac
{

    private final static int BITS_IN_BYTE = 8;

    private int macSize;
    private int blockSize;
    private DSTU7624Engine engine;

    private byte[] c, cTemp, kDelta;

    public DSTU7624Mac(int blockBitLength, int keyBitLength, int q)
    {

        this.engine = new DSTU7624Engine(blockBitLength, keyBitLength);
        this.blockSize = blockBitLength / BITS_IN_BYTE;
        this.macSize = q / BITS_IN_BYTE;
        this.c = new byte[blockSize];
        this.kDelta = new byte[blockSize];
        this.cTemp = new byte[blockSize];
    }

    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof KeyParameter)
        {
            engine.init(true, params);
            engine.processBlock(kDelta, 0, kDelta, 0);
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
        throws IllegalStateException
    {
        throw new NotImplementedException();
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        if (len < 0)
        {
            throw new IllegalArgumentException("Can't have negative input length!");
        }

        if ((inOff + len) % blockSize != 0)
        {
            //Partial blocks not supported
            throw new NotImplementedException();
        }

        if (inOff + len > in.length)
        {
            throw new DataLengthException("Input buffer too short");
        }

        while (len > blockSize)
        {
            xor(c, 0, in, inOff, cTemp);

            engine.processBlock(cTemp, 0, c, 0);

            len -= blockSize;
            inOff += blockSize;
        }

        //Last block
        xor(c, 0, in, inOff, cTemp);
        xor(cTemp, 0, kDelta, 0, c);
        engine.processBlock(c, 0, c, 0);
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {

        if (macSize + outOff > out.length)
        {
            throw new DataLengthException("Output buffer too short");
        }

        System.arraycopy(c, 0, out, outOff, macSize);

        return macSize;
    }

    public void reset()
    {
        Arrays.fill(c, (byte)0x00);
        Arrays.fill(cTemp, (byte)0x00);
        Arrays.fill(kDelta, (byte)0x00);
        engine.reset();
        engine.processBlock(kDelta, 0, kDelta, 0);
    }

    private void xor(byte[] x, int xOff, byte[] y, int yOff, byte[] x_xor_y)
    {

        if (x.length - xOff < blockSize || y.length - yOff < blockSize || x_xor_y.length < blockSize)
        {
            throw new IllegalArgumentException("Some of input buffers too short");
        }
        for (int byteIndex = 0; byteIndex < blockSize; byteIndex++)
        {
            x_xor_y[byteIndex] = (byte)(x[byteIndex + xOff] ^ y[byteIndex + yOff]);
        }
    }

}
