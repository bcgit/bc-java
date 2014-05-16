package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.SkippingCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Implements the Segmented Integer Counter (SIC) mode on top of a simple
 * block cipher. This mode is also known as CTR mode.
 */
public class SICBlockCipher
    implements BlockCipher, StreamCipher, SkippingCipher
{
    private final BlockCipher     cipher;
    private final int             blockSize;
    
    private byte[]          IV;
    private byte[]          counter;
    private byte[]          counterOut;
    private int             byteCount;

    /**
     * Basic constructor.
     *
     * @param c the block cipher to be used.
     */
    public SICBlockCipher(BlockCipher c)
    {
        this.cipher = c;
        this.blockSize = cipher.getBlockSize();
        this.IV = new byte[blockSize];
        this.counter = new byte[blockSize];
        this.counterOut = new byte[blockSize];
        this.byteCount = 0;
    }


    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    public BlockCipher getUnderlyingCipher()
    {
        return cipher;
    }


    public void init(
        boolean             forEncryption, //ignored by this CTR mode
        CipherParameters    params)
        throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            byte[] iv = ivParam.getIV();
            System.arraycopy(iv, 0, IV, 0, IV.length);

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
            }

            reset();
        }
        else
        {
            throw new IllegalArgumentException("SIC mode requires ParametersWithIV");
        }
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/SIC";
    }

    public byte returnByte(byte in)
    {
        return processByte(in);
    }

    public void processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        if (outOff + len > out.length)
        {
            throw new DataLengthException("output buffer too small");
        }

        if (inOff + len > in.length)
        {
            throw new DataLengthException("input buffer too small for len");
        }

        int inStart = inOff;
        int inEnd = inOff + len;
        int outStart = outOff;

        while (inStart < inEnd)
        {
             out[outStart++] = processByte(in[inStart++]);
        }
    }

    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }


    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
          throws DataLengthException, IllegalStateException
    {
        processBytes(in, inOff, blockSize, out, outOff);

        return blockSize;
    }

    private byte processByte(byte in)
          throws DataLengthException, IllegalStateException
    {
        if (byteCount == 0)
        {
            cipher.processBlock(counter, 0, counterOut, 0);
        }

        byte rv = (byte)(counterOut[byteCount++] ^ in);
        if (byteCount == counter.length)
        {
            byteCount = 0;

            incrementCounter();
        }

        return rv;
    }

    private void incrementCounter()
    {
        // increment counter by 1.
        for (int i = counter.length - 1; i >= 0 && ++counter[i] == 0; i--)
        {
            ; // do nothing - pre-increment and test for 0 in counter does the job.
        }
    }

    private void decrementCounter()
    {
        // increment counter by 1.
        for (int i = counter.length - 1; i >= 0 && --counter[i] == Integer.MIN_VALUE; i--)
        {
            ; // do nothing - pre-increment and test for 0 in counter does the job.
        }
    }

    private void adjustCounter(long n)
    {
        if (n >= 0)
        {
            long numBlocks = (n + byteCount) / blockSize;

            for (long i = 0; i != numBlocks; i++)
            {
                incrementCounter();
            }

            byteCount = (int)((n + byteCount) - (blockSize * numBlocks));
        }
        else
        {
            long numBlocks = (-n - byteCount) / blockSize;

            for (long i = 0; i != numBlocks; i++)
            {
                decrementCounter();
            }

            int gap = (int)(byteCount + n + (blockSize * numBlocks));

            if (gap >= 0)
            {
                byteCount = 0;
            }
            else
            {
                decrementCounter();
                byteCount =  blockSize + gap;
            }
        }
    }

    public void reset()
    {
        System.arraycopy(IV, 0, counter, 0, counter.length);
        cipher.reset();
        this.byteCount = 0;
    }

    public long skip(long numberOfBytes)
    {
        adjustCounter(numberOfBytes);

        cipher.processBlock(counter, 0, counterOut, 0);

        return numberOfBytes;
    }

    public long seekTo(long position)
    {
        reset();

        skip(position);

        return 0;
    }
}
