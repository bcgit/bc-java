package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Implements the Segmented Integer Counter (SIC) mode on top of a simple
 * block cipher. This mode is also known as CTR mode.
 * <p>
 * With an IV shorter than the block size, the counter occupies the remaining low bytes and
 * running past its range throws an IllegalStateException. With a full-block IV the whole block
 * is the counter; the advance since init is bounded at 2^64 blocks (the widest range
 * getPosition()/skip arithmetic can represent), past which the same exception is thrown.
 */
public class SICBlockCipher
    extends StreamBlockCipher
    implements CTRModeCipher
{
    private final BlockCipher     cipher;
    private final int             blockSize;
    // where the low 8-byte counter lane starts; 0 for block sizes of 8 or less
    private final int             laneOff;

    private byte[]          IV;
    private byte[]          counter;
    private byte[]          counterOut;
    private int             byteCount;

    private boolean         fullBlockIV;
    // full-block IV, block size over 8: counter[laneOff - 1] != guardByte proves the advance since init is below 2^64 blocks
    private byte            guardByte;
    // full-block IV, block size of 8 or less: advance since init in blocks mod 2^64, resynced on skip/seekTo
    private long            used;
    // full-block IV only: the advance since init has been seen to be out of range
    private boolean         overflow;
    // scratch for populateDelta in the range checks
    private byte[]          delta;

    /**
     * Return a new SIC/CTR mode cipher based on the passed in base cipher
     *
     * @param cipher the base cipher for the SIC/CTR mode.
     */
    public static CTRModeCipher newInstance(BlockCipher cipher)
    {
        return new SICBlockCipher(cipher);
    }

    /**
     * Basic constructor.
     *
     * @param c the block cipher to be used.
     * @deprecated use newInstance() method.
     */
    @Deprecated
    public SICBlockCipher(BlockCipher c)
    {
        super(c);

        this.cipher = c;
        this.blockSize = cipher.getBlockSize();
        this.laneOff = (blockSize > 8) ? blockSize - 8 : 0;
        this.IV = new byte[blockSize];
        this.counter = new byte[blockSize];
        this.counterOut = new byte[blockSize];
        this.delta = new byte[blockSize];
        this.byteCount = 0;
    }

    public void init(
        boolean             forEncryption, //ignored by this CTR mode
        CipherParameters    params)
        throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            this.IV = Arrays.clone(ivParam.getIV());

            if (blockSize < IV.length)
            {
                throw new IllegalArgumentException("CTR/SIC mode requires IV no greater than: " + blockSize + " bytes.");
            }

            int maxCounterSize = (8 > blockSize / 2) ? blockSize / 2 : 8;

            if (blockSize - IV.length > maxCounterSize)
            {
                throw new IllegalArgumentException("CTR/SIC mode requires IV of at least: " + (blockSize - maxCounterSize) + " bytes.");
            }

            this.fullBlockIV = (IV.length == blockSize);
            if (fullBlockIV && laneOff > 0)
            {
                this.guardByte = (byte)(IV[laneOff - 1] + 1);
            }

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
            }

            reset();
        }
        else
        {
            throw new IllegalArgumentException("CTR/SIC mode requires ParametersWithIV");
        }
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/SIC";
    }

    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
          throws DataLengthException, IllegalStateException
    {
        if (byteCount != 0)
        {
            processBytes(in, inOff, blockSize, out, outOff);
            return blockSize;
        }

        if (inOff + blockSize > in.length)
        {
            throw new DataLengthException("input buffer too small");
        }
        if (outOff + blockSize > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        checkLastIncrement();

        cipher.processBlock(counter, 0, counterOut, 0);
        for (int i = 0; i < blockSize; ++i)
        {
            out[outOff + i] = (byte)(in[inOff + i] ^ counterOut[i]);
        }
        incrementCounter();
        return blockSize;
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        if (inOff + len > in.length)
        {
            throw new DataLengthException("input buffer too small");
        }
        if (outOff + len > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        for (int i = 0; i < len; ++i)
        {
            byte next;

            if (byteCount == 0)
            {
                checkLastIncrement();

                cipher.processBlock(counter, 0, counterOut, 0);
                next = (byte)(in[inOff + i] ^ counterOut[byteCount++]);
            }
            else
            {
                next = (byte)(in[inOff + i] ^ counterOut[byteCount++]);
                if (byteCount == counter.length)
                {
                    byteCount = 0;
                    incrementCounter();
                }
            }
            out[outOff + i] = next;
        }

        return len;
    }

    protected byte calculateByte(byte in)
          throws DataLengthException, IllegalStateException
    {
        if (byteCount == 0)
        {
            checkLastIncrement();

            cipher.processBlock(counter, 0, counterOut, 0);

            return (byte)(counterOut[byteCount++] ^ in);
        }

        byte rv = (byte)(counterOut[byteCount++] ^ in);

        if (byteCount == counter.length)
        {
            byteCount = 0;
            incrementCounter();
        }

        return rv;
    }

    private void checkCounter()
    {
        if (IV.length < blockSize)
        {
            for (int i = IV.length - 1; i >= 0; i--)
            {
                if (counter[i] != IV[i])
                {
                    throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
                }
            }
        }
        else
        {
            // full-block IV: the authoritative bound of the advance since init at 2^64 blocks, run per skip/seekTo
            if (overflow || populateDelta(delta))
            {
                overflow = true;
                throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
            }
            if (laneOff == 0)
            {
                // no upper lane to watch per block - resync the block accumulator instead
                used = Pack.bigEndianToLong(delta, delta.length - 8);
            }
        }
    }

    private void checkLastIncrement()
    {
        if (IV.length < blockSize)
        {
            if (counter[IV.length - 1] != IV[IV.length - 1])
            {
                throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
            }
        }
        else if (laneOff > 0)
        {
            // full-block IV: on a guard byte match the full-width delta separates the legal terminal window from 2^64 blocks reached
            if (overflow || (counter[laneOff - 1] == guardByte && populateDelta(delta)))
            {
                overflow = true;
                throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
            }
        }
        else if (overflow)
        {
            // full-block IV on a block size of 8 or less: the block accumulator came around
            throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
        }
    }

    private void incrementCounter()
    {
        int i = counter.length;
        while (--i >= 0)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }

        if (laneOff == 0 && ++used == 0 && fullBlockIV)
        {
            // the advance since init has come around to 2^64 blocks - see checkLastIncrement
            overflow = true;
        }
    }

    // single big-endian addition of a 64-bit block count into the counter, modular like incrementCounter
    private void addToCounter(long numBlocks)
    {
        int carry = 0;
        for (int i = counter.length - 1; i >= 0; i--)
        {
            int pos = counter.length - 1 - i;
            int sum = (counter[i] & 0xff) + carry;
            if (pos < 8)
            {
                sum += (int)(numBlocks >>> (8 * pos)) & 0xff;
            }
            counter[i] = (byte)sum;
            carry = sum >>> 8;
        }
    }

    // single big-endian subtraction of a 64-bit block count from the counter, modular like addToCounter
    private void subtractFromCounter(long numBlocks)
    {
        int borrow = 0;
        for (int i = counter.length - 1; i >= 0; i--)
        {
            int pos = counter.length - 1 - i;
            int v = (counter[i] & 0xff) - borrow;
            if (pos < 8)
            {
                v -= (int)(numBlocks >>> (8 * pos)) & 0xff;
            }
            if (v < 0)
            {
                v += 256;
                borrow = 1;
            }
            else
            {
                borrow = 0;
            }
            counter[i] = (byte)v;
        }
    }

    private void adjustCounter(long n)
    {
        // split moves at the extremes of the long range in two: the (n + byteCount) / (-n - byteCount) arithmetic below overflows on them
        if (n == Long.MIN_VALUE || n > Long.MAX_VALUE - blockSize)
        {
            long half = n / 2;

            adjustCounter(half);
            adjustCounter(n - half);
            return;
        }

        if (n >= 0)
        {
            long numBlocks = (n + byteCount) / blockSize;

            addToCounter(numBlocks);

            byteCount = (int)((n + byteCount) - (blockSize * numBlocks));
        }
        else
        {
            long numBlocks = (-n - byteCount) / blockSize;

            subtractFromCounter(numBlocks);

            int gap = (int)(byteCount + n + (blockSize * numBlocks));

            if (gap >= 0)
            {
                byteCount = gap;
            }
            else
            {
                subtractFromCounter(1);
                byteCount = blockSize + gap;
            }
        }
    }

    public void reset()
    {
        Arrays.fill(counter, (byte)0);
        System.arraycopy(IV, 0, counter, 0, IV.length);
        cipher.reset();
        this.byteCount = 0;
        this.used = 0;
        this.overflow = false;
    }

    public long skip(long numberOfBytes)
    {
        adjustCounter(numberOfBytes);

        checkCounter();

        cipher.processBlock(counter, 0, counterOut, 0);

        return numberOfBytes;
    }

    public long seekTo(long position)
    {
        reset();

        return skip(position);
    }

    /**
     * Big-endian modular subtraction of the initial counter (the IV, zero-padded on the right) from
     * the current counter into res, carrying the borrow explicitly across every byte - a raw byte
     * decrement drops the borrow when the decremented byte wraps 0x00 -&gt; 0xFF.
     *
     * @return true when the difference has a non-zero byte above the low 8 - the counter has
     *         advanced 2^64 or more blocks since init, or moved below its starting value.
     */
    private boolean populateDelta(byte[] res)
    {
        int borrow = 0;

        for (int i = res.length - 1; i >= 0; i--)
        {
            int v = (counter[i] & 0xff) - borrow;

            if (i < IV.length)
            {
                v -= (IV[i] & 0xff);
            }

            if (v < 0)
            {
                v += 256;
                borrow = 1;
            }
            else
            {
                borrow = 0;
            }

            res[i] = (byte)v;
        }

        for (int i = 0; i != laneOff; i++)
        {
            if (res[i] != 0)
            {
                return true;
            }
        }

        return false;
    }

    public long getPosition()
    {
        populateDelta(delta);

        return Pack.bigEndianToLong(delta, delta.length - 8) * blockSize + byteCount;
    }
}
