package org.bouncycastle.crypto.fpe;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.util.Pack;

/**
 * Base class for format-preserving encryption.
 */
public abstract class FPEEngine
{
    protected final BlockCipher baseCipher;

    protected boolean forEncryption;
    protected FPEParameters fpeParameters;

    protected FPEEngine(BlockCipher baseCipher)
    {
        this.baseCipher = baseCipher;
    }

    /**
     * Process length bytes from inBuf, writing the output to outBuf.
     *
     * @param inBuf input data.
     * @param inOff offset in input data to start at.
     * @param length number of bytes to process.
     * @param outBuf destination buffer.
     * @param outOff offset to start writing at in destination buffer.
     * @return number of bytes output.
     */
    public int processBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
    {
        if (fpeParameters == null)
        {
            throw new IllegalStateException("FPE engine not initialized");
        }

        if (length < 0)
        {
            throw new IllegalArgumentException("input length cannot be negative");
        }

        if (inBuf == null || outBuf == null)
        {
            throw new NullPointerException("buffer value is null");
        }

        if (inBuf.length < inOff + length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if (outBuf.length < outOff + length)
        {
            throw new OutputLengthException("output buffer too short");
        }
        
        if (forEncryption)
        {
            return encryptBlock(inBuf, inOff, length, outBuf, outOff);
        }
        else
        {
            return decryptBlock(inBuf, inOff, length, outBuf, outOff);
        }
    }

    protected static short[] toShortArray(byte[] buf)
    {
        if ((buf.length & 1) != 0)
        {
            throw new IllegalArgumentException("data must be an even number of bytes for a wide radix");
        }

        short[] rv = new short[buf.length / 2];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Pack.bigEndianToShort(buf, i * 2);
        }

        return rv;
    }

    protected static byte[] toByteArray(short[] buf)
    {
        byte[] rv = new byte[buf.length * 2];

        for (int i = 0; i != buf.length; i++)
        {
            Pack.shortToBigEndian(buf[i], rv, i * 2);
        }

        return rv;
    }

    /**
     * Initialize the FPE engine for encryption/decryption.
     *
     * @param forEncryption true if initialising for encryption, false otherwise.
     * @param parameters the key and other parameters to use to set the engine up.
     */
    public abstract void init(boolean forEncryption, CipherParameters parameters);

    /**
     * Return the name of the algorithm the cipher implements.
     *
     * @return the name of the algorithm the cipher implements.
     */
    public abstract String getAlgorithmName();

    protected abstract int encryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff);

    protected abstract int decryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff);
}
