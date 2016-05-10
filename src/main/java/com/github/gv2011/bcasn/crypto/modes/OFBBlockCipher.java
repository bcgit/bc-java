package com.github.gv2011.bcasn.crypto.modes;

import com.github.gv2011.bcasn.crypto.BlockCipher;
import com.github.gv2011.bcasn.crypto.CipherParameters;
import com.github.gv2011.bcasn.crypto.DataLengthException;
import com.github.gv2011.bcasn.crypto.StreamBlockCipher;
import com.github.gv2011.bcasn.crypto.params.ParametersWithIV;

/**
 * implements a Output-FeedBack (OFB) mode on top of a simple cipher.
 */
public class OFBBlockCipher
    extends StreamBlockCipher
{
    private int             byteCount;
    private byte[]          IV;
    private byte[]          ofbV;
    private byte[]          ofbOutV;

    private final int             blockSize;
    private final BlockCipher     cipher;

    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * feedback mode.
     * @param blockSize the block size in bits (note: a multiple of 8)
     */
    public OFBBlockCipher(
        BlockCipher cipher,
        int         blockSize)
    {
        super(cipher);

        this.cipher = cipher;
        this.blockSize = blockSize / 8;

        this.IV = new byte[cipher.getBlockSize()];
        this.ofbV = new byte[cipher.getBlockSize()];
        this.ofbOutV = new byte[cipher.getBlockSize()];
    }

    /**
     * Initialise the cipher and, possibly, the initialisation vector (IV).
     * If an IV isn't passed as part of the parameter, the IV will be all zeros.
     * An IV which is too short is handled in FIPS compliant fashion.
     *
     * @param encrypting if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             encrypting, //ignored by this OFB mode
        CipherParameters    params)
        throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            byte[]      iv = ivParam.getIV();

            if (iv.length < IV.length)
            {
                // prepend the supplied IV with zeros (per FIPS PUB 81)
                System.arraycopy(iv, 0, IV, IV.length - iv.length, iv.length); 
                for (int i = 0; i < IV.length - iv.length; i++)
                {
                    IV[i] = 0;
                }
            }
            else
            {
                System.arraycopy(iv, 0, IV, 0, IV.length);
            }

            reset();

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
            }
        }
        else
        {
            reset();

            // if it's null, key is to be reused.
            if (params != null)
            {
                cipher.init(true, params);
            }
        }
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/OFB"
     * and the block size in bits
     */
    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/OFB" + (blockSize * 8);
    }


    /**
     * return the block size we are operating at (in bytes).
     *
     * @return the block size we are operating at (in bytes).
     */
    public int getBlockSize()
    {
        return blockSize;
    }

    /**
     * Process one block of input from the array in and write it to
     * the out array.
     *
     * @param in the array containing the input data.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception DataLengthException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    public int processBlock(
        byte[]      in,
        int         inOff,
        byte[]      out,
        int         outOff)
        throws DataLengthException, IllegalStateException
    {
        processBytes(in, inOff, blockSize, out, outOff);

        return blockSize;
    }

    /**
     * reset the feedback vector back to the IV and reset the underlying
     * cipher.
     */
    public void reset()
    {
        System.arraycopy(IV, 0, ofbV, 0, IV.length);
        byteCount = 0;

        cipher.reset();
    }

    protected byte calculateByte(byte in)
          throws DataLengthException, IllegalStateException
    {
        if (byteCount == 0)
        {
            cipher.processBlock(ofbV, 0, ofbOutV, 0);
        }

        byte rv = (byte)(ofbOutV[byteCount++] ^ in);

        if (byteCount == blockSize)
        {
            byteCount = 0;

            System.arraycopy(ofbV, blockSize, ofbV, 0, ofbV.length - blockSize);
            System.arraycopy(ofbOutV, 0, ofbV, ofbV.length - blockSize, blockSize);
        }

        return rv;
    }
}
