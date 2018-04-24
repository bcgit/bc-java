package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * implements the GOST 3412 2015 CTR counter mode (GCTR).
 */
public class G3413CTRBlockCipher
    extends StreamBlockCipher
{


    private final int s;
    private byte[] CTR;
    private byte[] IV;
    private byte[] buf;
    private final int blockSize;
    private final BlockCipher cipher;
    private int byteCount = 0;
    private boolean initialized;


    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     *               counter mode (must have a 64 bit block size).
     */
    public G3413CTRBlockCipher(
        BlockCipher cipher)
    {
        this(cipher, cipher.getBlockSize() * 8);
    }

    /**
     * Basic constructor.
     *
     * @param cipher       the block cipher to be used as the basis of the
     *                     counter mode (must have a 64 bit block size).
     * @param bitBlockSize basic unit (defined as s)
     */
    public G3413CTRBlockCipher(BlockCipher cipher, int bitBlockSize)
    {
        super(cipher);

        if (bitBlockSize < 0 || bitBlockSize > cipher.getBlockSize() * 8)
        {
            throw new IllegalArgumentException("Parameter bitBlockSize must be in range 0 < bitBlockSize <= "
                            + cipher.getBlockSize() * 8);
        }

        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        this.s = bitBlockSize / 8;
        CTR = new byte[blockSize];
    }

    /**
     * Initialise the cipher and, possibly, the initialisation vector (IV).
     * If an IV isn't passed as part of the parameter, the IV will be all zeros.
     * An IV which is too short is handled in FIPS compliant fashion.
     *
     * @param encrypting if true the cipher is initialised for
     *                   encryption, if false for decryption.
     * @param params     the key and other data required by the cipher.
     * @throws IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean encrypting, //ignored by this CTR mode
        CipherParameters params)
        throws IllegalArgumentException
    {

        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;

            initArrays();

            IV = Arrays.clone(ivParam.getIV());

            if (IV.length != blockSize / 2)
            {
                throw new IllegalArgumentException("Parameter IV length must be == blockSize/2");
            }

            System.arraycopy(IV, 0, CTR, 0, IV.length);
            for (int i = IV.length; i < blockSize; i++)
            {
                CTR[i] = 0;
            }

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
            }
        }
        else
        {
            initArrays();

            // if it's null, key is to be reused.
            if (params != null)
            {
                cipher.init(true, params);
            }
        }

        initialized = true;
    }
    
    private void initArrays()
    {
        IV = new byte[blockSize / 2];
        CTR = new byte[blockSize];
        buf = new byte[s];
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/GCTR"
     * and the block size in bits
     */
    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/GCTR";
    }

    /**
     * return the block size we are operating at (in bytes).
     *
     * @return the block size we are operating at (in bytes).
     */
    public int getBlockSize()
    {
        return s;
    }

    /**
     * Process one block of input from the array in and write it to
     * the out array.
     *
     * @param in     the array containing the input data.
     * @param inOff  offset into the in array the data starts at.
     * @param out    the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @return the number of bytes processed and produced.
     * @throws DataLengthException if there isn't enough data in in, or
     * space in out.
     * @throws IllegalStateException if the cipher isn't initialised.
     */
    public int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
        throws DataLengthException, IllegalStateException
    {

        processBytes(in, inOff, s, out, outOff);

        return s;
    }

    protected byte calculateByte(byte in)
    {

        if (byteCount == 0)
        {
            buf = generateBuf();
        }

        byte rv = (byte)(buf[byteCount] ^ in);
        byteCount++;

        if (byteCount == s)
        {
            byteCount = 0;
            generateCRT();
        }

        return rv;

    }

    private void generateCRT()
    {
        CTR[CTR.length - 1]++;
    }


    private byte[] generateBuf()
    {

        byte[] encryptedCTR = new byte[CTR.length];
        cipher.processBlock(CTR, 0, encryptedCTR, 0);

        return GOST3413CipherUtil.MSB(encryptedCTR, s);

    }


    /**
     * reset the feedback vector back to the IV and reset the underlying
     * cipher.
     */
    public void reset()
    {
        if (initialized)
        {
            System.arraycopy(IV, 0, CTR, 0, IV.length);
            for (int i = IV.length; i < blockSize; i++)
            {
                CTR[i] = 0;
            }
            byteCount = 0;
            cipher.reset();
        }
    }
}
