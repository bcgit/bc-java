package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * An implementation of the CFB mode for GOST 3412 2015 cipher.
 * See  <a href="https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
 */
public class G3413CFBBlockCipher
    extends StreamBlockCipher
{
    private final int s;
    private int m;
    private int blockSize;
    private byte[] R;
    private byte[] R_init;
    private BlockCipher cipher;
    private boolean forEncryption;
    private boolean initialized = false;

    private byte[] gamma;
    private byte[] inBuf;
    private int byteCount;

    /**
     * Base constructor.
     *
     * @param cipher base cipher
     */
    public G3413CFBBlockCipher(BlockCipher cipher)
    {
        this(cipher, cipher.getBlockSize() * 8);
    }

    /**
     * Base constructor with specific block size.
     *
     * @param cipher base cipher
     * @param bitBlockSize basic unit (defined as s)
     */
    public G3413CFBBlockCipher(BlockCipher cipher, int bitBlockSize)
    {
        super(cipher);

        if (bitBlockSize < 0 || bitBlockSize > cipher.getBlockSize() * 8)
        {
            throw new IllegalArgumentException("Parameter bitBlockSize must be in range 0 < bitBlockSize <= "
                            + cipher.getBlockSize() * 8);
        }

        this.blockSize = cipher.getBlockSize();
        this.cipher = cipher;
        this.s = bitBlockSize / 8;
        inBuf = new byte[getBlockSize()];
    }

    /**
     * Initialise the cipher and initialisation vector R.
     * If an IV isn't passed as part of the parameter, the IV will be all zeros.
     * An IV which is too short is handled in FIPS compliant fashion.
     * R_init = IV, and R1 = R_init
     *
     * @param forEncryption ignored because encryption and decryption are same
     * @param params        the key and other data required by the cipher.
     * @throws IllegalArgumentException
     */
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;

            byte[] iv = ivParam.getIV();

            if (iv.length < blockSize)
            {
                throw new IllegalArgumentException("Parameter m must blockSize <= m");
            }
            m = iv.length;

            initArrays();

            R_init = Arrays.clone(iv);
            System.arraycopy(R_init, 0, R, 0, R_init.length);


            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
            }
        }
        else
        {
            setupDefaultParams();

            initArrays();
            System.arraycopy(R_init, 0, R, 0, R_init.length);


            // if it's null, key is to be reused.
            if (params != null)
            {
                cipher.init(true, params);
            }
        }

        initialized = true;
    }

    /**
     * allocate memory for R and R_init arrays
     */
    private void initArrays()
    {
        R = new byte[m];
        R_init = new byte[m];
    }

    /**
     * this method sets default values to <b>s</b> and <b>m</b> parameters:<br>
     * s = <b>blockSize</b>; <br>
     * m = <b>2 * blockSize</b>
     */
    private void setupDefaultParams()
    {
        this.m = 2 * blockSize;
    }


    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
    }

    public int getBlockSize()
    {
        return s;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        this.processBytes(in, inOff, getBlockSize(), out, outOff);

        return getBlockSize();
    }

    protected byte calculateByte(byte in)
    {
        if (byteCount == 0)
        {
            gamma = createGamma();
        }

        byte rv = (byte)(gamma[byteCount] ^ in);
        inBuf[byteCount++] = (forEncryption) ? rv : in;

        if (byteCount == getBlockSize())
        {
            byteCount = 0;
            generateR(inBuf);
        }

        return rv;
    }

    /**
     * creating gamma value
     *
     * @return gamma
     */
    byte[] createGamma()
    {
        byte[] msb = GOST3413CipherUtil.MSB(R, blockSize);
        byte[] encryptedMsb = new byte[msb.length];
        cipher.processBlock(msb, 0, encryptedMsb, 0);
        return GOST3413CipherUtil.MSB(encryptedMsb, s);
    }

    /**
     * generate new R value
     *
     * @param C processed block
     */
    void generateR(byte[] C)
    {

        byte[] buf = GOST3413CipherUtil.LSB(R, m - s);
        System.arraycopy(buf, 0, R, 0, buf.length);
        System.arraycopy(C, 0, R, buf.length, m - buf.length);
    }

    /**
     * copy R_init into R and reset the underlying
     * cipher.
     */
    public void reset()
    {

        byteCount = 0;
        Arrays.clear(inBuf);
        Arrays.clear(gamma);

        if (initialized)
        {
            System.arraycopy(R_init, 0, R, 0, R_init.length);

            cipher.reset();
        }
    }
}
