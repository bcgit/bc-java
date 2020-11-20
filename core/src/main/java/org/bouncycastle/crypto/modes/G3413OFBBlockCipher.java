package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * An implementation of the OFB mode for GOST 3412 2015 cipher.
 * See  <a href="https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
 */
public class G3413OFBBlockCipher
    extends StreamBlockCipher
{
    //    private int s;
    private int m;
    private int blockSize;
    private byte[] R;
    private byte[] R_init;
    private byte[] Y;
    private BlockCipher cipher;
    private int byteCount;
    private boolean initialized = false;

    /**
     * @param cipher base cipher
     */
    public G3413OFBBlockCipher(BlockCipher cipher)
    {
        super(cipher);
        this.blockSize = cipher.getBlockSize();
        this.cipher = cipher;
        Y = new byte[blockSize];
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;

            byte[] iv = ivParam.getIV();

            if (iv.length < blockSize)
            {
                throw new IllegalArgumentException("Parameter m must blockSize <= m");
            }
            this.m = iv.length;

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
        return cipher.getAlgorithmName() + "/OFB";
    }

    public int getBlockSize()
    {
        return blockSize;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {

        processBytes(in, inOff, blockSize, out, outOff);
        return blockSize;
    }


    protected byte calculateByte(byte in)
    {
        if (byteCount == 0)
        {
            generateY();
        }

        byte rv = (byte)(Y[byteCount] ^ in);
        byteCount++;

        if (byteCount == getBlockSize())
        {
            byteCount = 0;
            generateR();
        }

        return rv;
    }

    /**
     * generate new Y value
     */
    private void generateY()
    {
        byte[] msb = GOST3413CipherUtil.MSB(R, blockSize);
        cipher.processBlock(msb, 0, Y, 0);
    }


    /**
     * generate new R value
     */
    private void generateR()
    {
        byte[] buf = GOST3413CipherUtil.LSB(R, m - blockSize);
        System.arraycopy(buf, 0, R, 0, buf.length);
        System.arraycopy(Y, 0, R, buf.length, m - buf.length);
    }


    public void reset()
    {
        if (initialized)
        {
            System.arraycopy(R_init, 0, R, 0, R_init.length);
            Arrays.clear(Y);
            byteCount = 0;
            cipher.reset();
        }
    }
}
