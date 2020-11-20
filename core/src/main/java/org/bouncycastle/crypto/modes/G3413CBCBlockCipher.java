package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * An implementation of the CBC mode for GOST 3412 2015 cipher.
 * See  <a href="https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
 */
public class G3413CBCBlockCipher
    implements BlockCipher
{

    private int m;
    private int blockSize;
    private byte[] R;
    private byte[] R_init;
    private BlockCipher cipher;
    private boolean initialized = false;
    private boolean forEncryption;

    /**
     * @param cipher base cipher
     */
    public G3413CBCBlockCipher(BlockCipher cipher)
    {
        this.blockSize = cipher.getBlockSize();
        this.cipher = cipher;
    }

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
            this.m = iv.length;

            initArrays();

            R_init = Arrays.clone(iv);
            System.arraycopy(R_init, 0, R, 0, R_init.length);

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(forEncryption, ivParam.getParameters());
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
                cipher.init(forEncryption, params);
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
     * this method sets default values to <b>m</b> parameter:<br>
     * m = <b>blockSize</b>
     */
    private void setupDefaultParams()
    {
        this.m = blockSize;
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/CBC";
    }

    public int getBlockSize()
    {
        return blockSize;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {

        return (forEncryption) ? encrypt(in, inOff, out, outOff) : decrypt(in, inOff, out, outOff);
    }


    private int encrypt(byte[] in, int inOff, byte[] out, int outOff)
    {

        byte[] msb = GOST3413CipherUtil.MSB(R, blockSize);
        byte[] input = GOST3413CipherUtil.copyFromInput(in, blockSize, inOff);
        byte[] sum = GOST3413CipherUtil.sum(input, msb);
        byte[] c = new byte[sum.length];
        cipher.processBlock(sum, 0, c, 0);

        System.arraycopy(c, 0, out, outOff, c.length);

        if (out.length > (outOff + sum.length))
        {
            generateR(c);
        }

        return c.length;
    }


    private int decrypt(byte[] in, int inOff, byte[] out, int outOff)
    {

        byte[] msb = GOST3413CipherUtil.MSB(R, blockSize);
        byte[] input = GOST3413CipherUtil.copyFromInput(in, blockSize, inOff);

        byte[] c = new byte[input.length];
        cipher.processBlock(input, 0, c, 0);

        byte[] sum = GOST3413CipherUtil.sum(c, msb);

        System.arraycopy(sum, 0, out, outOff, sum.length);


        if (out.length > (outOff + sum.length))
        {
            generateR(input);
        }

        return sum.length;
    }

    /**
     * generate new R value
     *
     * @param C processed block
     */
    private void generateR(byte[] C)
    {
        byte[] buf = GOST3413CipherUtil.LSB(R, m - blockSize);
        System.arraycopy(buf, 0, R, 0, buf.length);
        System.arraycopy(C, 0, R, buf.length, m - buf.length);
    }


    public void reset()
    {
        if (initialized)
        {
            System.arraycopy(R_init, 0, R, 0, R_init.length);
            cipher.reset();
        }
    }
}
