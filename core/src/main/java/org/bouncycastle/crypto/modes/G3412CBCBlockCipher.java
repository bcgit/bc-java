package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.GOST3412ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.util.GOST3412CipherUtil;
import org.bouncycastle.util.Arrays;

/**
 * An implementation of the CBC mode for GOST 3412 2015 cipher.
 * See  <a href="http://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
 */
public class G3412CBCBlockCipher implements BlockCipher {

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
    public G3412CBCBlockCipher(BlockCipher cipher) {
        this.blockSize = cipher.getBlockSize();
        this.cipher = cipher;
    }

    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {

        this.forEncryption = forEncryption;
        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV) params;

            setupDefaultParams();

            initArrays();

            initIV(ivParam.getIV());
            System.arraycopy(R_init, 0, R, 0, R_init.length);


            // if null it's an IV changed only.
            if (ivParam.getParameters() != null) {
                cipher.init(forEncryption, ivParam.getParameters());
            }


        }
        if (params instanceof GOST3412ParametersWithIV) {
            GOST3412ParametersWithIV ivParam = (GOST3412ParametersWithIV) params;

            this.m = ivParam.getM() / 8;

            validateParams();

            initArrays();

            initIV(ivParam.getIV());
            System.arraycopy(R_init, 0, R, 0, R_init.length);

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null) {
                cipher.init(forEncryption, ivParam.getParameters());
            }
        } else {

            setupDefaultParams();

            initArrays();
            System.arraycopy(R_init, 0, R, 0, R_init.length);

            // if it's null, key is to be reused.
            if (params != null) {
                cipher.init(forEncryption, params);
            }
        }

        initialized = true;
    }

    private void validateParams() throws IllegalArgumentException{

        if(m < blockSize){
            throw new IllegalArgumentException("Parameter m must blockSize <= m");
        }

    }


    /**
     * allocate memory for R and R_init arrays
     */
    private void initArrays() {
        R = new byte[m];
        R_init = new byte[m];
    }

    /**
     * this method sets default values to <b>m</b> parameter:<br>
     * m = <b>blockSize</b>
     */
    private void setupDefaultParams() {
        this.m = blockSize;
    }

    /**
     * init initial value for <b>R1</b>
     *
     * @param iv
     */
    private void initIV(byte[] iv) {
        if (iv.length < R.length) {
            System.arraycopy(iv, 0, R_init, R_init.length - iv.length, iv.length);
            for (int i = 0; i < R_init.length - iv.length; i++) {
                R_init[i] = 0;
            }
        } else {
            System.arraycopy(iv, 0, R_init, 0, R_init.length);
        }
    }

    public String getAlgorithmName() {
        return cipher.getAlgorithmName();
    }

    public int getBlockSize() {
        return blockSize;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {

        return (forEncryption) ? encrypt(in, inOff, out, outOff) : decrypt(in, inOff, out, outOff) ;
    }


    private int encrypt(byte[] in, int inOff, byte[] out, int outOff )
    {

        byte[] msb = GOST3412CipherUtil.MSB(R, blockSize);
        byte[] input = copyFromInput(in, blockSize, inOff);
        byte[] sum = GOST3412CipherUtil.sum(input, msb);
        byte[] c = new byte[sum.length];
        cipher.processBlock(sum, 0, c, 0);

        generateR(c);

        System.arraycopy(c, 0, out, outOff, c.length);
        return c.length;
    }


    private int decrypt(byte[] in, int inOff, byte[] out, int outOff )
    {

        byte[] msb = GOST3412CipherUtil.MSB(R, blockSize);
        byte[] input = copyFromInput(in, blockSize, inOff);

        byte[] c = new byte[input.length];
        cipher.processBlock(input, 0, c, 0);

        byte[] sum = GOST3412CipherUtil.sum(c, msb);


        generateR(input);

        System.arraycopy(sum, 0, out, outOff, sum.length);
        return sum.length;
    }

    /**
     * copy from <b>input</b> array <b>size</b> bytes with <b>offset</b>
     *
     * @param input  input byte array
     * @param size   count bytes to copy
     * @param offset <b>inputs</b> offset
     * @return
     */
    private byte[] copyFromInput(byte[] input, int size, int offset) {

        byte[] newIn = new byte[size];
        System.arraycopy(input, offset, newIn, 0, size);
        return newIn;
    }


    /**
     * generate new R value
     *
     * @param C processed block
     */
    private void generateR(byte[] C) {

        byte[] buf = GOST3412CipherUtil.LSB(R, m - blockSize);
        System.arraycopy(buf, 0, R, 0, buf.length);
        System.arraycopy(C, 0, R, buf.length, m - buf.length);
    }



    public void reset() {
        if (initialized) {
            System.arraycopy(R_init, 0, R, 0, R_init.length);
            cipher.reset();
        }
    }
}
