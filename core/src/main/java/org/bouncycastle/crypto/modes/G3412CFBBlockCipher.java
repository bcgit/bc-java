package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.GOST3412ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.util.GOST3412CipherUtil;

/**
 * An implementation of the CFB mode for GOST 3412 2015 cipher.
 * See  <a href="http://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
 */
public class G3412CFBBlockCipher implements BlockCipher {

    private int s;
    private int m;
    private int blockSize;
    private byte[] R;
    private byte[] R_init;
    private BlockCipher cipher;
    private boolean forEncryption;
    private boolean initialized = false;

    /**
     * @param cipher base cipher
     */
    public G3412CFBBlockCipher(BlockCipher cipher) {
        this.blockSize = cipher.getBlockSize();
        this.cipher = cipher;
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
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {

        this.forEncryption = forEncryption;
        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV) params;

            setupDefaultParams();

            initArrays();

            R_init = GOST3412CipherUtil.initIV(ivParam.getIV(), m);
            System.arraycopy(R_init, 0, R, 0, R_init.length);


            // if null it's an IV changed only.
            if (ivParam.getParameters() != null) {
                cipher.init(true, ivParam.getParameters());
            }
        } else if (params instanceof GOST3412ParametersWithIV) {
            GOST3412ParametersWithIV ivParam = (GOST3412ParametersWithIV) params;

            this.s = ivParam.getS() / 8;
            this.m = ivParam.getM() / 8;

            validateParams();

            initArrays();

            R_init = GOST3412CipherUtil.initIV(ivParam.getIV(), m);
            System.arraycopy(R_init, 0, R, 0, R_init.length);

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null) {
                cipher.init(true, ivParam.getParameters());
            }
        } else {
            setupDefaultParams();

            initArrays();
            System.arraycopy(R_init, 0, R, 0, R_init.length);


            // if it's null, key is to be reused.
            if (params != null) {
                cipher.init(true, params);
            }
        }

        initialized = true;
    }


    private void validateParams() throws IllegalArgumentException{

        if(s < 0 || s > blockSize){
            throw new IllegalArgumentException("Parameter s must be in range 0 < s <= blockSize");
        }

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
     * this method sets default values to <b>s</b> and <b>m</b> parameters:<br>
     * s = <b>blockSize</b>; <br>
     * m = <b>2 * blockSize</b>
     */
    private void setupDefaultParams() {
        this.s = blockSize;
        this.m = 2 * blockSize;
    }



    public String getAlgorithmName() {
        return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
    }

    public int getBlockSize() {
        return blockSize;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {

        byte[] gamma = createGamma();
        byte[] input = GOST3412CipherUtil.copyFromInput(in, blockSize, inOff);
        byte[] c = GOST3412CipherUtil.sum(input, gamma);

        System.arraycopy(c, 0, out, outOff, c.length);


        if(out.length > (outOff + c.length) ) {

            if (forEncryption) {
                generateR(c);
            } else {
                generateR(input);
            }
        }
        return c.length;
    }

    /**
     * creating gamma value
     *
     * @return gamma
     */
    byte[] createGamma() {
        byte[] msb = GOST3412CipherUtil.MSB(R, blockSize);
        byte[] encryptedMsb = new byte[msb.length];
        cipher.processBlock(msb, 0, encryptedMsb, 0);
        return GOST3412CipherUtil.MSB(encryptedMsb, s);
    }

    /**
     * generate new R value
     *
     * @param C processed block
     */
    void generateR(byte[] C) {

        byte[] buf = GOST3412CipherUtil.LSB(R, m - s);
        System.arraycopy(buf, 0, R, 0, buf.length);
        System.arraycopy(C, 0, R, buf.length, m - buf.length);
    }

    /**
     * copy R_init into R and reset the underlying
     * cipher.
     */
    public void reset() {

        if (initialized) {
            System.arraycopy(R_init, 0, R, 0, R_init.length);

            cipher.reset();
        }
    }
}
