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
 * An implementation of the OFB mode for GOST 3412 2015 cipher.
 * See  <a href="http://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
 */
public class G3412OFBBlockCipher extends StreamBlockCipher {

    private int s;
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
    public G3412OFBBlockCipher(BlockCipher cipher) {
        super(cipher);
        this.blockSize = cipher.getBlockSize();
        this.cipher = cipher;
        Y = new byte[blockSize];
    }

    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
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


        }
        if (params instanceof GOST3412ParametersWithIV) {
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
        return cipher.getAlgorithmName() +  "/OFB";
    }

    public int getBlockSize() {
        return blockSize;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {

        processBytes(in, inOff, blockSize, out, outOff);
        return blockSize;
    }


    protected byte calculateByte(byte in) {
        if (byteCount == 0) {
            generateY();
        }

        byte rv = (byte) (Y[byteCount] ^ in);
        byteCount++;

        if (byteCount == getBlockSize()) {
            byteCount = 0;
            generateR();
        }

        return rv;
    }

    /**
     * generate new Y value
     */
    private void generateY() {
        byte[] msb = GOST3412CipherUtil.MSB(R, blockSize);
        cipher.processBlock(msb, 0, Y, 0);
    }


    /**
     * generate new R value
     */
    private void generateR() {
        byte[] buf = GOST3412CipherUtil.LSB(R, m - blockSize);
        System.arraycopy(buf, 0, R, 0, buf.length);
        System.arraycopy(Y, 0, R, buf.length, m - buf.length);
    }


    public void reset() {
        if (initialized) {
            System.arraycopy(R_init, 0, R, 0, R_init.length);
            Arrays.clear(Y);
            byteCount = 0;
            cipher.reset();
        }
    }
}
