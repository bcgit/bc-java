package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * CFB mode for GOST 3412 2015 cipher. See  <a href="http://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
 */
public class G3412CFBBlockCipher extends StreamBlockCipher {

    private int s;
    private int m;
    private int blockSize;
    private byte[] R;
    private byte[] R_init;
    private BlockCipher cipher;

    /**
     * @param cipher base cipher
     * @param s      parameter s in bits
     * @param m      parameter m in bits
     */
    public G3412CFBBlockCipher(BlockCipher cipher, int s, int m) {
        super(cipher);
        this.blockSize = cipher.getBlockSize();
        this.cipher = cipher;
        this.s = s / 8;
        this.m = m / 8;
        this.R = new byte[this.m];
        R_init = new byte[this.m];
    }

    protected byte calculateByte(byte b) {
        return 0;
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

        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            byte[] iv = ivParam.getIV();

            if (iv.length < R.length) {
                System.arraycopy(iv, 0, R_init, R_init.length - iv.length, iv.length);
                for (int i = 0; i < R_init.length - iv.length; i++) {
                    R[i] = 0;
                }
            } else {
                System.arraycopy(iv, 0, R_init, 0, R_init.length);
            }

            reset();
            System.arraycopy(R_init, 0, R, 0, R_init.length);

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null) {
                cipher.init(true, ivParam.getParameters());
            }


        } else {
            reset();

            // if it's null, key is to be reused.
            if (params != null) {
                cipher.init(true, params);
            }
        }
    }

    /**
     * copy first <b>size</b> elements from <b>from</b>
     *
     * @param from source array
     * @param size size of new array
     * @return
     */
    private byte[] MSB(byte[] from, int size) {
        return Arrays.copyOf(from, size);
    }

    /**
     * copy last <b>size</b> elements from <b>from</b>
     *
     * @param from source array
     * @param size size of new array
     * @return
     */
    private byte[] LSB(byte[] from, int size) {
        byte[] result = new byte[size];
        int index = 0;
        for (int i = from.length - size; i < from.length; i++) {
            result[index] = from[i];
            index++;
        }
        return result;
    }


    public String getAlgorithmName() {
        return cipher.getAlgorithmName() + "/OFB" + (blockSize * 8);
    }


    public int getBlockSize() {
        return blockSize;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {


        int processedBlockSize;

        if(in.length < blockSize){
            byte[] C = processOneBlock(in, in.length);

            try {
                System.arraycopy(C, 0, out, outOff, C.length);
            } catch (Exception e) {
                e.printStackTrace();
            }

            processedBlockSize = in.length;
        }
        else {

            byte[] bufIn = copyInput(in, blockSize, inOff);
            byte[] C = processOneBlock(bufIn, s);

            generateR(C);

            System.arraycopy(C, 0, out, outOff, C.length);


            processedBlockSize = blockSize;
        }

        return processedBlockSize;
    }


    private byte[] copyInput(byte[]input, int size, int offset){

        byte[] newIn = new byte[size];
        for (int i = 0; i < size ; i++) {
            newIn[i] = input[i + offset];
        }
        return newIn;
    }

    /**
     * cipher main step
     *
     * @param in       input text
     * @param gammaLen gamma size
     * @return encrypted/decrypted block
     */
    private byte[] processOneBlock(byte[] in, int gammaLen) {

        byte[] msb = new byte[blockSize];
        cipher.processBlock(MSB(R, blockSize), 0, msb, 0);
        byte[] gamma = MSB(msb, gammaLen);
        return sum(in, gamma);
    }

    /**
     * componentwise addition modulo 2
     *
     * @param in    clear text
     * @param gamma gamma parameter
     * @return
     */
    private byte[] sum(byte[] in, byte[] gamma) {

        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ gamma[i]);
        }
        return out;

    }

    /**
     * generate new R value
     *
     * @param C processed block
     */
    private void generateR(byte[] C) {

        byte[] buf = LSB(R, m - s);
        System.arraycopy(buf, 0, R, 0, buf.length);

        int j = 0;
        for (int i = buf.length; i < m; j++, i++) {
            R[i] = C[j];
        }
    }

    /**
     * copy R_init into R and reset the underlying
     * cipher.
     */
    public void reset() {

//        System.arraycopy(R_init, 0, R, 0, R_init.length);

        cipher.reset();
    }
}
