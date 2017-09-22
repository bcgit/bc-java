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
public class GCTRBlockCipher2 implements BlockCipher {


    private int s;
    private byte[] ofbV;
    private byte[] ofbOutV;
    private byte[] CTR;
    private final int blockSize;
    private final BlockCipher cipher;
    private int byteCount = 0;
    private int inputCounter = 0;


    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     *               counter mode (must have a 64 bit block size).
     */
    public GCTRBlockCipher2(
        BlockCipher cipher, int s) {

        this.s = s;
        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        CTR = new byte[blockSize];
        ofbV = new byte[blockSize];
        ofbOutV = new byte[blockSize];

        if (s > blockSize || s <= 0) {
            throw new IllegalArgumentException("GCTR parameter s must be in range 0 < s <= block size");
        }
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
     *                                  inappropriate.
     */
    public void init(
        boolean encrypting, //ignored by this CTR mode
        CipherParameters params)
        throws IllegalArgumentException {

        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            byte[] iv = ivParam.getIV();

            if (iv.length != (blockSize / 2)) {
                throw new IllegalArgumentException("GCTR parameter IV must be = blocksize/2");
            }


            System.arraycopy(iv, 0, CTR, 0, iv.length);

            Arrays.fill(CTR, blockSize / 2, (byte) 0);

            reset();

            // if params is null we reuse the current working key.
            if (ivParam.getParameters() != null) {
                cipher.init(true, ivParam.getParameters());
            }
        } else {
            reset();

            // if params is null we reuse the current working key.
            if (params != null) {
                cipher.init(true, params);
            }
        }
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/GCTR"
     * and the block size in bits
     */
    public String getAlgorithmName() {
        return cipher.getAlgorithmName() + "/GCTR";
    }

    /**
     * return the block size we are operating at (in bytes).
     *
     * @return the block size we are operating at (in bytes).
     */
    public int getBlockSize() {
        return blockSize;
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
     * @throws DataLengthException   if there isn't enough data in in, or
     *                               space in out.
     * @throws IllegalStateException if the cipher isn't initialised.
     */
    public int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
        throws DataLengthException, IllegalStateException {

        int blocsize = 0;

        if (inputCounter < s) {
            cipher.processBlock(CTR, 0, CTR, 0);
            byte[] msb = MSB(CTR, s);
            byte[] sum = sum(in, msb);
            System.arraycopy(sum, 0, out, outOff, sum.length);
            blocsize = sum.length;
            CTR = add(CTR);
        } else {
            cipher.processBlock(CTR, 0, CTR, 0);
            byte[] msb = MSB(CTR, in.length);
            byte[] sum = sum(in, msb);
            System.arraycopy(sum, 0, out, outOff, sum.length);
            blocsize = sum.length;
            CTR = add(CTR);
        }

        return blocsize;

//        cipher.processBlock(in, inOff, out, outOff);
//
//        byte[] ts = MSB(out, blockSize);
//        for (int i = 0; i < ts.length; i++) {
//            ts[i] = (byte) (ts[i] ^ in[i]);
//        }
//
//        System.arraycopy(ts, 0, out, 0, ts.length);
//
//        return blockSize;
    }

    /**
     * reset the feedback vector back to the IV and reset the underlying
     * cipher.
     */
    public void reset() {
        System.arraycopy(CTR, 0, ofbV, 0, CTR.length);
        byteCount = 0;
        cipher.reset();
    }


    private byte[] MSB(byte[] from, int size) {
        return Arrays.copyOf(from, size);
    }


    private byte[] add(byte[] prevCTR) {

        byte[] newCTR = new byte[prevCTR.length];
        for (int i = 0; i < prevCTR.length; i++) {
            newCTR[i] = (byte) (prevCTR[i] + 1);
        }
        return newCTR;
    }

    private byte[] ek(byte[] CTR) {

        byte[] out = new byte[CTR.length];

        cipher.processBlock(CTR, 0, out, 0);

        return out;
    }

    private byte[] sum(byte[] in, byte[] ctr) {

        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ ctr[i]);
        }
        return out;

    }
}
