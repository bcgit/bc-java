package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;

/**
 * implements the GOST 3412 2015 OFB counter mode (GCTR).
 */
public class GOFB3412BlockCipher extends StreamBlockCipher {


    private byte[] IV;
    private byte[] ofbV;
    private byte[] ofbOutV;
    private int byteCount;

    private final int blockSize;
    private final BlockCipher cipher;

    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     *               counter mode (must have a 64 bit block size).
     */
    public GOFB3412BlockCipher(
        BlockCipher cipher) {
        super(cipher);

        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();

        if (blockSize != 16) {
            throw new IllegalArgumentException("GCTR only for 128 bit block ciphers");
        }

        this.IV = new byte[cipher.getBlockSize()];
        this.ofbV = new byte[cipher.getBlockSize()];
        this.ofbOutV = new byte[cipher.getBlockSize()];
    }


    protected byte calculateByte(byte b) {
        return 0;
    }

    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {

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

    public int getBlockSize() {
        return blockSize;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        return 0;
    }

    public void reset() {

        System.arraycopy(IV, 0, ofbV, 0, IV.length);
        byteCount = 0;
        cipher.reset();

    }
}
