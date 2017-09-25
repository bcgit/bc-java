package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * An implementation of the CFB mode for GOST 3412 2015 cipher in streaming mode.
 */
public class G3412CFBStreamBlockCipher extends StreamBlockCipher {

    private byte[] gamma;
    private byte[] inBuf;
    private int byteCount;
    private G3412CFBBlockCipher cipher;
    private boolean encrypting;

    public G3412CFBStreamBlockCipher(BlockCipher cipher) {
        super(cipher);
        this.cipher = new G3412CFBBlockCipher(cipher);
        inBuf = new byte[getBlockSize()];
    }

    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        cipher.init(forEncryption, params);
        encrypting = forEncryption;
        byteCount = 0;
    }

    public String getAlgorithmName() {
        return cipher.getAlgorithmName() + "Stream";
    }

    public int getBlockSize() {
        return cipher.getBlockSize();
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        int blockSize = getBlockSize();
        processBytes(in, inOff, blockSize, out, outOff);
        return blockSize;
    }

    protected byte calculateByte(byte in) {
        if (byteCount == 0) {
            gamma = cipher.createGamma();
        }

        byte rv = (byte) (gamma[byteCount] ^ in);
        inBuf[byteCount++] = (encrypting) ? rv : in;

        if (byteCount == getBlockSize()) {
            byteCount = 0;
            cipher.generateR(inBuf);
        }

        return rv;
    }

    public void reset() {
        byteCount = 0;
        Arrays.clear(inBuf);
        Arrays.clear(gamma);
        cipher.reset();
    }
}
