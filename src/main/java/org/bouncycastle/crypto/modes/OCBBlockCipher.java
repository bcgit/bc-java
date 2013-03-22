package org.bouncycastle.crypto.modes;

import java.util.Vector;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * An implementation of the "work in progress" Internet-Draft <a
 * href="http://tools.ietf.org/html/draft-irtf-cfrg-ocb-00">The OCB Authenticated-Encryption
 * Algorithm</a>, licensed per:
 * 
 * <blockquote> <a href="http://www.cs.ucdavis.edu/~rogaway/ocb/license1.pdf"</a> License for
 * Open-Source Software Implementations of OCB</a> (Jan 9, 2013) &mdash; &ldquo;License 1&rdquo; <br>
 * Under this license, you are authorized to make, use, and distribute open-source software
 * implementations of OCB. This license terminates for you if you sue someone over their open-source
 * software implementation of OCB claiming that you have a patent covering their implementation.
 * <p>
 * This is a non-binding summary of a legal document (the link above). The parameters of the license
 * are specified in the license document and that document is controlling. </blockquote>
 */
public class OCBBlockCipher implements AEADBlockCipher {

    private static final int BLOCK_SIZE = 16;

    private BlockCipher hashCipher;
    private BlockCipher mainCipher;

    // These fields are set by init and not modified by processing
    private boolean forEncryption;
    private int macSize;
    private byte[] initialAssociatedText;

    // L is key-dependent, but elements are lazily calculated
    private Vector L;

    // These fields are modified during processing
    private byte[] hashBlock, mainBlock;
    private int hashBlockPos, mainBlockPos;
    private long hashBlockCount, mainBlockCount;

    private byte[] Offset;
    private byte[] Sum;

    private byte[] macBlock;

    public OCBBlockCipher(BlockCipher hashCipher, BlockCipher mainCipher) {
        if (hashCipher == null) {
            throw new IllegalArgumentException("'hashCipher' cannot be null");
        }
        if (hashCipher.getBlockSize() != BLOCK_SIZE) {
            throw new IllegalArgumentException("'hashCipher' must have a block size of "
                + BLOCK_SIZE);
        }
        if (mainCipher == null) {
            throw new IllegalArgumentException("'mainCipher' cannot be null");
        }
        if (mainCipher.getBlockSize() != BLOCK_SIZE) {
            throw new IllegalArgumentException("'mainCipher' must have a block size of "
                + BLOCK_SIZE);
        }

        if (!hashCipher.getAlgorithmName().equals(mainCipher.getAlgorithmName())) {
            throw new IllegalArgumentException(
                "'hashCipher' and 'mainCipher' must be the same algorithm");
        }

        this.hashCipher = hashCipher;
        this.mainCipher = mainCipher;
    }

    public BlockCipher getUnderlyingCipher() {
        return mainCipher;
    }

    public String getAlgorithmName() {
        return mainCipher.getAlgorithmName() + "/OCB";
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException {

        this.forEncryption = forEncryption;
        this.macBlock = null;

        KeyParameter keyParam;

        byte[] N;
        if (params instanceof AEADParameters) {
            AEADParameters param = (AEADParameters) params;

            N = param.getNonce();
            initialAssociatedText = param.getAssociatedText();

            int macSizeBits = param.getMacSize();
            if (macSizeBits < 64 || macSizeBits > 128 || macSizeBits % 8 != 0) {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }

            macSize = macSizeBits / 8;
            keyParam = param.getKey();
        } else if (params instanceof ParametersWithIV) {
            ParametersWithIV param = (ParametersWithIV) params;

            N = param.getIV();
            initialAssociatedText = null;
            macSize = 16;
            keyParam = (KeyParameter) param.getParameters();
        } else {
            throw new IllegalArgumentException("invalid parameters passed to GCM");
        }

        this.hashBlock = new byte[16];
        this.mainBlock = new byte[forEncryption ? BLOCK_SIZE : (BLOCK_SIZE + macSize)];

        if (N == null) {
            N = new byte[0];
        }

        if (N.length > 16 || (N.length == 16 && (N[0] & 0x80) != 0)) {
            throw new IllegalArgumentException("IV must be no more than 127 bits");
        }

        /*
         * KEY-DEPENDENT INITIALISATION
         */

        // if keyParam is null we're reusing the last key.
        if (keyParam != null) {
            // TODO
        }

        // hashCipher always used in forward mode
        hashCipher.init(true, keyParam);
        mainCipher.init(forEncryption, keyParam);

        byte[] L_Star = new byte[16];
        hashCipher.processBlock(L_Star, 0, L_Star, 0);

        byte[] L_Dollar = new byte[16];
        OCB_double(L_Star, L_Dollar);

        byte[] L_0 = new byte[16];
        OCB_double(L_Star, L_Dollar);
        L.addElement(L_0);

        /*
         * NONCE-DEPENDENT AND PER-ENCRYPTION INITIALISATION
         */

        byte[] nonce = new byte[16];
        System.arraycopy(N, 0, nonce, nonce.length - N.length, N.length);
        if (N.length == 16) {
            nonce[0] &= 0x80;
        } else {
            nonce[15 - N.length] = 1;
        }

        int bottom = nonce[15] & 0x3F;

        byte[] Ktop = new byte[16];
        nonce[15] &= 0xC0;
        hashCipher.processBlock(nonce, 0, Ktop, 0);

        byte[] Stretch = new byte[24];
        System.arraycopy(Ktop, 0, Stretch, 0, 16);
        for (int i = 0; i < 8; ++i) {
            Stretch[16 + i] = (byte) (Ktop[i] ^ Ktop[i + 1]);
        }

        this.hashBlockPos = 0;
        this.mainBlockPos = 0;

        this.hashBlockCount = 0;
        this.mainBlockCount = 0;

        this.Offset = new byte[16];
        this.Sum = new byte[16];

        if (initialAssociatedText != null) {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    public byte[] getMac() {
        return Arrays.clone(macBlock);
    }

    public int getOutputSize(int len) {
        int totalData = len + mainBlockPos;
        if (forEncryption) {
            return totalData + macSize;
        }
        return totalData < macSize ? 0 : totalData - macSize;
    }

    public int getUpdateOutputSize(int len) {
        int totalData = len + mainBlockPos;
        if (!forEncryption) {
            if (totalData < macSize) {
                return 0;
            }
            totalData -= macSize;
        }
        return totalData - totalData % BLOCK_SIZE;
    }

    public void processAADByte(byte input) {
        hashBlock[hashBlockPos] = input;
        if (++hashBlockPos == hashBlock.length) {
            updateHASH();
        }
    }

    public void processAADBytes(byte[] input, int off, int len) {
        for (int i = 0; i < len; ++i) {
            hashBlock[hashBlockPos] = input[off + i];
            if (++hashBlockPos == hashBlock.length) {
                updateHASH();
            }
        }
    }

    private void updateHASH() {
//        assert hashBlockPos == hashBlock.length;
        hashBlockPos = 0;
        xor(Offset, getLSub(OCB_ntz(++hashBlockCount)));
        xor(hashBlock, Offset);
        hashCipher.processBlock(hashBlock, 0, hashBlock, 0);
        xor(Sum, hashBlock);
    }

    public int processByte(byte input, byte[] output, int outOff) throws DataLengthException {
        mainBlock[mainBlockPos] = input;
        if (++mainBlockPos == mainBlock.length) {
            updateCRYPT(output, outOff);
            return BLOCK_SIZE;
        }
        return 0;
    }

    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException {

        int resultLen = 0;

        for (int i = 0; i < len; ++i) {
            mainBlock[mainBlockPos] = input[inOff + i];
            if (++mainBlockPos == mainBlock.length) {
                updateCRYPT(output, outOff + resultLen);
                resultLen += BLOCK_SIZE;
            }
        }

        return resultLen;
    }

    private void updateCRYPT(byte[] output, int outOff) {
//      assert mainBlockPos == mainBlock.length;
        mainBlockPos = 0;
        
        // TODO
    }

    public int doFinal(byte[] out, int outOff) throws IllegalStateException,
        InvalidCipherTextException {

        // TODO

        reset(false);

        // TODO
        return 0;
    }

    public void reset() {
        reset(true);
    }

    protected void reset(boolean clearMac) {
        hashCipher.reset();
        mainCipher.reset();

        hashBlockPos = 0;
        mainBlockPos = 0;

        if (hashBlock != null) {
            Arrays.fill(hashBlock, (byte) 0);
        }
        if (mainBlock != null) {
            Arrays.fill(mainBlock, (byte) 0);
        }

        if (clearMac) {
            macBlock = null;
        }

        if (initialAssociatedText != null) {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    protected byte[] getLSub(int n) {
        while (n >= L.size()) {
            byte[] L_i = new byte[16];
            OCB_double((byte[]) L.lastElement(), L_i);
            L.addElement(L_i);
        }
        return (byte[]) L.elementAt(n);
    }

    protected static void OCB_double(byte[] block, byte[] output) {
        int carry = shiftLeft(block, output);
        if (carry != 0) {
            output[15] ^= 0x10000111;
        }
    }

    protected static int OCB_ntz(long x) {
        if (x == 0) {
            return 64;
        }

        int n = 0;
        while ((x & 1L) == 0L) {
            ++n;
            x >>= 1;
        }
        return n;
    }

    protected static int shiftLeft(byte[] block, byte[] output) {
        int i = 16;
        int bit = 0;
        while (--i >= 0) {
            int b = block[i] & 0xff;
            output[i] = (byte) ((b << 1) | bit);
            bit = (b >>> 7) & 1;
        }
        return bit;
    }

    protected static void xor(byte[] block, byte[] val)
    {
        for (int i = 15; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }
}
