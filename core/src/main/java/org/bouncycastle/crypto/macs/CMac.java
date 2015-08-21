package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

/**
 * CMAC - as specified at www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
 * <p>
 * CMAC is analogous to OMAC1 - see also en.wikipedia.org/wiki/CMAC
 * </p><p>
 * CMAC is a NIST recomendation - see 
 * csrc.nist.gov/CryptoToolkit/modes/800-38_Series_Publications/SP800-38B.pdf
 * </p><p>
 * CMAC/OMAC1 is a blockcipher-based message authentication code designed and
 * analyzed by Tetsu Iwata and Kaoru Kurosawa.
 * </p><p>
 * CMAC/OMAC1 is a simple variant of the CBC MAC (Cipher Block Chaining Message 
 * Authentication Code). OMAC stands for One-Key CBC MAC.
 * </p><p>
 * It supports 128- or 64-bits block ciphers, with any key size, and returns
 * a MAC with dimension less or equal to the block size of the underlying 
 * cipher.
 * </p>
 */
public class CMac implements Mac
{
    private byte[] poly;
    private byte[] ZEROES;

    private byte[] mac;

    private byte[] buf;
    private int bufOff;
    private BlockCipher cipher;

    private int macSize;

    private byte[] Lu, Lu2;

    /**
     * create a standard MAC based on a CBC block cipher (64 or 128 bit block).
     * This will produce an authentication code the length of the block size
     * of the cipher.
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     */
    public CMac(BlockCipher cipher)
    {
        this(cipher, cipher.getBlockSize() * 8);
    }

    /**
     * create a standard MAC based on a block cipher with the size of the
     * MAC been given in bits.
     * <p>
     * Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
     * or 16 bits if being used as a data authenticator (FIPS Publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see Handbook of Applied Cryptography).
     *
     * @param cipher        the cipher to be used as the basis of the MAC generation.
     * @param macSizeInBits the size of the MAC in bits, must be a multiple of 8 and &lt;= 128.
     */
    public CMac(BlockCipher cipher, int macSizeInBits)
    {
        if ((macSizeInBits % 8) != 0)
        {
            throw new IllegalArgumentException("MAC size must be multiple of 8");
        }

        if (macSizeInBits > (cipher.getBlockSize() * 8))
        {
            throw new IllegalArgumentException(
                "MAC size must be less or equal to "
                    + (cipher.getBlockSize() * 8));
        }

        this.cipher = new CBCBlockCipher(cipher);
        this.macSize = macSizeInBits / 8;
        this.poly = lookupPoly(cipher.getBlockSize());

        mac = new byte[cipher.getBlockSize()];

        buf = new byte[cipher.getBlockSize()];

        ZEROES = new byte[cipher.getBlockSize()];

        bufOff = 0;
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName();
    }

    private static int shiftLeft(byte[] block, byte[] output)
    {
        int i = block.length;
        int bit = 0;
        while (--i >= 0)
        {
            int b = block[i] & 0xff;
            output[i] = (byte)((b << 1) | bit);
            bit = (b >>> 7) & 1;
        }
        return bit;
    }

    private byte[] doubleLu(byte[] in)
    {
        byte[] ret = new byte[in.length];
        int carry = shiftLeft(in, ret);

        /*
         * NOTE: This construction is an attempt at a constant-time implementation.
         */
        int mask = (-carry) & 0xff;
        ret[in.length - 3] ^= poly[1] & mask;
        ret[in.length - 2] ^= poly[2] & mask;
        ret[in.length - 1] ^= poly[3] & mask;

        return ret;
    }

    private static byte[] lookupPoly(int blockSizeLength)
    {
        int xor;
        switch (blockSizeLength * 8)
        {
        case 64:
            xor = 0x1B;
            break;
        case 128:
            xor = 0x87;
            break;
        case 160:
            xor = 0x2D;
            break;
        case 192:
            xor = 0x87;
            break;
        case 224:
            xor = 0x309;
            break;
        case 256:
            xor = 0x425;
            break;
        case 320:
            xor = 0x1B;
            break;
        case 384:
            xor = 0x100D;
            break;
        case 448:
            xor = 0x851;
            break;
        case 512:
            xor = 0x125;
            break;
        case 768:
            xor = 0xA0011;
            break;
        case 1024:
            xor = 0x80043;
            break;
        case 2048:
            xor = 0x86001;
            break;
        default:
            throw new IllegalArgumentException("Unknown block size for CMAC: " + (blockSizeLength * 8));
        }

        return Pack.intToBigEndian(xor);
    }

    public void init(CipherParameters params)
    {
        validate(params);

        cipher.init(true, params);

        //initializes the L, Lu, Lu2 numbers
        byte[] L = new byte[ZEROES.length];
        cipher.processBlock(ZEROES, 0, L, 0);
        Lu = doubleLu(L);
        Lu2 = doubleLu(Lu);

        reset();
    }

    void validate(CipherParameters params)
    {
        if (params != null)
        {
            if (!(params instanceof KeyParameter))
            {
                // CMAC mode does not permit IV to underlying CBC mode
                throw new IllegalArgumentException("CMac mode only permits key to be set.");
            }
        }
    }

    public int getMacSize()
    {
        return macSize;
    }

    public void update(byte in)
    {
        if (bufOff == buf.length)
        {
            cipher.processBlock(buf, 0, mac, 0);
            bufOff = 0;
        }

        buf[bufOff++] = in;
    }

    public void update(byte[] in, int inOff, int len)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException(
                "Can't have a negative input length!");
        }

        int blockSize = cipher.getBlockSize();
        int gapLen = blockSize - bufOff;

        if (len > gapLen)
        {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);

            cipher.processBlock(buf, 0, mac, 0);

            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            while (len > blockSize)
            {
                cipher.processBlock(in, inOff, mac, 0);

                len -= blockSize;
                inOff += blockSize;
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);

        bufOff += len;
    }

    public int doFinal(byte[] out, int outOff)
    {
        int blockSize = cipher.getBlockSize();

        byte[] lu;
        if (bufOff == blockSize)
        {
            lu = Lu;
        }
        else
        {
            new ISO7816d4Padding().addPadding(buf, bufOff);
            lu = Lu2;
        }

        for (int i = 0; i < mac.length; i++)
        {
            buf[i] ^= lu[i];
        }

        cipher.processBlock(buf, 0, mac, 0);

        System.arraycopy(mac, 0, out, outOff, macSize);

        reset();

        return macSize;
    }

    /**
     * Reset the mac generator.
     */
    public void reset()
    {
        /*
         * clean the buffer.
         */
        for (int i = 0; i < buf.length; i++)
        {
            buf[i] = 0;
        }

        bufOff = 0;

        /*
         * reset the underlying cipher.
         */
        cipher.reset();
    }
}
