/**
 * A Cipher Text Stealing (CTS) mode cipher. CTS allows block ciphers to
 * be used to produce cipher text which is the same length as the plain text.
 */
package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;

/**
 * A Cipher Text Stealing (CTS) mode cipher. CTS allows block ciphers to
 * be used to produce cipher text which is the same length as the plain text.
 * <p>
 *     This class implements the NIST version as documented in "Addendum to NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation: Three Variants of Ciphertext Stealing for CBC Mode"
 * </p>
 */
public class NISTCTSBlockCipher
    extends BufferedBlockCipher
{
    public static final int CS1 = 1;
    public static final int CS2 = 2;
    public static final int CS3 = 3;

    private final int type;
    private final int blockSize;

    /**
     * Create a buffered block cipher that uses NIST Cipher Text Stealing
     *
     * @param type type of CTS mode (CS1, CS2, or CS3)
     * @param cipher the underlying block cipher used to create the CBC block cipher this cipher uses..
     */
    public NISTCTSBlockCipher(
        int type,
        BlockCipher cipher)
    {
        this.type = type;
        this.cipher = new CBCBlockCipher(cipher);

        blockSize = cipher.getBlockSize();

        buf = new byte[blockSize * 2];
        bufOff = 0;
    }

    /**
     * return the size of the output buffer required for an update
     * an input of len bytes.
     *
     * @param len the length of the input.
     * @return the space required to accommodate a call to update
     * with len bytes of input.
     */
    public int getUpdateOutputSize(
        int len)
    {
        int total       = len + bufOff;
        int leftOver    = total % buf.length;

        if (leftOver == 0)
        {
            return total - buf.length;
        }

        return total - leftOver;
    }

    /**
     * return the size of the output buffer required for an update plus a
     * doFinal with an input of len bytes.
     *
     * @param len the length of the input.
     * @return the space required to accommodate a call to update and doFinal
     * with len bytes of input.
     */
    public int getOutputSize(
        int len)
    {
        return len + bufOff;
    }

    /**
     * process a single byte, producing an output block if necessary.
     *
     * @param in the input byte.
     * @param out the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @exception org.bouncycastle.crypto.DataLengthException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     */
    public int processByte(
        byte        in,
        byte[]      out,
        int         outOff)
        throws DataLengthException, IllegalStateException
    {
        int         resultLen = 0;

        if (bufOff == buf.length)
        {
            resultLen = cipher.processBlock(buf, 0, out, outOff);
            System.arraycopy(buf, blockSize, buf, 0, blockSize);

            bufOff = blockSize;
        }

        buf[bufOff++] = in;

        return resultLen;
    }

    /**
     * process an array of bytes, producing output if necessary.
     *
     * @param in the input byte array.
     * @param inOff the offset at which the input data starts.
     * @param len the number of bytes to be copied out of the input array.
     * @param out the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @exception org.bouncycastle.crypto.DataLengthException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     */
    public int processBytes(
        byte[]      in,
        int         inOff,
        int         len,
        byte[]      out,
        int         outOff)
        throws DataLengthException, IllegalStateException
    {
        if (len < 0)
        {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }

        int blockSize   = getBlockSize();
        int length      = getUpdateOutputSize(len);

        if (length > 0)
        {
            if ((outOff + length) > out.length)
            {
                throw new OutputLengthException("output buffer too short");
            }
        }

        int resultLen = 0;
        int gapLen = buf.length - bufOff;

        if (len > gapLen)
        {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);

            resultLen += cipher.processBlock(buf, 0, out, outOff);
            System.arraycopy(buf, blockSize, buf, 0, blockSize);

            bufOff = blockSize;

            len -= gapLen;
            inOff += gapLen;

            while (len > blockSize)
            {
                System.arraycopy(in, inOff, buf, bufOff, blockSize);
                resultLen += cipher.processBlock(buf, 0, out, outOff + resultLen);
                System.arraycopy(buf, blockSize, buf, 0, blockSize);

                len -= blockSize;
                inOff += blockSize;
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);

        bufOff += len;

        return resultLen;
    }

    /**
     * Process the last block in the buffer.
     *
     * @param out the array the block currently being held is copied into.
     * @param outOff the offset at which the copying starts.
     * @return the number of output bytes copied to out.
     * @exception org.bouncycastle.crypto.DataLengthException if there is insufficient space in out for
     * the output.
     * @exception IllegalStateException if the underlying cipher is not
     * initialised.
     * @exception org.bouncycastle.crypto.InvalidCipherTextException if cipher text decrypts wrongly (in
     * case the exception will never get thrown).
     */
    public int doFinal(
        byte[]  out,
        int     outOff)
        throws DataLengthException, IllegalStateException, InvalidCipherTextException
    {
        if (bufOff + outOff > out.length)
        {
            throw new OutputLengthException("output buffer to small in doFinal");
        }

        int     blockSize = cipher.getBlockSize();
        int     len = bufOff - blockSize;
        byte[]  block = new byte[blockSize];

        if (forEncryption)
        {
            if (bufOff < blockSize)
            {
                throw new DataLengthException("need at least one block of input for NISTCTS");
            }

            if (bufOff > blockSize)
            {
                byte[]  lastBlock = new byte[blockSize];

                if (this.type == CS2 || this.type == CS3)
                {
                    cipher.processBlock(buf, 0, block, 0);

                    System.arraycopy(buf, blockSize, lastBlock, 0, len);

                    cipher.processBlock(lastBlock, 0, lastBlock, 0);

                    if (this.type == CS2 && len == blockSize)
                    {
                        System.arraycopy(block, 0, out, outOff, blockSize);

                        System.arraycopy(lastBlock, 0, out, outOff + blockSize, len);
                    }
                    else
                    {
                        System.arraycopy(lastBlock, 0, out, outOff, blockSize);

                        System.arraycopy(block, 0, out, outOff + blockSize, len);
                    }
                }
                else
                {
                    System.arraycopy(buf, 0, block, 0, blockSize);
                    cipher.processBlock(block, 0, block, 0);
                    System.arraycopy(block, 0, out, outOff, len);

                    System.arraycopy(buf, bufOff - len, lastBlock, 0, len);
                    cipher.processBlock(lastBlock, 0, lastBlock, 0);
                    System.arraycopy(lastBlock, 0, out, outOff + len, blockSize);
                }
            }
            else
            {
                cipher.processBlock(buf, 0, block, 0);

                System.arraycopy(block, 0, out, outOff, blockSize);
            }
        }
        else
        {
            if (bufOff < blockSize)
            {
                throw new DataLengthException("need at least one block of input for CTS");
            }

            byte[]  lastBlock = new byte[blockSize];

            if (bufOff > blockSize)
            {
                if (this.type == CS3 || (this.type == CS2 && ((buf.length - bufOff) % blockSize) != 0))
                {
                    if (cipher instanceof CBCBlockCipher)
                    {
                        BlockCipher c = ((CBCBlockCipher)cipher).getUnderlyingCipher();

                        c.processBlock(buf, 0, block, 0);
                    }
                    else
                    {
                        cipher.processBlock(buf, 0, block, 0);
                    }

                    for (int i = blockSize; i != bufOff; i++)
                    {
                        lastBlock[i - blockSize] = (byte)(block[i - blockSize] ^ buf[i]);
                    }

                    System.arraycopy(buf, blockSize, block, 0, len);

                    cipher.processBlock(block, 0, out, outOff);
                    System.arraycopy(lastBlock, 0, out, outOff + blockSize, len);
                }
                else
                {
                    BlockCipher c = ((CBCBlockCipher)cipher).getUnderlyingCipher();

                    c.processBlock(buf, bufOff - blockSize, lastBlock, 0);

                    System.arraycopy(buf, 0, block, 0, blockSize);

                    if (len != blockSize)
                    {
                        System.arraycopy(lastBlock, len, block, len, blockSize - len);
                    }

                    cipher.processBlock(block, 0, block, 0);

                    System.arraycopy(block, 0, out, outOff, blockSize);

                    for (int i = 0; i != len; i++)
                    {
                        lastBlock[i] ^= buf[i];
                    }

                    System.arraycopy(lastBlock, 0, out, outOff + blockSize, len);
                }
            }
            else
            {
                cipher.processBlock(buf, 0, block, 0);

                System.arraycopy(block, 0, out, outOff, blockSize);
            }
        }

        int offset = bufOff;

        reset();

        return offset;
    }
}
