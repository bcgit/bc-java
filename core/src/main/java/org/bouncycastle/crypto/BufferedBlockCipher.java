package org.bouncycastle.crypto;

/**
 * A wrapper class that allows block ciphers to be used to process data in
 * a piecemeal fashion. The BufferedBlockCipher outputs a block only when the
 * buffer is full and more data is being added, or on a doFinal.
 * <p>
 * Note: in the case where the underlying cipher is either a CFB cipher or an
 * OFB one the last block may not be a multiple of the block size.
 */
public class BufferedBlockCipher
{
    protected byte[] buf;
    protected int bufOff;

    protected boolean forEncryption;
    protected BlockCipher cipher;
    protected MultiBlockCipher mbCipher;

    protected boolean partialBlockOkay;
    protected boolean pgpCFB;

    /**
     * constructor for subclasses
     */
    BufferedBlockCipher()
    {
    }

    /**
     * Create a buffered block cipher without padding.
     *
     * @param cipher the underlying block cipher this buffering object wraps.
     * @deprecated use the constructor on DefaultBufferedBlockCipher.
     */
    public BufferedBlockCipher(
        BlockCipher cipher)
    {
        this.cipher = cipher;

        if (cipher instanceof MultiBlockCipher)
        {
            this.mbCipher = (MultiBlockCipher)cipher;
            buf = new byte[mbCipher.getMultiBlockSize()];
        }
        else
        {
            this.mbCipher = null;
            buf = new byte[cipher.getBlockSize()];
        }

        bufOff = 0;

        //
        // check if we can handle partial blocks on doFinal.
        //
        String name = cipher.getAlgorithmName();
        int idx = name.indexOf('/') + 1;

        pgpCFB = (idx > 0 && name.startsWith("PGP", idx));

        if (pgpCFB || cipher instanceof StreamCipher)
        {
            partialBlockOkay = true;
        }
        else
        {
            partialBlockOkay = (idx > 0 && (name.startsWith("OpenPGP", idx)));
        }
    }

    /**
     * return the cipher this object wraps.
     *
     * @return the cipher this object wraps.
     */
    public BlockCipher getUnderlyingCipher()
    {
        return cipher;
    }

    /**
     * initialise the cipher.
     *
     * @param forEncryption if true the cipher is initialised for
     *                      encryption, if false for decryption.
     * @param params        the key and other data required by the cipher.
     * @throws IllegalArgumentException if the params argument is
     *                                  inappropriate.
     */
    public void init(
        boolean forEncryption,
        CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;

        reset();

        cipher.init(forEncryption, params);
    }

    /**
     * return the blocksize for the underlying cipher.
     *
     * @return the blocksize for the underlying cipher.
     */
    public int getBlockSize()
    {
        return cipher.getBlockSize();
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
        int total = len + bufOff;
        int leftOver;

        if (pgpCFB)
        {
            if (forEncryption)
            {
                leftOver = total % buf.length - (cipher.getBlockSize() + 2);
            }
            else
            {
                leftOver = total % buf.length;
            }
        }
        else
        {
            leftOver = total % buf.length;
        }

        return total - leftOver;
    }

    /**
     * return the size of the output buffer required for an update plus a
     * doFinal with an input of 'length' bytes.
     *
     * @param length the length of the input.
     * @return the space required to accommodate a call to update and doFinal
     * with 'length' bytes of input.
     */
    public int getOutputSize(
        int length)
    {
        if (pgpCFB && forEncryption)
        {
            return length + bufOff + (cipher.getBlockSize() + 2);
        }

        // Note: Can assume partialBlockOkay is true for purposes of this calculation
        return length + bufOff;
    }

    /**
     * process a single byte, producing an output block if necessary.
     *
     * @param in the input byte.
     * @param out the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @exception DataLengthException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     */
    public int processByte(
        byte        in,
        byte[]      out,
        int         outOff)
        throws DataLengthException, IllegalStateException
    {
        int         resultLen = 0;

        buf[bufOff++] = in;

        if (bufOff == buf.length)
        {
            resultLen = processBuffer(out, outOff);
        }

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
     * @exception DataLengthException if there isn't enough space in out.
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
            if (bufOff != 0)
            {
                System.arraycopy(in, inOff, buf, bufOff, gapLen);
                inOff += gapLen;
                len -= gapLen;
            }

            if (in == out)
            {
                in = new byte[len];
                System.arraycopy(out, inOff, in, 0, len);
                inOff = 0;
            }

            // if bufOff non-zero buffer must now be full
            if (bufOff != 0)
            {
                resultLen += processBuffer(out, outOff);
            }

            if (mbCipher != null)
            {
                int blockCount = (len / mbCipher.getMultiBlockSize()) * (mbCipher.getMultiBlockSize() / blockSize);

                if (blockCount > 0)
                {
                    resultLen += mbCipher.processBlocks(in, inOff, blockCount, out, outOff + resultLen);

                    int processed = blockCount * blockSize;

                    len -= processed;
                    inOff += processed;
                }
            }
            else
            {
                while (len > buf.length)
                {
                    resultLen += cipher.processBlock(in, inOff, out, outOff + resultLen);

                    len -= blockSize;
                    inOff += blockSize;
                }
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);

        bufOff += len;

        if (bufOff == buf.length)
        {
            resultLen += processBuffer(out, outOff + resultLen);
        }

        return resultLen;
    }

    private int processBuffer(byte[] out, int outOff)
    {
        bufOff = 0;
        if (mbCipher != null)
        {
            return mbCipher.processBlocks(buf, 0, buf.length / mbCipher.getBlockSize(), out, outOff);
        }
        else
        {
            return cipher.processBlock(buf, 0, out, outOff);
        }
    }

    /**
     * Process the last block in the buffer.
     *
     * @param out    the array the block currently being held is copied into.
     * @param outOff the offset at which the copying starts.
     * @return the number of output bytes copied to out.
     * @throws DataLengthException        if there is insufficient space in out for
     *                                    the output, or the input is not block size aligned and should be.
     * @throws IllegalStateException      if the underlying cipher is not
     *                                    initialised.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @throws DataLengthException        if the input is not block size
     *                                    aligned.
     */
    public int doFinal(
        byte[] out,
        int outOff)
        throws DataLengthException, IllegalStateException, InvalidCipherTextException
    {
        try
        {
            int resultLen = 0;

            if (outOff + bufOff > out.length)
            {
                throw new OutputLengthException("output buffer too short for doFinal()");
            }

            if (bufOff != 0)
            {
                int index = 0;
                if (mbCipher != null)
                {
                    int nBlocks = bufOff / mbCipher.getBlockSize();
                    resultLen += mbCipher.processBlocks(buf, 0, nBlocks, out, outOff);
                    index = nBlocks * mbCipher.getBlockSize();
                }

                if (bufOff != index)
                {
                    if (!partialBlockOkay)
                    {
                        throw new DataLengthException("data not block size aligned");
                    }

                    cipher.processBlock(buf, index, buf, index);
                    System.arraycopy(buf, index, out, outOff + resultLen, bufOff - index);
                    resultLen += bufOff - index;
                    bufOff = 0;
                }
            }

            return resultLen;
        }
        finally
        {
            reset();
        }
    }

    /**
     * Reset the buffer and cipher. After resetting the object is in the same
     * state as it was after the last init (if there was one).
     */
    public void reset()
    {
        //
        // clean the buffer.
        //
        for (int i = 0; i < buf.length; i++)
        {
            buf[i] = 0;
        }

        bufOff = 0;

        //
        // reset the underlying cipher.
        //
        cipher.reset();
    }
}
