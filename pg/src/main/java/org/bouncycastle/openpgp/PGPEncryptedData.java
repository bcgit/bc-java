package org.bouncycastle.openpgp;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;

/**
 * A PGP encrypted data object.
 * <p>
 * Encrypted data packets are decrypted using a {@link PGPDataDecryptor} obtained from a
 * {@link PGPDataDecryptorFactory}.
 * </p>
 */
public abstract class PGPEncryptedData
    implements SymmetricKeyAlgorithmTags, AEADAlgorithmTags
{
    protected static class TruncatedStream
        extends InputStream
    {
        int[] lookAhead = new int[22];
        int bufPtr;
        InputStream in;
        byte[] readBuffer = new byte[8192];

        TruncatedStream(
            InputStream in)
            throws IOException
        {
            for (int i = 0; i != lookAhead.length; i++)
            {
                if ((lookAhead[i] = in.read()) < 0)
                {
                    throw new EOFException();
                }
            }

            bufPtr = 0;
            this.in = in;
        }

        public int read()
            throws IOException
        {
            int ch = in.read();

            if (ch >= 0)
            {
                int c = lookAhead[bufPtr];

                lookAhead[bufPtr] = ch;
                bufPtr = (bufPtr + 1) % lookAhead.length;

                return c;
            }

            return -1;
        }

        public int read(byte[] b)
            throws IOException
        {
            return read(b, 0, b.length);
        }

        public int read(byte[] b, int off, int len)
            throws IOException
        {
            // Efficient index check copied from BufferedInputStream
            if ((off | len | off + len | b.length - (off + len)) < 0)
            {
                throw new IndexOutOfBoundsException();
            }
            else if (len == 0)
            {
                return 0;
            }

            // read into our buffer
            int maxRead = Math.min(readBuffer.length, len);
            int bytesRead = in.read(readBuffer, 0, maxRead);
            if (bytesRead < 0)
            {
                return -1;
            }

            // Copy lookahead to output
            int bytesFromLookahead = Math.min(bytesRead, lookAhead.length);
            for (int i = 0; i < bytesFromLookahead; i++)
            {
                b[off + i] = (byte)lookAhead[(bufPtr + i) % lookAhead.length];
            }

            // write tail of readBuffer to lookahead
            int bufferTail = bytesRead - bytesFromLookahead;
            for (int i = bufferTail; i < bytesRead; i++)
            {
                lookAhead[bufPtr] = readBuffer[i] & 0xff; // we're not at end of file.
                bufPtr = (bufPtr + 1) % lookAhead.length;
            }

            // Copy head of readBuffer to output
            if (bufferTail != 0)
            {
                System.arraycopy(readBuffer, 0, b, off + bytesFromLookahead, bufferTail);
            }
            
            return bytesRead;
        }
        
        int[] getLookAhead()
        {
            int[] tmp = new int[lookAhead.length];
            int count = 0;

            for (int i = bufPtr; i != lookAhead.length; i++)
            {
                tmp[count++] = lookAhead[i];
            }
            for (int i = 0; i != bufPtr; i++)
            {
                tmp[count++] = lookAhead[i];
            }

            return tmp;
        }
    }

    InputStreamPacket encData;
    InputStream encStream;
    TruncatedStream truncStream;
    PGPDigestCalculator integrityCalculator;

    PGPEncryptedData(
        InputStreamPacket encData)
    {
        this.encData = encData;
    }

    /**
     * Return the raw input stream for the data stream.
     * <p>
     * Note this stream is shared with all other encryption methods in the same
     * {@link PGPEncryptedDataList} and with any decryption methods in sub-classes, so consuming
     * this stream will affect decryption.
     * </p>
     *
     * @return the encrypted data in this packet.
     */
    public InputStream getInputStream()
    {
        return encData.getInputStream();
    }

    /**
     * Checks whether the packet is integrity protected using a modification detection code package.
     *
     * @return <code>true</code> if there is a modification detection code package associated with
     * this stream
     */
    public boolean isIntegrityProtected()
    {
        return (encData instanceof SymmetricEncIntegrityPacket);
    }

    /**
     * Checks whether the packet is protected using an AEAD algorithm.
     *
     * @return <code>true</code> if there is a modification detection code package associated with
     * this stream
     */
    public boolean isAEAD()
    {
        return (encData instanceof AEADEncDataPacket);
    }

    /**
     * Verifies the integrity of the packet against the modification detection code associated with
     * it in the stream.
     * <p>
     * Note: This can only be called after the message has been read.
     * </p>
     *
     * @return <code>true</code> if the message verifies, <code>false</code> otherwise.
     * @throws PGPException if the message is not {@link #isIntegrityProtected() integrity
     *                      protected}.
     */
    public boolean verify()
        throws PGPException, IOException
    {
        if (!this.isIntegrityProtected())
        {
            throw new PGPException("data not integrity protected.");
        }

        //
        // make sure we are at the end.
        //
        while (encStream.read() >= 0)
        {
            // do nothing
        }

        //
        // process the MDC packet
        //
        int[] lookAhead = truncStream.getLookAhead();

        OutputStream dOut = integrityCalculator.getOutputStream();

        dOut.write((byte)lookAhead[0]);
        dOut.write((byte)lookAhead[1]);

        byte[] digest = integrityCalculator.getDigest();
        byte[] streamDigest = new byte[digest.length];

        for (int i = 0; i != streamDigest.length; i++)
        {
            streamDigest[i] = (byte)lookAhead[i + 2];
        }

        return Arrays.constantTimeAreEqual(digest, streamDigest);
    }

    /**
     * Return the version number of the Encrypted Session Key Packet.
     *
     * @return version
     */
    public int getVersion()
    {
        throw new UnsupportedOperationException("not supported - override required");
    }

    /**
     * Return the symmetric encryption algorithm that is used by the packet.
     *
     * @return algorithm
     */
    public int getAlgorithm()
    {
        throw new UnsupportedOperationException("not supported - override required");
    }
}
