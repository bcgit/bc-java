package org.bouncycastle.openpgp;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

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
    implements SymmetricKeyAlgorithmTags
{
    protected class TruncatedStream extends InputStream
    {
        int[]         lookAhead = new int[22];
        int           bufPtr;
        InputStream   in;

        TruncatedStream(
            InputStream    in)
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
            int    ch = in.read();

            if (ch >= 0)
            {
                int    c = lookAhead[bufPtr];

                lookAhead[bufPtr] = ch;
                bufPtr = (bufPtr + 1) % lookAhead.length;

                return c;
            }

            return -1;
        }

        int[] getLookAhead()
        {
            int[]    tmp = new int[lookAhead.length];
            int    count = 0;

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

    InputStreamPacket        encData;
    InputStream              encStream;
    TruncatedStream          truncStream;
    PGPDigestCalculator      integrityCalculator;

    PGPEncryptedData(
        InputStreamPacket    encData)
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
     * @return the encrypted data in this packet.
     */
    public InputStream getInputStream()
    {
        return encData.getInputStream();
    }

    /**
     * Checks whether the packet is integrity protected.
     *
     * @return <code>true</code> if there is a modification detection code package associated with
     *         this stream
     */
    public boolean isIntegrityProtected()
    {
        return (encData instanceof SymmetricEncIntegrityPacket);
    }

    /**
     * Verifies the integrity of the packet against the modification detection code associated with
     * it in the stream.
     * <p>
     * Note: This can only be called after the message has been read.
     * </p>
     * @return <code>true</code> if the message verifies, <code>false</code> otherwise.
     * @throws PGPException if the message is not {@link #isIntegrityProtected() integrity
     *             protected}.
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
}
