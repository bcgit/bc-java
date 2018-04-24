package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import org.bouncycastle.apache.bzip2.CBZip2OutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.PacketTags;

/**
 * Generator for producing compressed data packets.
 * <p>
 * A PGPCompressedDataGenerator is used by invoking one of the open functions to create an
 * OutputStream that raw data can be supplied to for compression:
 * </p><ul>
 * <li>If the data needs to written out in blocks, use {@link #open(OutputStream, byte[])} to create a
 * packet consisting of a series of compressed data objects (partials).</li>
 * </ul>
 *
 * <p>
 * A PGPCompressedDataGenerator is usually used to wrap the OutputStream
 * {@link PGPEncryptedDataGenerator#open(OutputStream, byte[]) obtained} from a
 * {@link PGPEncryptedDataGenerator} (i.e. to compress data prior to encrypting it).
 * </p><p>
 * Raw data is not typically written directly to the OutputStream obtained from a
 * PGPCompressedDataGenerator. The OutputStream is usually wrapped by a
 * {@link PGPLiteralDataGenerator}, which encodes the raw data prior to compression.
 * </p>
 * <p>
 * Once data for compression has been written to the constructed OutputStream, writing of the object
 * stream is completed by closing the OutputStream obtained from the <code>#open()</code> method, or
 * equivalently invoking {@link #close()} on this generator.
 * </p>
 */
public class PGPCompressedDataGenerator
    implements CompressionAlgorithmTags, StreamGenerator
{
    private int                     algorithm;
    private int                     compression;

    private OutputStream            dOut;
    private BCPGOutputStream        pkOut;

    /**
     * Construct a new compressed data generator.
     *
     * @param algorithm the identifier of the {@link CompressionAlgorithmTags compression algorithm}
     *            to use.
     */
    public PGPCompressedDataGenerator(
        int                    algorithm)
    {
        this(algorithm, Deflater.DEFAULT_COMPRESSION);
    }

    /**
     * Construct a new compressed data generator.
     *
     * @param algorithm the identifier of the {@link CompressionAlgorithmTags compression algorithm}
     *            to use.
     * @param compression the {@link Deflater} compression level to use.
     */
    public PGPCompressedDataGenerator(
        int                    algorithm,
        int                    compression)
    {
        switch (algorithm)
        {
            case CompressionAlgorithmTags.UNCOMPRESSED:
            case CompressionAlgorithmTags.ZIP:
            case CompressionAlgorithmTags.ZLIB:
            case CompressionAlgorithmTags.BZIP2:
                break;
            default:
                throw new IllegalArgumentException("unknown compression algorithm");
        }

        if (compression != Deflater.DEFAULT_COMPRESSION)
        {
            if ((compression < Deflater.NO_COMPRESSION) || (compression > Deflater.BEST_COMPRESSION))
            {
                throw new IllegalArgumentException("unknown compression level: " + compression);
            }
        }

        this.algorithm = algorithm;
        this.compression = compression;
    }

    /**
     * Return an OutputStream which will save the data being written to
     * the compressed object.
     * <p>
     * The stream created can be closed off by either calling close()
     * on the stream or close() on the generator. Closing the returned
     * stream does not close off the OutputStream parameter out.
     *
     * @param out underlying OutputStream to be used.
     * @return OutputStream
     * @throws IOException
     * @throws IllegalStateException
     */
    public OutputStream open(
        OutputStream    out)
        throws IOException
    {
        if (dOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }

        this.pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);

        doOpen();

        return new WrappedGeneratorStream(dOut, this);
    }

    /**
     * Return an OutputStream which will compress the data as it is written to it. The stream will
     * be written out in chunks (partials) according to the size of the passed in buffer.
     * <p>
     * The stream created can be closed off by either calling close() on the stream or close() on
     * the generator. Closing the returned stream does not close off the OutputStream parameter out.
     * <p>
     * <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2 bytes
     * worth of the buffer will be used.
     * </p>
     * <p>
     * <b>Note</b>: using this may break compatibility with RFC 1991 compliant tools. Only recent
     * OpenPGP implementations are capable of accepting these streams.
     * </p>
     *
     * @param out the stream to write compressed packets to.
     * @param buffer a buffer to use to buffer and write partial packets. The returned stream takes
     *            ownership of the buffer and will use it to buffer plaintext data for compression.
     * @return the output stream to write data to.
     * @throws IOException if an error occurs writing stream header information to the provider
     *             output stream.
     * @throws PGPException
     * @throws IllegalStateException if this generator already has an open OutputStream.
     */
    public OutputStream open(
        OutputStream    out,
        byte[]          buffer)
        throws IOException, PGPException
    {
        if (dOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }

        this.pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA, buffer);

        doOpen();

        return new WrappedGeneratorStream(dOut, this);
    }

    private void doOpen() throws IOException
    {
        pkOut.write(algorithm);

        switch (algorithm)
        {
            case CompressionAlgorithmTags.UNCOMPRESSED:
                dOut = pkOut;
                break;
            case CompressionAlgorithmTags.ZIP:
                dOut = new SafeDeflaterOutputStream(pkOut, compression, true);
                break;
            case CompressionAlgorithmTags.ZLIB:
                dOut = new SafeDeflaterOutputStream(pkOut, compression, false);
                break;
            case CompressionAlgorithmTags.BZIP2:
                dOut = new SafeCBZip2OutputStream(pkOut);
                break;
            default:
                // Constructor should guard against this possibility
                throw new IllegalStateException();
        }
    }

    /**
     * Close the compressed object - this is equivalent to calling close on the stream
     * returned by the open() method.
     *
     * @throws IOException
     */
    public void close()
        throws IOException
    {
        if (dOut != null)
        {
            if (dOut != pkOut)
            {
                dOut.close();
            }

            dOut = null;

            pkOut.finish();
            pkOut.flush();
            pkOut = null;
        }
    }

    private static class SafeCBZip2OutputStream extends CBZip2OutputStream
    {
        public SafeCBZip2OutputStream(OutputStream output) throws IOException
        {
            super(output);
        }

        public void close() throws IOException
        {
            finish();
        }
    }

    private class SafeDeflaterOutputStream extends DeflaterOutputStream
    {
        public SafeDeflaterOutputStream(OutputStream output, int compression, boolean nowrap)
        {
            super(output, new Deflater(compression, nowrap));
        }

        public void close() throws IOException
        {
            finish();
            def.end();
        }
    }
}
