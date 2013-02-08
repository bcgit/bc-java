package org.bouncycastle.openpgp;

import org.bouncycastle.apache.bzip2.CBZip2OutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.PacketTags;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 *class for producing compressed data packets.
 */
public class PGPCompressedDataGenerator 
    implements CompressionAlgorithmTags, StreamGenerator
{
    private int                     algorithm;
    private int                     compression;

    private OutputStream            dOut;
    private BCPGOutputStream        pkOut;
    
    public PGPCompressedDataGenerator(
        int                    algorithm)
    {
        this(algorithm, Deflater.DEFAULT_COMPRESSION);
    }
                    
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
     * @throws IOException, IllegalStateException
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
     * Return an OutputStream which will compress the data as it is written
     * to it. The stream will be written out in chunks according to the size of the
     * passed in buffer.
     * <p>
     * The stream created can be closed off by either calling close()
     * on the stream or close() on the generator. Closing the returned
     * stream does not close off the OutputStream parameter out.
     * <p>
     * <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
     * bytes worth of the buffer will be used.
     * </p>
     * <p>
     * <b>Note</b>: using this may break compatibility with RFC 1991 compliant tools. Only recent OpenPGP
     * implementations are capable of accepting these streams.
     * </p>
     * 
     * @param out underlying OutputStream to be used.
     * @param buffer the buffer to use.
     * @return OutputStream
     * @throws IOException
     * @throws PGPException
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
                dOut.flush();
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
