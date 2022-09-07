package org.bouncycastle.openpgp;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.util.Arrays;

/**
 * Generator for producing filtered literal data packets which are automatically canonicalized.
 * <p>
 * PGPCanonicalizedDataGenerator is used by invoking one of the open functions to create an OutputStream that raw
 * data can be supplied to for encoding:  </p>
 * <ul>
 * <li>If the length of the originating data to be written is known in advance, use
 * {@link #open(OutputStream, char, String, Date)} to create a packet containing a single
 * literal data object.</li>
 * <li>If the length of the data is unknown, use
 * {@link #open(OutputStream, char, String, Date, byte[])} to create a packet consisting of a series
 * of literal data objects (partials).</li>
 * </ul>
 * <p>
 * A PGPCanonicalizedDataGenerator is usually used to wrap the OutputStream
 * {@link PGPEncryptedDataGenerator#open(OutputStream, byte[]) obtained} from a
 * {@link PGPEncryptedDataGenerator} or a {@link PGPCompressedDataGenerator}.
 * </p><p>
 * Once literal data has been written to the constructed OutputStream, writing of the object stream
 * is completed by closing the OutputStream obtained from the <code>open()</code> method, or
 * equivalently invoking {@link #close()} on this generator.
 * </p>
 */
public class PGPCanonicalizedDataGenerator
    implements StreamGenerator
{
    /**
     * Format tag for textual literal data
     */
    public static final char TEXT = PGPLiteralData.TEXT;
    /**
     * Format tag for UTF-8 encoded textual literal data
     */
    public static final char UTF8 = PGPLiteralData.UTF8;

    /**
     * The special name indicating a "for your eyes only" packet.
     */
    // TODO: Not used?
    public static final String CONSOLE = PGPLiteralData.CONSOLE;

    /**
     * The special time for a modification time of "now" or
     * the present time.
     */
    public static final Date NOW = PGPLiteralData.NOW;

    private PGPLiteralDataGenerator lGen;
    private boolean oldFormat = false;

    /**
     * Constructs a generator for literal data objects.
     */
    public PGPCanonicalizedDataGenerator()
    {
    }

    /**
     * Constructs a generator for literal data objects, specifying to use new or old (PGP 2.6.x
     * compatible) format.
     * <p>
     * This can be used for compatibility with PGP 2.6.x.
     * </p>
     *
     * @param oldFormat <code>true</code> to use PGP 2.6.x compatible format.
     */
    public PGPCanonicalizedDataGenerator(
        boolean oldFormat)
    {
        this.oldFormat = oldFormat;
    }

    /**
     * Open a literal data packet, returning a stream to store the data inside the packet.
     * <p>
     * The stream created can be closed off by either calling close() on the stream or close() on
     * the generator. Closing the returned stream does not close off the OutputStream parameter out.
     *
     * @param out              the underlying output stream to write the literal data packet to.
     * @param format           the format of the literal data that will be written to the output stream (one
     *                         of {@link #TEXT} or {@link #UTF8}).
     * @param name             the name of the "file" to encode in the literal data object.
     * @param modificationTime the time of last modification we want stored.
     */
    public OutputStream open(
        OutputStream out,
        char format,
        String name,
        Date modificationTime)
        throws IOException
    {
        if (lGen != null)
        {
            throw new IllegalStateException("generator already in open state");
        }
        this.lGen = new PGPLiteralDataGenerator(oldFormat);

        return new ArrayCRLFGeneratorStream(out, lGen, format, name, new Date(modificationTime.getTime()));
    }

    /**
     * Open a literal data packet, returning a stream to store the data inside the packet.
     * <p>
     * The stream created can be closed off by either calling close() on the stream or close() on
     * the generator. Closing the returned stream does not close off the OutputStream parameter out.
     *
     * @param out              the underlying output stream to write the literal data packet to.
     * @param format           the format of the literal data that will be written to the output stream (one
     *                         of {@link #TEXT} or {@link #UTF8}).
     * @param name             the name of the "file" to encode in the literal data object.
     * @param modificationTime the time of last modification we want stored.
     */
    public OutputStream open(
        OutputStream out,
        char format,
        String name,
        Date modificationTime,
        File backingFile)
        throws IOException
    {
        if (lGen != null)
        {
            throw new IllegalStateException("generator already in open state");
        }
        this.lGen = new PGPLiteralDataGenerator(oldFormat);

        return new FileCRLFGeneratorStream(out, lGen, format, name, new Date(modificationTime.getTime()), backingFile);
    }

    /**
     * Open a literal data packet, returning a stream to store the data inside the packet as an
     * indefinite-length stream. The stream is written out as a series of partial packets with a
     * chunk size determined by the size of the passed in buffer.
     * <p>
     * The stream created can be closed off by either calling close() on the stream or close() on
     * the generator. Closing the returned stream does not close off the OutputStream parameter out.
     *
     * <p>
     * <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2 bytes
     * worth of the buffer will be used.
     *
     * @param out              the underlying output stream to write the literal data packet to.
     * @param format           the format of the literal data that will be written to the output stream (one
     *                         of {@link #TEXT} or {@link #UTF8}).
     * @param name             the name of the "file" to encode in the literal data object.
     * @param modificationTime the time of last modification we want stored (will be stored to
     *                         second level precision).
     * @param buffer           a buffer to use to buffer and write partial packets. The returned stream takes
     *                         ownership of the buffer.
     * @return the output stream to write data to.
     * @throws IOException           if an error occurs writing stream header information to the provider
     *                               output stream.
     * @throws IllegalStateException if this generator already has an open OutputStream.
     */
    public OutputStream open(
        OutputStream out,
        char format,
        String name,
        Date modificationTime,
        byte[] buffer)
        throws IOException
    {
        if (lGen != null)
        {
            throw new IllegalStateException("generator already in open state");
        }
        this.lGen = new PGPLiteralDataGenerator(oldFormat);
        
        return new IndefiniteCRLFGeneratorStream(out, lGen, format, name, new Date(modificationTime.getTime()), buffer);
    }

    /**
     * Open a literal data packet for the passed in File object, returning an output stream for
     * saving the file contents.
     * <p>
     * This method configures the generator to store the file contents in a single literal data
     * packet, taking the filename and modification time from the file, but does not store the
     * actual file data.
     * </p><p>
     * The stream created can be closed off by either calling close() on the stream or close() on
     * the generator. Closing the returned stream does not close off the OutputStream parameter out.
     * </p>
     *
     * @param out    the underlying output stream to write the literal data packet to.
     * @param format the format of the literal data that will be written to the output stream (one
     *               of {@link #TEXT} or {@link #UTF8}).
     * @param file   the file to determine the filename from.
     * @return the output stream to write data to.
     * @throws IOException           if an error occurs writing stream header information to the provider
     *                               output stream.
     * @throws IllegalStateException if this generator already has an open OutputStream.
     */
    public OutputStream open(
        OutputStream out,
        char format,
        File file)
        throws IOException
    {
        return open(out, format, file.getName(), new Date(file.lastModified()));
    }

    /**
     * Close the literal data packet - this is equivalent to calling close on the stream
     * returned by the open() method.
     *
     * @throws IOException
     */
    public void close()
        throws IOException
    {
        if (lGen != null)
        {
            lGen.close();
            lGen = null;
        }
    }

    static class CRLFGeneratorStream
        extends OutputStream
    {
        protected final OutputStream crlfOut;
        private final boolean isBinary;
        private int lastB = 0;

        public CRLFGeneratorStream(OutputStream crlfOut, boolean isBinary)
        {
            this.crlfOut = crlfOut;
            this.isBinary = isBinary;
        }

        public void write(int b)
            throws IOException
        {
            if (!isBinary)
            {
                if (b == '\n' && lastB != '\r')    // Unix
                {
                    crlfOut.write('\r');
                }
                else if (lastB == '\r')  // MAC
                {
                    if (b != '\n')
                    {
                        crlfOut.write('\n');
                    }
                }
                lastB = b;
            }
            crlfOut.write(b);
        }

        public void close()
            throws IOException
        {
            if (!isBinary && lastB == '\r')     // MAC
            {
                crlfOut.write('\n');
            }
            crlfOut.close();
        }
    }

    private static class FileCRLFGeneratorStream
        extends CRLFGeneratorStream
    {
        private final OutputStream out;
        private final PGPLiteralDataGenerator lGen;
        private final char format;
        private final String name;
        private final Date modificationTime;
        private final File backingFile;

        public FileCRLFGeneratorStream(OutputStream out, PGPLiteralDataGenerator sGen, char format, String name, Date modificationTime, File backingFile)
            throws FileNotFoundException
        {
            super(new BufferedOutputStream(new FileOutputStream(backingFile)), format == PGPLiteralData.BINARY);

            this.out = out;
            this.lGen = sGen;
            this.format = format;
            this.name = name;
            this.modificationTime = modificationTime;
            this.backingFile = backingFile;
        }

        public void close()
            throws IOException
        {
            super.close();

            OutputStream lOut = lGen.open(out, format, name, backingFile.length(), modificationTime);

            PGPUtil.pipeFileContents(backingFile, lOut, 32678);
        }
    }

    private static class IndefiniteCRLFGeneratorStream
        extends CRLFGeneratorStream
    {
        public IndefiniteCRLFGeneratorStream(OutputStream out, PGPLiteralDataGenerator sGen, char format, String name, Date modificationTime, byte[] buffer)
            throws IOException
        {
            super(sGen.open(out, format, name, modificationTime, buffer), format == PGPLiteralData.BINARY);
        }

        public void close()
            throws IOException
        {
            super.close();
        }
    }

    private static class ArrayCRLFGeneratorStream
        extends CRLFGeneratorStream
    {
        private final OutputStream out;
        private final PGPLiteralDataGenerator lGen;
        private final char format;
        private final String name;
        private final Date modificationTime;

        public ArrayCRLFGeneratorStream(OutputStream out, PGPLiteralDataGenerator sGen, char format, String name, Date modificationTime)
        {
            super(new ErasableOutputStream(), format == PGPLiteralData.BINARY);

            this.out = out;
            this.lGen = sGen;
            this.format = format;
            this.name = name;
            this.modificationTime = modificationTime;
        }

        public void close()
            throws IOException
        {
            super.close();

            ErasableOutputStream bOut = (ErasableOutputStream)crlfOut;

            byte[] buf = bOut.getBuf();
            int length = bOut.size();

            OutputStream lOut = lGen.open(out, format, name, length, modificationTime);

            lOut.write(buf, 0, length);

            lOut.close();

            bOut.erase();
        }
    }

    private static final class ErasableOutputStream
        extends ByteArrayOutputStream
    {
        public ErasableOutputStream()
        {
        }

        public byte[] getBuf()
        {
            return buf;
        }

        public void erase()
        {
            Arrays.fill(this.buf, (byte)0);
            reset();
        }
    }
}
