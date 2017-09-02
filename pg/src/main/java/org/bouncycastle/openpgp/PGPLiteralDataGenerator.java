package org.bouncycastle.openpgp;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.util.Strings;

/**
 * Generator for producing literal data packets.
 * <p>
 * A PGPLiteralData is used by invoking one of the open functions to create an OutputStream that raw
 * data can be supplied to for encoding:  </p>
 * <ul>
 * <li>If the length of the data to be written is known in advance, use
 * {@link #open(OutputStream, char, String, long, Date)} to create a packet containing a single
 * literal data object.</li>
 * <li>If the length of the data is unknown, use
 * {@link #open(OutputStream, char, String, Date, byte[])} to create a packet consisting of a series
 * of literal data objects (partials).</li>
 * </ul>
 * <p>
 * A PGPLiteralDataGenerator is usually used to wrap the OutputStream
 * {@link PGPEncryptedDataGenerator#open(OutputStream, byte[]) obtained} from a
 * {@link PGPEncryptedDataGenerator} or a {@link PGPCompressedDataGenerator}.
 * </p><p>
 * Once literal data has been written to the constructed OutputStream, writing of the object stream
 * is completed by closing the OutputStream obtained from the <code>open()</code> method, or
 * equivalently invoking {@link #close()} on this generator.
 * </p>
 */
public class PGPLiteralDataGenerator implements StreamGenerator
{
    /** Format tag for binary literal data */
    public static final char BINARY = PGPLiteralData.BINARY;
    /** Format tag for textual literal data */
    public static final char    TEXT = PGPLiteralData.TEXT;
    /** Format tag for UTF-8 encoded textual literal data */
    public static final char    UTF8 = PGPLiteralData.UTF8;

    /**
     * The special name indicating a "for your eyes only" packet.
     */
    // TODO: Not used?
    public static final String  CONSOLE = PGPLiteralData.CONSOLE;

    /**
     * The special time for a modification time of "now" or
     * the present time.
     */
    public static final Date    NOW = PGPLiteralData.NOW;

    private BCPGOutputStream    pkOut;
    private boolean             oldFormat = false;

    /**
     * Constructs a generator for literal data objects.
     */
    public PGPLiteralDataGenerator()
    {
    }

    /**
     * Constructs a generator for literal data objects, specifying to use new or old (PGP 2.6.x
     * compatible) format.
     * <p>
     * This can be used for compatibility with PGP 2.6.x.
     * </p>
     * @param oldFormat <code>true</code> to use PGP 2.6.x compatible format.
     */
    public PGPLiteralDataGenerator(
        boolean    oldFormat)
    {
        this.oldFormat = oldFormat;
    }

    private void writeHeader(
        OutputStream    out,
        char            format,
        byte[]          encName,
        long            modificationTime)
        throws IOException
    {
        out.write(format);

        out.write((byte)encName.length);

        for (int i = 0; i != encName.length; i++)
        {
            out.write(encName[i]);
        }

        long    modDate = modificationTime / 1000;

        out.write((byte)(modDate >> 24));
        out.write((byte)(modDate >> 16));
        out.write((byte)(modDate >> 8));
        out.write((byte)(modDate));
    }

    /**
     * Open a literal data packet, returning a stream to store the data inside the packet.
     * <p>
     * The stream created can be closed off by either calling close() on the stream or close() on
     * the generator. Closing the returned stream does not close off the OutputStream parameter out.
     *
     * @param out the underlying output stream to write the literal data packet to.
     * @param format the format of the literal data that will be written to the output stream (one
     *            of {@link #BINARY}, {@link #TEXT} or {@link #UTF8}).
     * @param name the name of the "file" to encode in the literal data object.
     * @param length the length of the data that will be written.
     * @param modificationTime the time of last modification we want stored.
     */
    public OutputStream open(
        OutputStream    out,
        char            format,
        String          name,
        long            length,
        Date            modificationTime)
        throws IOException
    {
        if (pkOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }

        byte[] encName = Strings.toUTF8ByteArray(name);

        pkOut = new BCPGOutputStream(out, PacketTags.LITERAL_DATA, length + 2 + encName.length + 4, oldFormat);

        writeHeader(pkOut, format, encName, modificationTime.getTime());

        return new WrappedGeneratorStream(pkOut, this);
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
     * @param out the underlying output stream to write the literal data packet to.
     * @param format the format of the literal data that will be written to the output stream (one
     *            of {@link #BINARY}, {@link #TEXT} or {@link #UTF8}).
     * @param name the name of the "file" to encode in the literal data object.
     * @param modificationTime the time of last modification we want stored (will be stored to
     *            second level precision).
     * @param buffer a buffer to use to buffer and write partial packets. The returned stream takes
     *            ownership of the buffer.
     *
     * @return the output stream to write data to.
     * @throws IOException if an error occurs writing stream header information to the provider
     *             output stream.
     * @throws IllegalStateException if this generator already has an open OutputStream.
     */
    public OutputStream open(
        OutputStream    out,
        char            format,
        String          name,
        Date            modificationTime,
        byte[]          buffer)
        throws IOException
    {
        if (pkOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }

        pkOut = new BCPGOutputStream(out, PacketTags.LITERAL_DATA, buffer);

        byte[] encName = Strings.toUTF8ByteArray(name);

        writeHeader(pkOut, format, encName, modificationTime.getTime());

        return new WrappedGeneratorStream(pkOut, this);
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
     * @param out the underlying output stream to write the literal data packet to.
     * @param format the format of the literal data that will be written to the output stream (one
     *            of {@link #BINARY}, {@link #TEXT} or {@link #UTF8}).
     * @param file the file to determine the length and filename from.
     * @return the output stream to write data to.
     * @throws IOException if an error occurs writing stream header information to the provider
     *             output stream.
     * @throws IllegalStateException if this generator already has an open OutputStream.
     */
    public OutputStream open(
        OutputStream    out,
        char            format,
        File            file)
        throws IOException
    {
        return open(out, format, file.getName(), file.length(), new Date(file.lastModified()));
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
        if (pkOut != null)
        {
            pkOut.finish();
            pkOut.flush();
            pkOut = null;
        }
    }
}
