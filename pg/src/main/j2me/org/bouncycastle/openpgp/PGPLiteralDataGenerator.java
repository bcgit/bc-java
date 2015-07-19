package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.util.Strings;

/**
 * Class for producing literal data packets.
 */
public class PGPLiteralDataGenerator implements StreamGenerator
{    
    public static final char    BINARY = PGPLiteralData.BINARY;
    public static final char    TEXT = PGPLiteralData.TEXT;
    public static final char    UTF8 = PGPLiteralData.UTF8;
    
    /**
     * The special name indicating a "for your eyes only" packet.
     */
    public static final String  CONSOLE = PGPLiteralData.CONSOLE;
    
    /**
     * The special time for a modification time of "now" or
     * the present time.
     */
    public static final Date    NOW = PGPLiteralData.NOW;
    
    private BCPGOutputStream    pkOut;
    private boolean             oldFormat = false;
    
    public PGPLiteralDataGenerator()
    {        
    }
    
    /**
     * Generates literal data objects in the old format, this is
     * important if you need compatability with  PGP 2.6.x.
     * 
     * @param oldFormat
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
     * Open a literal data packet, returning a stream to store the data inside
     * the packet.
     * <p>
     * The stream created can be closed off by either calling close()
     * on the stream or close() on the generator. Closing the returned
     * stream does not close off the OutputStream parameter out.
     * 
     * @param out the stream we want the packet in
     * @param format the format we are using
     * @param name the name of the "file"
     * @param length the length of the data we will write
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
     * Open a literal data packet, returning a stream to store the data inside
     * the packet as an indefinite-length stream. The stream is written out as a
     * series of partial packets with a chunk size determined by the size of the
     * passed in buffer.
     * <p>
     * The stream created can be closed off by either calling close()
     * on the stream or close() on the generator. Closing the returned
     * stream does not close off the OutputStream parameter out.
     * <p>
     * <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
     * bytes worth of the buffer will be used.
     * 
     * @param out the stream we want the packet in
     * @param format the format we are using
     * @param name the name of the "file"
     * @param modificationTime the time of last modification we want stored.
     * @param buffer the buffer to use for collecting data to put into chunks.
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
