package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.LiteralDataPacket;

/**
 * A single literal data packet in a PGP object stream.
 */
public class PGPLiteralData
{
    /** Format tag for binary literal data */
    public static final char    BINARY = 'b';
    /** Format tag for textual literal data */
    public static final char    TEXT = 't';
    /** Format tag for UTF-8 encoded textual literal data */
    public static final char    UTF8 = 'u';

    /**
     * The special name indicating a "for your eyes only" packet.
     */
    public static final String  CONSOLE = "_CONSOLE";

    /**
     * The special time for a modification time of "now" or
     * the present time.
     */
    public static final Date    NOW = new Date(0L);

    LiteralDataPacket    data;

    public PGPLiteralData(
        BCPGInputStream    pIn)
        throws IOException
    {
        data  = (LiteralDataPacket)pIn.readPacket();
    }

    /**
     * Return the format of the data packet. One of {@link #BINARY}, {@link #TEXT} or {@link #UTF8}
     */
    public int getFormat()
    {
        return data.getFormat();
    }

    /**
     * Return the file name associated with the data packet.
     */
    public String getFileName()
    {
        return data.getFileName();
    }

    /**
     * Return the file name as an uninterpreted (UTF-8 encoded) byte array.
     */
    public byte[] getRawFileName()
    {
        return data.getRawFileName();
    }

    /**
     * Return the modification time for the file (at second level precision).
     */
    public Date getModificationTime()
    {
        return new Date(data.getModificationTime());
    }

    /**
     * Return the raw input stream for the data packet.
     */
    public InputStream getInputStream()
    {
        return data.getInputStream();
    }

    /**
     * Return the input stream representing the data stream. <br/>
     * Equivalent to {@link #getInputStream()}.
     */
    public InputStream getDataStream()
    {
        return this.getInputStream();
    }
}
