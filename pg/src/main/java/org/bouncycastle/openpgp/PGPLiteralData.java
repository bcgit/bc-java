package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.LiteralDataPacket;

/**
 * class for processing literal data objects.
 */
public class PGPLiteralData 
{
    public static final char    BINARY = 'b';
    public static final char    TEXT = 't';
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
     * Return the format of the data stream - BINARY or TEXT.
     * 
     * @return int
     */
    public int getFormat()
    {
        return data.getFormat();
    }
    
    /**
     * Return the file name that's associated with the data stream.
     * 
     * @return String
     */
    public String getFileName()
    {
        return data.getFileName();
    }

    /**
     * Return the file name as an unintrepreted byte array.
     */
    public byte[] getRawFileName()
    {
        return data.getRawFileName();
    }

    /**
     * Return the modification time for the file.
     * 
     * @return the modification time.
     */
    public Date getModificationTime()
    {
        return new Date(data.getModificationTime());
    }
    
    /**
     * Return the raw input stream for the data stream.
     * 
     * @return InputStream
     */
    public InputStream getInputStream()
    {
        return data.getInputStream();
    }
    
    /**
     * Return the input stream representing the data stream
     * 
     * @return InputStream
     */
    public InputStream getDataStream()
    {
        return this.getInputStream();
    }
}
