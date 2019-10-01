package org.bouncycastle.gpg.keybox;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


/**
 * First blob contains meta data about the KeyBox.
 */
public class FirstBlob
    extends Blob
{
    private final int headerFlags;
    private final long fileCreatedAt;
    private final long lastMaintenanceRun;

    private FirstBlob(
        int base,
        long length,
        BlobType type,
        int version,
        int headerFlags,
        long fileCreatedAt,
        long lastMaintenanceRun)
    {
        super(base, length, type, version);
        this.headerFlags = headerFlags;
        this.fileCreatedAt = fileCreatedAt;
        this.lastMaintenanceRun = lastMaintenanceRun;
    }

    static FirstBlob parseContent(int base, long length, BlobType type, int version, KeyBoxByteBuffer buffer)
        throws IOException
    {

        int headerFlags = buffer.u16();
        byte[] magic = buffer.bN(4);


        if (!Arrays.areEqual(magic, magicBytes))
        {
            throw new IOException("Incorrect magic expecting " + Hex.toHexString(magicBytes) + " but got " + Hex.toHexString(magic));
        }


        buffer.u32(); // RFU = Reserved for Future Use
        long fileCreatedAt = buffer.u32();
        long lastMaintenanceRun = buffer.u32();
        buffer.u32();  // RFU
        buffer.u32();  // RFU


        return new FirstBlob(base, length, type, version, headerFlags, fileCreatedAt, lastMaintenanceRun);
    }

    public int getHeaderFlags()
    {
        return headerFlags;
    }

    public long getFileCreatedAt()
    {
        return fileCreatedAt;
    }

    public long getLastMaintenanceRun()
    {
        return lastMaintenanceRun;
    }
}
