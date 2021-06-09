package org.bouncycastle.cms;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.util.io.Streams;

/**
 * a holding class for a file of data to be processed.
 */
public class CMSProcessableFile
    implements CMSTypedData, CMSReadable
{
    private static final int DEFAULT_BUF_SIZE = 32 * 1024;

    private final ASN1ObjectIdentifier type;
    private final File file;
    private final int bufSize;

    public CMSProcessableFile(
        File file)
    {
        this(file, DEFAULT_BUF_SIZE);
    }
    
    public CMSProcessableFile(
        File file,
        int  bufSize)
    {
        this(CMSObjectIdentifiers.data, file, bufSize);
    }

    public CMSProcessableFile(
        ASN1ObjectIdentifier type,
        File file,
        int  bufSize)
    {
        this.type = type;
        this.file = file;
        this.bufSize = bufSize;
    }

    public InputStream getInputStream()
        throws IOException, CMSException
    {
        return new BufferedInputStream(new FileInputStream(file), bufSize);
    }

    public void write(OutputStream zOut)
        throws IOException, CMSException
    {
        FileInputStream fIn = new FileInputStream(file);
        Streams.pipeAll(fIn, zOut, bufSize);
        fIn.close();
    }

    /**
     * Return the file handle.
     */
    public Object getContent()
    {
        return file;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return type;
    }
}
