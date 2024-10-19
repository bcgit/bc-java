package org.bouncycastle.tsp.ers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.io.Streams;

/**
 * Generic class for processing an InputStream of data RFC 4998 ERS.
 */
public class ERSInputStreamData
    extends ERSCachingData
{
    private final File contentFile;
    private final byte[] contentBytes;

    public ERSInputStreamData(File content)
        throws FileNotFoundException
    {
        if (content.isDirectory())
        {
            throw new IllegalArgumentException("directory not allowed");
        }
        if (!content.exists())
        {
            throw new FileNotFoundException(content + " not found");
        }
        this.contentBytes = null;
        this.contentFile = content;
    }

    public ERSInputStreamData(InputStream content)
    {
        try
        {
            this.contentBytes = Streams.readAll(content);
        }
        catch (IOException e)
        {
            throw ExpUtil.createIllegalState("unable to open content: " + e.getMessage(), e);
        }
        this.contentFile = null;
    }
    
    protected byte[] calculateHash(DigestCalculator digestCalculator, byte[] previousChainHash)
    {
        byte[] hash;
        if (contentBytes != null)
        {
            hash = ERSUtil.calculateDigest(digestCalculator, contentBytes);
        }
        else
        {
            try
            {
                InputStream content = new FileInputStream(contentFile);
                hash = ERSUtil.calculateDigest(digestCalculator, content);
                content.close();
            }
            catch (IOException e)
            {
                throw ExpUtil.createIllegalState("unable to open content: " + e.getMessage(), e);
            }
        }

        if (previousChainHash != null)
        {
            return ERSUtil.concatPreviousHashes(digestCalculator, previousChainHash, hash);
        }

        return hash;
    }
}
