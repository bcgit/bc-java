package org.bouncycastle.tsp.ers;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.IOException;

import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.io.Streams;

/**
 * Generic class for processing an InputStream of data RFC 4998 ERS.
 */
public class ERSInputStreamData
    extends ERSCachingData
{
    private final InputStream content;

    public ERSInputStreamData(File content)
        throws FileNotFoundException
    {
        if (content.isDirectory())
        {
            throw new IllegalArgumentException("directory not allowed");
        }
        this.content = new FileInputStream(content);
    }

    public ERSInputStreamData(InputStream content)
    {
        this.content = content;
    }

    protected ERSByteData toByteData()
        throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Streams.pipeAll(this.content, baos);
        return new ERSByteData(baos.toByteArray());
    }
    
    protected byte[] calculateHash(DigestCalculator digestCalculator, byte[] previousChainHash)
    {
        byte[] hash = ERSUtil.calculateDigest(digestCalculator, content);

        if (previousChainHash != null)
        {
            return ERSUtil.concatPreviousHashes(digestCalculator, previousChainHash, hash);
        }

        return hash;
    }
}
