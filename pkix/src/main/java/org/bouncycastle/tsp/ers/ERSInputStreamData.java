package org.bouncycastle.tsp.ers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import org.bouncycastle.operator.DigestCalculator;

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

    protected byte[] calculateHash(DigestCalculator digestCalculator)
    {
        // TODO: this method may get called twice if the digest calculator changes...
        return ERSUtil.calculateDigest(digestCalculator, content);
    }
}
