package org.bouncycastle.tsp.ers;

import org.bouncycastle.operator.DigestCalculator;

/**
 * Generic class for holding byte[] data for RFC 4998 ERS.
 */
public class ERSByteData
    extends ERSCachingData
{
    private final byte[] content;

    public ERSByteData(byte[] content)
    {
        this.content = content;
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
