package org.bouncycastle.cms;

import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Properties;

/**
 * The digests of one SignedData's content, computed while its signers are verified and keyed on
 * the digest algorithm identifier, so that signers sharing an algorithm digest the content once.
 * The number of distinct algorithms held is bounded by {@link Properties#CMS_MAX_DIGEST_ALGORITHMS}.
 */
final class ContentDigestCache
{
    private final Map digests = new TreeMap(CMSUtils.ALGORITHM_IDENTIFIER_ORDER);
    private final int limit = Properties.asInteger(Properties.CMS_MAX_DIGEST_ALGORITHMS, 0);

    synchronized byte[] get(AlgorithmIdentifier digestAlgorithm)
    {
        return (byte[])digests.get(digestAlgorithm);
    }

    /**
     * Check that a digest under the algorithm could be added, before the work of computing it.
     */
    synchronized void checkRoom(AlgorithmIdentifier digestAlgorithm)
        throws CMSException
    {
        if (!digests.containsKey(digestAlgorithm))
        {
            checkLimit(limit, digests.size() + 1);
        }
    }

    synchronized void put(AlgorithmIdentifier digestAlgorithm, byte[] digest)
        throws CMSException
    {
        checkRoom(digestAlgorithm);

        digests.put(digestAlgorithm, digest);
    }

    static void checkLimit(int limit, int count)
        throws CMSException
    {
        if (limit > 0 && count > limit)
        {
            throw new CMSException("number of digest algorithms exceeds the limit of " + limit);
        }
    }
}
