package org.bouncycastle.tsp.ers;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Arrays;

/**
 * Base {@link ERSData} implementation that caches calculated hashes, keyed by
 * digest algorithm and previous-chain hash, so the (potentially expensive) hash
 * of a data object is computed only once per combination. Subclasses supply the
 * actual hash in {@link #calculateHash(DigestCalculator, byte[])}.
 */
public abstract class ERSCachingData
    implements ERSData
{
    private Map<CacheIndex, byte[]> preCalcs = new HashMap<CacheIndex, byte[]>();

    /**
     * Return the hash for this data object, computing it (via the subclass)
     * on first request and returning the cached value thereafter.
     *
     * @param digestCalculator the {@link DigestCalculator} to use for computing the hash.
     * @param previousChainHash hash from an earlier chain to fold in, or null.
     * @return the calculated hash for this data object.
     */
    public byte[] getHash(DigestCalculator digestCalculator, byte[] previousChainHash)
    {
        CacheIndex digAlgID = new CacheIndex(digestCalculator.getAlgorithmIdentifier(), previousChainHash);
        if (preCalcs.containsKey(digAlgID))
        {
            return (byte[])preCalcs.get(digAlgID);
        }

        byte[] hash = calculateHash(digestCalculator, previousChainHash);

        preCalcs.put(digAlgID, hash);

        return hash;
    }

    /**
     * Compute the hash for this data object. Implemented by subclasses; the result
     * is cached by {@link #getHash(DigestCalculator, byte[])}.
     *
     * @param digestCalculator the digest calculator to use.
     * @param previousChainHash hash from an earlier chain to fold in, or null.
     * @return the calculated hash.
     */
    protected abstract byte[] calculateHash(DigestCalculator digestCalculator, byte[] previousChainHash);

    private static class CacheIndex
    {
        final AlgorithmIdentifier algId;
        final byte[] chainHash;

        private CacheIndex(AlgorithmIdentifier algId, byte[] chainHash)
        {
            this.algId = algId;
            this.chainHash = chainHash;
        }

        public boolean equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (!(o instanceof CacheIndex))
            {
                return false;
            }
            CacheIndex that = (CacheIndex)o;
            return algId.equals(that.algId) && Arrays.areEqual(chainHash, that.chainHash);
        }

        public int hashCode()
        {
            int result = algId.hashCode();
            return 31 * result + Arrays.hashCode(chainHash);
        }
    }
}
