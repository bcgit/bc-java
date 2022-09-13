package org.bouncycastle.tsp.ers;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Arrays;

/**
 * An ERSData object that caches hash calculations.
 */
public abstract class ERSCachingData
    implements ERSData
{
    private Map<CacheIndex, byte[]> preCalcs = new HashMap<CacheIndex, byte[]>();

    /**
     * Generates a hash for the whole DataGroup.
     *
     * @param digestCalculator the {@link DigestCalculator} to use for computing the hash
     * @return a hash that is representative of the whole DataGroup
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
