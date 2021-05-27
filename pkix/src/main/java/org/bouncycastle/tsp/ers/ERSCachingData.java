package org.bouncycastle.tsp.ers;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;

/**
 * An ERSData object that caches hash calculations.
 */
public abstract class ERSCachingData
    implements ERSData
{
    private Map<AlgorithmIdentifier, byte[]> preCalcs = new HashMap<AlgorithmIdentifier, byte[]>();

    /**
     * Generates a hash for the whole DataGroup.
     *
     * @param digestCalculator the {@link DigestCalculator} to use for computing the hash
     * @return a hash that is representative of the whole DataGroup
     */
    public byte[] getHash(DigestCalculator digestCalculator)
    {
        AlgorithmIdentifier digAlgID = digestCalculator.getAlgorithmIdentifier();
        if (preCalcs.containsKey(digAlgID))
        {
            return (byte[])preCalcs.get(digAlgID);
        }

        byte[] hash = calculateHash(digestCalculator);

        preCalcs.put(digAlgID, hash);

        return hash;
    }

    protected abstract byte[] calculateHash(DigestCalculator digestCalculator);
}
