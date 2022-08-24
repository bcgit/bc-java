package org.bouncycastle.tsp.ers;

import org.bouncycastle.operator.DigestCalculator;

/**
 * General interface for an ERSData data group object.
 */
public interface ERSData
{
    /**
     * Return the calculated hash for the Data
     *
     * @param digestCalculator  digest calculator to use.
     * @param previousChainHash hash from an earlier chain if it needs to be included.
     * @return calculated hash.
     */
    byte[] getHash(DigestCalculator digestCalculator, byte[] previousChainHash);
}
