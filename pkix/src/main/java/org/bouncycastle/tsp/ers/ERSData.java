package org.bouncycastle.tsp.ers;

import org.bouncycastle.operator.DigestCalculator;

/**
 * General interface for a data object covered by an RFC 4998 Evidence Record -
 * anything (a byte array, file, stream, or {@link ERSDataGroup}) that can produce
 * the hash used as a leaf in the archive time-stamp's hash tree.
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
