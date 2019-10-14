package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

/**
 * Base interface for an XMSSMT private key
 */
public interface XMSSMTPrivateKey
    extends XMSSMTKey, PrivateKey
{
    /**
     * Return the index of the next signature.
     *
     * @return the index number for the next signature.
     */
    long getIndex();

    /**
     * Return the number of usages left for the private key.
     *
     * @return the number of times the key can be used before it is exhausted.
     */
    long getUsagesRemaining();

    /**
     * Return a key representing a shard of the key space that can be used usageCount times.
     * <p>
     * Note: this will use the range [index...index + usageCount) for the current key.
     * </p>
     * @param usageCount the number of usages the key should have.
     * @return a key based on the current key that can be used usageCount times.
     */
    XMSSMTPrivateKey extractKeyShard(int usageCount);
}
