package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

/**
 * Base interface for an LMS private key
 *
 * @deprecated use {@link org.bouncycastle.jcajce.interfaces.LMSPrivateKey} instead.
 */
@Deprecated
public interface LMSPrivateKey
    extends LMSKey, org.bouncycastle.jcajce.interfaces.LMSPrivateKey
{
    /**
     * Return a key representing a shard of the key space that can be used usageCount times.
     * <p>
     * Note: this will use the range [index...index + usageCount) for the current key.
     * </p>
     * @param usageCount the number of usages the key should have.
     * @return a key based on the current key that can be used usageCount times.
     */
    LMSPrivateKey extractKeyShard(int usageCount);
}
