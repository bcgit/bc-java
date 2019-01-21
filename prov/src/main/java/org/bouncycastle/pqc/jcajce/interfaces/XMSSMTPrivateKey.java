package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

/**
 * Base interface for an XMSSMT private key
 */
public interface XMSSMTPrivateKey
    extends XMSSMTKey, PrivateKey
{
    /**
     * Return the number of usages left for the private key.
     *
     * @return the number of times the key can be used before it is exhausted.
     */
    long getUsagesRemaining();
}
