package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

/**
 * Base interface for Leighton-Micali Hash-Based Signatures (LMS) keys.
 */
public interface LMSKey
    extends Key
{
    /**
     * Return the number of levels (L) associated with the key.
     *
     * @return L.
     */
    int getLevels();
}
