package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.SDitHParameterSpec;

public interface SDitHKey
    extends Key
{
    /**
     * Return the parameter spec associated with this SDitH key.
     */
    SDitHParameterSpec getParameterSpec();
}
