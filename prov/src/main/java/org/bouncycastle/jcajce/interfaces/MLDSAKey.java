package org.bouncycastle.jcajce.interfaces;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

import java.security.Key;

public interface MLDSAKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a MLDSAParameterSpec
     */
    MLDSAParameterSpec getParameterSpec();
}
