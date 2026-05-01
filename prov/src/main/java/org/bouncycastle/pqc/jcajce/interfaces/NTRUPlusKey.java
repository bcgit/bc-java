package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;

public interface NTRUPlusKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a NTRUPlusParameterSpec
     */
    NTRUPlusParameterSpec getParameterSpec();
}
