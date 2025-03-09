package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.MayoParameterSpec;

public interface MayoKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a MayoParameterSpec
     */
    MayoParameterSpec getParameterSpec();
}
