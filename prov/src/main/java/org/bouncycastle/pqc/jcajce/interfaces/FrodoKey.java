package org.bouncycastle.pqc.jcajce.interfaces;

import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;

import java.security.Key;

public interface FrodoKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a FrodoParameterSpec
     */
    FrodoParameterSpec getParameterSpec();
}
