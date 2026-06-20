package org.bouncycastle.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;

public interface FrodoKEMKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a FrodoKEMParameterSpec
     */
    FrodoKEMParameterSpec getParameterSpec();
}
