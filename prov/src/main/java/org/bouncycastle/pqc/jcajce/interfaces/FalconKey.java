package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

public interface FalconKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a FalconParameterSpec
     */
    FalconParameterSpec getParameterSpec();
}
