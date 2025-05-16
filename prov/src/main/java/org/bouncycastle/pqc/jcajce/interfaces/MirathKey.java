package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.MirathParameterSpec;

public interface MirathKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a MayoParameterSpec
     */
    MirathParameterSpec getParameterSpec();
}

