package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

public interface SPHINCSPlusKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a SPHINCSPlusParameterSpec
     */
    SPHINCSPlusParameterSpec getParameterSpec();
}
