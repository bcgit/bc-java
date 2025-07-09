package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.CrossParameterSpec;

public interface CrossKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a CrossParameterSpec
     */
    CrossParameterSpec getParameterSpec();
}
