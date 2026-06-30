package org.bouncycastle.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.jcajce.spec.CMCEParameterSpec;

public interface CMCEKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a CMCEParameterSpec
     */
    CMCEParameterSpec getParameterSpec();
}
