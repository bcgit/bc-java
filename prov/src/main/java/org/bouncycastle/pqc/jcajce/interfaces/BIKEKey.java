package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;

public interface BIKEKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a BIKEParameterSpec
     */
    BIKEParameterSpec getParameterSpec();
}
