package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

public interface KyberKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a KyberParameterSpec
     */
    KyberParameterSpec getParameterSpec();
}
