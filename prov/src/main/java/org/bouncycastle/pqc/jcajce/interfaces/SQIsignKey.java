package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec;

public interface SQIsignKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a SQIsignParameterSpec
     */
    SQIsignParameterSpec getParameterSpec();
}
