package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.MQOMParameterSpec;

public interface MQOMKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a MQOMParameterSpec
     */
    MQOMParameterSpec getParameterSpec();
}
