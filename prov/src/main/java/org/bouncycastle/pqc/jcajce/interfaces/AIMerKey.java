package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.AIMerParameterSpec;

public interface AIMerKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a AIMerParameterSpec
     */
    AIMerParameterSpec getParameterSpec();
}

