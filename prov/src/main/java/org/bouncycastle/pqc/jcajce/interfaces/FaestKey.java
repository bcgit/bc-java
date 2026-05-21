package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.FaestParameterSpec;

public interface FaestKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a FaestParameterSpec
     */
    FaestParameterSpec getParameterSpec();
}
