package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.HaetaeParameterSpec;

public interface HaetaeKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a HaetaeParameterSpec
     */
    HaetaeParameterSpec getParameterSpec();
}
