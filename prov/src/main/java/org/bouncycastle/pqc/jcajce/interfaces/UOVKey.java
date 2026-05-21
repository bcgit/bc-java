package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec;

/**
 * Marker interface for an Unbalanced Oil and Vinegar (UOV) key.
 */
public interface UOVKey
    extends Key
{
    /**
     * Return the parameter set this key is bound to.
     *
     * @return a UOVParameterSpec naming the (security-level, encoding-variant) pair.
     */
    UOVParameterSpec getParameterSpec();
}
