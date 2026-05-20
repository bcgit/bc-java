package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

/**
 * @deprecated to be deleted - use SLH-DSA instead.
 */
@Deprecated
public interface SPHINCSPlusKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a SPHINCSPlusParameterSpec
     */
    SPHINCSPlusParameterSpec getParameterSpec();
}
