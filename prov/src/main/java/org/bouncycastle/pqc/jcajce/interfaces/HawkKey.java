package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.HawkParameterSpec;

/**
 * Marker interface implemented by Hawk public and private JCA keys; exposes
 * the underlying {@link HawkParameterSpec} so callers can identify which Hawk
 * parameter set the key belongs to.
 */
public interface HawkKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a HawkParameterSpec
     */
    HawkParameterSpec getParameterSpec();
}
