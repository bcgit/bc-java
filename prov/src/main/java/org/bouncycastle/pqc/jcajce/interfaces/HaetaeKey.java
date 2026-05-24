package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.HaetaeParameterSpec;

/**
 * Marker interface implemented by HAETAE public and private JCA keys; exposes
 * the underlying {@link HaetaeParameterSpec} so callers can identify which
 * HAETAE parameter set the key belongs to.
 */
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
