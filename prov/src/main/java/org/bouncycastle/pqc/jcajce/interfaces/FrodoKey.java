package org.bouncycastle.pqc.jcajce.interfaces;

import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;

import java.security.Key;

/**
 * @deprecated the standardised FrodoKEM (ISO/IEC 18033-2:2006/Amd 2:2026) is now provided under org.bouncycastle.crypto and org.bouncycastle.jcajce (see FrodoKEMParameters / FrodoKEMParameterSpec). This is the legacy NIST round 3 (unsalted, eFrodoKEM) implementation, retained for backwards compatibility.
 */
@Deprecated
public interface FrodoKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a FrodoParameterSpec
     */
    FrodoParameterSpec getParameterSpec();
}
