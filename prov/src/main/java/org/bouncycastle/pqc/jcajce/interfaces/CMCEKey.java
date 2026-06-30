package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;

/**
 * @deprecated the standardised Classic McEliece KEM (ISO/IEC 18033-2:2006/Amd 2:2026) is now provided under org.bouncycastle.crypto and org.bouncycastle.jcajce (see org.bouncycastle.crypto.params.CMCEParameters and org.bouncycastle.jcajce.spec.CMCEParameterSpec). This is the legacy NIST round 3 (non-pc, incl. mceliece348864) implementation, retained for backwards compatibility.
 */
@Deprecated
public interface CMCEKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a CMCEParameterSpec
     */
    CMCEParameterSpec getParameterSpec();
}
