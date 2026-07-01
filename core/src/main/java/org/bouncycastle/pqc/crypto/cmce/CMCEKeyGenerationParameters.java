package org.bouncycastle.pqc.crypto.cmce;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * @deprecated the standardised Classic McEliece KEM (ISO/IEC 18033-2:2006/Amd 2:2026) is now provided under org.bouncycastle.crypto and org.bouncycastle.jcajce (see org.bouncycastle.crypto.params.CMCEParameters and org.bouncycastle.jcajce.spec.CMCEParameterSpec). This is the legacy NIST round 3 (non-pc, incl. mceliece348864) implementation, retained for backwards compatibility.
 */
@Deprecated
public class CMCEKeyGenerationParameters
    extends KeyGenerationParameters
{
    private CMCEParameters params;

    public CMCEKeyGenerationParameters(
        SecureRandom random,
        CMCEParameters cmceParams)
    {
        super(random, 256);
        this.params = cmceParams;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }
}
