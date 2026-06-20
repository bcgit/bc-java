package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

/**
 * @deprecated the standardised FrodoKEM (ISO/IEC 18033-2:2006/Amd 2:2026) is now provided under org.bouncycastle.crypto and org.bouncycastle.jcajce (see FrodoKEMParameters / FrodoKEMParameterSpec). This is the legacy NIST round 3 (unsalted, eFrodoKEM) implementation, retained for backwards compatibility.
 */
@Deprecated
public class FrodoKeyGenerationParameters
    extends KeyGenerationParameters
{
    private FrodoParameters params;

    public FrodoKeyGenerationParameters(
            SecureRandom random,
            FrodoParameters frodoParameters)
    {
        super(random, 256);
        this.params = frodoParameters;
    }

    public  FrodoParameters getParameters()
    {
        return params;
    }
}
