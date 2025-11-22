package org.bouncycastle.jcajce.provider.kdf.hkdf;

import org.bouncycastle.crypto.params.HKDFParameters;

import java.security.spec.AlgorithmParameterSpec;

public class HKDFParameterSpec
        extends HKDFParameters
        implements AlgorithmParameterSpec
{
    public HKDFParameterSpec(byte[] ikm, byte[] salt, byte[] info)
    {
        super(ikm, salt, info);
    }
}
