package org.bouncycastle.jcajce;

import java.security.PublicKey;

import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

/**
 * An ML-DSA private key wrapper which acts as a proxy to allow an ML-DSA public key
 * to be passed in for external-mu calculation.
 */
public class MLDSAProxyPrivateKey
    implements MLDSAPrivateKey
{
    private final MLDSAPublicKey publicKey;

    public MLDSAProxyPrivateKey(PublicKey publicKey)
    {
        if (!(publicKey instanceof MLDSAPublicKey))
        {
            throw new IllegalArgumentException("public key must be an ML-DSA public key");
        }
        this.publicKey = (MLDSAPublicKey)publicKey;
    }

    public MLDSAPublicKey getPublicKey()
    {
        return publicKey;
    }

    @Override
    public String getAlgorithm()
    {
        return publicKey.getAlgorithm();
    }

    @Override
    public String getFormat()
    {
        return null;
    }

    @Override
    public byte[] getEncoded()
    {
        return new byte[0];
    }

    @Override
    public MLDSAParameterSpec getParameterSpec()
    {
        return publicKey.getParameterSpec();
    }

    @Override
    public byte[] getPrivateData()
    {
        return new byte[0];
    }

    @Override
    public byte[] getSeed()
    {
        return new byte[0];
    }

    @Override
    public MLDSAPrivateKey getPrivateKey(boolean preferSeedOnly)
    {
        return null;
    }
}
