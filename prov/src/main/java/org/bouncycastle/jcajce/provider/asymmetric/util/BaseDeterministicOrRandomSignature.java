package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;

public abstract class BaseDeterministicOrRandomSignature
    extends SignatureSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();
    private final AlgorithmParameterSpec originalSpec;

    protected AlgorithmParameters engineParams;
    protected ContextParameterSpec paramSpec;

    protected AsymmetricKeyParameter keyParams;
    protected boolean isInitState = true;

    protected BaseDeterministicOrRandomSignature()
    {
        this.originalSpec = null;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        verifyInit(publicKey);
        paramSpec = null;
        isInitState = true;
        reInit();
    }

    protected abstract void verifyInit(PublicKey publicKey) throws InvalidKeyException;

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        signInit(privateKey, null);
        paramSpec = null;
        isInitState = true;
        reInit();
    }

    protected void engineInitSign(
        PrivateKey privateKey,
        SecureRandom random)
        throws InvalidKeyException
    {
        signInit(privateKey, random);
        paramSpec = null;
        isInitState = true;
        reInit();
    }

    protected abstract void signInit(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException;

    protected void engineUpdate(
        byte b)
        throws SignatureException
    {
        isInitState = false;
        updateEngine(b);
    }

    protected abstract void updateEngine(byte b) throws SignatureException;

    protected void engineUpdate(
        byte[] b,
        int off,
        int len)
        throws SignatureException
    {
        isInitState = false;
        updateEngine(b, off, len);
    }

    protected abstract void updateEngine(byte[] buf, int off, int len) throws SignatureException;

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            if (originalSpec != null)
            {
                params = originalSpec;
            }
            else
            {
                return;
            }
        }

        if (!isInitState)
        {
            throw new ProviderException("cannot call setParameter in the middle of update");
        }

        if (params instanceof ContextParameterSpec)
        {
            this.paramSpec = (ContextParameterSpec)params;
            reInit();
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown AlgorithmParameterSpec in signature");
        }
    }

    abstract protected void reInit();

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (paramSpec != null)
            {
                try
                {
                    engineParams = helper.createAlgorithmParameters("CONTEXT");
                    engineParams.init(paramSpec);
                }
                catch (Exception e)
                {
                    throw new IllegalStateException(e.toString(), e);
                }
            }
        }

        return engineParams;
    }

    /**
     * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a>
     */
    protected void engineSetParameter(
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("SetParameter unsupported");
    }

    /**
     * @deprecated replaced with <a href = "#engineGetParameters()">engineGetParameters()</a>
     */
    protected Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("GetParameter unsupported");
    }
}
