package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Exceptions;

public abstract class BaseDeterministicOrRandomSignature
    extends Signature
{
    private final JcaJceHelper helper = new BCJcaJceHelper();
    private final AlgorithmParameterSpec originalSpec;

    protected AlgorithmParameters engineParams;
    protected ContextParameterSpec paramSpec;

    protected AsymmetricKeyParameter keyParams;
    protected boolean isInitState = true;

    protected BaseDeterministicOrRandomSignature(String name)
    {
        super(name);
        this.originalSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
    }

    final protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        verifyInit(publicKey);
        paramSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
        isInitState = true;
        reInit();
    }

    protected abstract void verifyInit(PublicKey publicKey) throws InvalidKeyException;

    final protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        signInit(privateKey, null);
        paramSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
        isInitState = true;
        reInit();
    }

    final protected void engineInitSign(
        PrivateKey privateKey,
        SecureRandom random)
        throws InvalidKeyException
    {
        signInit(privateKey, random);
        paramSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
        isInitState = true;
        reInit();
    }

    protected abstract void signInit(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException;

    final protected void engineUpdate(
        byte b)
        throws SignatureException
    {
        isInitState = false;
        updateEngine(b);
    }

    protected abstract void updateEngine(byte b) throws SignatureException;

    final protected void engineUpdate(
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

    private void reInit()
    {
        CipherParameters param = keyParams;

        if (keyParams.isPrivate())
        {
            if (appRandom != null)
            {
                param = new ParametersWithRandom(param, appRandom);
            }

            if (paramSpec != null)
            {
                param = new ParametersWithContext(param, paramSpec.getContext());
            }

            reInitialize(true, param);
        }
        else
        {
            if (paramSpec != null)
            {
                param = new ParametersWithContext(param, paramSpec.getContext());
            }

            reInitialize(false, param);
        }
    }

    protected abstract void reInitialize(boolean forSigning, CipherParameters params);

    protected final AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (paramSpec != null && paramSpec != ContextParameterSpec.EMPTY_CONTEXT_SPEC)
            {
                try
                {
                    engineParams = helper.createAlgorithmParameters("CONTEXT");
                    engineParams.init(paramSpec);
                }
                catch (Exception e)
                {
                    throw Exceptions.illegalStateException(e.toString(), e);
                }
            }
        }

        return engineParams;
    }

    /**
     * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a>
     */
    protected final void engineSetParameter(
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("SetParameter unsupported");
    }

    /**
     * @deprecated replaced with <a href = "#engineGetParameters()">engineGetParameters()</a>
     */
    protected final Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("GetParameter unsupported");
    }
}
