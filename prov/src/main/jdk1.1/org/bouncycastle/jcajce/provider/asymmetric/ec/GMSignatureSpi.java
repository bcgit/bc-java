package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;

public class GMSignatureSpi
    extends java.security.Signature
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private AlgorithmParameters engineParams;
    private SM2ParameterSpec paramSpec;

    private SecureRandom              appRandom;

    private SM2Signer signer;

    GMSignatureSpi(SM2Signer signer)
    {
        super("SM3withSM2");
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param = ECUtils.generatePublicKeyParameter(publicKey);

        if (paramSpec != null)
        {
            param = new ParametersWithID(param, paramSpec.getID());
        }

        signer.init(false, param);
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        CipherParameters param = ECUtil.generatePrivateKeyParameter(privateKey);

        if (appRandom != null)
        {
            param = new ParametersWithRandom(param, appRandom);
        }

        if (paramSpec != null)
        {
            signer.init(true, new ParametersWithID(param, paramSpec.getID()));
        }
        else
        {
            signer.init(true, param);
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        signer.update(b);
    }

    protected void engineUpdate(byte[] bytes, int off, int length)
        throws SignatureException
    {
        signer.update(bytes, off, length);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            return signer.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new SignatureException("unable to create signature: " + e.getMessage());
        }
    }

    protected boolean engineVerify(byte[] bytes)
        throws SignatureException
    {
        return signer.verifySignature(bytes);
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params instanceof SM2ParameterSpec)
        {
            paramSpec = (SM2ParameterSpec)params;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("only SM2ParameterSpec supported");
        }
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (paramSpec != null)
            {
                try
                {
                    engineParams = helper.createAlgorithmParameters("PSS");
                    engineParams.init(paramSpec);
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e.toString());
                }
            }
        }

        return engineParams;
    }

    protected void engineSetParameter(
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    static public class sm3WithSM2
        extends GMSignatureSpi
    {
        public sm3WithSM2()
        {
            super(new SM2Signer());
        }
    }
}
