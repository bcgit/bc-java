package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;

public class SignatureSpi
    extends BaseDeterministicOrRandomSignature
{
    private final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    private final SLHDSASigner signer;

    protected SignatureSpi(SLHDSASigner signer)
    {
        this.signer = signer;
    }

    protected void verifyInit(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (publicKey instanceof BCSLHDSAPublicKey)
        {
            BCSLHDSAPublicKey key = (BCSLHDSAPublicKey)publicKey;

            this.keyParams = key.getKeyParams();
        }
        else
        {
            throw new InvalidKeyException("unknown public key passed to SLH-DSA");
        }
    }

    protected void signInit(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        this.appRandom = random;
        if (privateKey instanceof BCSLHDSAPrivateKey)
        {
            BCSLHDSAPrivateKey key = (BCSLHDSAPrivateKey)privateKey;

            this.keyParams = key.getKeyParams();
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to SLH-DSA");
        }
    }

    protected void updateEngine(byte b)
        throws SignatureException
    {
        bOut.write(b);
    }

    protected void updateEngine(byte[] buf, int off, int len)
        throws SignatureException
    {
        bOut.write(buf, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        CipherParameters param = keyParams;

        if (!(param instanceof SLHDSAPrivateKeyParameters))
        {
            throw new SignatureException("engine initialized for verification");
        }

        if (appRandom != null)
        {
            param = new ParametersWithRandom(param, appRandom);
        }

        if (paramSpec != null)
        {
            param = new ParametersWithContext(param, paramSpec.getContext());
        }

        try
        {
            signer.init(true, param);

            byte[] sig = signer.generateSignature(bOut.toByteArray());

            return sig;
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
        finally
        {
            this.isInitState = true;
            bOut.reset();
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        CipherParameters param = keyParams;

        if (!(param instanceof SLHDSAPublicKeyParameters))
        {
            throw new SignatureException("engine initialized for signing");
        }

        if (paramSpec != null)
        {
            param = new ParametersWithContext(param, paramSpec.getContext());
        }

        try
        {
            signer.init(false, param);

            return signer.verifySignature(bOut.toByteArray(), sigBytes);
        }
        finally
        {
            this.isInitState = true;
            bOut.reset();
        }
    }

    protected void reInit()
    {
        bOut.reset();
    }
    
    static public class Direct
        extends SignatureSpi
    {
        public Direct()
        {
            super(new SLHDSASigner());
        }
    }
}
