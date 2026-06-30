package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed25519ctxSigner;
import org.bouncycastle.crypto.signers.Ed25519phSigner;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.Ed448phSigner;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

public class SignatureSpi
    extends java.security.SignatureSpi
{
    private static final byte[] EMPTY_CONTEXT = new byte[0];

    private final JcaJceHelper helper = new BCJcaJceHelper();

    private final String algorithm;

    private Signer signer;

    // RFC 8032 instance selectors captured by engineSetParameter, applied at init time.
    protected boolean prehash = false;
    protected byte[] context = null;
    protected boolean parametersSet = false;

    // curve resolved at init time; for the generic EdDSA SPI (algorithm == null) it comes from the key.
    private String resolvedAlgorithm;
    private AlgorithmParameters engineParams;

    SignatureSpi(String algorithm)
    {
        this.algorithm = algorithm;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        AsymmetricKeyParameter pub = getLwEdDSAKeyPublic(publicKey);

        if (pub instanceof Ed25519PublicKeyParameters)
        {
            signer = getSigner("Ed25519");
        }
        else if (pub instanceof Ed448PublicKeyParameters)
        {
            signer = getSigner("Ed448");
        }
        else
        {
            throw new InvalidKeyException("unsupported public key type");
        }

        signer.init(false, pub);
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        AsymmetricKeyParameter priv = getLwEdDSAKeyPrivate(privateKey);

        if (priv instanceof Ed25519PrivateKeyParameters)
        {
            signer = getSigner("Ed25519");
        }
        else if (priv instanceof Ed448PrivateKeyParameters)
        {
            signer = getSigner("Ed448");
        }
        else
        {
            throw new InvalidKeyException("unsupported private key type");
        }

        signer.init(true, priv);
    }

    private static AsymmetricKeyParameter getLwEdDSAKeyPrivate(PrivateKey key)
        throws InvalidKeyException
    {
        return EdECUtil.generatePrivateKeyParameter(key);
    }

    private static AsymmetricKeyParameter getLwEdDSAKeyPublic(PublicKey key)
        throws InvalidKeyException
    {
        return EdECUtil.generatePublicKeyParameter(key);
    }

    private Signer getSigner(String alg)
        throws InvalidKeyException
    {
        if (algorithm != null && !alg.equals(algorithm))
        {
            throw new InvalidKeyException("inappropriate key for " + algorithm);
        }

        resolvedAlgorithm = alg;

        byte[] ctx = (context != null) ? context : EMPTY_CONTEXT;

        if (alg.equals("Ed448"))
        {
            return prehash ? (Signer)new Ed448phSigner(ctx) : new Ed448Signer(ctx);
        }
        else
        {
            if (prehash)
            {
                return new Ed25519phSigner(ctx);
            }
            // RFC 8032: Ed25519ctx requires a non-empty context; an empty context is pure Ed25519.
            if (ctx.length != 0)
            {
                return new Ed25519ctxSigner(ctx);
            }
            return new Ed25519Signer();
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        signer.update(b);
    }

    protected void engineUpdate(byte[] bytes, int off, int len)
        throws SignatureException
    {
        signer.update(bytes, off, len);
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
            throw new SignatureException(e.getMessage());
        }
    }

    protected boolean engineVerify(byte[] signature)
        throws SignatureException
    {
        return signer.verifySignature(signature);
    }

    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params instanceof EdDSAParameterSpec)
        {
            EdDSAParameterSpec edSpec = (EdDSAParameterSpec)params;

            checkCurve(edSpec.getCurveName());
            applyParams(edSpec.isPrehash(), edSpec.getContext());
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown AlgorithmParameterSpec for EdDSA: "
                + ((params == null) ? "null" : params.getClass().getName()));
        }
    }

    /**
     * Apply the RFC 8032 instance selectors. Parameters must be set before initSign / initVerify
     * (the signer that consumes them is built at init time), matching the SunEC EdDSA behaviour.
     */
    protected final void applyParams(boolean prehash, byte[] context)
        throws InvalidAlgorithmParameterException
    {
        if (signer != null)
        {
            throw new InvalidAlgorithmParameterException("cannot set parameters after initSign / initVerify");
        }
        if (context != null && context.length > 255)
        {
            throw new InvalidAlgorithmParameterException("context too long - must be at most 255 bytes");
        }

        this.prehash = prehash;
        this.context = Arrays.clone(context);
        this.parametersSet = true;
        this.engineParams = null;
    }

    /**
     * When the spec names a curve, reject it if it cannot match a single-algorithm SPI
     * (the per-curve Ed25519 / Ed448 SignatureSpi subclasses). The generic EdDSA SPI
     * (algorithm == null) defers the curve to the key.
     */
    protected final void checkCurve(String curveName)
        throws InvalidAlgorithmParameterException
    {
        if (curveName != null && algorithm != null && !curveName.equals(algorithm))
        {
            throw new InvalidAlgorithmParameterException(
                "parameterSpec for " + curveName + " inappropriate for " + algorithm);
        }
    }

    protected void engineSetParameter(String s, Object o)
        throws InvalidParameterException
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(String s)
        throws InvalidParameterException
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null && parametersSet)
        {
            // for the per-curve SPIs the curve is fixed; for the generic EdDSA SPI it is known only
            // once a key has been supplied. Without a curve there is nothing to report yet.
            String curve = (algorithm != null) ? algorithm : resolvedAlgorithm;
            if (curve == null)
            {
                return null;
            }

            try
            {
                engineParams = helper.createAlgorithmParameters(curve);
                engineParams.init(new EdDSAParameterSpec(curve, prehash, context));
            }
            catch (Exception e)
            {
                throw Exceptions.illegalStateException(e.getMessage(), e);
            }
        }

        return engineParams;
    }

    public final static class EdDSA
        extends SignatureSpi
    {
        public EdDSA()
        {
            super(null);
        }
    }

    public final static class Ed448
        extends SignatureSpi
    {
        public Ed448()
        {
            super("Ed448");
        }
    }

    public final static class Ed25519
        extends SignatureSpi
    {
        public Ed25519()
        {
            super("Ed25519");
        }
    }
}
