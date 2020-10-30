package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class SignatureSpi
    extends java.security.SignatureSpi
{
    private static final byte[] EMPTY_CONTEXT = new byte[0];

    private final String algorithm;

    private Signer signer;

    SignatureSpi(String algorithm)
    {
        this.algorithm = algorithm;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        AsymmetricKeyParameter pub;
        if (publicKey instanceof BCEdDSAPublicKey)
        {
            pub = ((BCEdDSAPublicKey)publicKey).engineGetKeyParameters();
        }
        else if (publicKey instanceof EdECPublicKey)
        {
            EdECPublicKey jcaPub = (EdECPublicKey)publicKey;

            byte[] keyData = Arrays.reverse(BigIntegers.asUnsignedByteArray(jcaPub.getPoint().getY()));

            if (keyData.length == Ed448PublicKeyParameters.KEY_SIZE)
            {
                pub = new Ed448PublicKeyParameters(keyData, 0);
            }
            else
            {
                pub = new Ed25519PublicKeyParameters(keyData, 0);
            }
        }
        else
        {
            throw new InvalidKeyException("cannot identify EdDSA public key");
        }

        if (pub instanceof Ed448PublicKeyParameters)
        {
            signer = getSigner("Ed448");
        }
        else
        {
            signer = getSigner("Ed25519");
        }

        signer.init(false, pub);
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        AsymmetricKeyParameter priv;
        if (privateKey instanceof BCEdDSAPrivateKey)
        {
            priv = ((BCEdDSAPrivateKey)privateKey).engineGetKeyParameters();
        }
        else if (privateKey instanceof EdECPrivateKey)
        {
            EdECPrivateKey jcaPriv = (EdECPrivateKey)privateKey;

            if (jcaPriv.getBytes().isPresent())
            {
                byte[] keyData = jcaPriv.getBytes().get();

                if (keyData.length == Ed448PrivateKeyParameters.KEY_SIZE)
                {
                    priv = new Ed448PrivateKeyParameters(keyData, 0);
                }
                else
                {
                    priv = new Ed25519PrivateKeyParameters(keyData, 0);
                }
            }
            else
            {
                throw new InvalidKeyException("cannot use other provider EdDSA private key");
            }
        }
        else
        {
            throw new InvalidKeyException("cannot identify EdDSA private key");
        }

        if (priv instanceof Ed448PrivateKeyParameters)
        {
            signer = getSigner("Ed448");
        }
        else
        {
            signer = getSigner("Ed25519");
        }

        signer.init(true, priv);
    }

    private Signer getSigner(String alg)
        throws InvalidKeyException
    {
        if (algorithm != null && !alg.equals(algorithm))
        {
            throw new InvalidKeyException("inappropriate key for " + algorithm);
        }

        if (alg.equals("Ed448"))
        {
            return new Ed448Signer(EMPTY_CONTEXT);
        }
        else
        {
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
        return null;
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
