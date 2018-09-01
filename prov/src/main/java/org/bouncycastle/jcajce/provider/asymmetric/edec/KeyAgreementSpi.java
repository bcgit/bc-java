package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;

public class KeyAgreementSpi
    extends BaseAgreementSpi
{
    private RawAgreement agreement;

    private byte[] result;

    KeyAgreementSpi(String algorithm)
    {
        super(algorithm, null);
    }

    protected byte[] calcSecret()
    {
        return result;
    }

    protected void engineInit(Key key, SecureRandom secureRandom)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPrivateKey)
        {
            AsymmetricKeyParameter priv = ((BCXDHPrivateKey)key).engineGetKeyParameters();

            if (priv instanceof X448PrivateKeyParameters)
            {
                agreement = getAgreement("X448");
            }
            else
            {
                agreement = getAgreement("X25519");
            }

            agreement.init(priv);
        }
        else
        {
            throw new InvalidKeyException("cannot identify XDH private key");
        }
    }

    protected void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (key instanceof BCXDHPrivateKey)
        {
            AsymmetricKeyParameter priv = ((BCXDHPrivateKey)key).engineGetKeyParameters();

            if (priv instanceof X448PrivateKeyParameters)
            {
                agreement = getAgreement("X448");
            }
            else
            {
                agreement = getAgreement("X25519");
            }

            agreement.init(priv);
        }
        else
        {
            throw new InvalidKeyException("cannot identify XDH private key");
        }
    }

    protected Key engineDoPhase(Key key, boolean lastPhase)
        throws InvalidKeyException, IllegalStateException
    {
        if (agreement == null)
        {
            throw new IllegalStateException(kaAlgorithm + " not initialised.");
        }

        if (!lastPhase)
        {
            throw new IllegalStateException(kaAlgorithm + " can only be between two parties.");
        }

        if (!(key instanceof BCXDHPublicKey))
        {
            throw new InvalidKeyException("cannot identify XDH private key");
        }

        AsymmetricKeyParameter pub = ((BCXDHPublicKey)key).engineGetKeyParameters();

        result = new byte[agreement.getAgreementSize()];

        agreement.calculateAgreement(pub, result, 0);

        return null;
    }

    private RawAgreement getAgreement(String alg)
        throws InvalidKeyException
    {
        if (!(kaAlgorithm.equals("XDH") || alg.equals(kaAlgorithm)))
        {
            throw new InvalidKeyException("inappropriate key for " + kaAlgorithm);
        }

        if (alg.equals("X448"))
        {
            return new X448Agreement();
        }
        else
        {
            return new X25519Agreement();
        }
    }

    public final static class XDH
        extends KeyAgreementSpi
    {
        public XDH()
        {
            super("XDH");
        }
    }

    public final static class X448
        extends KeyAgreementSpi
    {
        public X448()
        {
            super("X448");
        }
    }

    public final static class X25519
        extends KeyAgreementSpi
    {
        public X25519()
        {
            super("X25519");
        }
    }
}
