package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.agreement.XDHUnifiedAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.XDHUPrivateParameters;
import org.bouncycastle.crypto.params.XDHUPublicParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.util.Properties;

public class KeyAgreementSpi
    extends BaseAgreementSpi
{
    private RawAgreement agreement;
    private DHUParameterSpec dhuSpec;
    private byte[] result;

    KeyAgreementSpi(String algorithm)
    {
        super(Properties.isOverrideSet(Properties.EMULATE_ORACLE) ? "XDH" : algorithm, null);
    }

    KeyAgreementSpi(String algorithm, DerivationFunction kdf)
    {
        super(Properties.isOverrideSet(Properties.EMULATE_ORACLE) ? "XDH" : algorithm, kdf);
    }

    protected byte[] doCalcSecret()
    {
        return result;
    }

    protected void doInitFromKey(Key key, AlgorithmParameterSpec params, SecureRandom secureRandom)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (!(key instanceof PrivateKey))
        {
            throw new InvalidKeyException("private XDH key required");
        }

        AsymmetricKeyParameter priv = EdECUtil.generatePrivateKeyParameter((PrivateKey)key);

        if (priv instanceof X25519PrivateKeyParameters)
        {
            agreement = getAgreement("X25519");
        }
        else if (priv instanceof X448PrivateKeyParameters)
        {
            agreement = getAgreement("X448");
        }
        else
        {
            throw new IllegalStateException("unsupported private key type");
        }

        ukmParameters = null;
        if (params instanceof DHUParameterSpec)
        {
            if (kaAlgorithm.indexOf('U') < 0)
            {
                throw new InvalidAlgorithmParameterException("agreement algorithm not DHU based");
            }

            dhuSpec = (DHUParameterSpec)params;

            ukmParameters = dhuSpec.getUserKeyingMaterial();

            agreement.init(new XDHUPrivateParameters(
                priv, ((BCXDHPrivateKey)dhuSpec.getEphemeralPrivateKey()).engineGetKeyParameters(),
                ((BCXDHPublicKey)dhuSpec.getEphemeralPublicKey()).engineGetKeyParameters()));
        }
        else if (params != null)
        {
            agreement.init(priv);

            if (params instanceof UserKeyingMaterialSpec)
            {
                if (kdf == null)
                {
                    throw new InvalidAlgorithmParameterException("no KDF specified for UserKeyingMaterialSpec");
                }
                this.ukmParameters = ((UserKeyingMaterialSpec)params).getUserKeyingMaterial();
            }
            else
            {
                throw new InvalidAlgorithmParameterException("unknown ParameterSpec");
            }
        }
        else
        {
            agreement.init(priv);
        }

        if (kdf != null && ukmParameters == null)
        {
            ukmParameters = new byte[0];
        }
    }

    protected Key engineDoPhase(Key key, boolean lastPhase)
        throws InvalidKeyException, IllegalStateException
    {
        if (!(key instanceof PublicKey))
        {
            throw new InvalidKeyException("public XDH key required");
        }

        if (agreement == null)
        {
            throw new IllegalStateException(kaAlgorithm + " not initialised.");
        }

        if (!lastPhase)
        {
            throw new IllegalStateException(kaAlgorithm + " can only be between two parties.");
        }

        AsymmetricKeyParameter pub = EdECUtil.generatePublicKeyParameter((PublicKey)key);

        result = new byte[agreement.getAgreementSize()];

        if (dhuSpec != null)
        {
            agreement.calculateAgreement(new XDHUPublicParameters(pub, ((BCXDHPublicKey)dhuSpec.getOtherPartyEphemeralKey()).engineGetKeyParameters()), result, 0);
        }
        else
        {
            agreement.calculateAgreement(pub, result, 0);
        }

        return null;
    }

    private RawAgreement getAgreement(String alg)
        throws InvalidKeyException
    {
        if (!(kaAlgorithm.equals("XDH") || kaAlgorithm.startsWith(alg)))
        {
            throw new InvalidKeyException("inappropriate key for " + kaAlgorithm);
        }

        if (kaAlgorithm.indexOf('U') > 0)
        {
            if (alg.startsWith("X448"))
            {
                return new XDHUnifiedAgreement(new X448Agreement());
            }
            else
            {
                return new XDHUnifiedAgreement(new X25519Agreement());
            }
        }
        else
        {
            if (alg.startsWith("X448"))
            {
                return new X448Agreement();
            }
            else
            {
                return new X25519Agreement();
            }
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

    public final static class X25519withSHA256CKDF
        extends KeyAgreementSpi
    {
        public X25519withSHA256CKDF()
        {
            super("X25519withSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
        }
    }

    public static class X25519withSHA384CKDF
        extends KeyAgreementSpi
    {
        public X25519withSHA384CKDF()
        {
            super("X25519withSHA384CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
        }
    }

    public static class X25519withSHA512CKDF
        extends KeyAgreementSpi
    {
        public X25519withSHA512CKDF()
        {
            super("X25519withSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
        }
    }

    public final static class X448withSHA256CKDF
        extends KeyAgreementSpi
    {
        public X448withSHA256CKDF()
        {
            super("X448withSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
        }
    }

    public static class X448withSHA384CKDF
        extends KeyAgreementSpi
    {
        public X448withSHA384CKDF()
        {
            super("X448withSHA384CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
        }
    }

    public final static class X448withSHA512CKDF
        extends KeyAgreementSpi
    {
        public X448withSHA512CKDF()
        {
            super("X448withSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
        }
    }

    public final static class X25519withSHA256KDF
        extends KeyAgreementSpi
    {
        public X25519withSHA256KDF()
        {
            super("X25519withSHA256KDF", new KDF2BytesGenerator(DigestFactory.createSHA256()));
        }
    }

    public final static class X448withSHA512KDF
        extends KeyAgreementSpi
    {
        public X448withSHA512KDF()
        {
            super("X448withSHA512KDF", new KDF2BytesGenerator(DigestFactory.createSHA512()));
        }
    }

    public static class X25519UwithSHA256CKDF
        extends KeyAgreementSpi
    {
        public X25519UwithSHA256CKDF()
        {
            super("X25519UwithSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
        }
    }

    public static class X448UwithSHA512CKDF
        extends KeyAgreementSpi
    {
        public X448UwithSHA512CKDF()
        {
            super("X448UwithSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
        }
    }

    public static class X25519UwithSHA256KDF
        extends KeyAgreementSpi
    {
        public X25519UwithSHA256KDF()
        {
            super("X25519UwithSHA256KDF", new KDF2BytesGenerator(DigestFactory.createSHA256()));
        }
    }

    public static class X448UwithSHA512KDF
        extends KeyAgreementSpi
    {
        public X448UwithSHA512KDF()
        {
            super("X448UwithSHA512KDF", new KDF2BytesGenerator(DigestFactory.createSHA512()));
        }
    }
}
