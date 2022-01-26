package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.agreement.XDHUnifiedAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.params.XDHUPrivateParameters;
import org.bouncycastle.crypto.params.XDHUPublicParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class KeyAgreementSpi
    extends BaseAgreementSpi
{
    private RawAgreement agreement;
    private DHUParameterSpec dhuSpec;
    private byte[] result;

    KeyAgreementSpi(String algorithm)
    {
        super(algorithm, null);
    }

    KeyAgreementSpi(String algorithm, DerivationFunction kdf)
    {
        super(algorithm, kdf);
    }

    protected byte[] doCalcSecret()
    {
        return result;
    }

    protected void doInitFromKey(Key key, AlgorithmParameterSpec params, SecureRandom secureRandom)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AsymmetricKeyParameter priv = getLwXDHKeyPrivate(key);

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
        if (agreement == null)
        {
            throw new IllegalStateException(kaAlgorithm + " not initialised.");
        }

        if (!lastPhase)
        {
            throw new IllegalStateException(kaAlgorithm + " can only be between two parties.");
        }

        AsymmetricKeyParameter pub = getLwXDHKeyPublic(key);

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

    private static AsymmetricKeyParameter getLwXDHKeyPrivate(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPrivateKey)
        {
            return ((BCXDHPrivateKey)key).engineGetKeyParameters();
        }

        if (key instanceof XECPrivateKey)
        {
            XECPrivateKey jcePriv = (XECPrivateKey)key;

            Optional<byte[]> scalar = jcePriv.getScalar();
            if (!scalar.isPresent())
            {
                throw new InvalidKeyException("cannot use XEC private key without scalar");
            }

            String algorithm = jcePriv.getAlgorithm();

            if ("X25519".equalsIgnoreCase(algorithm))
            {
                return getX25519PrivateKey(scalar.get());
            }

            if ("X448".equalsIgnoreCase(algorithm))
            {
                return getX448PrivateKey(scalar.get());
            }

            if ("XDH".equalsIgnoreCase(algorithm))
            {
                AlgorithmParameterSpec params = jcePriv.getParams();
                if (params instanceof NamedParameterSpec)
                {
                    NamedParameterSpec namedParams = (NamedParameterSpec)params;

                    String name = namedParams.getName();

                    if ("X25519".equalsIgnoreCase(name))
                    {
                        return getX25519PrivateKey(scalar.get());
                    }

                    if ("X448".equalsIgnoreCase(name))
                    {
                        return getX448PrivateKey(scalar.get());
                    }
                }
            }

            throw new InvalidKeyException("cannot use XEC private key with unknown algorithm");
        }

        throw new InvalidKeyException("cannot identify XDH private key");
    }

    private AsymmetricKeyParameter getLwXDHKeyPublic(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPublicKey)
        {
            return ((BCXDHPublicKey)key).engineGetKeyParameters();
        }

        if (key instanceof XECPublicKey)
        {
            XECPublicKey jcePub = (XECPublicKey)key;

            BigInteger u = jcePub.getU();
            if (u.signum() < 0)
            {
                throw new InvalidKeyException("cannot use XEC public key with negative U value");
            }

            String algorithm = jcePub.getAlgorithm();

            if ("X25519".equalsIgnoreCase(algorithm))
            {
                return getX25519PublicKey(u);
            }

            if ("X448".equalsIgnoreCase(algorithm))
            {
                return getX448PublicKey(u);
            }

            if ("XDH".equalsIgnoreCase(algorithm))
            {
                AlgorithmParameterSpec params = jcePub.getParams();
                if (params instanceof NamedParameterSpec)
                {
                    NamedParameterSpec namedParams = (NamedParameterSpec)params;

                    String name = namedParams.getName();

                    if ("X25519".equalsIgnoreCase(name))
                    {
                        return getX25519PublicKey(u);
                    }

                    if ("X448".equalsIgnoreCase(name))
                    {
                        return getX448PublicKey(u);
                    }
                }
            }

            throw new InvalidKeyException("cannot use XEC public key with unknown algorithm");
        }

        throw new InvalidKeyException("cannot identify XDH public key");
    }

    private static byte[] getPublicKeyData(int length, BigInteger u)
        throws InvalidKeyException
    {
        try
        {
            return Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(length, u));
        }
        catch (RuntimeException e)
        {
            throw new InvalidKeyException("cannot use XEC public key with invalid U value");
        }
    }

    private static X25519PrivateKeyParameters getX25519PrivateKey(byte[] keyData)
        throws InvalidKeyException
    {
        if (X25519PrivateKeyParameters.KEY_SIZE != keyData.length)
        {
            throw new InvalidKeyException("cannot use XEC private key (X25519) with scalar of incorrect length");
        }

        return new X25519PrivateKeyParameters(keyData, 0);
    }

    private static X25519PublicKeyParameters getX25519PublicKey(BigInteger u)
        throws InvalidKeyException
    {
        byte[] keyData = getPublicKeyData(X25519PublicKeyParameters.KEY_SIZE, u);

        return new X25519PublicKeyParameters(keyData, 0);
    }

    private static X448PrivateKeyParameters getX448PrivateKey(byte[] keyData)
        throws InvalidKeyException
    {
        if (X448PrivateKeyParameters.KEY_SIZE != keyData.length)
        {
            throw new InvalidKeyException("cannot use XEC private key (X448) with scalar of incorrect length");
        }

        return new X448PrivateKeyParameters(keyData, 0);
    }

    private static X448PublicKeyParameters getX448PublicKey(BigInteger u)
        throws InvalidKeyException
    {
        byte[] keyData = getPublicKeyData(X448PublicKeyParameters.KEY_SIZE, u);

        return new X448PublicKeyParameters(keyData, 0);
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
