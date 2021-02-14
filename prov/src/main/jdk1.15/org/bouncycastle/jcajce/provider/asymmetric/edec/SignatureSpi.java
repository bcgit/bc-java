package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

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
            throw new IllegalStateException("unsupported public key type");
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
            throw new IllegalStateException("unsupported private key type");
        }

        signer.init(true, priv);
    }

    private static Ed25519PrivateKeyParameters getEd25519PrivateKey(byte[] keyData)
        throws InvalidKeyException
    {
        if (Ed25519PrivateKeyParameters.KEY_SIZE != keyData.length)
        {
            throw new InvalidKeyException("cannot use EdEC private key (Ed25519) with bytes of incorrect length");
        }

        return new Ed25519PrivateKeyParameters(keyData, 0);
    }

    private static Ed25519PublicKeyParameters getEd25519PublicKey(EdECPoint point)
        throws InvalidKeyException
    {
        byte[] keyData = getPublicKeyData(Ed25519PublicKeyParameters.KEY_SIZE, point);

        return new Ed25519PublicKeyParameters(keyData, 0);
    }

    private static Ed448PrivateKeyParameters getEd448PrivateKey(byte[] keyData)
        throws InvalidKeyException
    {
        if (Ed448PrivateKeyParameters.KEY_SIZE != keyData.length)
        {
            throw new InvalidKeyException("cannot use EdEC private key (Ed448) with bytes of incorrect length");
        }

        return new Ed448PrivateKeyParameters(keyData, 0);
    }

    private static Ed448PublicKeyParameters getEd448PublicKey(EdECPoint point)
        throws InvalidKeyException
    {
        byte[] keyData = getPublicKeyData(Ed448PublicKeyParameters.KEY_SIZE, point);

        return new Ed448PublicKeyParameters(keyData, 0);
    }

    private static AsymmetricKeyParameter getLwEdDSAKeyPrivate(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCEdDSAPrivateKey)
        {
            return ((BCEdDSAPrivateKey)key).engineGetKeyParameters();
        }

        if (key instanceof EdECPrivateKey)
        {
            EdECPrivateKey jcaPriv = (EdECPrivateKey)key;

            Optional<byte[]> bytes = jcaPriv.getBytes();
            if (!bytes.isPresent())
            {
                throw new InvalidKeyException("cannot use EdEC private key without bytes");
            }

            String algorithm = jcaPriv.getAlgorithm();

            if ("Ed25519".equalsIgnoreCase(algorithm))
            {
                return getEd25519PrivateKey(bytes.get());
            }

            if ("Ed448".equalsIgnoreCase(algorithm))
            {
                return getEd448PrivateKey(bytes.get());
            }

            if ("EdDSA".equalsIgnoreCase(algorithm))
            {
                AlgorithmParameterSpec params = jcaPriv.getParams();
                if (params instanceof NamedParameterSpec)
                {
                    NamedParameterSpec namedParams = (NamedParameterSpec)params;

                    String name = namedParams.getName();

                    if ("Ed25519".equalsIgnoreCase(name))
                    {
                        return getEd25519PrivateKey(bytes.get());
                    }

                    if ("Ed448".equalsIgnoreCase(name))
                    {
                        return getEd448PrivateKey(bytes.get());
                    }
                }
            }

            throw new InvalidKeyException("cannot use EdEC private key with unknown algorithm");
        }

        throw new InvalidKeyException("cannot identify EdDSA private key");
    }

    private static AsymmetricKeyParameter getLwEdDSAKeyPublic(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCEdDSAPublicKey)
        {
            return ((BCEdDSAPublicKey)key).engineGetKeyParameters();
        }

        if (key instanceof EdECPublicKey)
        {
            EdECPublicKey jcaPub = (EdECPublicKey)key;

            EdECPoint point = jcaPub.getPoint();

            String algorithm = jcaPub.getAlgorithm();

            if ("Ed25519".equalsIgnoreCase(algorithm))
            {
                return getEd25519PublicKey(point);
            }

            if ("Ed448".equalsIgnoreCase(algorithm))
            {
                return getEd448PublicKey(point);
            }

            if ("EdDSA".equalsIgnoreCase(algorithm))
            {
                AlgorithmParameterSpec params = jcaPub.getParams();
                if (params instanceof NamedParameterSpec)
                {
                    NamedParameterSpec namedParams = (NamedParameterSpec)params;

                    String name = namedParams.getName();

                    if ("Ed25519".equalsIgnoreCase(name))
                    {
                        return getEd25519PublicKey(point);
                    }

                    if ("Ed448".equalsIgnoreCase(name))
                    {
                        return getEd448PublicKey(point);
                    }
                }
            }

            throw new InvalidKeyException("cannot use EdEC public key with unknown algorithm");
        }

        throw new InvalidKeyException("cannot identify EdDSA public key");
    }

    private static byte[] getPublicKeyData(int length, EdECPoint point)
        throws InvalidKeyException
    {
        BigInteger y = point.getY();
        if (y.signum() < 0)
        {
            throw new InvalidKeyException("cannot use EdEC public key with negative Y value");
        }

        try
        {
            byte[] keyData = BigIntegers.asUnsignedByteArray(length, y);
            if ((keyData[0] & 0x80) == 0)
            {
                if (point.isXOdd())
                {
                    keyData[0] |= 0x80;
                }

                return Arrays.reverseInPlace(keyData);
            }
        }
        catch (RuntimeException e)
        {
        }        

        throw new InvalidKeyException("cannot use EdEC public key with invalid Y value");
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
