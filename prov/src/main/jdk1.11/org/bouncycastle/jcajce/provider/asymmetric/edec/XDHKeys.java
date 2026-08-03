package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * jdk1.11 multi-release twin of XDHKeys: produces the {@code XECKey}-implementing
 * {@code BC11XDHPublicKey} / {@code BC11XDHPrivateKey} classes and accepts incoming JDK
 * {@code XECPublicKey} / {@code XECPrivateKey} objects. Keep the method set in step with the
 * base copy.
 */
class XDHKeys
{
    static PublicKey publicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        return new BC11XDHPublicKey(prefix, rawData);
    }

    static PublicKey publicKey(SubjectPublicKeyInfo keyInfo)
    {
        return new BC11XDHPublicKey(keyInfo);
    }

    static PublicKey publicKey(AsymmetricKeyParameter params)
    {
        return new BC11XDHPublicKey(params);
    }

    static PrivateKey privateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BC11XDHPrivateKey(keyInfo);
    }

    static PrivateKey privateKey(AsymmetricKeyParameter params)
    {
        return new BC11XDHPrivateKey(params);
    }

    static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
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
                return EdECUtil.getX25519PrivateKey(scalar.get());
            }

            if ("X448".equalsIgnoreCase(algorithm))
            {
                return EdECUtil.getX448PrivateKey(scalar.get());
            }

            if ("XDH".equalsIgnoreCase(algorithm))
            {
                AlgorithmParameterSpec params = jcePriv.getParams();
                if (params instanceof NamedParameterSpec)
                {
                    String name = ((NamedParameterSpec)params).getName();

                    if ("X25519".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getX25519PrivateKey(scalar.get());
                    }

                    if ("X448".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getX448PrivateKey(scalar.get());
                    }
                }
            }

            throw new InvalidKeyException("cannot use XEC private key with unknown algorithm");
        }

        // fall back to the shared handling (BC key classes, then getEncoded()) so third-party
        // provider keys are accepted on JDK 11+ exactly as they are on JDK 8.
        return EdECUtil.generatePrivateKeyParameter(key);
    }

    static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
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
                return EdECUtil.getX25519PublicKey(u);
            }

            if ("X448".equalsIgnoreCase(algorithm))
            {
                return EdECUtil.getX448PublicKey(u);
            }

            if ("XDH".equalsIgnoreCase(algorithm))
            {
                AlgorithmParameterSpec params = jcePub.getParams();
                if (params instanceof NamedParameterSpec)
                {
                    String name = ((NamedParameterSpec)params).getName();

                    if ("X25519".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getX25519PublicKey(u);
                    }

                    if ("X448".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getX448PublicKey(u);
                    }
                }
            }

            throw new InvalidKeyException("cannot use XEC public key with unknown algorithm");
        }

        // fall back to the shared handling (BC key classes, then getEncoded()) so third-party
        // provider keys are accepted on JDK 11+ exactly as they are on JDK 8.
        return EdECUtil.generatePublicKeyParameter(key);
    }
}
