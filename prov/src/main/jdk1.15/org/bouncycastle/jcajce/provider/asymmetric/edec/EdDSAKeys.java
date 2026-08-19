package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;

/**
 * jdk1.15 multi-release twin of EdDSAKeys: produces the {@code EdECKey}-implementing
 * {@code BC15EdDSAPublicKey} / {@code BC15EdDSAPrivateKey} classes, accepts incoming JDK
 * {@code EdECPublicKey} / {@code EdECPrivateKey} objects, and bridges the standard JDK 15+
 * EdEC key specs and {@code java.security.spec.EdDSAParameterSpec}. Keep the method set in
 * step with the base copy.
 */
class EdDSAKeys
{
    static PublicKey publicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        return new BC15EdDSAPublicKey(prefix, rawData);
    }

    static PublicKey publicKey(SubjectPublicKeyInfo keyInfo)
    {
        return new BC15EdDSAPublicKey(keyInfo);
    }

    static PublicKey publicKey(AsymmetricKeyParameter params)
    {
        return new BC15EdDSAPublicKey(params);
    }

    static PrivateKey privateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BC15EdDSAPrivateKey(keyInfo);
    }

    static PrivateKey privateKey(AsymmetricKeyParameter params)
    {
        return new BC15EdDSAPrivateKey(params);
    }

    static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
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
                return EdECUtil.getEd25519PrivateKey(bytes.get());
            }

            if ("Ed448".equalsIgnoreCase(algorithm))
            {
                return EdECUtil.getEd448PrivateKey(bytes.get());
            }

            if ("EdDSA".equalsIgnoreCase(algorithm))
            {
                AlgorithmParameterSpec params = jcaPriv.getParams();
                if (params instanceof NamedParameterSpec)
                {
                    String name = ((NamedParameterSpec)params).getName();

                    if ("Ed25519".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getEd25519PrivateKey(bytes.get());
                    }

                    if ("Ed448".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getEd448PrivateKey(bytes.get());
                    }
                }
            }

            throw new InvalidKeyException("cannot use EdEC private key with unknown algorithm");
        }

        // fall back to the shared handling (BC key classes, then getEncoded()) so third-party
        // provider keys are accepted on JDK 15+ exactly as they are on JDK 8.
        return EdECUtil.generatePrivateKeyParameter(key);
    }

    static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
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
                return EdECUtil.getEd25519PublicKey(point.getY(), point.isXOdd());
            }

            if ("Ed448".equalsIgnoreCase(algorithm))
            {
                return EdECUtil.getEd448PublicKey(point.getY(), point.isXOdd());
            }

            if ("EdDSA".equalsIgnoreCase(algorithm))
            {
                AlgorithmParameterSpec params = jcaPub.getParams();
                if (params instanceof NamedParameterSpec)
                {
                    String name = ((NamedParameterSpec)params).getName();

                    if ("Ed25519".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getEd25519PublicKey(point.getY(), point.isXOdd());
                    }

                    if ("Ed448".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getEd448PublicKey(point.getY(), point.isXOdd());
                    }
                }
            }

            throw new InvalidKeyException("cannot use EdEC public key with unknown algorithm");
        }

        // fall back to the shared handling (BC key classes, then getEncoded()) so third-party
        // provider keys are accepted on JDK 15+ exactly as they are on JDK 8.
        return EdECUtil.generatePublicKeyParameter(key);
    }

    /**
     * Return a KeySpec for a version-specific spec type - here the JDK 15+ EdEC key specs -
     * or null when the request is not one this JDK version bridges.
     */
    static KeySpec getKeySpec(Key key, Class<?> spec)
        throws InvalidKeySpecException
    {
        if (spec.isAssignableFrom(EdECPrivateKeySpec.class))
        {
            if (key instanceof EdECPrivateKey)
            {
                EdECPrivateKey edKey = (EdECPrivateKey)key;

                Optional<byte[]> bytes = edKey.getBytes();
                if (bytes.isPresent())
                {
                    return new EdECPrivateKeySpec(edKey.getParams(), bytes.get());
                }
                else
                {
                    throw new IllegalArgumentException("no byte[] data associated with key");
                }
            }
        }
        else if (spec.isAssignableFrom(EdECPublicKeySpec.class))
        {
            if (key instanceof EdECPublicKey)
            {
                EdECPublicKey edKey = (EdECPublicKey)key;

                return new EdECPublicKeySpec(edKey.getParams(), edKey.getPoint());
            }
        }

        return null;
    }

    /**
     * Generate a private key from a version-specific KeySpec - here the JDK 15+
     * EdECPrivateKeySpec - or return null when the spec is not one this JDK version bridges.
     */
    static PrivateKey generatePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof EdECPrivateKeySpec)
        {
            EdECPrivateKeySpec edSpec = (EdECPrivateKeySpec)keySpec;
            try
            {
                AsymmetricKeyParameter parameters;
                if (NamedParameterSpec.ED448.getName().equalsIgnoreCase(edSpec.getParams().getName()))
                {
                    parameters = EdECUtil.getEd448PrivateKey(edSpec.getBytes());
                }
                else if (NamedParameterSpec.ED25519.getName().equalsIgnoreCase(edSpec.getParams().getName()))
                {
                    parameters = EdECUtil.getEd25519PrivateKey(edSpec.getBytes());
                }
                else
                {
                    throw new InvalidKeySpecException("unrecognized named parameters: " + edSpec.getParams().getName());
                }

                return new BC15EdDSAPrivateKey(parameters);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidKeySpecException(e.getMessage(), e);
            }
        }

        return null;
    }

    /**
     * Generate a public key from a version-specific KeySpec - here the JDK 15+
     * EdECPublicKeySpec - or return null when the spec is not one this JDK version bridges.
     */
    static PublicKey generatePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof EdECPublicKeySpec)
        {
            EdECPublicKeySpec edSpec = (EdECPublicKeySpec)keySpec;
            try
            {
                EdECPoint point = edSpec.getPoint();

                AsymmetricKeyParameter parameters;
                if (NamedParameterSpec.ED448.getName().equalsIgnoreCase(edSpec.getParams().getName()))
                {
                    parameters = EdECUtil.getEd448PublicKey(point.getY(), point.isXOdd());
                }
                else if (NamedParameterSpec.ED25519.getName().equalsIgnoreCase(edSpec.getParams().getName()))
                {
                    parameters = EdECUtil.getEd25519PublicKey(point.getY(), point.isXOdd());
                }
                else
                {
                    throw new InvalidKeySpecException("unrecognized named parameters: " + edSpec.getParams().getName());
                }

                return new BC15EdDSAPublicKey(parameters);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidKeySpecException(e.getMessage(), e);
            }
        }

        return null;
    }

    /**
     * Extract the RFC 8032 instance selectors (prehash / context) from a parameter spec, or
     * return null when the spec type is not recognized. As well as the BC EdDSAParameterSpec
     * this twin reads the standard JDK 15+ {@code java.security.spec.EdDSAParameterSpec} -
     * the JDK spec carries no curve name (the curve is taken from the key), so the carrier's
     * curveName is null and there is nothing to cross-check.
     */
    static EdDSAInstanceParams getInstanceParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof java.security.spec.EdDSAParameterSpec)
        {
            java.security.spec.EdDSAParameterSpec jdkSpec = (java.security.spec.EdDSAParameterSpec)paramSpec;

            Optional<byte[]> ctx = jdkSpec.getContext();

            return new EdDSAInstanceParams(null, jdkSpec.isPrehash(), ctx.isPresent() ? ctx.get() : null);
        }

        if (paramSpec instanceof EdDSAParameterSpec)
        {
            EdDSAParameterSpec edSpec = (EdDSAParameterSpec)paramSpec;

            return new EdDSAInstanceParams(edSpec.getCurveName(), edSpec.isPrehash(), edSpec.getContext());
        }

        return null;
    }

    /**
     * Produce a version-specific parameter spec - here the JDK 15+
     * {@code java.security.spec.EdDSAParameterSpec} - carrying the given selectors, or return
     * null when the requested class is not one this JDK version bridges.
     */
    static AlgorithmParameterSpec getParameterSpec(Class paramSpec, boolean prehash, byte[] context)
    {
        if (paramSpec == java.security.spec.EdDSAParameterSpec.class)
        {
            return (context == null)
                ? new java.security.spec.EdDSAParameterSpec(prehash)
                : new java.security.spec.EdDSAParameterSpec(prehash, context);
        }

        return null;
    }
}
