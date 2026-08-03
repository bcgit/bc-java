package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;

/**
 * Construction and conversion hooks for the EdDSA (Ed25519 / Ed448) key classes. The SPI
 * classes in this package exist only in the base source tree and route all version-specific
 * key and spec handling through here: this class has a jdk1.15 multi-release twin which
 * produces the {@code EdECKey}-implementing {@code BC15EdDSAPublicKey} /
 * {@code BC15EdDSAPrivateKey} classes, accepts incoming JDK {@code EdECPublicKey} /
 * {@code EdECPrivateKey} objects, and bridges the standard JDK 15+ EdEC key specs and
 * {@code java.security.spec.EdDSAParameterSpec}. Keep the method set of the two copies in
 * step.
 */
class EdDSAKeys
{
    static PublicKey publicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        return new BCEdDSAPublicKey(prefix, rawData);
    }

    static PublicKey publicKey(SubjectPublicKeyInfo keyInfo)
    {
        return new BCEdDSAPublicKey(keyInfo);
    }

    static PublicKey publicKey(AsymmetricKeyParameter params)
    {
        return new BCEdDSAPublicKey(params);
    }

    static PrivateKey privateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCEdDSAPrivateKey(keyInfo);
    }

    static PrivateKey privateKey(AsymmetricKeyParameter params)
    {
        return new BCEdDSAPrivateKey(params);
    }

    static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
        throws InvalidKeyException
    {
        return EdECUtil.generatePrivateKeyParameter(key);
    }

    static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
        throws InvalidKeyException
    {
        return EdECUtil.generatePublicKeyParameter(key);
    }

    /**
     * Return a KeySpec for a version-specific spec type (the JDK 15+ EdEC key specs), or null
     * when the request is not one this JDK version bridges - the caller then falls through to
     * its own handling.
     */
    static KeySpec getKeySpec(Key key, Class spec)
        throws InvalidKeySpecException
    {
        return null;
    }

    /**
     * Generate a private key from a version-specific KeySpec (the JDK 15+ EdECPrivateKeySpec),
     * or return null when the spec is not one this JDK version bridges.
     */
    static PrivateKey generatePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        return null;
    }

    /**
     * Generate a public key from a version-specific KeySpec (the JDK 15+ EdECPublicKeySpec),
     * or return null when the spec is not one this JDK version bridges.
     */
    static PublicKey generatePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        return null;
    }

    /**
     * Extract the RFC 8032 instance selectors (prehash / context) from a parameter spec, or
     * return null when the spec type is not recognized. The jdk1.15 twin also reads the
     * standard {@code java.security.spec.EdDSAParameterSpec} here.
     */
    static EdDSAInstanceParams getInstanceParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof EdDSAParameterSpec)
        {
            EdDSAParameterSpec edSpec = (EdDSAParameterSpec)paramSpec;

            return new EdDSAInstanceParams(edSpec.getCurveName(), edSpec.isPrehash(), edSpec.getContext());
        }

        return null;
    }

    /**
     * Produce a version-specific parameter spec (the JDK 15+
     * {@code java.security.spec.EdDSAParameterSpec}) carrying the given selectors, or return
     * null when the requested class is not one this JDK version bridges.
     */
    static AlgorithmParameterSpec getParameterSpec(Class paramSpec, boolean prehash, byte[] context)
    {
        return null;
    }
}
