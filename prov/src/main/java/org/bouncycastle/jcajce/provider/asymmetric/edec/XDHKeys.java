package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Construction and conversion hooks for the XDH (X25519 / X448) key classes. The SPI classes
 * in this package exist only in the base source tree and route all version-specific key
 * handling through here: this class has a jdk1.11 multi-release twin which produces the
 * {@code XECKey}-implementing {@code BC11XDHPublicKey} / {@code BC11XDHPrivateKey} classes and
 * accepts incoming JDK {@code XECPublicKey} / {@code XECPrivateKey} objects. Keep the method
 * set of the two copies in step.
 */
class XDHKeys
{
    static PublicKey publicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        return new BCXDHPublicKey(prefix, rawData);
    }

    static PublicKey publicKey(SubjectPublicKeyInfo keyInfo)
    {
        return new BCXDHPublicKey(keyInfo);
    }

    static PublicKey publicKey(AsymmetricKeyParameter params)
    {
        return new BCXDHPublicKey(params);
    }

    static PrivateKey privateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCXDHPrivateKey(keyInfo);
    }

    static PrivateKey privateKey(AsymmetricKeyParameter params)
    {
        return new BCXDHPrivateKey(params);
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
}
