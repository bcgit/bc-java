/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package org.bouncycastle.jcajce.provider.asymmetric.rfc7748;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.rfc7748.RFC7748ObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748PrivateKeySpec;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748PublicKeySpec;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author str4d
 *
 */
public class KeyFactorySpi
extends BaseKeyFactorySpi
implements AsymmetricKeyInfoConverter
{
    String algorithm;
    ProviderConfiguration configuration;

    public KeyFactorySpi(
        String algorithm,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.configuration = configuration;
    }

    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
            throws InvalidKeySpecException
    {
        if (keySpec instanceof RFC7748PrivateKeySpec)
        {
            return new RFC7748PrivateKey((RFC7748PrivateKeySpec) keySpec);
        }
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            return new RFC7748PrivateKey((PKCS8EncodedKeySpec) keySpec);
        }
        throw new InvalidKeySpecException("key spec not recognised: " + keySpec.getClass());
    }

    protected PublicKey engineGeneratePublic(KeySpec keySpec)
            throws InvalidKeySpecException
    {
        if (keySpec instanceof RFC7748PublicKeySpec)
        {
            return new RFC7748PublicKey((RFC7748PublicKeySpec) keySpec);
        }
        if (keySpec instanceof X509EncodedKeySpec)
        {
            return new RFC7748PublicKey((X509EncodedKeySpec) keySpec);
        }
        throw new InvalidKeySpecException("key spec not recognised: " + keySpec.getClass());
    }

    @SuppressWarnings("unchecked")
    protected KeySpec engineGetKeySpec(Key key, Class keySpec)
            throws InvalidKeySpecException
    {
        if (keySpec.isAssignableFrom(RFC7748PublicKeySpec.class) && key instanceof RFC7748PublicKey)
        {
            RFC7748PublicKey k = (RFC7748PublicKey) key;
            if (k.getParams() != null)
            {
                return new RFC7748PublicKeySpec(k.getA(), k.getParams());
            }
        }
        else if (keySpec.isAssignableFrom(RFC7748PrivateKeySpec.class) && key instanceof RFC7748PrivateKey)
        {
            RFC7748PrivateKey k = (RFC7748PrivateKey) key;
            if (k.getParams() != null)
            {
                return new RFC7748PrivateKeySpec(k.getSeed(), k.getH(), k.geta(), k.getA(), k.getParams());
            }
        }

        return super.engineGetKeySpec(key, keySpec);
    }

    protected Key engineTranslateKey(Key key) throws InvalidKeyException
    {
        throw new InvalidKeyException("No other RFC7748 key providers known");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo) throws IOException {
        ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (algOid.equals(RFC7748ObjectIdentifiers.id_Ed25519))
        {
            try 
            {
                return new RFC7748PrivateKey(keyInfo, "Ed25519");
            }
            catch (InvalidKeySpecException e)
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        throw new IOException("algorithm identifier " + algOid + " in key not recognised");
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo) throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

        if (algOid.equals(RFC7748ObjectIdentifiers.id_Ed25519))
        {
            try
            {
                return new RFC7748PublicKey(keyInfo, "Ed25519");
            }
            catch (InvalidKeySpecException e)
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        throw new IOException("algorithm identifier " + algOid + " in key not recognised");
    }

    public static class Ed25519 extends KeyFactorySpi
    {
        public Ed25519()
        {
            super("Ed25519", BouncyCastleProvider.CONFIGURATION);
        }
    }
}
