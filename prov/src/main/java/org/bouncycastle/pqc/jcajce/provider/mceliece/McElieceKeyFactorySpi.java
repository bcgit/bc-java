package org.bouncycastle.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.asn1.McEliecePrivateKey;
import org.bouncycastle.pqc.asn1.McEliecePublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;

/**
 * This class is used to translate between McEliece keys and key specifications.
 *
 * @see BCMcEliecePrivateKey
 * @see BCMcEliecePublicKey
 */
public class McElieceKeyFactorySpi
    extends KeyFactorySpi
    implements AsymmetricKeyInfoConverter
{
    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.1";

    /**
     * Converts, if possible, a key specification into a
     * {@link BCMcEliecePublicKey}.  {@link X509EncodedKeySpec}.
     *
     * @param keySpec the key specification
     * @return the McEliece public key
     * @throws InvalidKeySpecException if the key specification is not supported.
     */
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            // get the DER-encoded Key according to X.509 from the spec
            byte[] encKey = ((X509EncodedKeySpec)keySpec).getEncoded();

            // decode the SubjectPublicKeyInfo data structure to the pki object
            SubjectPublicKeyInfo pki;
            try
            {
                pki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey));
            }
            catch (IOException e)
            {
                throw new InvalidKeySpecException(e.toString());
            }

            try
            {
                if (PQCObjectIdentifiers.mcEliece.equals(pki.getAlgorithm().getAlgorithm()))
                {
                    McEliecePublicKey key = McEliecePublicKey.getInstance(pki.parsePublicKey());

                    return new BCMcEliecePublicKey(new McEliecePublicKeyParameters(key.getN(), key.getT(), key.getG()));
                }
                else
                {
                    throw new InvalidKeySpecException("Unable to recognise OID in McEliece public key");
                }
            }
            catch (IOException cce)
            {
                throw new InvalidKeySpecException(
                    "Unable to decode X509EncodedKeySpec: "
                        + cce.getMessage());
            }
        }

        throw new InvalidKeySpecException("Unsupported key specification: "
            + keySpec.getClass() + ".");
    }

    /**
     * Converts, if possible, a key specification into a
     * {@link BCMcEliecePrivateKey}.
     *
     * @param keySpec the key specification
     * @return the McEliece private key
     * @throws InvalidKeySpecException if the KeySpec is not supported.
     */
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            // get the DER-encoded Key according to PKCS#8 from the spec
            byte[] encKey = ((PKCS8EncodedKeySpec)keySpec).getEncoded();

            // decode the PKCS#8 data structure to the pki object
            PrivateKeyInfo pki;

            try
            {
                pki = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey));
            }
            catch (IOException e)
            {
                throw new InvalidKeySpecException("Unable to decode PKCS8EncodedKeySpec: " + e);
            }

            try
            {
                if (PQCObjectIdentifiers.mcEliece.equals(pki.getPrivateKeyAlgorithm().getAlgorithm()))
                {
                    McEliecePrivateKey key = McEliecePrivateKey.getInstance(pki.parsePrivateKey());

                    return new BCMcEliecePrivateKey(new McEliecePrivateKeyParameters(key.getN(), key.getK(), key.getField(), key.getGoppaPoly(), key.getP1(), key.getP2(), key.getSInv()));
                }
                else
                {
                    throw new InvalidKeySpecException("Unable to recognise OID in McEliece private key");
                }
            }
            catch (IOException cce)
            {
                throw new InvalidKeySpecException(
                    "Unable to decode PKCS8EncodedKeySpec.");
            }
        }

        throw new InvalidKeySpecException("Unsupported key specification: "
            + keySpec.getClass() + ".");
    }

    /**
     * Converts, if possible, a given key into a key specification. Currently,
     * the following key specifications are supported:
     *
     * @param key     the key
     * @param keySpec the key specification
     * @return the specification of the McEliece key
     * @throws InvalidKeySpecException if the key type or the key specification is not
     * supported.
     * @see BCMcEliecePrivateKey
     * @see BCMcEliecePublicKey
     */
    public KeySpec getKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCMcEliecePrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCMcEliecePublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new X509EncodedKeySpec(key.getEncoded());
            }
        }
        else
        {
            throw new InvalidKeySpecException("Unsupported key type: "
                + key.getClass() + ".");
        }

        throw new InvalidKeySpecException("Unknown key specification: "
            + keySpec + ".");
    }

    /**
     * Translates a key into a form known by the FlexiProvider. Currently, only
     * the following "source" keys are supported: {@link BCMcEliecePrivateKey},
     * {@link BCMcEliecePublicKey}.
     *
     * @param key the key
     * @return a key of a known key type
     * @throws InvalidKeyException if the key type is not supported.
     */
    public Key translateKey(Key key)
        throws InvalidKeyException
    {
        if ((key instanceof BCMcEliecePrivateKey)
            || (key instanceof BCMcEliecePublicKey))
        {
            return key;
        }
        throw new InvalidKeyException("Unsupported key type.");

    }

    public PublicKey generatePublic(SubjectPublicKeyInfo pki)
        throws IOException
    {
        // get the inner type inside the BIT STRING
        ASN1Primitive innerType = pki.parsePublicKey();
        McEliecePublicKey key = McEliecePublicKey.getInstance(innerType);
        return new BCMcEliecePublicKey(new McEliecePublicKeyParameters(key.getN(), key.getT(), key.getG()));
    }

    public PrivateKey generatePrivate(PrivateKeyInfo pki)
        throws IOException
    {
        // get the inner type inside the BIT STRING
        ASN1Primitive innerType = pki.parsePrivateKey().toASN1Primitive();
        McEliecePrivateKey key = McEliecePrivateKey.getInstance(innerType);
        return new BCMcEliecePrivateKey(new McEliecePrivateKeyParameters(key.getN(), key.getK(), key.getField(), key.getGoppaPoly(), key.getP1(), key.getP2(), key.getSInv()));
    }

    protected KeySpec engineGetKeySpec(Key key, Class tClass)
        throws InvalidKeySpecException
    {
        // TODO:
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    protected Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        // TODO:
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    private static Digest getDigest(AlgorithmIdentifier algId)
    {
        return new SHA256Digest();
    }
}
