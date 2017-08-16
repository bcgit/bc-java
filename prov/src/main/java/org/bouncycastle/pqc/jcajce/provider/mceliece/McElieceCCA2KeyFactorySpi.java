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
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.asn1.McElieceCCA2PrivateKey;
import org.bouncycastle.pqc.asn1.McElieceCCA2PublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;

/**
 * This class is used to translate between McEliece CCA2 keys and key
 * specifications.
 *
 * @see BCMcElieceCCA2PrivateKey
 * @see BCMcElieceCCA2PublicKey
 */
public class McElieceCCA2KeyFactorySpi
    extends KeyFactorySpi
    implements AsymmetricKeyInfoConverter
{

    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2";

    /**
     * Converts, if possible, a key specification into a
     * {@link BCMcElieceCCA2PublicKey}. Currently, the following key
     * specifications are supported:
     * {@link X509EncodedKeySpec}.
     *
     * @param keySpec the key specification
     * @return the McEliece CCA2 public key
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
                if (PQCObjectIdentifiers.mcElieceCca2.equals(pki.getAlgorithm().getAlgorithm()))
                {
                    McElieceCCA2PublicKey key = McElieceCCA2PublicKey.getInstance(pki.parsePublicKey());

                    return new BCMcElieceCCA2PublicKey(new McElieceCCA2PublicKeyParameters(key.getN(), key.getT(), key.getG(), Utils.getDigest(key.getDigest()).getAlgorithmName()));
                }
                else
                {
                    throw new InvalidKeySpecException("Unable to recognise OID in McEliece private key");
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
     * {@link BCMcElieceCCA2PrivateKey}. Currently, the following key
     * specifications are supported:
     * {@link PKCS8EncodedKeySpec}.
     *
     * @param keySpec the key specification
     * @return the McEliece CCA2 private key
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
                if (PQCObjectIdentifiers.mcElieceCca2.equals(pki.getPrivateKeyAlgorithm().getAlgorithm()))
                {
                    McElieceCCA2PrivateKey key = McElieceCCA2PrivateKey.getInstance(pki.parsePrivateKey());

                    return new BCMcElieceCCA2PrivateKey(new McElieceCCA2PrivateKeyParameters(key.getN(), key.getK(), key.getField(), key.getGoppaPoly(), key.getP(), Utils.getDigest(key.getDigest()).getAlgorithmName()));
                }
                else
                {
                    throw new InvalidKeySpecException("Unable to recognise OID in McEliece public key");
                }
            }
            catch (IOException cce)
            {
                throw new InvalidKeySpecException(
                    "Unable to decode PKCS8EncodedKeySpec.");
            }
        }

        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass() + ".");
    }

    /**
     * Converts, if possible, a given key into a key specification. Currently,
     * the following key specifications are supported:
     *
     * @param key     the key
     * @param keySpec the key specification
     * @return the specification of the McEliece CCA2 key
     * @throws InvalidKeySpecException if the key type or the key specification is not
     * supported.
     * @see BCMcElieceCCA2PrivateKey
     * @see BCMcElieceCCA2PublicKey
     */
    public KeySpec getKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCMcElieceCCA2PrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCMcElieceCCA2PublicKey)
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
     * the following "source" keys are supported: {@link BCMcElieceCCA2PrivateKey},
     * {@link BCMcElieceCCA2PublicKey}.
     *
     * @param key the key
     * @return a key of a known key type
     * @throws InvalidKeyException if the key type is not supported.
     */
    public Key translateKey(Key key)
        throws InvalidKeyException
    {
        if ((key instanceof BCMcElieceCCA2PrivateKey)
            || (key instanceof BCMcElieceCCA2PublicKey))
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
        McElieceCCA2PublicKey key = McElieceCCA2PublicKey.getInstance(innerType);
        return new BCMcElieceCCA2PublicKey(new McElieceCCA2PublicKeyParameters(key.getN(), key.getT(), key.getG(), Utils.getDigest(key.getDigest()).getAlgorithmName()));
    }

    public PrivateKey generatePrivate(PrivateKeyInfo pki)
        throws IOException
    {
        // get the inner type inside the BIT STRING
        ASN1Primitive innerType = pki.parsePrivateKey().toASN1Primitive();
        McElieceCCA2PrivateKey key = McElieceCCA2PrivateKey.getInstance(innerType);
        return new BCMcElieceCCA2PrivateKey(new McElieceCCA2PrivateKeyParameters(key.getN(), key.getK(), key.getField(), key.getGoppaPoly(), key.getP(), null));
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
}
