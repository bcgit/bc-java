package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.SM9EncUserPrivateKeySpec;
import org.bouncycastle.jcajce.spec.SM9SigUserPrivateKeySpec;

/**
 * KeyFactory for the SM9 master keys ({@code sm9sign} and {@code sm9encrypt}): the master
 * public and private keys round-trip through their JCA X.509 / PKCS#8 encodings (the GM/T 0080-2020 key
 * material under the GM algorithm OID; the bare GM/T 0080-2020 form is the lightweight
 * key-parameter class's {@code getEncoded()}).
 * <p>
 * A user's identity-based key is <b>not</b> decodable in isolation - it additionally needs
 * the master public key and the identity, and for an encryption key the hid and the usage
 * (KEM / decryption or key exchange) too - so it does not decode from a plain PKCS#8 spec. Rebuild a stored user key from its encoding plus that
 * context with an {@link org.bouncycastle.jcajce.spec.SM9SigUserPrivateKeySpec} /
 * {@link org.bouncycastle.jcajce.spec.SM9EncUserPrivateKeySpec} (also handed back by
 * {@code getKeySpec}), or derive it afresh from the master private key via the master
 * key's {@code generateUserKeyPair} method.
 */
public class KeyFactorySpi
    extends java.security.KeyFactorySpi
{
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (!(keySpec instanceof X509EncodedKeySpec))
        {
            throw new InvalidKeySpecException("unsupported key spec: " + keySpec);
        }
        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(((X509EncodedKeySpec)keySpec).getEncoded());
            ASN1ObjectIdentifier oid = info.getAlgorithm().getAlgorithm();
            if (GMObjectIdentifiers.sm9sign.equals(oid))
            {
                return new BCSM9SigMasterPublicKey(
                    SM9SigMasterPublicKeyParameters.fromEncoded(info.getPublicKeyData().getOctets()));
            }
            if (GMObjectIdentifiers.sm9encrypt.equals(oid))
            {
                return new BCSM9EncMasterPublicKey(
                    SM9EncMasterPublicKeyParameters.fromEncoded(info.getPublicKeyData().getOctets()));
            }
            throw new InvalidKeySpecException("not an SM9 master public key: " + oid);
        }
        catch (RuntimeException e)
        {
            throw SecurityExceptions.invalidKeySpecException("unable to decode SM9 public key: " + e.getMessage(), e);
        }
    }

    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof SM9SigUserPrivateKeySpec)
        {
            SM9SigUserPrivateKeySpec userSpec = (SM9SigUserPrivateKeySpec)keySpec;
            try
            {
                return new BCSM9SigPrivateKey(SM9SigPrivateKeyParameters.fromEncoded(
                    userKeyOctets(userSpec.getEncoded(), GMObjectIdentifiers.sm9sign),
                    sigMasterParameters(userSpec.getMasterPublicKey()), userSpec.getIdentity()));
            }
            catch (java.io.IOException e)
            {
                throw SecurityExceptions.invalidKeySpecException("unable to decode SM9 user private key: " + e.getMessage(), e);
            }
            catch (RuntimeException e)
            {
                throw SecurityExceptions.invalidKeySpecException("unable to decode SM9 user private key: " + e.getMessage(), e);
            }
        }
        if (keySpec instanceof SM9EncUserPrivateKeySpec)
        {
            SM9EncUserPrivateKeySpec userSpec = (SM9EncUserPrivateKeySpec)keySpec;
            try
            {
                byte[] octets = userKeyOctets(userSpec.getEncoded(), GMObjectIdentifiers.sm9encrypt);
                SM9EncMasterPublicKeyParameters master = encMasterParameters(userSpec.getMasterPublicKey());
                return new BCSM9EncPrivateKey(userSpec.isExchangeKey()
                    ? SM9EncPrivateKeyParameters.fromEncodedExchangeKey(octets, master, userSpec.getIdentity(), userSpec.getHid())
                    : SM9EncPrivateKeyParameters.fromEncoded(octets, master, userSpec.getIdentity(), userSpec.getHid()));
            }
            catch (java.io.IOException e)
            {
                throw SecurityExceptions.invalidKeySpecException("unable to decode SM9 user private key: " + e.getMessage(), e);
            }
            catch (RuntimeException e)
            {
                throw SecurityExceptions.invalidKeySpecException("unable to decode SM9 user private key: " + e.getMessage(), e);
            }
        }
        if (!(keySpec instanceof PKCS8EncodedKeySpec))
        {
            throw new InvalidKeySpecException("unsupported key spec: " + keySpec);
        }
        try
        {
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded());
            ASN1ObjectIdentifier oid = info.getPrivateKeyAlgorithm().getAlgorithm();
            byte[] data = ASN1OctetString.getInstance(info.parsePrivateKey()).getOctets();

            if (data.length != 32)
            {
                throw new InvalidKeySpecException(
                    "SM9 user private keys cannot be decoded standalone - use an SM9SigUserPrivateKeySpec / SM9EncUserPrivateKeySpec, or derive them from a master key");
            }
            if (GMObjectIdentifiers.sm9sign.equals(oid))
            {
                return new BCSM9SigMasterPrivateKey(SM9SigMasterPrivateKeyParameters.fromEncoded(data));
            }
            if (GMObjectIdentifiers.sm9encrypt.equals(oid))
            {
                return new BCSM9EncMasterPrivateKey(SM9EncMasterPrivateKeyParameters.fromEncoded(data));
            }
            throw new InvalidKeySpecException("not an SM9 master private key: " + oid);
        }
        catch (java.io.IOException e)
        {
            throw SecurityExceptions.invalidKeySpecException("unable to decode SM9 private key: " + e.getMessage(), e);
        }
        catch (RuntimeException e)
        {
            throw SecurityExceptions.invalidKeySpecException("unable to decode SM9 private key: " + e.getMessage(), e);
        }
    }

    protected KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec == null)
        {
            throw new InvalidKeySpecException("keySpec is null");
        }
        if (keySpec.isAssignableFrom(SM9SigUserPrivateKeySpec.class) && key instanceof BCSM9SigPrivateKey)
        {
            SM9SigPrivateKeyParameters keyParams = ((BCSM9SigPrivateKey)key).getKeyParameters();
            return new SM9SigUserPrivateKeySpec(key.getEncoded(),
                new BCSM9SigMasterPublicKey(keyParams.getMasterPublicKey()), keyParams.getIdentity());
        }
        if (keySpec.isAssignableFrom(SM9EncUserPrivateKeySpec.class) && key instanceof BCSM9EncPrivateKey)
        {
            SM9EncPrivateKeyParameters keyParams = ((BCSM9EncPrivateKey)key).getKeyParameters();
            return new SM9EncUserPrivateKeySpec(key.getEncoded(),
                new BCSM9EncMasterPublicKey(keyParams.getMasterPublicKey()), keyParams.getIdentity(),
                keyParams.getHid(), keyParams.isExchangeKey());
        }
        if (keySpec.isAssignableFrom(X509EncodedKeySpec.class) && key instanceof PublicKey && isSM9(key))
        {
            return new X509EncodedKeySpec(key.getEncoded());
        }
        if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class) && key instanceof PrivateKey && isSM9(key))
        {
            return new PKCS8EncodedKeySpec(key.getEncoded());
        }
        throw new InvalidKeySpecException("not an SM9 key or unsupported spec: " + keySpec.getName());
    }

    protected Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (isSM9(key))
        {
            return key;
        }
        throw new InvalidKeyException("key is not an SM9 key");
    }

    private static boolean isSM9(Key key)
    {
        return key instanceof BCSM9SigMasterPublicKey
            || key instanceof BCSM9SigMasterPrivateKey
            || key instanceof BCSM9SigPrivateKey
            || key instanceof BCSM9EncMasterPublicKey
            || key instanceof BCSM9EncMasterPrivateKey
            || key instanceof BCSM9EncPrivateKey;
    }

    /**
     * The octet-string key material inside a user key's PKCS#8 encoding, which shares its
     * outer AlgorithmIdentifier OID with the matching master key - the length of the inner
     * octets (32 bytes for a master scalar, a G1/G2 point encoding for a user key) is what
     * distinguishes them, and {@code fromEncoded} on the target parameter class validates that.
     */
    private static byte[] userKeyOctets(byte[] pkcs8Encoding, ASN1ObjectIdentifier expectedOid)
        throws java.io.IOException
    {
        PrivateKeyInfo info = PrivateKeyInfo.getInstance(pkcs8Encoding);
        ASN1ObjectIdentifier oid = info.getPrivateKeyAlgorithm().getAlgorithm();
        if (!expectedOid.equals(oid))
        {
            throw new IllegalArgumentException("not an SM9 user private key: " + oid);
        }
        return ASN1OctetString.getInstance(info.parsePrivateKey()).getOctets();
    }

    private static SM9SigMasterPublicKeyParameters sigMasterParameters(SM9SigMasterPublicKey masterPublicKey)
    {
        if (masterPublicKey instanceof BCSM9SigMasterPublicKey)
        {
            return ((BCSM9SigMasterPublicKey)masterPublicKey).getKeyParameters();
        }
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(masterPublicKey.getEncoded());
        return SM9SigMasterPublicKeyParameters.fromEncoded(info.getPublicKeyData().getOctets());
    }

    private static SM9EncMasterPublicKeyParameters encMasterParameters(SM9EncMasterPublicKey masterPublicKey)
    {
        if (masterPublicKey instanceof BCSM9EncMasterPublicKey)
        {
            return ((BCSM9EncMasterPublicKey)masterPublicKey).getKeyParameters();
        }
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(masterPublicKey.getEncoded());
        return SM9EncMasterPublicKeyParameters.fromEncoded(info.getPublicKeyData().getOctets());
    }
}
