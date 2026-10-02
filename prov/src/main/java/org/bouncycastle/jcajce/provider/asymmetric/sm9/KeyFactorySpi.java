package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.SM9EncUserPrivateKeySpec;
import org.bouncycastle.jcajce.spec.SM9SigUserPrivateKeySpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * KeyFactory for the SM9 master keys ({@code sm9sign} and {@code sm9encrypt}): the master
 * public and private keys round-trip through their JCA X.509 / PKCS#8 encodings (the GM/T 0080-2020 key
 * material under the GM algorithm OID; the bare GM/T 0080-2020 form is the lightweight
 * key-parameter class's {@code getEncoded()}).
 * <p>
 * A user's identity-based key is <b>not</b> decodable in isolation - it additionally needs
 * the master public key and the identity, and for an encryption key the hid and the usage
 * (KEM / decryption or key exchange) too - so it does not decode from a plain PKCS#8 spec, and
 * {@code getKeySpec} hands out no such spec for one. Rebuild a stored user key from its encoding plus that
 * context with an {@link org.bouncycastle.jcajce.spec.SM9SigUserPrivateKeySpec} /
 * {@link org.bouncycastle.jcajce.spec.SM9EncUserPrivateKeySpec} (also handed back by
 * {@code getKeySpec}), or derive it afresh from the master private key via the master
 * key's {@code generateUserKeyPair} method.
 */
public class KeyFactorySpi
    extends java.security.KeyFactorySpi
    implements AsymmetricKeyInfoConverter
{
    /**
     * The {@link AsymmetricKeyInfoConverter} half, registered against both SM9 algorithm
     * identifiers so that {@code BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo)} and
     * any other generic BC path that resolves a key by its OID answer for SM9 rather than
     * returning null, as they did before. Only the master keys decode from an encoding alone;
     * a user's identity-based key additionally needs the master public key, the identity and,
     * for an encryption key, the hid, none of which the encoding carries, so it is reported as
     * undecodable here and the spec-taking {@code KeyFactory.SM9} path remains the way to
     * rebuild one.
     */
    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        try
        {
            return masterPublicKey(keyInfo);
        }
        catch (IllegalArgumentException e)
        {
            throw Exceptions.ioException("unable to decode SM9 public key: " + e.getMessage(), e);
        }
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        try
        {
            return masterPrivateKey(keyInfo);
        }
        catch (IllegalArgumentException e)
        {
            throw Exceptions.ioException("unable to decode SM9 private key: " + e.getMessage(), e);
        }
    }

    private static PublicKey masterPublicKey(SubjectPublicKeyInfo info)
        throws IOException
    {
        checkNoParameters(info.getAlgorithm());
        ASN1ObjectIdentifier oid = info.getAlgorithm().getAlgorithm();
        if (GMObjectIdentifiers.sm9sign.equals(oid))
        {
            return new BCSM9SigMasterPublicKey(
                SM9SigMasterPublicKeyParameters.fromEncoded(publicKeyOctets(info.getPublicKeyData())));
        }
        if (GMObjectIdentifiers.sm9encrypt.equals(oid))
        {
            return new BCSM9EncMasterPublicKey(
                SM9EncMasterPublicKeyParameters.fromEncoded(publicKeyOctets(info.getPublicKeyData())));
        }
        throw new IOException("not an SM9 master public key: " + oid);
    }

    private static PrivateKey masterPrivateKey(PrivateKeyInfo info)
        throws IOException
    {
        checkNoParametersOrAttributes(info);
        ASN1ObjectIdentifier oid = info.getPrivateKeyAlgorithm().getAlgorithm();
        byte[] data = privateKeyOctets(info);

        if (data.length != 32)
        {
            throw new IOException(
                "SM9 user private keys cannot be decoded standalone - use an SM9SigUserPrivateKeySpec / SM9EncUserPrivateKeySpec, or derive them from a master key");
        }
        // a PKCS#8 encoding that carries the public key (RFC 5958 OneAsymmetricKey) is held to it,
        // as the ML-DSA and ML-KEM decoders hold theirs; BC does not write one itself
        byte[] publicKey = publicKeyOctets(info.getPublicKeyData());
        if (GMObjectIdentifiers.sm9sign.equals(oid))
        {
            return new BCSM9SigMasterPrivateKey(publicKey == null
                ? SM9SigMasterPrivateKeyParameters.fromEncoded(data)
                : SM9SigMasterPrivateKeyParameters.fromEncoded(data, SM9SigMasterPublicKeyParameters.fromEncoded(publicKey)));
        }
        if (GMObjectIdentifiers.sm9encrypt.equals(oid))
        {
            return new BCSM9EncMasterPrivateKey(publicKey == null
                ? SM9EncMasterPrivateKeyParameters.fromEncoded(data)
                : SM9EncMasterPrivateKeyParameters.fromEncoded(data, SM9EncMasterPublicKeyParameters.fromEncoded(publicKey)));
        }
        throw new IOException("not an SM9 master private key: " + oid);
    }

    /**
     * An SM9 key's algorithm identifier is the OID alone, as getEncoded() writes it. Parameters of
     * any kind - an ASN.1 NULL, another OID - were ignored, which gave the same key a further
     * accepted encoding for each; they are refused instead, as the hybrid point form was.
     */
    private static void checkNoParameters(AlgorithmIdentifier algorithm)
        throws IOException
    {
        if (algorithm.getParameters() != null)
        {
            throw new IOException("SM9 key algorithm identifier takes no parameters");
        }
    }

    /**
     * An SM9 private key's PKCS#8 encoding carries no parameters and no attributes, as getEncoded()
     * writes it - for the reason checkNoParameters gives.
     */
    private static void checkNoParametersOrAttributes(PrivateKeyInfo info)
        throws IOException
    {
        checkNoParameters(info.getPrivateKeyAlgorithm());
        if (info.getAttributes() != null)
        {
            throw new IOException("SM9 private key takes no attributes");
        }
    }

    /**
     * An encoding handed to the factory has to be the DER one, the form getEncoded() writes, and
     * not only decode: BER, or DER with a length written long, would be a further accepted
     * encoding of the same key.
     */
    private static void checkDER(ASN1Object decoded, byte[] encoding)
        throws IOException
    {
        if (!Arrays.areEqual(decoded.getEncoded(ASN1Encoding.DER), encoding))
        {
            throw new IOException("SM9 key encoding is not DER");
        }
    }

    /**
     * The octets of an SM9 private key's inner OCTET STRING. checkDER holds a PKCS#8 encoding to DER,
     * but to it the privateKey field is octets like any other, which are parsed on their own: a
     * long-form length, or the constructed form, of the OCTET STRING inside it decoded to the same
     * key, a further accepted encoding of it, as did a version of v2 with no public key - RFC 5958
     * sec. 2 gives v2 only to an encoding that carries the public key, and getEncoded() writes v1.
     */
    private static byte[] privateKeyOctets(PrivateKeyInfo info)
        throws IOException
    {
        if (info.getVersion().hasValue(1) && !info.hasPublicKey())
        {
            throw new IOException("SM9 private key of version v2 carries no public key");
        }
        ASN1Primitive inner = info.parsePrivateKey().toASN1Primitive();
        if (!Arrays.areEqual(inner.getEncoded(ASN1Encoding.DER), info.getPrivateKey().getOctets()))
        {
            throw new IOException("SM9 key encoding is not DER");
        }
        return ASN1OctetString.getInstance(inner).getOctets();
    }

    /**
     * The octets of an SM9 master public key's BIT STRING - a SubjectPublicKeyInfo's, or the one a
     * PKCS#8 encoding may carry beside the scalar, which is null when it carries none. The point is
     * read from whole octets, which a BIT STRING with pad bits does not hold: asked for them anyway
     * it throws IllegalStateException, which escaped generatePublic(SubjectPublicKeyInfo) past the
     * IOException it declares, so every read of one comes through here and is refused as that.
     */
    private static byte[] publicKeyOctets(ASN1BitString publicKeyData)
        throws IOException
    {
        if (publicKeyData == null)
        {
            return null;
        }
        if (publicKeyData.getPadBits() != 0)
        {
            throw new IOException("SM9 master public key must be an octet-aligned BIT STRING");
        }
        return publicKeyData.getOctets();
    }

    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (!(keySpec instanceof X509EncodedKeySpec))
        {
            throw new InvalidKeySpecException("unsupported key spec: " + specName(keySpec));
        }
        try
        {
            byte[] encoding = ((X509EncodedKeySpec)keySpec).getEncoded();
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(encoding);
            checkDER(info, encoding);
            return masterPublicKey(info);
        }
        catch (IOException e)
        {
            throw SecurityExceptions.invalidKeySpecException(e.getMessage(), e);
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
            catch (IOException e)
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
            catch (IOException e)
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
            throw new InvalidKeySpecException("unsupported key spec: " + specName(keySpec));
        }
        try
        {
            byte[] encoding = ((PKCS8EncodedKeySpec)keySpec).getEncoded();
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(encoding);
            checkDER(info, encoding);
            return masterPrivateKey(info);
        }
        catch (IOException e)
        {
            throw SecurityExceptions.invalidKeySpecException(e.getMessage(), e);
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
        if (key instanceof Destroyable && ((Destroyable)key).isDestroyed())
        {
            // a destroyed key has no encoding left, and asking it for one threw an
            // IllegalStateException this method does not declare
            throw new InvalidKeySpecException("key destroyed");
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
        // only the master public keys have an X.509 encoding. A user's public key is its identity
        // under the master public key and has no encoding of its own, and the key-exchange
        // ephemeral is the raw point, so taking either for one failed with a NullPointerException
        // or handed back a spec that decodes to nothing
        if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)
            && (key instanceof BCSM9SigMasterPublicKey || key instanceof BCSM9EncMasterPublicKey))
        {
            return new X509EncodedKeySpec(key.getEncoded());
        }
        // likewise only the master private keys decode from their PKCS#8 encoding alone. A user's
        // private key also needs the master public key and the identity, and an encryption key the
        // hid and usage, none of which its encoding carries, so the PKCS#8 spec handed out for one
        // was refused by generatePrivate(); its SM9SigUserPrivateKeySpec / SM9EncUserPrivateKeySpec
        // above is the spec that carries that context
        if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)
            && (key instanceof BCSM9SigMasterPrivateKey || key instanceof BCSM9EncMasterPrivateKey))
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

    /**
     * Every key class this provider hands out for SM9. The three public-key wrappers - a user's
     * signature and encryption public keys and a key-exchange ephemeral - used to be missing, so
     * translateKey() refused keys BC had just given the caller.
     */
    private static boolean isSM9(Key key)
    {
        return key instanceof BCSM9SigMasterPublicKey
            || key instanceof BCSM9SigMasterPrivateKey
            || key instanceof BCSM9SigPrivateKey
            || key instanceof BCSM9SigPublicKey
            || key instanceof BCSM9EncMasterPublicKey
            || key instanceof BCSM9EncMasterPrivateKey
            || key instanceof BCSM9EncPrivateKey
            || key instanceof BCSM9EncPublicKey
            || key instanceof BCSM9ExchangeEphemeralPublicKey;
    }

    /**
     * The name of a key spec for an exception message - its class, never its toString(), which for
     * a third-party spec over key material may well print the material.
     */
    private static String specName(KeySpec keySpec)
    {
        return keySpec == null ? "null" : keySpec.getClass().getName();
    }

    /**
     * The octet-string key material inside a user key's PKCS#8 encoding, which shares its
     * outer AlgorithmIdentifier OID with the matching master key - the length of the inner
     * octets (32 bytes for a master scalar, a G1/G2 point encoding for a user key) is what
     * distinguishes them, and {@code fromEncoded} on the target parameter class validates that.
     */
    private static byte[] userKeyOctets(byte[] pkcs8Encoding, ASN1ObjectIdentifier expectedOid)
        throws IOException
    {
        PrivateKeyInfo info = PrivateKeyInfo.getInstance(pkcs8Encoding);
        checkDER(info, pkcs8Encoding);
        checkNoParametersOrAttributes(info);
        ASN1ObjectIdentifier oid = info.getPrivateKeyAlgorithm().getAlgorithm();
        if (!expectedOid.equals(oid))
        {
            throw new IllegalArgumentException("not an SM9 user private key: " + oid);
        }
        return privateKeyOctets(info);
    }

    /**
     * A master public key supplied by a third-party implementation is taken through its X.509
     * encoding, whose algorithm identifier is checked before the octets are used - as
     * userKeyOctets() already checks the PKCS#8 one. Without it the octets of any SPKI that
     * happened to hold a decodable point were read as an SM9 master key.
     */
    private static void checkAlgorithm(SubjectPublicKeyInfo info, ASN1ObjectIdentifier expected)
    {
        if (!expected.equals(info.getAlgorithm().getAlgorithm()))
        {
            throw new IllegalArgumentException("master public key is not an SM9 key: " + info.getAlgorithm().getAlgorithm());
        }
    }

    private static SM9SigMasterPublicKeyParameters sigMasterParameters(SM9SigMasterPublicKey masterPublicKey)
        throws IOException
    {
        if (masterPublicKey instanceof BCSM9SigMasterPublicKey)
        {
            return ((BCSM9SigMasterPublicKey)masterPublicKey).getKeyParameters();
        }
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(masterPublicKey.getEncoded());
        checkAlgorithm(info, GMObjectIdentifiers.sm9sign);
        return SM9SigMasterPublicKeyParameters.fromEncoded(publicKeyOctets(info.getPublicKeyData()));
    }

    private static SM9EncMasterPublicKeyParameters encMasterParameters(SM9EncMasterPublicKey masterPublicKey)
        throws IOException
    {
        if (masterPublicKey instanceof BCSM9EncMasterPublicKey)
        {
            return ((BCSM9EncMasterPublicKey)masterPublicKey).getKeyParameters();
        }
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(masterPublicKey.getEncoded());
        checkAlgorithm(info, GMObjectIdentifiers.sm9encrypt);
        return SM9EncMasterPublicKeyParameters.fromEncoded(publicKeyOctets(info.getPublicKeyData()));
    }
}
