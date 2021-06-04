package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;

/**
 * utility class for converting jce/jca XDH, and EdDSA
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class EdECUtil
{

    public static AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPublicKey)
        {
            return ((BCXDHPublicKey) key).engineGetKeyParameters();
        }
        else if (key instanceof BCEdDSAPublicKey)
        {
            return ((BCEdDSAPublicKey) key).engineGetKeyParameters();
        }
        else
        {
            // see if we can build a key from key.getEncoded()
            try
            {
                byte[] bytes = key.getEncoded();

                if (bytes == null)
                {
                    throw new InvalidKeyException("no encoding for EdEC/XDH public key");
                }

                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(bytes);
                ASN1ObjectIdentifier oid = subjectPublicKeyInfo.getAlgorithm().getAlgorithm();
                byte[] keyData = subjectPublicKeyInfo.getPublicKeyData().getOctets();
                if (EdECObjectIdentifiers.id_X25519.equals(oid))
                {
                    return new X25519PublicKeyParameters(keyData, 0);
                }
                else if (EdECObjectIdentifiers.id_X448.equals(oid))
                {
                    return new X448PublicKeyParameters(keyData, 0);
                }
                else if (EdECObjectIdentifiers.id_Ed25519.equals(oid))
                {
                    return new Ed25519PublicKeyParameters(keyData, 0);
                }
                else if (EdECObjectIdentifiers.id_Ed448.equals(oid))
                {
                    return new Ed448PublicKeyParameters(keyData, 0);
                }
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("cannot identify EdEC/XDH public key: " + e.toString());
            }
        }

        throw new InvalidKeyException("cannot identify EdEC/XDH public key.");
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey    key)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPrivateKey)
        {
            return ((BCXDHPrivateKey) key).engineGetKeyParameters();
        }
        else if (key instanceof BCEdDSAPrivateKey)
        {
            return ((BCEdDSAPrivateKey) key).engineGetKeyParameters();
        }
        else
        {
            // see if we can build a key from key.getEncoded()
            try
            {
                byte[] bytes = key.getEncoded();

                if (bytes == null)
                {
                    throw new InvalidKeyException("no encoding for EdEC/XDH private key");
                }

                PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(key.getEncoded());
                ASN1ObjectIdentifier oid = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();

                byte[] keyData = ASN1OctetString.getInstance(privateKeyInfo.getPrivateKey().getOctets()).getOctets();
                if (EdECObjectIdentifiers.id_X25519.equals(oid))
                {
                    return new X25519PrivateKeyParameters(keyData, 0);
                }
                else if (EdECObjectIdentifiers.id_X448.equals(oid))
                {
                    return new X448PrivateKeyParameters(keyData, 0);
                }
                else if (EdECObjectIdentifiers.id_Ed25519.equals(oid))
                {
                    return new Ed25519PrivateKeyParameters(keyData, 0);
                }
                else if (EdECObjectIdentifiers.id_Ed448.equals(oid))
                {
                    return new Ed448PrivateKeyParameters(keyData, 0);
                }
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("cannot identify EdEC/XDH private key: " + e.toString());
            }
        }

        throw new InvalidKeyException("can't identify EdEC/XDH private key.");
    }

}
