package org.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;

/**
 * utility class for converting jce/jca DSA objects
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class DSAUtil
{
    public static final ASN1ObjectIdentifier[] dsaOids =
    {
        X9ObjectIdentifiers.id_dsa,
        OIWObjectIdentifiers.dsaWithSHA1,
        X9ObjectIdentifiers.id_dsa_with_sha1
    };

    /**
     * Return true if the passed in OID could be associated with a DSA key.
     *
     * @param algOid algorithm OID from a key.
     * @return true if it's for a DSA key, false otherwise.
     */
    public static boolean isDsaOid(
        ASN1ObjectIdentifier algOid)
    {
        for (int i = 0; i != dsaOids.length; i++)
        {
            if (algOid.equals(dsaOids[i]))
            {
                return true;
            }
        }

        return false;
    }

    static DSAParameters toDSAParameters(DSAParams spec)
    {
        if (spec != null)
        {
             return new DSAParameters(spec.getP(), spec.getQ(), spec.getG());
        }

        return null;
    }

    static public AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        if (key instanceof BCDSAPublicKey)
        {
            return ((BCDSAPublicKey)key).engineGetKeyParameters();
        }

        if (key instanceof DSAPublicKey)
        {
            return new BCDSAPublicKey((DSAPublicKey)key).engineGetKeyParameters();
        }

        try
        {
            byte[]  bytes = key.getEncoded();

            BCDSAPublicKey bckey = new BCDSAPublicKey(SubjectPublicKeyInfo.getInstance(bytes));

            return bckey.engineGetKeyParameters();
        }
        catch (Exception e)
        {
            throw new InvalidKeyException("can't identify DSA public key: " + key.getClass().getName());
        }
    }

    static public AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey    key)
        throws InvalidKeyException
    {
        if (key instanceof DSAPrivateKey)
        {
            DSAPrivateKey    k = (DSAPrivateKey)key;

            return new DSAPrivateKeyParameters(k.getX(),
                new DSAParameters(k.getParams().getP(), k.getParams().getQ(), k.getParams().getG()));
        }
                        
        throw new InvalidKeyException("can't identify DSA private key.");
    }

    static String generateKeyFingerprint(BigInteger y, DSAParams params)
    {
        return new Fingerprint(Arrays.concatenate(y.toByteArray(), params.getP().toByteArray(), params.getQ().toByteArray(), params.getG().toByteArray())).toString();
    }
}
