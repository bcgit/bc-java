package org.bouncycastle.crypto.util;

import java.io.IOException;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.CMCEPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.FrodoKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;

/**
 * Factory to create ASN.1 private key info objects from lightweight private keys.
 */
public class PrivateKeyInfoFactory
{
    private PrivateKeyInfoFactory()
    {

    }

    /**
     * Create a PrivateKeyInfo representation of a private key.
     *
     * @param privateKey the key to be encoded into the info object.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey)
        throws IOException
    {
        return createPrivateKeyInfo(privateKey, null);
    }

    /**
     * Create a PrivateKeyInfo representation of a private key with attributes.
     *
     * @param privateKey the key to be encoded into the info object.
     * @param attributes the set of attributes to be included.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes)
        throws IOException
    {
        // the two helpers below answer null for anything they do not handle, so they are asked
        // rather than tested for - encoding a key is the work this method exists to do, and doing
        // it once to decide whether it can be done and again to keep the answer would do it twice
        PrivateKeyInfo keyInfo;

        if (privateKey instanceof RSAKeyParameters)
        {
            RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)privateKey;

            return new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                new RSAPrivateKey(priv.getModulus(), priv.getPublicExponent(), priv.getExponent(), priv.getP(), priv.getQ(), priv.getDP(), priv.getDQ(), priv.getQInv()),
                attributes);
        }
        else if (privateKey instanceof DSAPrivateKeyParameters)
        {
            DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)privateKey;
            DSAParameters params = priv.getParameters();

            return new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa,
                new DSAParameter(params.getP(), params.getQ(), params.getG())), new ASN1Integer(priv.getX()),
                attributes);
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            ECPrivateKeyParameters priv = (ECPrivateKeyParameters)privateKey;
            ECDomainParameters domainParams = priv.getParameters();
            ASN1Encodable params;
            int orderBitLength;

            if (domainParams == null)
            {
                params = new X962Parameters(DERNull.INSTANCE);      // Implicitly CA
                orderBitLength = priv.getD().bitLength();   // TODO: this is as good as currently available, must be a better way...
            }
            else if (domainParams instanceof ECGOST3410Parameters)
            {
                ECGOST3410Parameters gostParams = (ECGOST3410Parameters)domainParams;

                AlgorithmIdentifier algID = ECGOST3410Util.createAlgorithmIdentifier(gostParams);

                int size = ECGOST3410Util.getFieldElementEncodingLength(gostParams);

                byte[] encKey = new byte[size];
                extractBytes(encKey, size, 0, priv.getD());

                return new PrivateKeyInfo(algID, new DEROctetString(encKey), attributes);
            }
            else if (domainParams instanceof ECNamedDomainParameters)
            {
                params = new X962Parameters(((ECNamedDomainParameters)domainParams).getName());
                orderBitLength = domainParams.getN().bitLength();
            }
            else
            {
                X9ECParameters ecP = new X9ECParameters(
                    domainParams.getCurve(),
                    new X9ECPoint(domainParams.getG(), false),
                    domainParams.getN(),
                    domainParams.getH(),
                    domainParams.getSeed());

                params = new X962Parameters(ecP);
                orderBitLength = domainParams.getN().bitLength();
            }

            ECPoint q = new FixedPointCombMultiplier().multiply(domainParams.getG(), priv.getD());

            // TODO Support point compression
            DERBitString publicKey = new DERBitString(q.getEncoded(false));

            return new PrivateKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params),
                new ECPrivateKey(orderBitLength, priv.getD(), publicKey, params),
                attributes);
        }
        else if (privateKey instanceof MLDSAPrivateKeyParameters)
        {
            MLDSAPrivateKeyParameters params = (MLDSAPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mldsaOidLookup(params.getParameters()));

            if (params.getPreferredFormat() == MLDSAPrivateKeyParameters.SEED_ONLY)
            {
                return new PrivateKeyInfo(algorithmIdentifier, new DERTaggedObject(false, 0, new DEROctetString(params.getSeed())), attributes);
            }
            else if (params.getPreferredFormat() == MLDSAPrivateKeyParameters.EXPANDED_KEY)
            {
                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes);
            }
            return new PrivateKeyInfo(algorithmIdentifier, getBasicPQCEncoding(params.getSeed(), params.getEncoded()), attributes);
        }
        else if (privateKey instanceof MLKEMPrivateKeyParameters)
        {
            MLKEMPrivateKeyParameters params = (MLKEMPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mlkemOidLookup(params.getParameters()));

            if (params.getPreferredFormat() == MLKEMPrivateKeyParameters.SEED_ONLY)
            {
                return new PrivateKeyInfo(algorithmIdentifier, new DERTaggedObject(false, 0, new DEROctetString(params.getSeed())), attributes);
            }
            else if (params.getPreferredFormat() == MLKEMPrivateKeyParameters.EXPANDED_KEY)
            {
                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes);
            }
            return new PrivateKeyInfo(algorithmIdentifier, getBasicPQCEncoding(params.getSeed(), params.getEncoded()), attributes);
        }
        else if ((keyInfo = LmsKeyUtil.createPrivateKeyInfo(privateKey, attributes)) != null)
        {
            return keyInfo;
        }
        else if ((keyInfo = XmssKeyUtil.createPrivateKeyInfo(privateKey, attributes)) != null)
        {
            return keyInfo;
        }
        else if (privateKey instanceof CMCEPrivateKeyParameters)
        {
            CMCEPrivateKeyParameters params = (CMCEPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.cmceOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes);
        }
        else if (privateKey instanceof FrodoKEMPrivateKeyParameters)
        {
            FrodoKEMPrivateKeyParameters params = (FrodoKEMPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.frodoKemOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes);
        }
        else if (privateKey instanceof XWingPrivateKeyParameters)
        {
            XWingPrivateKeyParameters params = (XWingPrivateKeyParameters)privateKey;

            // draft-connolly-cfrg-xwing-kem 5.8.2: the raw seed, publicKey absent
            return new PrivateKeyInfo(new AlgorithmIdentifier(BCObjectIdentifiers.xwing), params.getSeed(), attributes);
        }
        else if (privateKey instanceof SLHDSAPrivateKeyParameters)
        {
            SLHDSAPrivateKeyParameters params = (SLHDSAPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.slhdsaOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, params.getEncoded(), attributes);
        }
        else if (privateKey instanceof X448PrivateKeyParameters)
        {
            X448PrivateKeyParameters key = (X448PrivateKeyParameters)privateKey;

            return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448),
                new DEROctetString(key.getEncoded()), attributes, key.generatePublicKey().getEncoded());
        }
        else if (privateKey instanceof X25519PrivateKeyParameters)
        {
            X25519PrivateKeyParameters key = (X25519PrivateKeyParameters)privateKey;

            return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519),
                new DEROctetString(key.getEncoded()), attributes, key.generatePublicKey().getEncoded());
        }
        else if (privateKey instanceof Ed448PrivateKeyParameters)
        {
            Ed448PrivateKeyParameters key = (Ed448PrivateKeyParameters)privateKey;

            return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448),
                new DEROctetString(key.getEncoded()), attributes, key.generatePublicKey().getEncoded());
        }
        else if (privateKey instanceof Ed25519PrivateKeyParameters)
        {
            Ed25519PrivateKeyParameters key = (Ed25519PrivateKeyParameters)privateKey;

            return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                new DEROctetString(key.getEncoded()), attributes, key.generatePublicKey().getEncoded());
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }

    private static ASN1Sequence getBasicPQCEncoding(byte[] seed, byte[] expanded)
    {
        return new DERSequence(new DEROctetString(seed), new DEROctetString(expanded));
    }

    private static void extractBytes(byte[] encKey, int size, int offSet, BigInteger bI)
    {
        byte[] val = bI.toByteArray();
        if (val.length < size)
        {
            byte[] tmp = new byte[size];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }

        for (int i = 0; i != size; i++)
        {
            encKey[offSet + i] = val[val.length - 1 - i];
        }
    }
}
