package org.bouncycastle.crypto.util;

import java.io.IOException;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.CMCEPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.FrodoKEMPublicKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * Factory to create ASN.1 subject public key info objects from lightweight public keys.
 */
public class SubjectPublicKeyInfoFactory
{
    private SubjectPublicKeyInfoFactory()
    {

    }

    /**
     * Create a SubjectPublicKeyInfo public key.
     *
     * @param publicKey the key to be encoded into the info object.
     * @return a SubjectPublicKeyInfo representing the key.
     * @throws java.io.IOException on an error encoding the key
     */
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        // the two helpers below answer null for anything they do not handle, so they are asked
        // rather than tested for - encoding a key is the work this method exists to do, and doing
        // it once to decide whether it can be done and again to keep the answer would do it twice
        SubjectPublicKeyInfo keyInfo;

        if (publicKey instanceof RSAKeyParameters)
        {
            RSAKeyParameters pub = (RSAKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(pub.getModulus(), pub.getExponent()));
        }
        else if (publicKey instanceof MLDSAPublicKeyParameters)
        {
            MLDSAPublicKeyParameters params = (MLDSAPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mldsaOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getEncoded());
        }
        else if (publicKey instanceof MLKEMPublicKeyParameters)
        {
            MLKEMPublicKeyParameters params = (MLKEMPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mlkemOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getEncoded());
        }
        else if (publicKey instanceof CMCEPublicKeyParameters)
        {
            CMCEPublicKeyParameters params = (CMCEPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.cmceOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getEncoded());
        }
        else if (publicKey instanceof FrodoKEMPublicKeyParameters)
        {
            FrodoKEMPublicKeyParameters params = (FrodoKEMPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.frodoKemOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getEncoded());
        }
        else if (publicKey instanceof XWingPublicKeyParameters)
        {
            XWingPublicKeyParameters params = (XWingPublicKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(BCObjectIdentifiers.xwing), params.getEncoded());
        }
        else if (publicKey instanceof SLHDSAPublicKeyParameters)
        {
            SLHDSAPublicKeyParameters params = (SLHDSAPublicKeyParameters)publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.slhdsaOidLookup(params.getParameters()));
            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
        else if (publicKey instanceof DSAPublicKeyParameters)
        {
            DSAPublicKeyParameters pub = (DSAPublicKeyParameters)publicKey;

            DSAParameter params = null;
            DSAParameters dsaParams = pub.getParameters();
            if (dsaParams != null)
            {
                params = new DSAParameter(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
            }

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, params), new ASN1Integer(pub.getY()));
        }
        else if (publicKey instanceof ECPublicKeyParameters)
        {
            ECPublicKeyParameters pub = (ECPublicKeyParameters)publicKey;
            ECDomainParameters domainParams = pub.getParameters();
            ASN1Encodable params;

            if (domainParams == null)
            {
                params = new X962Parameters(DERNull.INSTANCE);      // Implicitly CA
            }
            else if (domainParams instanceof ECGOST3410Parameters)
            {
                ECGOST3410Parameters gostParams = (ECGOST3410Parameters)domainParams;

                BigInteger bX = pub.getQ().getAffineXCoord().toBigInteger();
                BigInteger bY = pub.getQ().getAffineYCoord().toBigInteger();

                AlgorithmIdentifier algID = ECGOST3410Util.createAlgorithmIdentifier(gostParams);

                int fieldSize = ECGOST3410Util.getFieldElementEncodingLength(gostParams);

                byte[] encKey = new byte[2 * fieldSize];
                extractBytes(encKey, fieldSize, 0, bX);
                extractBytes(encKey, fieldSize, fieldSize, bY);

                try
                {
                    return new SubjectPublicKeyInfo(algID, new DEROctetString(encKey));
                }
                catch (IOException e)
                {
                    return null;
                }
            }
            else if (domainParams instanceof ECNamedDomainParameters)
            {
                params = new X962Parameters(((ECNamedDomainParameters)domainParams).getName());
            }
            else
            {
                X9ECParameters ecP = new X9ECParameters(
                    domainParams.getCurve(),
                    // TODO Support point compression
                    new X9ECPoint(domainParams.getG(), false),
                    domainParams.getN(),
                    domainParams.getH(),
                    domainParams.getSeed());

                params = new X962Parameters(ecP);
            }

            // TODO Support point compression
            byte[] pubKeyOctets = pub.getQ().getEncoded(false);

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), pubKeyOctets);
        }
        else if (publicKey instanceof X448PublicKeyParameters)
        {
            X448PublicKeyParameters key = (X448PublicKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448), key.getEncoded());
        }
        else if (publicKey instanceof X25519PublicKeyParameters)
        {
            X25519PublicKeyParameters key = (X25519PublicKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), key.getEncoded());
        }
        else if (publicKey instanceof Ed448PublicKeyParameters)
        {
            Ed448PublicKeyParameters key = (Ed448PublicKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), key.getEncoded());
        }
        else if (publicKey instanceof Ed25519PublicKeyParameters)
        {
            Ed25519PublicKeyParameters key = (Ed25519PublicKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), key.getEncoded());
        }
        else if ((keyInfo = LmsKeyUtil.createSubjectPublicKeyInfo(publicKey)) != null)
        {
            return keyInfo;
        }
        else if ((keyInfo = XmssKeyUtil.createSubjectPublicKeyInfo(publicKey)) != null)
        {
            return keyInfo;
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
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
