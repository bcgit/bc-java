package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * Factory for creating private key objects from PKCS8 PrivateKeyInfo objects.
 */
public class PrivateKeyFactory
{
    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding.
     *
     * @param privateKeyInfoData the PrivateKeyInfo encoding
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(byte[] privateKeyInfoData)
        throws IOException
    {
        return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyInfoData)));
    }

    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding read from a
     * stream.
     *
     * @param inStr the stream to read the PrivateKeyInfo encoding from
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(InputStream inStr)
        throws IOException
    {
        return createKey(PrivateKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    /**
     * Create a private key parameter from the passed in PKCS8 PrivateKeyInfo object.
     *
     * @param keyInfo the PrivateKeyInfo object containing the key material
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();

        if (algOID.equals(PKCSObjectIdentifiers.rsaEncryption)
            || algOID.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)
            || algOID.equals(X509ObjectIdentifiers.id_ea_rsa))
        {
            RSAPrivateKey keyStructure = RSAPrivateKey.getInstance(keyInfo.parsePrivateKey());

            return new RSAPrivateCrtKeyParameters(keyStructure.getModulus(),
                keyStructure.getPublicExponent(), keyStructure.getPrivateExponent(),
                keyStructure.getPrime1(), keyStructure.getPrime2(), keyStructure.getExponent1(),
                keyStructure.getExponent2(), keyStructure.getCoefficient());
        }
        // TODO?
//      else if (algOID.equals(X9ObjectIdentifiers.dhpublicnumber))
        else if (algOID.equals(PKCSObjectIdentifiers.dhKeyAgreement))
        {
            DHParameter params = DHParameter.getInstance(algId.getParameters());
            ASN1Integer derX = (ASN1Integer)keyInfo.parsePrivateKey();

            BigInteger lVal = params.getL();
            int l = lVal == null ? 0 : lVal.intValue();
            DHParameters dhParams = new DHParameters(params.getP(), params.getG(), null, l);

            return new DHPrivateKeyParameters(derX.getValue(), dhParams);
        }
        else if (algOID.equals(OIWObjectIdentifiers.elGamalAlgorithm))
        {
            ElGamalParameter params = ElGamalParameter.getInstance(algId.getParameters());
            ASN1Integer derX = (ASN1Integer)keyInfo.parsePrivateKey();

            return new ElGamalPrivateKeyParameters(derX.getValue(), new ElGamalParameters(
                params.getP(), params.getG()));
        }
        else if (algOID.equals(X9ObjectIdentifiers.id_dsa))
        {
            ASN1Integer derX = (ASN1Integer)keyInfo.parsePrivateKey();
            ASN1Encodable de = algId.getParameters();

            DSAParameters parameters = null;
            if (de != null)
            {
                DSAParameter params = DSAParameter.getInstance(de.toASN1Primitive());
                parameters = new DSAParameters(params.getP(), params.getQ(), params.getG());
            }

            return new DSAPrivateKeyParameters(derX.getValue(), parameters);
        }
        else if (algOID.equals(X9ObjectIdentifiers.id_ecPublicKey))
        {
            X962Parameters params = X962Parameters.getInstance(algId.getParameters());

            X9ECParameters x9;
            ECDomainParameters dParams;

            if (params.isNamedCurve())
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)params.getParameters();

                x9 = CustomNamedCurves.getByOID(oid);
                if (x9 == null)
                {
                    x9 = ECNamedCurveTable.getByOID(oid);
                }
                dParams = new ECNamedDomainParameters(oid, x9);
            }
            else
            {
                x9 = X9ECParameters.getInstance(params.getParameters());
                dParams = new ECDomainParameters(
                    x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
            }

            ECPrivateKey ec = ECPrivateKey.getInstance(keyInfo.parsePrivateKey());
            BigInteger d = ec.getKey();

            return new ECPrivateKeyParameters(d, dParams);
        }
        else if (algOID.equals(EdECObjectIdentifiers.id_X25519))
        {
            return new X25519PrivateKeyParameters(getRawKey(keyInfo, X25519PrivateKeyParameters.KEY_SIZE), 0);
        }
        else if (algOID.equals(EdECObjectIdentifiers.id_X448))
        {
            return new X448PrivateKeyParameters(getRawKey(keyInfo, X448PrivateKeyParameters.KEY_SIZE), 0);
        }
        else if (algOID.equals(EdECObjectIdentifiers.id_Ed25519))
        {
            return new Ed25519PrivateKeyParameters(getRawKey(keyInfo, Ed25519PrivateKeyParameters.KEY_SIZE), 0);
        }
        else if (algOID.equals(EdECObjectIdentifiers.id_Ed448))
        {
            return new Ed448PrivateKeyParameters(getRawKey(keyInfo, Ed448PrivateKeyParameters.KEY_SIZE), 0);
        }
        else if (
            algOID.equals(CryptoProObjectIdentifiers.gostR3410_2001) ||
                algOID.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512) ||
                algOID.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256))
        {
            GOST3410PublicKeyAlgParameters gostParams = GOST3410PublicKeyAlgParameters.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
            ECGOST3410Parameters ecSpec = null;
            BigInteger d = null;
            ASN1Primitive p = keyInfo.getPrivateKeyAlgorithm().getParameters().toASN1Primitive();
            if (p instanceof ASN1Sequence && (ASN1Sequence.getInstance(p).size() == 2 || ASN1Sequence.getInstance(p).size() == 3))
            {

                X9ECParameters ecP = ECGOST3410NamedCurves.getByOIDX9(gostParams.getPublicKeyParamSet());

                ecSpec = new ECGOST3410Parameters(
                    new ECNamedDomainParameters(
                        gostParams.getPublicKeyParamSet(), ecP),
                    gostParams.getPublicKeyParamSet(),
                    gostParams.getDigestParamSet(),
                    gostParams.getEncryptionParamSet());
                ASN1OctetString privEnc = keyInfo.getPrivateKey();

                if (privEnc.getOctets().length == 32 || privEnc.getOctets().length == 64)
                {
                    d = new BigInteger(1, Arrays.reverse(privEnc.getOctets()));
                }
                else
                {
                    ASN1Encodable privKey = keyInfo.parsePrivateKey();
                    if (privKey instanceof ASN1Integer)
                    {
                        d = ASN1Integer.getInstance(privKey).getPositiveValue();
                    }
                    else
                    {
                        byte[] dVal = Arrays.reverse(ASN1OctetString.getInstance(privKey).getOctets());
                        d = new BigInteger(1, dVal);
                    }
                }
            }
            else
            {
                X962Parameters params = X962Parameters.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());

                if (params.isNamedCurve())
                {
                    ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
                    X9ECParameters ecP = ECNamedCurveTable.getByOID(oid);

                    ecSpec = new ECGOST3410Parameters(new ECNamedDomainParameters(oid, ecP),
                        gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(),
                        gostParams.getEncryptionParamSet());
                }
                else if (params.isImplicitlyCA())
                {
                    ecSpec = null;
                }
                else
                {
                    X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());
                    ecSpec = new ECGOST3410Parameters(new ECNamedDomainParameters(algOID, ecP),
                        gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(),
                        gostParams.getEncryptionParamSet());
                }

                ASN1Encodable privKey = keyInfo.parsePrivateKey();
                if (privKey instanceof ASN1Integer)
                {
                    ASN1Integer derD = ASN1Integer.getInstance(privKey);

                    d = derD.getValue();
                }
                else
                {
                    ECPrivateKey ec = ECPrivateKey.getInstance(privKey);

                    d = ec.getKey();
                }

            }

            return new ECPrivateKeyParameters(
                d,
                new ECGOST3410Parameters(
                    ecSpec,
                    gostParams.getPublicKeyParamSet(),
                    gostParams.getDigestParamSet(),
                    gostParams.getEncryptionParamSet()));

        }
        else
        {
            throw new RuntimeException("algorithm identifier in private key not recognised");
        }
    }

    private static byte[] getRawKey(PrivateKeyInfo keyInfo, int expectedSize)
        throws IOException
    {
        byte[] result = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
        if (expectedSize != result.length)
        {
            throw new RuntimeException("private key encoding has incorrect length");
        }
        return result;
    }
}
