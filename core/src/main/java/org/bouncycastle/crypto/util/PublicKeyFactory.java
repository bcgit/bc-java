package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.ua.DSTU4145BinaryField;
import org.bouncycastle.asn1.ua.DSTU4145ECBinary;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.asn1.ua.DSTU4145PointEncoder;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.ValidationParams;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

/**
 * Factory to create asymmetric public key parameters for asymmetric ciphers from range of
 * ASN.1 encoded SubjectPublicKeyInfo objects.
 */
public class PublicKeyFactory
{
    private static Map converters = new HashMap();

    static
    {
        converters.put(PKCSObjectIdentifiers.rsaEncryption, new RSAConverter());
        converters.put(PKCSObjectIdentifiers.id_RSASSA_PSS, new RSAConverter());
        converters.put(X509ObjectIdentifiers.id_ea_rsa, new RSAConverter());
        converters.put(X9ObjectIdentifiers.dhpublicnumber, new DHPublicNumberConverter());
        converters.put(PKCSObjectIdentifiers.dhKeyAgreement, new DHAgreementConverter());
        converters.put(X9ObjectIdentifiers.id_dsa, new DSAConverter());
        converters.put(OIWObjectIdentifiers.dsaWithSHA1, new DSAConverter());
        converters.put(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalConverter());
        converters.put(X9ObjectIdentifiers.id_ecPublicKey, new ECConverter());
        converters.put(CryptoProObjectIdentifiers.gostR3410_2001, new GOST3410_2001Converter());
        converters.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, new GOST3410_2012Converter());
        converters.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, new GOST3410_2012Converter());
        converters.put(UAObjectIdentifiers.dstu4145be, new DSTUConverter());
        converters.put(UAObjectIdentifiers.dstu4145le, new DSTUConverter());
        converters.put(EdECObjectIdentifiers.id_X25519, new X25519Converter());
        converters.put(EdECObjectIdentifiers.id_X448, new X448Converter());
        converters.put(EdECObjectIdentifiers.id_Ed25519, new Ed25519Converter());
        converters.put(EdECObjectIdentifiers.id_Ed448, new Ed448Converter());
    }

    /**
     * Create a public key from a SubjectPublicKeyInfo encoding
     *
     * @param keyInfoData the SubjectPublicKeyInfo encoding
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(byte[] keyInfoData)
        throws IOException
    {
        return createKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(keyInfoData)));
    }

    /**
     * Create a public key from a SubjectPublicKeyInfo encoding read from a stream
     *
     * @param inStr the stream to read the SubjectPublicKeyInfo encoding from
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(InputStream inStr)
        throws IOException
    {
        return createKey(SubjectPublicKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    /**
     * Create a public key from the passed in SubjectPublicKeyInfo
     *
     * @param keyInfo the SubjectPublicKeyInfo containing the key data
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return createKey(keyInfo, null);
    }

    /**
     * Create a public key from the passed in SubjectPublicKeyInfo
     *
     * @param keyInfo       the SubjectPublicKeyInfo containing the key data
     * @param defaultParams default parameters that might be needed.
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        throws IOException
    {
        AlgorithmIdentifier algID = keyInfo.getAlgorithm();

        SubjectPublicKeyInfoConverter converter = (SubjectPublicKeyInfoConverter)converters.get(algID.getAlgorithm());
        if (null == converter)
        {
            throw new IOException("algorithm identifier in public key not recognised: " + algID.getAlgorithm());
        }

        return converter.getPublicKeyParameters(keyInfo, defaultParams);
    }

    private static abstract class SubjectPublicKeyInfoConverter
    {
        abstract AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException;
    }

    private static class RSAConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            RSAPublicKey pubKey = RSAPublicKey.getInstance(keyInfo.parsePublicKey());

            return new RSAKeyParameters(false, pubKey.getModulus(), pubKey.getPublicExponent());
        }
    }

    private static class DHPublicNumberConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            DHPublicKey dhPublicKey = DHPublicKey.getInstance(keyInfo.parsePublicKey());

            BigInteger y = dhPublicKey.getY();

            DomainParameters dhParams = DomainParameters.getInstance(keyInfo.getAlgorithm().getParameters());

            BigInteger p = dhParams.getP();
            BigInteger g = dhParams.getG();
            BigInteger q = dhParams.getQ();

            BigInteger j = null;
            if (dhParams.getJ() != null)
            {
                j = dhParams.getJ();
            }

            DHValidationParameters validation = null;
            ValidationParams dhValidationParms = dhParams.getValidationParams();
            if (dhValidationParms != null)
            {
                byte[] seed = dhValidationParms.getSeed();
                BigInteger pgenCounter = dhValidationParms.getPgenCounter();

                // TODO Check pgenCounter size?

                validation = new DHValidationParameters(seed, pgenCounter.intValue());
            }

            return new DHPublicKeyParameters(y, new DHParameters(p, g, q, j, validation));
        }
    }

    private static class DHAgreementConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            DHParameter params = DHParameter.getInstance(keyInfo.getAlgorithm().getParameters());
            ASN1Integer derY = (ASN1Integer)keyInfo.parsePublicKey();

            BigInteger lVal = params.getL();
            int l = lVal == null ? 0 : lVal.intValue();
            DHParameters dhParams = new DHParameters(params.getP(), params.getG(), null, l);

            return new DHPublicKeyParameters(derY.getValue(), dhParams);
        }
    }

    private static class ElGamalConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            ElGamalParameter params = ElGamalParameter.getInstance(keyInfo.getAlgorithm().getParameters());
            ASN1Integer derY = (ASN1Integer)keyInfo.parsePublicKey();

            return new ElGamalPublicKeyParameters(derY.getValue(), new ElGamalParameters(
                params.getP(), params.getG()));
        }
    }

    private static class DSAConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            ASN1Integer derY = (ASN1Integer)keyInfo.parsePublicKey();
            ASN1Encodable de = keyInfo.getAlgorithm().getParameters();

            DSAParameters parameters = null;
            if (de != null)
            {
                DSAParameter params = DSAParameter.getInstance(de.toASN1Primitive());
                parameters = new DSAParameters(params.getP(), params.getQ(), params.getG());
            }

            return new DSAPublicKeyParameters(derY.getValue(), parameters);
        }
    }

    private static class ECConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        {
            X962Parameters params = X962Parameters.getInstance(keyInfo.getAlgorithm().getParameters());
            ECDomainParameters dParams;

            if (params.isNamedCurve())
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)params.getParameters();

                X9ECParameters x9 = CustomNamedCurves.getByOID(oid);
                if (x9 == null)
                {
                    x9 = ECNamedCurveTable.getByOID(oid);
                }
                dParams = new ECNamedDomainParameters(oid, x9);
            }
            else if (params.isImplicitlyCA())
            {
                dParams = (ECDomainParameters)defaultParams;
            }
            else
            {
                X9ECParameters x9 = X9ECParameters.getInstance(params.getParameters());
                dParams = new ECDomainParameters(x9);
            }

            DERBitString bits = keyInfo.getPublicKeyData();
            byte[] data = bits.getBytes();
            ASN1OctetString key = new DEROctetString(data);

            //
            // extra octet string - the old extra embedded octet string
            //
            if (data[0] == 0x04 && data[1] == data.length - 2
                && (data[2] == 0x02 || data[2] == 0x03))
            {
                int qLength = new X9IntegerConverter().getByteLength(dParams.getCurve());

                if (qLength >= data.length - 3)
                {
                    try
                    {
                        key = (ASN1OctetString)ASN1Primitive.fromByteArray(data);
                    }
                    catch (IOException ex)
                    {
                        throw new IllegalArgumentException("error recovering public key");
                    }
                }
            }

            X9ECPoint derQ = new X9ECPoint(dParams.getCurve(), key);

            return new ECPublicKeyParameters(derQ.getPoint(), dParams);
        }
    }

    private static class GOST3410_2001Converter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        {
            AlgorithmIdentifier algID = keyInfo.getAlgorithm();
//            ASN1ObjectIdentifier algOid = algID.getAlgorithm();
            GOST3410PublicKeyAlgParameters gostParams = GOST3410PublicKeyAlgParameters.getInstance(algID.getParameters());
            ASN1ObjectIdentifier publicKeyParamSet = gostParams.getPublicKeyParamSet();

            ECGOST3410Parameters ecDomainParameters = new ECGOST3410Parameters(
                new ECNamedDomainParameters(publicKeyParamSet, ECGOST3410NamedCurves.getByOIDX9(publicKeyParamSet)),
                publicKeyParamSet,
                gostParams.getDigestParamSet(),
                gostParams.getEncryptionParamSet());

            ASN1OctetString key;
            try
            {
                key = (ASN1OctetString)keyInfo.parsePublicKey();
            }
            catch (IOException ex)
            {
                throw new IllegalArgumentException("error recovering GOST3410_2001 public key");
            }

            int fieldSize = 32;
            int keySize = 2 * fieldSize;

            byte[] keyEnc = key.getOctets();
            if (keyEnc.length != keySize)
            {
                throw new IllegalArgumentException("invalid length for GOST3410_2001 public key");
            }

            byte[] x9Encoding = new byte[1 + keySize];
            x9Encoding[0] = 0x04;
            for (int i = 1; i <= fieldSize; ++i)
            {
                x9Encoding[i] = keyEnc[fieldSize - i];
                x9Encoding[i + fieldSize] = keyEnc[keySize - i];
            }

            ECPoint q = ecDomainParameters.getCurve().decodePoint(x9Encoding);

            return new ECPublicKeyParameters(q, ecDomainParameters);
        }
    }

    private static class GOST3410_2012Converter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        {
            AlgorithmIdentifier algID = keyInfo.getAlgorithm();
            ASN1ObjectIdentifier algOid = algID.getAlgorithm();
            GOST3410PublicKeyAlgParameters gostParams = GOST3410PublicKeyAlgParameters.getInstance(algID.getParameters());
            ASN1ObjectIdentifier publicKeyParamSet = gostParams.getPublicKeyParamSet();

            ECGOST3410Parameters ecDomainParameters = new ECGOST3410Parameters(
                new ECNamedDomainParameters(publicKeyParamSet, ECGOST3410NamedCurves.getByOIDX9(publicKeyParamSet)),
                publicKeyParamSet,
                gostParams.getDigestParamSet(),
                gostParams.getEncryptionParamSet());

            ASN1OctetString key;
            try
            {
                key = (ASN1OctetString)keyInfo.parsePublicKey();
            }
            catch (IOException ex)
            {
                throw new IllegalArgumentException("error recovering GOST3410_2012 public key");
            }

            int fieldSize = 32;
            if (algOid.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512))
            {
                fieldSize = 64;
            }
            int keySize = 2 * fieldSize;

            byte[] keyEnc = key.getOctets();
            if (keyEnc.length != keySize)
            {
                throw new IllegalArgumentException("invalid length for GOST3410_2012 public key");
            }

            byte[] x9Encoding = new byte[1 + keySize];
            x9Encoding[0] = 0x04;
            for (int i = 1; i <= fieldSize; ++i)
            {
                x9Encoding[i] = keyEnc[fieldSize - i];
                x9Encoding[i + fieldSize] = keyEnc[keySize - i];
            }

            ECPoint q = ecDomainParameters.getCurve().decodePoint(x9Encoding);

            return new ECPublicKeyParameters(q, ecDomainParameters);
        }
    }

    private static class DSTUConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            AlgorithmIdentifier algID = keyInfo.getAlgorithm();
            ASN1ObjectIdentifier algOid = algID.getAlgorithm();
            DSTU4145Params dstuParams = DSTU4145Params.getInstance(algID.getParameters());

            ASN1OctetString key;
            try
            {
                key = (ASN1OctetString)keyInfo.parsePublicKey();
            }
            catch (IOException ex)
            {
                throw new IllegalArgumentException("error recovering DSTU public key");
            }

            byte[] keyEnc = Arrays.clone(key.getOctets());

            if (algOid.equals(UAObjectIdentifiers.dstu4145le))
            {
                reverseBytes(keyEnc);
            }

            ECDomainParameters ecDomain;
            if (dstuParams.isNamedCurve())
            {
                ecDomain = DSTU4145NamedCurves.getByOID(dstuParams.getNamedCurve());
            }
            else
            {
                DSTU4145ECBinary binary = dstuParams.getECBinary();
                byte[] b_bytes = binary.getB();
                if (algOid.equals(UAObjectIdentifiers.dstu4145le))
                {
                    reverseBytes(b_bytes);
                }
                BigInteger b = new BigInteger(1, b_bytes);
                DSTU4145BinaryField field = binary.getField();
                ECCurve curve = new ECCurve.F2m(field.getM(), field.getK1(), field.getK2(), field.getK3(), binary.getA(), b);
                byte[] g_bytes = binary.getG();
                if (algOid.equals(UAObjectIdentifiers.dstu4145le))
                {
                    reverseBytes(g_bytes);
                }
                ECPoint g = DSTU4145PointEncoder.decodePoint(curve, g_bytes);
                ecDomain = new ECDomainParameters(curve, g, binary.getN());
            }

            ECPoint q = DSTU4145PointEncoder.decodePoint(ecDomain.getCurve(), keyEnc);

            return new ECPublicKeyParameters(q, ecDomain);
        }

        private void reverseBytes(byte[] bytes)
        {
            byte tmp;

            for (int i = 0; i < bytes.length / 2; i++)
            {
                tmp = bytes[i];
                bytes[i] = bytes[bytes.length - 1 - i];
                bytes[bytes.length - 1 - i] = tmp;
            }
        }
    }

    private static class X25519Converter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        {
            return new X25519PublicKeyParameters(getRawKey(keyInfo, defaultParams, X25519PublicKeyParameters.KEY_SIZE), 0);
        }
    }

    private static class X448Converter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        {
            return new X448PublicKeyParameters(getRawKey(keyInfo, defaultParams, X448PublicKeyParameters.KEY_SIZE), 0);
        }
    }

    private static class Ed25519Converter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        {
            return new Ed25519PublicKeyParameters(getRawKey(keyInfo, defaultParams, Ed25519PublicKeyParameters.KEY_SIZE), 0);
        }
    }

    private static class Ed448Converter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        {
            return new Ed448PublicKeyParameters(getRawKey(keyInfo, defaultParams, Ed448PublicKeyParameters.KEY_SIZE), 0);
        }
    }

    private static byte[] getRawKey(SubjectPublicKeyInfo keyInfo, Object defaultParams, int expectedSize)
    {
        /*
         * TODO[RFC 8422]
         * - Require defaultParams == null?
         * - Require keyInfo.getAlgorithm().getParameters() == null?
         */
        byte[] result = keyInfo.getPublicKeyData().getOctets();
        if (expectedSize != result.length)
        {
            throw new RuntimeException("public key encoding has incorrect length");
        }
        return result;
    }
}
