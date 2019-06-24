package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;

/**
 * Factory to create ASN.1 subject public key info objects from lightweight public keys.
 */
public class SubjectPublicKeyInfoFactory
{
    private static Set cryptoProOids = new HashSet(5);

    static
    {
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB);
    }

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
        if (publicKey instanceof RSAKeyParameters)
        {
            RSAKeyParameters pub = (RSAKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(pub.getModulus(), pub.getExponent()));
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

                params = new GOST3410PublicKeyAlgParameters(gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet());

                int encKeySize;
                int offset;
                ASN1ObjectIdentifier algIdentifier;


                if (cryptoProOids.contains(gostParams.getPublicKeyParamSet()))
                {
                    encKeySize = 64;
                    offset = 32;
                    algIdentifier = CryptoProObjectIdentifiers.gostR3410_2001;
                }
                else
                {
                    boolean is512 = (bX.bitLength() > 256);
                    if (is512)
                    {
                        encKeySize = 128;
                        offset = 64;
                        algIdentifier = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;
                    }
                    else
                    {
                        encKeySize = 64;
                        offset = 32;
                        algIdentifier = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
                    }
                }

                byte[] encKey = new byte[encKeySize];
                extractBytes(encKey, encKeySize / 2, 0, bX);
                extractBytes(encKey, encKeySize / 2, offset, bY);

                try
                {
                    return new SubjectPublicKeyInfo(new AlgorithmIdentifier(algIdentifier, params), new DEROctetString(encKey));
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
