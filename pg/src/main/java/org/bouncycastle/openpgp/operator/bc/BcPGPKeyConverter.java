package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.openpgp.PGPAlgorithmParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKdfParameters;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class BcPGPKeyConverter
{
    // We default to these as they are specified as mandatory in RFC 6631.
    private static final PGPKdfParameters DEFAULT_KDF_PARAMETERS = new PGPKdfParameters(HashAlgorithmTags.SHA256,
        SymmetricKeyAlgorithmTags.AES_128);

    public PGPPrivateKey getPGPPrivateKey(PGPPublicKey pubKey, AsymmetricKeyParameter privKey)
        throws PGPException
    {
        BCPGKey privPk = getPrivateBCPGKey(pubKey, privKey);

        return new PGPPrivateKey(pubKey.getKeyID(), pubKey.getPublicKeyPacket(), privPk);
    }

    /**
     * Create a PGPPublicKey from the passed in JCA one.
     * <p>
     * Note: the time passed in affects the value of the key's keyID, so you probably only want
     * to do this once for a JCA key, or make sure you keep track of the time you used.
     * </p>
     *
     * @param algorithm asymmetric algorithm type representing the public key.
     * @param pubKey    actual public key to associate.
     * @param time      date of creation.
     * @throws PGPException on key creation problem.
     */
    public PGPPublicKey getPGPPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, AsymmetricKeyParameter pubKey, Date time)
        throws PGPException
    {
        BCPGKey bcpgKey = getPublicBCPGKey(algorithm, algorithmParameters, pubKey);

        return new PGPPublicKey(new PublicKeyPacket(algorithm, time, bcpgKey), new BcKeyFingerprintCalculator());
    }

    public AsymmetricKeyParameter getPrivateKey(PGPPrivateKey privKey)
        throws PGPException
    {
        PublicKeyPacket pubPk = privKey.getPublicKeyPacket();
        BCPGKey privPk = privKey.getPrivateKeyDataPacket();

        try
        {
            switch (pubPk.getAlgorithm())
            {
            case PublicKeyAlgorithmTags.DSA:
            {
                DSAPublicBCPGKey dsaPub = (DSAPublicBCPGKey)pubPk.getKey();
                DSASecretBCPGKey dsaPriv = (DSASecretBCPGKey)privPk;
                return new DSAPrivateKeyParameters(dsaPriv.getX(),
                    new DSAParameters(dsaPub.getP(), dsaPub.getQ(), dsaPub.getG()));
            }

            case PublicKeyAlgorithmTags.ECDH:
            {
                ECDHPublicBCPGKey ecdhPub = (ECDHPublicBCPGKey)pubPk.getKey();

                if (CryptlibObjectIdentifiers.curvey25519.equals(ecdhPub.getCurveOID()))
                {
                    // 'reverse' because the native format for X25519 private keys is little-endian
                    return implGetPrivateKeyPKCS8(EdECObjectIdentifiers.id_X25519, privPk);
                }
                else if (EdECObjectIdentifiers.id_X448.equals(ecdhPub.getCurveOID()))
                {
                    // 'reverse' because the native format for X448 private keys is little-endian
                    return implGetPrivateKeyPKCS8(EdECObjectIdentifiers.id_X448, privPk);
                }
                else
                {
                    return implGetPrivateKeyEC(ecdhPub, (ECSecretBCPGKey)privPk);
                }
            }
            case PublicKeyAlgorithmTags.X25519:
            {
                return implGetPrivateKeyPKCS8(EdECObjectIdentifiers.id_X25519, privPk);
            }
            case PublicKeyAlgorithmTags.X448:
            {
                return implGetPrivateKeyPKCS8(EdECObjectIdentifiers.id_X448, privPk);
            }
            case PublicKeyAlgorithmTags.ECDSA:
                return implGetPrivateKeyEC((ECDSAPublicBCPGKey)pubPk.getKey(), (ECSecretBCPGKey)privPk);

            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                if (((EdDSAPublicBCPGKey)pubPk.getKey()).getCurveOID().equals(EdECObjectIdentifiers.id_Ed448))
                {
                    return implGetPrivateKeyPKCS8(EdECObjectIdentifiers.id_Ed448, Ed448.SECRET_KEY_SIZE, privPk);
                }
                return implGetPrivateKeyPKCS8(EdECObjectIdentifiers.id_Ed25519, Ed25519.SECRET_KEY_SIZE, privPk);
            }
            case PublicKeyAlgorithmTags.Ed25519:
            {
                return implGetPrivateKeyPKCS8(EdECObjectIdentifiers.id_Ed25519, Ed25519.SECRET_KEY_SIZE, privPk);
            }
            case PublicKeyAlgorithmTags.Ed448:
            {
                return implGetPrivateKeyPKCS8(EdECObjectIdentifiers.id_Ed448, Ed448.SECRET_KEY_SIZE, privPk);
            }

            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            {
                ElGamalPublicBCPGKey elPub = (ElGamalPublicBCPGKey)pubPk.getKey();
                ElGamalSecretBCPGKey elPriv = (ElGamalSecretBCPGKey)privPk;
                return new ElGamalPrivateKeyParameters(elPriv.getX(), new ElGamalParameters(elPub.getP(), elPub.getG()));
            }

            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            {
                RSAPublicBCPGKey rsaPub = (RSAPublicBCPGKey)pubPk.getKey();
                RSASecretBCPGKey rsaPriv = (RSASecretBCPGKey)privPk;
                return new RSAPrivateCrtKeyParameters(rsaPriv.getModulus(), rsaPub.getPublicExponent(),
                    rsaPriv.getPrivateExponent(), rsaPriv.getPrimeP(), rsaPriv.getPrimeQ(), rsaPriv.getPrimeExponentP(),
                    rsaPriv.getPrimeExponentQ(), rsaPriv.getCrtCoefficient());
            }

            default:
                throw new PGPException("unknown public key algorithm encountered");
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception constructing key", e);
        }
    }

    public AsymmetricKeyParameter getPublicKey(PGPPublicKey publicKey)
        throws PGPException
    {
        PublicKeyPacket publicPk = publicKey.getPublicKeyPacket();

        try
        {
            switch (publicPk.getAlgorithm())
            {
            case PublicKeyAlgorithmTags.DSA:
            {
                DSAPublicBCPGKey dsaK = (DSAPublicBCPGKey)publicPk.getKey();
                return new DSAPublicKeyParameters(dsaK.getY(), new DSAParameters(dsaK.getP(), dsaK.getQ(), dsaK.getG()));
            }

            case PublicKeyAlgorithmTags.ECDH:
            {
                ECDHPublicBCPGKey ecdhK = (ECDHPublicBCPGKey)publicPk.getKey();

                if (ecdhK.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    return getX25519PublicKey(ecdhK);
                }
                else if (ecdhK.getCurveOID().equals(EdECObjectIdentifiers.id_X448))
                {
                    return getX448PublicKey(ecdhK);
                }
                else
                {
                    return implGetPublicKeyEC(ecdhK);
                }
            }
            case PublicKeyAlgorithmTags.X25519:
            {
                return getX25519PublicKey((ECDHPublicBCPGKey)publicPk.getKey());
            }
            case PublicKeyAlgorithmTags.X448:
            {
                return getX448PublicKey((ECDHPublicBCPGKey)publicPk.getKey());
            }
            case PublicKeyAlgorithmTags.ECDSA:
                return implGetPublicKeyEC((ECDSAPublicBCPGKey)publicPk.getKey());

            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                EdDSAPublicBCPGKey eddsaK = (EdDSAPublicBCPGKey)publicPk.getKey();

                byte[] pEnc = BigIntegers.asUnsignedByteArray(eddsaK.getEncodedPoint());

                if (pEnc.length < 1)
                {
                    throw new IllegalArgumentException("Invalid EdDSA public key");
                }

                if (pEnc[0] == 0x40 && !eddsaK.getCurveOID().equals(EdECObjectIdentifiers.id_Ed448))
                {
                    return implGetPublicKeyX509(EdECObjectIdentifiers.id_Ed25519, pEnc, 1);
                }
                else if (eddsaK.getCurveOID().equals(EdECObjectIdentifiers.id_Ed448))
                {
                    return implGetPublicKeyX509(EdECObjectIdentifiers.id_Ed448, pEnc, 0);
                }

                throw new IllegalArgumentException("Invalid EdDSA public key");
            }
            case PublicKeyAlgorithmTags.Ed25519:
            {
                EdDSAPublicBCPGKey eddsaK = (EdDSAPublicBCPGKey)publicPk.getKey();

                byte[] pEnc = BigIntegers.asUnsignedByteArray(eddsaK.getEncodedPoint());

                if (pEnc.length < 1 || pEnc[0] != 0x40)
                {
                    throw new IllegalArgumentException("Invalid Ed25519 public key");
                }

                return implGetPublicKeyX509(EdECObjectIdentifiers.id_Ed25519, pEnc, 1);

            }
            case PublicKeyAlgorithmTags.Ed448:
            {
                EdDSAPublicBCPGKey eddsaK = (EdDSAPublicBCPGKey)publicPk.getKey();

                byte[] pEnc = BigIntegers.asUnsignedByteArray(eddsaK.getEncodedPoint());

                return implGetPublicKeyX509(EdECObjectIdentifiers.id_Ed448, pEnc, 0);
            }

            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                ElGamalPublicBCPGKey elK = (ElGamalPublicBCPGKey)publicPk.getKey();
                return new ElGamalPublicKeyParameters(elK.getY(), new ElGamalParameters(elK.getP(), elK.getG()));

            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            {
                RSAPublicBCPGKey rsaK = (RSAPublicBCPGKey)publicPk.getKey();
                return new RSAKeyParameters(false, rsaK.getModulus(), rsaK.getPublicExponent());
            }

            default:
                throw new PGPException("unknown public key algorithm encountered");
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("exception constructing public key", e);
        }
    }

    private AsymmetricKeyParameter getX448PublicKey(ECDHPublicBCPGKey ecdhK)
        throws IOException
    {
        return implGetPublicKeyX509(EdECObjectIdentifiers.id_X448, BigIntegers.asUnsignedByteArray(ecdhK.getEncodedPoint()), 0);
    }

    private AsymmetricKeyParameter getX25519PublicKey(ECDHPublicBCPGKey ecdhK)
        throws IOException
    {
        byte[] pEnc = BigIntegers.asUnsignedByteArray(ecdhK.getEncodedPoint());

        // skip the 0x40 header byte.
        if (pEnc.length < 1 || 0x40 != pEnc[0])
        {
            throw new IllegalArgumentException("Invalid Curve25519 public key");
        }

        return implGetPublicKeyX509(EdECObjectIdentifiers.id_X25519, pEnc, 1);
    }

    private AsymmetricKeyParameter implGetPublicKeyX509(ASN1ObjectIdentifier algorithm, byte[] pEnc, int pEncOff)
        throws IOException
    {
        return PublicKeyFactory.createKey(new SubjectPublicKeyInfo(new AlgorithmIdentifier(algorithm),
            Arrays.copyOfRange(pEnc, pEncOff, pEnc.length)));
    }

    private BCPGKey getPrivateBCPGKey(PGPPublicKey pubKey, AsymmetricKeyParameter privKey)
        throws PGPException
    {
        switch (pubKey.getAlgorithm())
        {
        case PublicKeyAlgorithmTags.DSA:
        {
            DSAPrivateKeyParameters dsK = (DSAPrivateKeyParameters)privKey;
            return new DSASecretBCPGKey(dsK.getX());
        }

        case PublicKeyAlgorithmTags.ECDH:
        {
            if (privKey instanceof ECPrivateKeyParameters)
            {
                ECPrivateKeyParameters ecK = (ECPrivateKeyParameters)privKey;
                return new ECSecretBCPGKey(ecK.getD());
            }
            else if (privKey instanceof X25519PrivateKeyParameters)
            {
                // 'reverse' because the native format for X25519 private keys is little-endian
                return getEdSecretBCPGKey(Arrays.reverseInPlace(((X25519PrivateKeyParameters)privKey).getEncoded()));
            }
            else if (privKey instanceof X448PrivateKeyParameters)
            {
                // 'reverse' because the native format for X448 private keys is little-endian
                return getEdSecretBCPGKey(Arrays.reverseInPlace(((X448PrivateKeyParameters)privKey).getEncoded()));
            }
        }
        case PublicKeyAlgorithmTags.X25519:
        {
            // 'reverse' because the native format for X25519 private keys is little-endian
            return getEdSecretBCPGKey(Arrays.reverseInPlace(((X25519PrivateKeyParameters)privKey).getEncoded()));
        }
        case PublicKeyAlgorithmTags.X448:
        {
            // 'reverse' because the native format for X448 private keys is little-endian
            return getEdSecretBCPGKey(Arrays.reverseInPlace(((X448PrivateKeyParameters)privKey).getEncoded()));
        }

        case PublicKeyAlgorithmTags.ECDSA:
        {
            ECPrivateKeyParameters ecK = (ECPrivateKeyParameters)privKey;
            return new ECSecretBCPGKey(ecK.getD());
        }

        case PublicKeyAlgorithmTags.EDDSA_LEGACY:
        {
            if (privKey instanceof Ed25519PrivateKeyParameters)
            {
                return getEdSecretBCPGKey(((Ed25519PrivateKeyParameters)privKey).getEncoded());
            }
            else
            {
                return getEdSecretBCPGKey(((Ed448PrivateKeyParameters)privKey).getEncoded());
            }
        }
        case PublicKeyAlgorithmTags.Ed25519:
        {
            return getEdSecretBCPGKey(((Ed25519PrivateKeyParameters)privKey).getEncoded());
        }
        case PublicKeyAlgorithmTags.Ed448:
        {
            return getEdSecretBCPGKey(((Ed448PrivateKeyParameters)privKey).getEncoded());
        }
        case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
        case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
        {
            ElGamalPrivateKeyParameters esK = (ElGamalPrivateKeyParameters)privKey;
            return new ElGamalSecretBCPGKey(esK.getX());
        }

        case PublicKeyAlgorithmTags.RSA_ENCRYPT:
        case PublicKeyAlgorithmTags.RSA_GENERAL:
        case PublicKeyAlgorithmTags.RSA_SIGN:
        {
            RSAPrivateCrtKeyParameters rsK = (RSAPrivateCrtKeyParameters)privKey;
            return new RSASecretBCPGKey(rsK.getExponent(), rsK.getP(), rsK.getQ());
        }

        default:
            throw new PGPException("unknown key class");
        }
    }

    private BCPGKey getEdSecretBCPGKey(byte[] x)
    {
        return new EdSecretBCPGKey(new BigInteger(1, x));
    }

    private BCPGKey getPublicBCPGKey(int algorithm, PGPAlgorithmParameters algorithmParameters,
                                     AsymmetricKeyParameter pubKey)
        throws PGPException
    {
        if (pubKey instanceof RSAKeyParameters)
        {
            RSAKeyParameters rK = (RSAKeyParameters)pubKey;
            return new RSAPublicBCPGKey(rK.getModulus(), rK.getExponent());
        }
        else if (pubKey instanceof DSAPublicKeyParameters)
        {
            DSAPublicKeyParameters dK = (DSAPublicKeyParameters)pubKey;
            DSAParameters dP = dK.getParameters();
            return new DSAPublicBCPGKey(dP.getP(), dP.getQ(), dP.getG(), dK.getY());
        }
        else if (pubKey instanceof ElGamalPublicKeyParameters)
        {
            ElGamalPublicKeyParameters eK = (ElGamalPublicKeyParameters)pubKey;
            ElGamalParameters eS = eK.getParameters();
            return new ElGamalPublicBCPGKey(eS.getP(), eS.getG(), eK.getY());
        }
        else if (pubKey instanceof ECPublicKeyParameters)
        {
            ECPublicKeyParameters ecK = (ECPublicKeyParameters)pubKey;

            // TODO Should we have a way to recognize named curves when the name is missing?
            ECNamedDomainParameters parameters = (ECNamedDomainParameters)ecK.getParameters();

            if (algorithm == PGPPublicKey.ECDH)
            {
                PGPKdfParameters kdfParams = implGetKdfParameters(algorithmParameters);

                return new ECDHPublicBCPGKey(parameters.getName(), ecK.getQ(), kdfParams.getHashAlgorithm(),
                    kdfParams.getSymmetricWrapAlgorithm());
            }
            else if (algorithm == PGPPublicKey.ECDSA)
            {
                return new ECDSAPublicBCPGKey(parameters.getName(), ecK.getQ());
            }
            else
            {
                throw new PGPException("unknown EC algorithm");
            }
        }
        else if (pubKey instanceof Ed25519PublicKeyParameters)
        {
            byte[] pointEnc = new byte[1 + Ed25519PublicKeyParameters.KEY_SIZE];
            pointEnc[0] = 0x40;
            ((Ed25519PublicKeyParameters)pubKey).encode(pointEnc, 1);
            return new EdDSAPublicBCPGKey(GNUObjectIdentifiers.Ed25519, new BigInteger(1, pointEnc));
        }
        else if (pubKey instanceof Ed448PublicKeyParameters)
        {
            byte[] pointEnc = new byte[Ed448PublicKeyParameters.KEY_SIZE];
            ((Ed448PublicKeyParameters)pubKey).encode(pointEnc, 0);
            return new EdDSAPublicBCPGKey(EdECObjectIdentifiers.id_Ed448, new BigInteger(1, pointEnc));
        }
        else if (pubKey instanceof X25519PublicKeyParameters)
        {
            byte[] pointEnc = new byte[1 + X25519PublicKeyParameters.KEY_SIZE];
            pointEnc[0] = 0x40;
            ((X25519PublicKeyParameters)pubKey).encode(pointEnc, 1);

            PGPKdfParameters kdfParams = implGetKdfParameters(algorithmParameters);

            return new ECDHPublicBCPGKey(CryptlibObjectIdentifiers.curvey25519, new BigInteger(1, pointEnc),
                kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
        }
        else if (pubKey instanceof X448PublicKeyParameters)
        {
            byte[] pointEnc = new byte[X448PublicKeyParameters.KEY_SIZE];
            ((X448PublicKeyParameters)pubKey).encode(pointEnc, 0);

            PGPKdfParameters kdfParams = implGetKdfParameters(algorithmParameters);

            return new ECDHPublicBCPGKey(EdECObjectIdentifiers.id_X448, new BigInteger(1, pointEnc),
                kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
        }
        else
        {
            throw new PGPException("unknown key class");
        }
    }

    private PGPKdfParameters implGetKdfParameters(PGPAlgorithmParameters algorithmParameters)
    {
        return null == algorithmParameters ? DEFAULT_KDF_PARAMETERS : (PGPKdfParameters)algorithmParameters;
    }

    private ECNamedDomainParameters implGetParametersEC(ECPublicBCPGKey ecPub)
    {
        ASN1ObjectIdentifier curveOID = ecPub.getCurveOID();
        X9ECParameters x9 = BcUtil.getX9Parameters(curveOID);
        return new ECNamedDomainParameters(curveOID, x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
    }

    private AsymmetricKeyParameter implGetPrivateKeyEC(ECPublicBCPGKey ecPub, ECSecretBCPGKey ecPriv)
        throws IOException, PGPException
    {
        ECNamedDomainParameters parameters = implGetParametersEC(ecPub);
        return new ECPrivateKeyParameters(ecPriv.getX(), parameters);
    }

    private AsymmetricKeyParameter implGetPrivateKeyPKCS8(ASN1ObjectIdentifier algorithm, BCPGKey privPk)
        throws IOException
    {
        return PrivateKeyFactory.createKey((new PrivateKeyInfo(
            new AlgorithmIdentifier(algorithm),
            new DEROctetString(Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(((ECSecretBCPGKey)privPk).getX()))))));
    }

    private AsymmetricKeyParameter implGetPrivateKeyPKCS8(ASN1ObjectIdentifier algorithm, int keySize, BCPGKey privPk)
        throws IOException
    {
        return PrivateKeyFactory.createKey((new PrivateKeyInfo(
            new AlgorithmIdentifier(algorithm),
            new DEROctetString(BigIntegers.asUnsignedByteArray(keySize, ((EdSecretBCPGKey)privPk).getX())))));
    }

    private AsymmetricKeyParameter implGetPublicKeyEC(ECPublicBCPGKey ecPub)
        throws IOException, PGPException
    {
        ECNamedDomainParameters parameters = implGetParametersEC(ecPub);
        ECPoint pubPoint = BcUtil.decodePoint(ecPub.getEncodedPoint(), parameters.getCurve());
        return new ECPublicKeyParameters(pubPoint, parameters);
    }
}
