package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
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
import org.bouncycastle.bcpg.Ed25519PublicBCPGKey;
import org.bouncycastle.bcpg.Ed25519SecretBCPGKey;
import org.bouncycastle.bcpg.Ed448PublicBCPGKey;
import org.bouncycastle.bcpg.Ed448SecretBCPGKey;
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.MLDSACompositePublicBCPGKey;
import org.bouncycastle.bcpg.MLDSACompositeSecretBCPGKey;
import org.bouncycastle.bcpg.MLKEMCompositePublicBCPGKey;
import org.bouncycastle.bcpg.MLKEMCompositeSecretBCPGKey;
import org.bouncycastle.bcpg.OctetArrayBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.SLHDSAPublicBCPGKey;
import org.bouncycastle.bcpg.SLHDSASecretBCPGKey;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.bcpg.X25519SecretBCPGKey;
import org.bouncycastle.bcpg.X448PublicBCPGKey;
import org.bouncycastle.bcpg.X448SecretBCPGKey;
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
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
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
import org.bouncycastle.openpgp.operator.PGPKeyConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class BcPGPKeyConverter
    extends PGPKeyConverter
{
    public PGPPrivateKey getPGPPrivateKey(PGPPublicKey pubKey, AsymmetricKeyParameter privKey)
        throws PGPException
    {
        BCPGKey privPk = getPrivateBCPGKey(pubKey, privKey);

        return new PGPPrivateKey(pubKey.getKeyID(), pubKey.getPublicKeyPacket(), privPk);
    }

    /**
     * Create a version 4 PGPPublicKey from the passed in JCA one.
     * <p>
     * Note: the time passed in affects the value of the key's keyID, so you probably only want
     * to do this once for a JCA key, or make sure you keep track of the time you used.
     * </p>
     *
     * @param algorithm asymmetric algorithm type representing the public key.
     * @param pubKey    actual public key to associate.
     * @param time      date of creation.
     * @throws PGPException on key creation problem.
     * @deprecated use versioned {@link #getPGPPublicKey(int, int, PGPAlgorithmParameters, AsymmetricKeyParameter, Date)} instead
     */
    @Deprecated
    @SuppressWarnings("InlineMeSuggester")
    public PGPPublicKey getPGPPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, AsymmetricKeyParameter pubKey, Date time)
        throws PGPException
    {
        return getPGPPublicKey(PublicKeyPacket.VERSION_4, algorithm, algorithmParameters, pubKey, time);
    }

    /**
     * Create a PGPPublicKey from the passed in JCA one.
     * <p>
     * Note: the time passed in affects the value of the key's keyID, so you probably only want
     * to do this once for a JCA key, or make sure you keep track of the time you used.
     * </p>
     *
     * @param version   key version.
     * @param algorithm asymmetric algorithm type representing the public key.
     * @param pubKey    actual public key to associate.
     * @param time      date of creation.
     * @throws PGPException on key creation problem.
     */
    public PGPPublicKey getPGPPublicKey(int version, int algorithm, PGPAlgorithmParameters algorithmParameters, AsymmetricKeyParameter pubKey, Date time)
        throws PGPException
    {
        BCPGKey bcpgKey = getPublicBCPGKey(algorithm, algorithmParameters, pubKey);

        return new PGPPublicKey(new PublicKeyPacket(version, algorithm, time, bcpgKey), new BcKeyFingerprintCalculator());
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

                // Legacy XDH on Curve25519 (legacy X25519)
                // 1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110
                if (BcUtil.isX25519(ecdhPub.getCurveOID()))
                {
                    return PrivateKeyFactory.createKey(getPrivateKeyInfo(EdECObjectIdentifiers.id_X25519,
                        Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(((ECSecretBCPGKey)privPk).getX()))));
                }
                // Legacy X448 (1.3.101.111)
                else if (EdECObjectIdentifiers.id_X448.equals(ecdhPub.getCurveOID()))
                {
                    return PrivateKeyFactory.createKey(getPrivateKeyInfo(EdECObjectIdentifiers.id_X448,
                            Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(((ECSecretBCPGKey)privPk).getX()))));
                }
                // NIST, Brainpool etc.
                else
                {
                    return implGetPrivateKeyEC(ecdhPub, (ECSecretBCPGKey)privPk);
                }
            }
            // Modern X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
            case PublicKeyAlgorithmTags.X25519:
            {
                return PrivateKeyFactory.createKey(getPrivateKeyInfo(EdECObjectIdentifiers.id_X25519, X25519SecretBCPGKey.LENGTH,
                    privPk.getEncoded()));
            }
            // Modern X448 (1.3.101.111)
            case PublicKeyAlgorithmTags.X448:
            {
                return PrivateKeyFactory.createKey(getPrivateKeyInfo(EdECObjectIdentifiers.id_X448, X448SecretBCPGKey.LENGTH,
                    privPk.getEncoded()));
            }
            case PublicKeyAlgorithmTags.ECDSA:
            {
                return implGetPrivateKeyEC((ECDSAPublicBCPGKey) pubPk.getKey(), (ECSecretBCPGKey) privPk);
            }
            // Legacy EdDSA (legacy Ed448, legacy Ed25519)
            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                // Legacy Ed448 (1.3.101.113)
                if (((EdDSAPublicBCPGKey)pubPk.getKey()).getCurveOID().equals(EdECObjectIdentifiers.id_Ed448))
                {
                    return implGetPrivateKeyPKCS8(EdECObjectIdentifiers.id_Ed448, Ed448.SECRET_KEY_SIZE, privPk);
                }
                // Legacy Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
                return implGetPrivateKeyPKCS8(EdECObjectIdentifiers.id_Ed25519, Ed25519.SECRET_KEY_SIZE, privPk);
            }
            // Modern Ed22519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
            case PublicKeyAlgorithmTags.Ed25519:
            {
                return PrivateKeyFactory.createKey(getPrivateKeyInfo(EdECObjectIdentifiers.id_Ed25519, Ed25519SecretBCPGKey.LENGTH, privPk.getEncoded()));
            }
            // Modern Ed448 (1.3.101.113)
            case PublicKeyAlgorithmTags.Ed448:
            {
                return PrivateKeyFactory.createKey(getPrivateKeyInfo(EdECObjectIdentifiers.id_Ed448, Ed448SecretBCPGKey.LENGTH, privPk.getEncoded()));
            }
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            {
                ElGamalPublicBCPGKey elPub = (ElGamalPublicBCPGKey)pubPk.getKey();
                ElGamalSecretBCPGKey elPriv = (ElGamalSecretBCPGKey)privPk;
                return new ElGamalPrivateKeyParameters(elPriv.getX(), new ElGamalParameters(elPub.getP(), elPub.getG()));
            }
            // RFC 9980 ML-DSA + EdDSA composites: EdDSA secret key || 32 octet ML-DSA seed
            case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            {
                MLDSACompositeSecretBCPGKey compPriv = (MLDSACompositeSecretBCPGKey)privPk;
                int algorithm = pubPk.getAlgorithm();
                AsymmetricKeyParameter eddsaPriv;
                if (algorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519)
                {
                    eddsaPriv = new Ed25519PrivateKeyParameters(compPriv.getEdDSASecretKey());
                }
                else
                {
                    eddsaPriv = new Ed448PrivateKeyParameters(compPriv.getEdDSASecretKey());
                }
                // the seed form expands the signing key with ML-DSA.KeyGen_internal (RFC 9980 sec. 5.3.2.2)
                MLDSAPrivateKeyParameters mldsaPriv = new MLDSAPrivateKeyParameters(getMLDSAParameters(algorithm), compPriv.getMLDSASeed());
                return new BcPGPCompositeKeyParameters(true, eddsaPriv, mldsaPriv);
            }
            // RFC 9980 SLH-DSA: SK.seed || SK.prf || PK.seed || PK.root
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            {
                return new SLHDSAPrivateKeyParameters(getSLHDSAParameters(pubPk.getAlgorithm()), ((SLHDSASecretBCPGKey)privPk).getKey());
            }
            // RFC 9980 ML-KEM + ECDH composites: ECDH secret key || 64 octet ML-KEM seed d || z
            case PublicKeyAlgorithmTags.MLKEM768_X25519:
            case PublicKeyAlgorithmTags.MLKEM1024_X448:
            {
                MLKEMCompositeSecretBCPGKey compPriv = (MLKEMCompositeSecretBCPGKey)privPk;
                int algorithm = pubPk.getAlgorithm();
                AsymmetricKeyParameter ecdhPriv;
                if (algorithm == PublicKeyAlgorithmTags.MLKEM768_X25519)
                {
                    ecdhPriv = new X25519PrivateKeyParameters(compPriv.getECDHSecretKey());
                }
                else
                {
                    ecdhPriv = new X448PrivateKeyParameters(compPriv.getECDHSecretKey());
                }
                // the seed form expands the decapsulation key with ML-KEM.KeyGen_internal (RFC 9980 sec. 4.3.2.2)
                MLKEMPrivateKeyParameters mlkemPriv = new MLKEMPrivateKeyParameters(getMLKEMParameters(algorithm), compPriv.getMLKEMSeed());
                return new BcPGPCompositeKeyParameters(true, ecdhPriv, mlkemPriv);
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
                throw new PGPException("unknown public key algorithm encountered: " + pubPk.getAlgorithm());
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

                // Legacy XDH on Curve25519 (legacy X25519)
                // 1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110
                if (BcUtil.isX25519(ecdhK.getCurveOID()))
                {
                    byte[] pEnc = BigIntegers.asUnsignedByteArray(ecdhK.getEncodedPoint());
                    // skip the 0x40 header byte.
                    if (pEnc.length < 1 || 0x40 != pEnc[0])
                    {
                        throw new IllegalArgumentException("Invalid Curve25519 public key");
                    }
                    return implGetPublicKeyX509(EdECObjectIdentifiers.id_X25519, pEnc, 1);
                }
                // Legacy X448 (1.3.101.111)
                else if (ecdhK.getCurveOID().equals(EdECObjectIdentifiers.id_X448))
                {
                    byte[] pEnc = BigIntegers.asUnsignedByteArray(ecdhK.getEncodedPoint());
                    // skip the 0x40 header byte.
                    if (pEnc.length < 1 || 0x40 != pEnc[0])
                    {
                        throw new IllegalArgumentException("Invalid X448 public key");
                    }
                    return implGetPublicKeyX509(EdECObjectIdentifiers.id_X448, pEnc, 1);
                }
                else
                {
                    return implGetPublicKeyEC(ecdhK);
                }
            }
            // Modern X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
            case PublicKeyAlgorithmTags.X25519:
            {
                return implGetPublicKeyX509((X25519PublicBCPGKey)publicPk.getKey(), EdECObjectIdentifiers.id_X25519);
            }
            // Modern X448 (1.3.101.111)
            case PublicKeyAlgorithmTags.X448:
            {
                return implGetPublicKeyX509((X448PublicBCPGKey)publicPk.getKey(), EdECObjectIdentifiers.id_X448);
            }
            case PublicKeyAlgorithmTags.ECDSA:
            {
                return implGetPublicKeyEC((ECDSAPublicBCPGKey)publicPk.getKey());
            }
            // Legacy EdDSA (legacy Ed448, legacy Ed25519)
            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                EdDSAPublicBCPGKey eddsaK = (EdDSAPublicBCPGKey)publicPk.getKey();

                byte[] pEnc = BigIntegers.asUnsignedByteArray(eddsaK.getEncodedPoint());

                if (pEnc.length < 1)
                {
                    throw new IllegalArgumentException("Invalid EdDSA public key");
                }

                // Legacy Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
                if (!eddsaK.getCurveOID().equals(EdECObjectIdentifiers.id_Ed448))
                {
                    return implGetPublicKeyX509(EdECObjectIdentifiers.id_Ed25519, pEnc, pEnc[0] == 0x40 ? 1 : 0);
                }
                // Legacy Ed448 (1.3.101.113)
                if (eddsaK.getCurveOID().equals(EdECObjectIdentifiers.id_Ed448))
                {
                    return implGetPublicKeyX509(EdECObjectIdentifiers.id_Ed448, pEnc, pEnc[0] == 0x40 ? 1 : 0);
                }

                throw new IllegalArgumentException("Invalid EdDSA public key");
            }
            // Modern Ed22519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
            case PublicKeyAlgorithmTags.Ed25519:
            {
                return implGetPublicKeyX509((Ed25519PublicBCPGKey)publicPk.getKey(), EdECObjectIdentifiers.id_Ed25519);
            }
            // Modern Ed448 (1.3.101.113)
            case PublicKeyAlgorithmTags.Ed448:
            {
                return implGetPublicKeyX509((Ed448PublicBCPGKey)publicPk.getKey(), EdECObjectIdentifiers.id_Ed448);
            }
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            {
                ElGamalPublicBCPGKey elK = (ElGamalPublicBCPGKey) publicPk.getKey();
                return new ElGamalPublicKeyParameters(elK.getY(), new ElGamalParameters(elK.getP(), elK.getG()));
            }
            // RFC 9980 ML-DSA + EdDSA composites
            case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            {
                MLDSACompositePublicBCPGKey compK = (MLDSACompositePublicBCPGKey)publicPk.getKey();
                int algorithm = publicPk.getAlgorithm();
                AsymmetricKeyParameter eddsaPub;
                if (algorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519)
                {
                    eddsaPub = new Ed25519PublicKeyParameters(compK.getEdDSAPublicKey());
                }
                else
                {
                    eddsaPub = new Ed448PublicKeyParameters(compK.getEdDSAPublicKey());
                }
                MLDSAPublicKeyParameters mldsaPub = new MLDSAPublicKeyParameters(getMLDSAParameters(algorithm), compK.getMLDSAPublicKey());
                return new BcPGPCompositeKeyParameters(false, eddsaPub, mldsaPub);
            }
            // RFC 9980 SLH-DSA
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            {
                return new SLHDSAPublicKeyParameters(getSLHDSAParameters(publicPk.getAlgorithm()), ((SLHDSAPublicBCPGKey)publicPk.getKey()).getKey());
            }
            // RFC 9980 ML-KEM + ECDH composites
            case PublicKeyAlgorithmTags.MLKEM768_X25519:
            case PublicKeyAlgorithmTags.MLKEM1024_X448:
            {
                MLKEMCompositePublicBCPGKey compK = (MLKEMCompositePublicBCPGKey)publicPk.getKey();
                int algorithm = publicPk.getAlgorithm();
                AsymmetricKeyParameter ecdhPub;
                if (algorithm == PublicKeyAlgorithmTags.MLKEM768_X25519)
                {
                    ecdhPub = new X25519PublicKeyParameters(compK.getECDHPublicKey());
                }
                else
                {
                    ecdhPub = new X448PublicKeyParameters(compK.getECDHPublicKey());
                }
                // the constructor applies the FIPS 203 sec. 7.2 modulus check to the encapsulation key
                MLKEMPublicKeyParameters mlkemPub = new MLKEMPublicKeyParameters(getMLKEMParameters(algorithm), compK.getMLKEMPublicKey());
                return new BcPGPCompositeKeyParameters(false, ecdhPub, mlkemPub);
            }

            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            {
                RSAPublicBCPGKey rsaK = (RSAPublicBCPGKey)publicPk.getKey();
                return new RSAKeyParameters(false, rsaK.getModulus(), rsaK.getPublicExponent());
            }

            default:
                throw new PGPException("unknown public key algorithm encountered: " + publicKey.getAlgorithm());
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
            // Legacy XDH on Curve25519 (legacy X25519)
            // 1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110
            if (privKey instanceof X25519PrivateKeyParameters)
            {
                return new ECSecretBCPGKey(new BigInteger(1, Arrays.reverseInPlace(((X25519PrivateKeyParameters)privKey).getEncoded())));
            }
            // Legacy X448 (1.3.101.111)
            else if (privKey instanceof X448PrivateKeyParameters)
            {
                return new ECSecretBCPGKey(new BigInteger(1, Arrays.reverseInPlace(((X448PrivateKeyParameters)privKey).getEncoded())));
            }
            // NIST, Brainpool etc.
            else
            {
                ECPrivateKeyParameters ecK = (ECPrivateKeyParameters)privKey;
                return new ECSecretBCPGKey(ecK.getD());
            }
        }
        // Modern X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
        case PublicKeyAlgorithmTags.X25519:
        {
            return new X25519SecretBCPGKey(((X25519PrivateKeyParameters)privKey).getEncoded());
        }
        // Modern X448 (1.3.101.111)
        case PublicKeyAlgorithmTags.X448:
        {
            return new X448SecretBCPGKey(((X448PrivateKeyParameters)privKey).getEncoded());
        }
        case PublicKeyAlgorithmTags.ECDSA:
        {
            ECPrivateKeyParameters ecK = (ECPrivateKeyParameters)privKey;
            return new ECSecretBCPGKey(ecK.getD());
        }
        // Legacy EdDSA
        case PublicKeyAlgorithmTags.EDDSA_LEGACY:
        {
            // Legacy Ed25519 (1.3.101.112 & 1.3.6.1.4.1.11591.15.1)
            if (privKey instanceof Ed25519PrivateKeyParameters)
            {
                return new EdSecretBCPGKey(new BigInteger(1, ((Ed25519PrivateKeyParameters)privKey).getEncoded()));
            }
            // Legacy Ed448 (1.3.101.113)
            else
            {
                return new EdSecretBCPGKey(new BigInteger(1, ((Ed448PrivateKeyParameters) privKey).getEncoded()));
            }
        }
        // Modern Ed22519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
        case PublicKeyAlgorithmTags.Ed25519:
        {
            return new Ed25519SecretBCPGKey(((Ed25519PrivateKeyParameters)privKey).getEncoded());
        }
        // Modern Ed448 (1.3.101.113)
        case PublicKeyAlgorithmTags.Ed448:
        {
            return new Ed448SecretBCPGKey(((Ed448PrivateKeyParameters)privKey).getEncoded());
        }
        case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
        case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
        {
            ElGamalPrivateKeyParameters esK = (ElGamalPrivateKeyParameters)privKey;
            return new ElGamalSecretBCPGKey(esK.getX());
        }
        // RFC 9980 ML-DSA + EdDSA composites
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
        {
            int algorithm = pubKey.getAlgorithm();
            BcPGPCompositeKeyParameters comp = getCompositeKey(algorithm, privKey);
            byte[] eddsaEnc;
            if (algorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519)
            {
                eddsaEnc = ((Ed25519PrivateKeyParameters)comp.getTraditionalKey()).getEncoded();
            }
            else
            {
                eddsaEnc = ((Ed448PrivateKeyParameters)comp.getTraditionalKey()).getEncoded();
            }
            MLDSAPrivateKeyParameters mldsaPriv = (MLDSAPrivateKeyParameters)comp.getPostQuantumKey();
            checkParameters(algorithm, getMLDSAParameters(algorithm), mldsaPriv.getParameters());
            byte[] seed = mldsaPriv.getSeed();
            if (seed == null)
            {
                throw new PGPException("ML-DSA private key carries no seed - RFC 9980 sec. 5.3.2.2 stores the secret key in seed format only");
            }
            return new MLDSACompositeSecretBCPGKey(algorithm, eddsaEnc, seed);
        }
        // RFC 9980 SLH-DSA
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
        {
            int algorithm = pubKey.getAlgorithm();
            SLHDSAPrivateKeyParameters slhPriv = (SLHDSAPrivateKeyParameters)privKey;
            checkParameters(algorithm, getSLHDSAParameters(algorithm), slhPriv.getParameters());
            return new SLHDSASecretBCPGKey(algorithm, slhPriv.getEncoded());
        }
        // RFC 9980 ML-KEM + ECDH composites
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
        {
            int algorithm = pubKey.getAlgorithm();
            BcPGPCompositeKeyParameters comp = getCompositeKey(algorithm, privKey);
            byte[] ecdhEnc;
            if (algorithm == PublicKeyAlgorithmTags.MLKEM768_X25519)
            {
                ecdhEnc = ((X25519PrivateKeyParameters)comp.getTraditionalKey()).getEncoded();
            }
            else
            {
                ecdhEnc = ((X448PrivateKeyParameters)comp.getTraditionalKey()).getEncoded();
            }
            MLKEMPrivateKeyParameters mlkemPriv = (MLKEMPrivateKeyParameters)comp.getPostQuantumKey();
            checkParameters(algorithm, getMLKEMParameters(algorithm), mlkemPriv.getParameters());
            byte[] seed = mlkemPriv.getSeed();
            if (seed == null)
            {
                throw new PGPException("ML-KEM private key carries no seed - RFC 9980 sec. 4.3.2.2 stores the secret key in seed format only");
            }
            return new MLKEMCompositeSecretBCPGKey(algorithm, ecdhEnc, seed);
        }
        case PublicKeyAlgorithmTags.RSA_ENCRYPT:
        case PublicKeyAlgorithmTags.RSA_GENERAL:
        case PublicKeyAlgorithmTags.RSA_SIGN:
        {
            RSAPrivateCrtKeyParameters rsK = (RSAPrivateCrtKeyParameters)privKey;
            return new RSASecretBCPGKey(rsK.getExponent(), rsK.getP(), rsK.getQ());
        }

        default:
            throw new PGPException("unknown public key algorithm encountered: " + pubKey.getAlgorithm());
        }
    }

    private BCPGKey getPublicBCPGKey(int algorithm, PGPAlgorithmParameters algorithmParameters, AsymmetricKeyParameter pubKey)
        throws PGPException
    {
        switch (algorithm)
        {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            {
                RSAKeyParameters rK = (RSAKeyParameters)pubKey;
                return new RSAPublicBCPGKey(rK.getModulus(), rK.getExponent());
            }
            case PublicKeyAlgorithmTags.DSA:
            {
                DSAPublicKeyParameters dK = (DSAPublicKeyParameters)pubKey;
                DSAParameters dP = dK.getParameters();
                return new DSAPublicBCPGKey(dP.getP(), dP.getQ(), dP.getG(), dK.getY());
            }
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            {
                ElGamalPublicKeyParameters eK = (ElGamalPublicKeyParameters)pubKey;
                ElGamalParameters eS = eK.getParameters();
                return new ElGamalPublicBCPGKey(eS.getP(), eS.getG(), eK.getY());
            }
            // NIST, Brainpool, Legacy X25519, Legacy X448
            case PublicKeyAlgorithmTags.ECDH:
            {
                // Legacy X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
                if (pubKey instanceof X25519PublicKeyParameters)
                {
                    byte[] pointEnc = new byte[1 + X25519PublicKeyParameters.KEY_SIZE];
                    pointEnc[0] = 0x40;
                    ((X25519PublicKeyParameters)pubKey).encode(pointEnc, 1);

                    PGPKdfParameters kdfParams = implGetKdfParameters(CryptlibObjectIdentifiers.curvey25519, algorithmParameters);

                    return new ECDHPublicBCPGKey(CryptlibObjectIdentifiers.curvey25519, new BigInteger(1, pointEnc),
                        kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
                }
                // Legacy X448 (1.3.101.111)
                if (pubKey instanceof X448PublicKeyParameters)
                {
                    byte[] pointEnc = new byte[1 + X448PublicKeyParameters.KEY_SIZE];
                    pointEnc[0] = 0x40;
                    ((X448PublicKeyParameters)pubKey).encode(pointEnc, 1);

                    PGPKdfParameters kdfParams = implGetKdfParameters(EdECObjectIdentifiers.id_X448, algorithmParameters);

                    return new ECDHPublicBCPGKey(EdECObjectIdentifiers.id_X448, new BigInteger(1, pointEnc),
                        kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
                }
                // NIST, Brainpool etc.
                ECPublicKeyParameters ecK = (ECPublicKeyParameters)pubKey;
                ECNamedDomainParameters parameters = (ECNamedDomainParameters)ecK.getParameters();
                PGPKdfParameters kdfParams = implGetKdfParameters(parameters.getName(), algorithmParameters);

                return new ECDHPublicBCPGKey(parameters.getName(), ecK.getQ(), kdfParams.getHashAlgorithm(),
                        kdfParams.getSymmetricWrapAlgorithm());
            }
            case PublicKeyAlgorithmTags.ECDSA:
            {
                ECPublicKeyParameters ecK = (ECPublicKeyParameters)pubKey;
                ECNamedDomainParameters parameters = (ECNamedDomainParameters)ecK.getParameters();
                return new ECDSAPublicBCPGKey(parameters.getName(), ecK.getQ());
            }
            // Legacy Ed255519, Legacy Ed448
            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                // Legacy Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
                if (pubKey instanceof Ed25519PublicKeyParameters)
                {
                    byte[] pointEnc = new byte[1 + Ed25519PublicKeyParameters.KEY_SIZE];
                    pointEnc[0] = 0x40;
                    ((Ed25519PublicKeyParameters)pubKey).encode(pointEnc, 1);
                    return new EdDSAPublicBCPGKey(GNUObjectIdentifiers.Ed25519, new BigInteger(1, pointEnc));
                }
                // Legacy Ed448 (1.3.101.113)
                else if (pubKey instanceof Ed448PublicKeyParameters)
                {
                    byte[] pointEnc = new byte[1 + Ed448PublicKeyParameters.KEY_SIZE];
                    pointEnc[0] = 0x40;
                    ((Ed448PublicKeyParameters)pubKey).encode(pointEnc, 1);
                    return new EdDSAPublicBCPGKey(EdECObjectIdentifiers.id_Ed448, new BigInteger(1, pointEnc));
                }
                else
                {
                    throw new PGPException("Unknown LegacyEdDSA key type: " + pubKey.getClass().getName());
                }
            }
            // Modern Ed22519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
            case PublicKeyAlgorithmTags.Ed25519:
            {
                byte[] pointEnc = new byte[Ed25519PublicKeyParameters.KEY_SIZE];
                ((Ed25519PublicKeyParameters)pubKey).encode(pointEnc, 0);
                return new Ed25519PublicBCPGKey(pointEnc);
            }
            // Modern Ed448 (1.3.101.113)
            case PublicKeyAlgorithmTags.Ed448:
            {
                byte[] pointEnc = new byte[Ed448PublicKeyParameters.KEY_SIZE];
                ((Ed448PublicKeyParameters)pubKey).encode(pointEnc, 0);
                return new Ed448PublicBCPGKey(pointEnc);
            }
            // Modern X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
            case PublicKeyAlgorithmTags.X25519:
            {
                byte[] pointEnc = new byte[X25519PublicKeyParameters.KEY_SIZE];
                ((X25519PublicKeyParameters)pubKey).encode(pointEnc, 0);
                return new X25519PublicBCPGKey(pointEnc);
            }
            // Modern X448 (1.3.101.111)
            case PublicKeyAlgorithmTags.X448:
            {
                byte[] pointEnc = new byte[X448PublicKeyParameters.KEY_SIZE];
                ((X448PublicKeyParameters)pubKey).encode(pointEnc, 0);
                return new X448PublicBCPGKey(pointEnc);
            }
            // RFC 9980 ML-DSA + EdDSA composites
            case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            {
                BcPGPCompositeKeyParameters comp = getCompositeKey(algorithm, pubKey);
                byte[] eddsaEnc;
                if (algorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519)
                {
                    eddsaEnc = ((Ed25519PublicKeyParameters)comp.getTraditionalKey()).getEncoded();
                }
                else
                {
                    eddsaEnc = ((Ed448PublicKeyParameters)comp.getTraditionalKey()).getEncoded();
                }
                MLDSAPublicKeyParameters mldsaPub = (MLDSAPublicKeyParameters)comp.getPostQuantumKey();
                checkParameters(algorithm, getMLDSAParameters(algorithm), mldsaPub.getParameters());
                return new MLDSACompositePublicBCPGKey(algorithm, eddsaEnc, mldsaPub.getEncoded());
            }
            // RFC 9980 SLH-DSA
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            {
                SLHDSAPublicKeyParameters slhPub = (SLHDSAPublicKeyParameters)pubKey;
                checkParameters(algorithm, getSLHDSAParameters(algorithm), slhPub.getParameters());
                return new SLHDSAPublicBCPGKey(algorithm, slhPub.getEncoded());
            }
            // RFC 9980 ML-KEM + ECDH composites
            case PublicKeyAlgorithmTags.MLKEM768_X25519:
            case PublicKeyAlgorithmTags.MLKEM1024_X448:
            {
                BcPGPCompositeKeyParameters comp = getCompositeKey(algorithm, pubKey);
                byte[] ecdhEnc;
                if (algorithm == PublicKeyAlgorithmTags.MLKEM768_X25519)
                {
                    ecdhEnc = ((X25519PublicKeyParameters)comp.getTraditionalKey()).getEncoded();
                }
                else
                {
                    ecdhEnc = ((X448PublicKeyParameters)comp.getTraditionalKey()).getEncoded();
                }
                MLKEMPublicKeyParameters mlkemPub = (MLKEMPublicKeyParameters)comp.getPostQuantumKey();
                checkParameters(algorithm, getMLKEMParameters(algorithm), mlkemPub.getParameters());
                return new MLKEMCompositePublicBCPGKey(algorithm, ecdhEnc, mlkemPub.getEncoded());
            }

            default:
            {
                throw new PGPException("unknown public key algorithm encountered: " + algorithm);
            }
        }
    }

    private AsymmetricKeyParameter implGetPublicKeyX509(OctetArrayBCPGKey eddsaK, ASN1ObjectIdentifier algorithm)
        throws IOException
    {
        byte[] pEnc = Arrays.clone(eddsaK.getKey());
        return PublicKeyFactory.createKey(new SubjectPublicKeyInfo(new AlgorithmIdentifier(algorithm),
            Arrays.copyOfRange(pEnc, 0, pEnc.length)));
    }

    private AsymmetricKeyParameter implGetPublicKeyX509(ASN1ObjectIdentifier algorithm, byte[] pEnc, int pEncOff)
        throws IOException
    {
        return PublicKeyFactory.createKey(new SubjectPublicKeyInfo(new AlgorithmIdentifier(algorithm),
            Arrays.copyOfRange(pEnc, pEncOff, pEnc.length)));
    }

    private ECNamedDomainParameters implGetParametersEC(ECPublicBCPGKey ecPub)
    {
        ASN1ObjectIdentifier curveOID = ecPub.getCurveOID();
        X9ECParameters x9 = BcUtil.getX9Parameters(curveOID);
        return new ECNamedDomainParameters(curveOID, x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
    }

    private AsymmetricKeyParameter implGetPrivateKeyEC(ECPublicBCPGKey ecPub, ECSecretBCPGKey ecPriv)
        throws PGPException
    {
        ECNamedDomainParameters parameters = implGetParametersEC(ecPub);
        return new ECPrivateKeyParameters(ecPriv.getX(), parameters);
    }

    private AsymmetricKeyParameter implGetPrivateKeyPKCS8(ASN1ObjectIdentifier algorithm, int keySize, BCPGKey privPk)
        throws IOException
    {
        return PrivateKeyFactory.createKey(getPrivateKeyInfo(algorithm, BigIntegers.asUnsignedByteArray(keySize, ((EdSecretBCPGKey)privPk).getX())));
    }

    private AsymmetricKeyParameter implGetPublicKeyEC(ECPublicBCPGKey ecPub)
        throws PGPException
    {
        ECNamedDomainParameters parameters = implGetParametersEC(ecPub);
        ECPoint pubPoint = BcUtil.decodePoint(ecPub.getEncodedPoint(), parameters.getCurve());
        return new ECPublicKeyParameters(pubPoint, parameters);
    }

    private static BcPGPCompositeKeyParameters getCompositeKey(int algorithm, AsymmetricKeyParameter key)
        throws PGPException
    {
        if (!(key instanceof BcPGPCompositeKeyParameters))
        {
            throw new PGPException("public key algorithm " + algorithm + " requires a BcPGPCompositeKeyParameters, got "
                + key.getClass().getName());
        }
        return (BcPGPCompositeKeyParameters)key;
    }

    private static void checkParameters(int algorithm, Object expected, Object actual)
        throws PGPException
    {
        if (expected != actual)
        {
            throw new PGPException("component key parameters " + actual + " do not match public key algorithm " + algorithm);
        }
    }

    /**
     * Return the ML-DSA parameter set of an RFC 9980 ML-DSA + EdDSA composite algorithm.
     *
     * @param algorithm {@link PublicKeyAlgorithmTags#MLDSA65_Ed25519} or {@link PublicKeyAlgorithmTags#MLDSA87_Ed448}
     * @return ML-DSA-65 or ML-DSA-87
     */
    public static MLDSAParameters getMLDSAParameters(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            return MLDSAParameters.ml_dsa_65;
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            return MLDSAParameters.ml_dsa_87;
        default:
            throw new IllegalArgumentException("not an ML-DSA composite algorithm: " + algorithm);
        }
    }

    /**
     * Return the SLH-DSA parameter set of an RFC 9980 SLH-DSA algorithm.
     *
     * @param algorithm one of the SLH-DSA code points
     * @return SLH-DSA-SHAKE-128s, -128f or -256s
     */
    public static SLHDSAParameters getSLHDSAParameters(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
            return SLHDSAParameters.shake_128s;
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
            return SLHDSAParameters.shake_128f;
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            return SLHDSAParameters.shake_256s;
        default:
            throw new IllegalArgumentException("not an SLH-DSA algorithm: " + algorithm);
        }
    }

    /**
     * Return the ML-KEM parameter set of an RFC 9980 ML-KEM + ECDH composite algorithm.
     *
     * @param algorithm {@link PublicKeyAlgorithmTags#MLKEM768_X25519} or {@link PublicKeyAlgorithmTags#MLKEM1024_X448}
     * @return ML-KEM-768 or ML-KEM-1024
     */
    public static MLKEMParameters getMLKEMParameters(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
            return MLKEMParameters.ml_kem_768;
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
            return MLKEMParameters.ml_kem_1024;
        default:
            throw new IllegalArgumentException("not an ML-KEM composite algorithm: " + algorithm);
        }
    }
}
