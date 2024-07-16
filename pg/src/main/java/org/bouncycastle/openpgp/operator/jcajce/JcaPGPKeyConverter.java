package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
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
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.bcpg.X25519SecretBCPGKey;
import org.bouncycastle.bcpg.X448PublicBCPGKey;
import org.bouncycastle.bcpg.X448SecretBCPGKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.openpgp.PGPAlgorithmParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKdfParameters;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPKeyConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class JcaPGPKeyConverter
    extends PGPKeyConverter
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private KeyFingerPrintCalculator fingerPrintCalculator = new JcaKeyFingerprintCalculator();

    public JcaPGPKeyConverter setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcaPGPKeyConverter setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    /**
     * Convert a PrivateKey into a PGPPrivateKey.
     *
     * @param pub     the corresponding PGPPublicKey to privKey.
     * @param privKey the private key for the key in pub.
     * @return a PGPPrivateKey
     * @throws PGPException
     */
    public PGPPrivateKey getPGPPrivateKey(PGPPublicKey pub, PrivateKey privKey)
        throws PGPException
    {
        BCPGKey privPk = getPrivateBCPGKey(pub, privKey);

        return new PGPPrivateKey(pub.getKeyID(), pub.getPublicKeyPacket(), privPk);
    }

    /**
     * Create a PGPPublicKey from the passed in JCA one.
     * <p>
     * Note: the time passed in affects the value of the key's keyID, so you probably only want
     * to do this once for a JCA key, or make sure you keep track of the time you used.
     * </p>
     *
     * @param algorithm           asymmetric algorithm type representing the public key.
     * @param algorithmParameters additional parameters to be stored against the public key.
     * @param pubKey              actual public key to associate.
     * @param time                date of creation.
     * @throws PGPException on key creation problem.
     */
    public PGPPublicKey getPGPPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey, Date time)
        throws PGPException
    {
        BCPGKey bcpgKey = getPublicBCPGKey(algorithm, algorithmParameters, pubKey);

        return new PGPPublicKey(new PublicKeyPacket(algorithm, time, bcpgKey), fingerPrintCalculator);
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
    public PGPPublicKey getPGPPublicKey(int algorithm, PublicKey pubKey, Date time)
        throws PGPException
    {
        return getPGPPublicKey(algorithm, null, pubKey, time);
    }

    public PrivateKey getPrivateKey(PGPPrivateKey privKey)
        throws PGPException
    {
        if (privKey instanceof JcaPGPPrivateKey)
        {
            return ((JcaPGPPrivateKey)privKey).getPrivateKey();
        }

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
                DSAPrivateKeySpec dsaPrivSpec = new DSAPrivateKeySpec(dsaPriv.getX(), dsaPub.getP(), dsaPub.getQ(),
                    dsaPub.getG());
                return implGeneratePrivate("DSA", dsaPrivSpec);
            }

            case PublicKeyAlgorithmTags.ECDH:
            {
                ECDHPublicBCPGKey ecdhPub = (ECDHPublicBCPGKey)pubPk.getKey();
                ECSecretBCPGKey ecdhK = (ECSecretBCPGKey)privPk;

                // Legacy XDH on Curve25519 (legacy X25519)
                // 1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110
                if (CryptlibObjectIdentifiers.curvey25519.equals(ecdhPub.getCurveOID()) ||
                        EdECObjectIdentifiers.id_X25519.equals(ecdhPub.getCurveOID()))
                {
                    // 'reverse' because the native format for X25519 private keys is little-endian
                    return implGeneratePrivate("XDH", () -> getPrivateKeyInfo(EdECObjectIdentifiers.id_X25519,
                        Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(((ECSecretBCPGKey)privPk).getX()))));
                }
                // Legacy X448 (1.3.101.111)
                else if (EdECObjectIdentifiers.id_X448.equals(ecdhPub.getCurveOID()))
                {
                    // 'reverse' because the native format for X448 private keys is little-endian (?)
                    return implGeneratePrivate("XDH", () -> getPrivateKeyInfo(EdECObjectIdentifiers.id_X448,
                            Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(((ECSecretBCPGKey)privPk).getX()))));
                }
                // Brainpool, NIST etc.
                else
                {
                    return implGetPrivateKeyEC("ECDH", ecdhPub, ecdhK);
                }
            }
            // Modern X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
            case PublicKeyAlgorithmTags.X25519:
            {
                return implGeneratePrivate("XDH", () -> getPrivateKeyInfo(EdECObjectIdentifiers.id_X25519,
                    X25519SecretBCPGKey.LENGTH, privPk.getEncoded()));
            }
            // Modern X448 (1.3.101.111)
            case PublicKeyAlgorithmTags.X448:
            {
                return implGeneratePrivate("XDH", () -> getPrivateKeyInfo(EdECObjectIdentifiers.id_X448,
                    X448SecretBCPGKey.LENGTH, privPk.getEncoded()));
            }
            case PublicKeyAlgorithmTags.ECDSA:
            {
                return implGetPrivateKeyEC("EC", (ECDSAPublicBCPGKey)pubPk.getKey(), (ECSecretBCPGKey)privPk);
            }
            // Legacy EdDSA (legacy Ed448, legacy Ed25519)
            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                EdDSAPublicBCPGKey eddsaPub = (EdDSAPublicBCPGKey) pubPk.getKey();
                // Legacy Ed448 (1.3.101.113)
                if (EdECObjectIdentifiers.id_Ed448.equals(eddsaPub.getCurveOID()))
                {
                    return implGeneratePrivate("EdDSA", () -> getPrivateKeyInfo(EdECObjectIdentifiers.id_Ed448,
                            BigIntegers.asUnsignedByteArray(Ed448.SECRET_KEY_SIZE, ((EdSecretBCPGKey)privPk).getX())));
                }
                // Legacy Ed25519
                // 1.3.6.1.4.1.11591.15.1 & 1.3.101.112
                return implGeneratePrivate("EdDSA", () -> getPrivateKeyInfo(EdECObjectIdentifiers.id_Ed25519,
                    BigIntegers.asUnsignedByteArray(Ed25519.SECRET_KEY_SIZE, ((EdSecretBCPGKey)privPk).getX())));
            }
            // Modern Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
            case PublicKeyAlgorithmTags.Ed25519:
            {
                return implGeneratePrivate("EdDSA", () -> getPrivateKeyInfo(EdECObjectIdentifiers.id_Ed25519,
                    Ed25519SecretBCPGKey.LENGTH, privPk.getEncoded()));
            }
            // Modern Ed448 (1.3.101.113)
            case PublicKeyAlgorithmTags.Ed448:
            {
                return implGeneratePrivate("EdDSA", () -> getPrivateKeyInfo(EdECObjectIdentifiers.id_Ed448,
                    Ed448SecretBCPGKey.LENGTH, privPk.getEncoded()));
            }
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            {
                ElGamalPublicBCPGKey elPub = (ElGamalPublicBCPGKey)pubPk.getKey();
                ElGamalSecretBCPGKey elPriv = (ElGamalSecretBCPGKey)privPk;
                DHPrivateKeySpec elSpec = new DHPrivateKeySpec(elPriv.getX(), elPub.getP(), elPub.getG());
                return implGeneratePrivate("ElGamal", elSpec);
            }

            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            {
                RSAPublicBCPGKey rsaPub = (RSAPublicBCPGKey)pubPk.getKey();
                RSASecretBCPGKey rsaPriv = (RSASecretBCPGKey)privPk;
                RSAPrivateCrtKeySpec rsaPrivSpec = new RSAPrivateCrtKeySpec(rsaPriv.getModulus(),
                    rsaPub.getPublicExponent(), rsaPriv.getPrivateExponent(), rsaPriv.getPrimeP(), rsaPriv.getPrimeQ(),
                    rsaPriv.getPrimeExponentP(), rsaPriv.getPrimeExponentQ(), rsaPriv.getCrtCoefficient());
                return implGeneratePrivate("RSA", rsaPrivSpec);
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

    public PublicKey getPublicKey(PGPPublicKey publicKey)
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
                DSAPublicKeySpec dsaSpec = new DSAPublicKeySpec(dsaK.getY(), dsaK.getP(), dsaK.getQ(), dsaK.getG());
                return implGeneratePublic("DSA", dsaSpec);
            }

            case PublicKeyAlgorithmTags.ECDH:
            {
                ECDHPublicBCPGKey ecdhK = (ECDHPublicBCPGKey)publicPk.getKey();

                // Legacy XDH on Curve25519 (legacy X25519)
                // 1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110
                if (ecdhK.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    return get25519PublicKey(ecdhK.getEncodedPoint(), EdECObjectIdentifiers.id_X25519, "XDH", "Curve");
                }
                // Legacy X448 (1.3.101.111)
                else if (ecdhK.getCurveOID().equals(EdECObjectIdentifiers.id_X448))
                {
                    return get448PublicKey(ecdhK.getEncodedPoint(), EdECObjectIdentifiers.id_X448, "XDH", "Curve");
                }
                // Brainpool, NIST etc.
                else
                {
                    return implGetPublicKeyEC("ECDH", ecdhK);
                }
            }
            // Modern X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
            case PublicKeyAlgorithmTags.X25519:
            {
                return implGetPublicKeyX509(publicPk.getKey().getEncoded(), 0, EdECObjectIdentifiers.id_X25519, "XDH");
            }
            // Modern X448 (1.3.101.111)
            case PublicKeyAlgorithmTags.X448:
            {
                return implGetPublicKeyX509(publicPk.getKey().getEncoded(), 0, EdECObjectIdentifiers.id_X448, "XDH");
            }
            case PublicKeyAlgorithmTags.ECDSA:
            {
                return implGetPublicKeyEC("EC", (ECDSAPublicBCPGKey) publicPk.getKey());
            }
            // Legacy EdDSA (legacy Ed448, legacy Ed25519)
            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                EdDSAPublicBCPGKey eddsaKey = (EdDSAPublicBCPGKey) publicPk.getKey();
                // Legacy Ed448 (1.3.101.113)
                if (EdECObjectIdentifiers.id_Ed448.equals(eddsaKey.getCurveOID()))
                {
                    return get448PublicKey(eddsaKey.getEncodedPoint(), EdECObjectIdentifiers.id_Ed448, "EdDSA", "Ed");
                }
                // Legacy Ed25519
                // 1.3.6.1.4.1.11591.15.1 & 1.3.101.112
                else
                {
                    return get25519PublicKey(eddsaKey.getEncodedPoint(), EdECObjectIdentifiers.id_Ed25519, "EdDSA", "Ed");
                }
            }
            // Modern Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
            case PublicKeyAlgorithmTags.Ed25519:
            {
                return implGetPublicKeyX509(publicPk.getKey().getEncoded(),
                        0, EdECObjectIdentifiers.id_Ed25519, "EdDSA");
            }
            // Modern Ed448 (1.3.101.113)
            case PublicKeyAlgorithmTags.Ed448:
            {
                return implGetPublicKeyX509(publicPk.getKey().getEncoded(),
                    0, EdECObjectIdentifiers.id_Ed448, "EdDSA");
            }
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            {
                ElGamalPublicBCPGKey elK = (ElGamalPublicBCPGKey)publicPk.getKey();
                DHPublicKeySpec elSpec = new DHPublicKeySpec(elK.getY(), elK.getP(), elK.getG());
                return implGeneratePublic("ElGamal", elSpec);
            }

            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            {
                RSAPublicBCPGKey rsaK = (RSAPublicBCPGKey)publicPk.getKey();
                RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsaK.getModulus(), rsaK.getPublicExponent());
                return implGeneratePublic("RSA", rsaSpec);
            }

            default:
                throw new PGPException("unknown public key algorithm encountered: " + publicPk.getAlgorithm());
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

    private ECParameterSpec getECParameterSpec(ASN1ObjectIdentifier curveOid)
        throws IOException, GeneralSecurityException
    {
        AlgorithmParameters params = helper.createAlgorithmParameters("EC");

        params.init(new X962Parameters(curveOid).getEncoded());

        return params.getParameterSpec(ECParameterSpec.class);
    }

    private BCPGKey getPrivateBCPGKey(PrivateKey privKey, BCPGKeyOperation operation)
        throws PGPException
    {
        PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());

        try
        {
            return operation.getBCPGKey(ASN1OctetString.getInstance(pInfo.parsePrivateKey()).getOctets());
        }
        catch (IOException e)
        {
            throw new PGPException(e.getMessage(), e);
        }
    }

    private BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
        throws PGPException
    {
        switch (pub.getAlgorithm())
        {
        case PublicKeyAlgorithmTags.DSA:
        {
            DSAPrivateKey dsK = (DSAPrivateKey)privKey;
            return new DSASecretBCPGKey(dsK.getX());
        }

        case PublicKeyAlgorithmTags.ECDH:
        {
            if (privKey instanceof ECPrivateKey)
            {
                ECPrivateKey ecK = (ECPrivateKey)privKey;
                return new ECSecretBCPGKey(ecK.getS());
            }
            else
            {
                // 'reverse' because the native format for X25519,X448 private keys is little-endian
                return getPrivateBCPGKey(privKey, (pInfoEncoded) -> new ECSecretBCPGKey(new BigInteger(1, Arrays.reverse(pInfoEncoded))));
            }
        }
        // Modern X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
        case PublicKeyAlgorithmTags.X25519:
        {
            return getPrivateBCPGKey(privKey, (pInfoEncoded) -> new X25519SecretBCPGKey(pInfoEncoded));
        }
        // Modern X448 (1.3.101.111)
        case PublicKeyAlgorithmTags.X448:
        {
            return getPrivateBCPGKey(privKey, (pInfoEncoded) -> new X448SecretBCPGKey(pInfoEncoded));
        }
        case PublicKeyAlgorithmTags.ECDSA:
        {
            return new ECSecretBCPGKey(((ECPrivateKey)privKey).getS());
        }
        // Legacy EdDSA (legacy Ed448, legacy Ed25519)
        case PublicKeyAlgorithmTags.EDDSA_LEGACY:
        {
            return getPrivateBCPGKey(privKey, (pInfoEncoded) -> new EdSecretBCPGKey(new BigInteger(1, pInfoEncoded)));
        }
        // Modern Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
        case PublicKeyAlgorithmTags.Ed25519:
        {
            return getPrivateBCPGKey(privKey, Ed25519SecretBCPGKey::new);
        }
        // Modern Ed448 (1.3.101.113)
        case PublicKeyAlgorithmTags.Ed448:
        {
            return getPrivateBCPGKey(privKey, Ed448SecretBCPGKey::new);
        }
        case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
        case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
        {
            DHPrivateKey esK = (DHPrivateKey)privKey;
            return new ElGamalSecretBCPGKey(esK.getX());
        }
        case PublicKeyAlgorithmTags.RSA_ENCRYPT:
        case PublicKeyAlgorithmTags.RSA_GENERAL:
        case PublicKeyAlgorithmTags.RSA_SIGN:
        {
            RSAPrivateCrtKey rsK = (RSAPrivateCrtKey)privKey;
            return new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
        }
        default:
            throw new PGPException("unknown public key algorithm encountered: " + pub.getAlgorithm());
        }
    }

    private BCPGKey getPublicBCPGKey(int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey)
        throws PGPException
    {
        switch (algorithm)
        {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            {
                RSAPublicKey rK = (RSAPublicKey) pubKey;
                return new RSAPublicBCPGKey(rK.getModulus(), rK.getPublicExponent());
            }
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            {
                ElGamalPublicKey egK = (ElGamalPublicKey) pubKey;
                return new ElGamalPublicBCPGKey(egK.getParameters().getP(), egK.getParameters().getG(), egK.getY());
            }
            case PublicKeyAlgorithmTags.DSA:
            {
                DSAPublicKey dK = (DSAPublicKey) pubKey;
                DSAParams dP = dK.getParams();
                return new DSAPublicBCPGKey(dP.getP(), dP.getQ(), dP.getG(), dK.getY());
            }

            case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
            {
                DHPublicKey eK = (DHPublicKey) pubKey;
                DHParameterSpec eS = eK.getParams();
                return new ElGamalPublicBCPGKey(eS.getP(), eS.getG(), eK.getY());
            }

            case PublicKeyAlgorithmTags.ECDH:
            case PublicKeyAlgorithmTags.ECDSA:
            {
                SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());

                // TODO: should probably match curve by comparison as well
                ASN1Encodable enc = keyInfo.getAlgorithm().getAlgorithm();
                ASN1ObjectIdentifier curveOid;
                curveOid = ASN1ObjectIdentifier.getInstance(enc);

                // BCECPublicKey uses explicit parameter encoding, so we need to find the named curve manually
                if (X9ObjectIdentifiers.id_ecPublicKey.equals(curveOid))
                {
                    enc = getNamedCurveOID(X962Parameters.getInstance(keyInfo.getAlgorithm().getParameters()));
                    ASN1ObjectIdentifier nCurveOid = ASN1ObjectIdentifier.getInstance(enc);
                    if (nCurveOid != null)
                    {
                        curveOid = nCurveOid;
                    }
                }

                // Legacy XDH on Curve25519 (legacy X25519)
                // 1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110
                if (pubKey.getAlgorithm().regionMatches(true, 0, "X2", 0, 2))
                {
                    PGPKdfParameters kdfParams = implGetKdfParameters(CryptlibObjectIdentifiers.curvey25519, algorithmParameters);

                    return new ECDHPublicBCPGKey(CryptlibObjectIdentifiers.curvey25519, new BigInteger(1, getPointEncUncompressed(pubKey, X25519.SCALAR_SIZE)),
                                kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
                }
                // Legacy X448 (1.3.101.111)
                if (pubKey.getAlgorithm().regionMatches(true, 0, "X4", 0, 2))
                {

                    PGPKdfParameters kdfParams = implGetKdfParameters(EdECObjectIdentifiers.id_X448, algorithmParameters);

                    return new ECDHPublicBCPGKey(EdECObjectIdentifiers.id_X448, new BigInteger(1, getPointEncUncompressed(pubKey, X448.SCALAR_SIZE)),
                                kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
                }
                // sun.security.ec.XDHPublicKeyImpl returns "XDH" for getAlgorithm()
                // In this case we need to determine the curve by looking at the length of the encoding :/
                else if (pubKey.getAlgorithm().regionMatches(true, 0, "XDH", 0, 3))
                {
                    // Legacy X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
                    if (X25519.SCALAR_SIZE + 12 == pubKey.getEncoded().length) // + 12 for some reason
                    {
                        PGPKdfParameters kdfParams = implGetKdfParameters(CryptlibObjectIdentifiers.curvey25519, algorithmParameters);

                        return new ECDHPublicBCPGKey(CryptlibObjectIdentifiers.curvey25519, new BigInteger(1, getPointEncUncompressed(pubKey, X25519.SCALAR_SIZE)),
                                    kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
                    }
                    // Legacy X448 (1.3.101.111)
                    else
                    {
                        PGPKdfParameters kdfParams = implGetKdfParameters(EdECObjectIdentifiers.id_X448, algorithmParameters);

                        return new ECDHPublicBCPGKey(EdECObjectIdentifiers.id_X448, new BigInteger(1, getPointEncUncompressed(pubKey, X448.SCALAR_SIZE)),
                                    kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
                    }
                }

                X9ECParametersHolder params = ECNamedCurveTable.getByOIDLazy(curveOid);

                ASN1OctetString key = new DEROctetString(keyInfo.getPublicKeyData().getBytes());
                X9ECPoint derQ = new X9ECPoint(params.getCurve(), key);

                if (algorithm == PGPPublicKey.ECDH)
                {

                    PGPKdfParameters kdfParams = implGetKdfParameters(curveOid, algorithmParameters);

                    return new ECDHPublicBCPGKey(curveOid, derQ.getPoint(), kdfParams.getHashAlgorithm(),
                            kdfParams.getSymmetricWrapAlgorithm());
                }
                else
                {
                    return new ECDSAPublicBCPGKey(curveOid, derQ.getPoint());
                }
            }

            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                // Legacy Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
                if (pubKey.getAlgorithm().regionMatches(true, 0, "ED2", 0, 3))
                {
                    return new EdDSAPublicBCPGKey(GNUObjectIdentifiers.Ed25519, new BigInteger(1, getPointEncUncompressed(pubKey, Ed25519.PUBLIC_KEY_SIZE)));
                }
                // Legacy Ed448 (1.3.101.113)
                if (pubKey.getAlgorithm().regionMatches(true, 0, "ED4", 0, 3))
                {
                    return new EdDSAPublicBCPGKey(EdECObjectIdentifiers.id_Ed448, new BigInteger(1, getPointEncUncompressed(pubKey, Ed448.PUBLIC_KEY_SIZE)));
                }
                // Manual matching on curve encoding length
                else
                {
                    // sun.security.ec.ed.EdDSAPublicKeyImpl returns "EdDSA" for getAlgorithm()
                    // if algorithm is just EdDSA, we need to detect the curve based on encoding length :/
                    if (pubKey.getEncoded().length == 12 + Ed25519.PUBLIC_KEY_SIZE) // +12 for some reason
                    {
                        // Legacy Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
                        return new EdDSAPublicBCPGKey(GNUObjectIdentifiers.Ed25519, new BigInteger(1, getPointEncUncompressed(pubKey, Ed25519.PUBLIC_KEY_SIZE)));
                    }
                    else
                    {
                        // Legacy Ed448 (1.3.101.113)
                        return new EdDSAPublicBCPGKey(EdECObjectIdentifiers.id_Ed448, new BigInteger(1, getPointEncUncompressed(pubKey, Ed448.PUBLIC_KEY_SIZE)));
                    }
                }
            }

            // Modern Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
            case PublicKeyAlgorithmTags.Ed25519:
            {
                return getPublicBCPGKey(pubKey, Ed25519PublicBCPGKey.LENGTH, Ed25519PublicBCPGKey::new);
            }

            // Modern Ed448 (1.3.101.113)
            case PublicKeyAlgorithmTags.Ed448:
            {
                return getPublicBCPGKey(pubKey, Ed448PublicBCPGKey.LENGTH, Ed448PublicBCPGKey::new);
            }

            // Modern X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
            case PublicKeyAlgorithmTags.X25519:
            {
                return getPublicBCPGKey(pubKey, X25519PublicBCPGKey.LENGTH, X25519PublicBCPGKey::new);
            }
            // Modern X448 (1.3.101.111)
            case PublicKeyAlgorithmTags.X448:
            {
                return getPublicBCPGKey(pubKey, X448PublicBCPGKey.LENGTH, X448PublicBCPGKey::new);
            }

            default:
                throw new PGPException("unknown public key algorithm encountered: " + algorithm);
        }
    }

    private ASN1Encodable getNamedCurveOID(X962Parameters ecParams)
    {
        ECCurve curve = null;
        if (ecParams.isNamedCurve())
        {
            return ASN1ObjectIdentifier.getInstance(ecParams.getParameters());
        }
        else if (ecParams.isImplicitlyCA())
        {
            curve = ((X9ECParameters)CryptoServicesRegistrar.getProperty(CryptoServicesRegistrar.Property.EC_IMPLICITLY_CA)).getCurve();
        }
        else
        {
            curve = X9ECParameters.getInstance(ecParams.getParameters()).getCurve();
        }

        // Iterate through all registered curves to find applicable OID
        Enumeration names = ECNamedCurveTable.getNames();
        while (names.hasMoreElements())
        {
            String name = (String)names.nextElement();
            X9ECParameters parms = ECNamedCurveTable.getByName(name);
            if (curve.equals(parms.getCurve()))
            {
                return ECNamedCurveTable.getOID(name);
            }
        }
        return null;
    }

    @FunctionalInterface
    private interface BCPGKeyOperation
    {
        BCPGKey getBCPGKey(byte[] key);
    }

    private BCPGKey getPublicBCPGKey(PublicKey pubKey, int keySize, BCPGKeyOperation operation)
    {
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());
        byte[] pointEnc = new byte[keySize];

        System.arraycopy(pubInfo.getPublicKeyData().getBytes(), 0, pointEnc, 0, pointEnc.length);
        return operation.getBCPGKey(pointEnc);
    }

    private byte[] getPointEncUncompressed(PublicKey pubKey, int publicKeySize)
    {
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());
        byte[] pointEnc = new byte[1 + publicKeySize];

        pointEnc[0] = 0x40;
        System.arraycopy(pubInfo.getPublicKeyData().getBytes(), 0, pointEnc, 1, pointEnc.length - 1);
        return pointEnc;
    }

    @FunctionalInterface
    private interface Operation
    {
        PrivateKeyInfo getPrivateKeyInfo()
            throws IOException;
    }

    private PrivateKey implGeneratePrivate(String keyAlgorithm, Operation operation)
        throws GeneralSecurityException, PGPException, IOException
    {
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(operation.getPrivateKeyInfo().getEncoded());
        KeyFactory keyFactory = helper.createKeyFactory(keyAlgorithm);
        return keyFactory.generatePrivate(pkcs8Spec);
    }

    private PrivateKey implGeneratePrivate(String keyAlgorithm, KeySpec keySpec)
        throws GeneralSecurityException, PGPException
    {
        KeyFactory keyFactory = helper.createKeyFactory(keyAlgorithm);
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey implGeneratePublic(String keyAlgorithm, KeySpec keySpec)
        throws GeneralSecurityException, PGPException
    {
        KeyFactory keyFactory = helper.createKeyFactory(keyAlgorithm);
        return keyFactory.generatePublic(keySpec);
    }

    private PublicKey implGetPublicKeyX509(byte[] pEnc, int pEncOff, ASN1ObjectIdentifier algorithm, String keyAlgorithm)
        throws IOException, PGPException, GeneralSecurityException
    {
        return implGeneratePublic(keyAlgorithm, new X509EncodedKeySpec(new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(algorithm), Arrays.copyOfRange(pEnc, pEncOff, pEnc.length)).getEncoded()));
    }

    private PrivateKey implGetPrivateKeyEC(String keyAlgorithm, ECPublicBCPGKey ecPub, ECSecretBCPGKey ecPriv)
        throws GeneralSecurityException, PGPException, IOException
    {
        ASN1ObjectIdentifier curveOid = ecPub.getCurveOID();
        ECPrivateKeySpec ecPrivSpec = new ECPrivateKeySpec(ecPriv.getX(), getECParameterSpec(curveOid));
        return implGeneratePrivate(keyAlgorithm, ecPrivSpec);
    }

    private PublicKey implGetPublicKeyEC(String keyAlgorithm, ECPublicBCPGKey ecPub)
        throws GeneralSecurityException, IOException, PGPException
    {
        ASN1ObjectIdentifier curveOID = ecPub.getCurveOID();
        X9ECParameters x9Params = JcaJcePGPUtil.getX9Parameters(curveOID);
        ECPoint ecPubPoint = JcaJcePGPUtil.decodePoint(ecPub.getEncodedPoint(), x9Params.getCurve());
        ECPublicKeySpec ecPubSpec = new ECPublicKeySpec(
            new java.security.spec.ECPoint(
                ecPubPoint.getAffineXCoord().toBigInteger(),
                ecPubPoint.getAffineYCoord().toBigInteger()),
            getECParameterSpec(curveOID));
        return implGeneratePublic(keyAlgorithm, ecPubSpec);
    }

    private PublicKey get25519PublicKey(BigInteger x, ASN1ObjectIdentifier algorithm, String keyAlgorithm, String name)
        throws PGPException, GeneralSecurityException, IOException
    {
        byte[] pEnc = BigIntegers.asUnsignedByteArray(x);

        // skip the 0x40 header byte.
        if (pEnc.length < 1 || 0x40 != pEnc[0])
        {
            throw new IllegalArgumentException("Invalid " + name + "25519 public key");
        }
        return implGetPublicKeyX509(pEnc, 1, algorithm, keyAlgorithm);
    }

    private PublicKey get448PublicKey(BigInteger x, ASN1ObjectIdentifier algorithm, String keyAlgorithm, String name)
            throws PGPException, GeneralSecurityException, IOException
    {
        byte[] pEnc = BigIntegers.asUnsignedByteArray(x);

        // skip the 0x40 header byte.
        if (pEnc.length < 1 || 0x40 != pEnc[0])
        {
            throw new IllegalArgumentException("Invalid " + name + "448 public key");
        }
        return implGetPublicKeyX509(pEnc, 1, algorithm, keyAlgorithm);
    }
}
