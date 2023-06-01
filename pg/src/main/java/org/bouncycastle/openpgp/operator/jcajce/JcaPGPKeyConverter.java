package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

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
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.asn1.x9.X9ECPoint;
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
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.bcpg.X25519SecretBCPGKey;
import org.bouncycastle.bcpg.X448PublicBCPGKey;
import org.bouncycastle.bcpg.X448SecretBCPGKey;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.openpgp.PGPAlgorithmParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKdfParameters;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class JcaPGPKeyConverter
{
    private static final int X25519_KEY_SIZE = 32;
    private static final int ED25519_KEY_SIZE = 32;

    // We default to these as they are specified as mandatory in RFC 6631.
    private static final PGPKdfParameters DEFAULT_KDF_PARAMETERS = new PGPKdfParameters(HashAlgorithmTags.SHA256,
        SymmetricKeyAlgorithmTags.AES_128);

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
     * @param pub   the corresponding PGPPublicKey to privKey.
     * @param privKey  the private key for the key in pub.
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
     * @param algorithm asymmetric algorithm type representing the public key.
     * @param algorithmParameters additional parameters to be stored against the public key.
     * @param pubKey    actual public key to associate.
     * @param time      date of creation.
     * @throws PGPException on key creation problem.
     */
    public PGPPublicKey getPGPPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey, Date time)
        throws PGPException
    {
        BCPGKey bcpgKey = getPublicBCPGKey(algorithm, algorithmParameters, pubKey, time);

        return new PGPPublicKey(new PublicKeyPacket(algorithm, time, bcpgKey), fingerPrintCalculator);
    }

    /**
     * Create a PGPPublicKey from the passed in JCA one.
     * <p>
     * Note: the time passed in affects the value of the key's keyID, so you probably only want
     * to do this once for a JCA key, or make sure you keep track of the time you used.
     * </p>
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

                if (CryptlibObjectIdentifiers.curvey25519.equals(ecdhPub.getCurveOID()))
                {
                    // 'reverse' because the native format for X25519 private keys is little-endian
                    return implGetPrivateKeyPKCS8("XDH", new PrivateKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519),
                        new DEROctetString(Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(ecdhK.getX())))));
                }
                else
                {
                    return implGetPrivateKeyEC("ECDH", ecdhPub, ecdhK);
                }
            }

            case PublicKeyAlgorithmTags.ECDSA:
                return implGetPrivateKeyEC("ECDSA", (ECDSAPublicBCPGKey)pubPk.getKey(), (ECSecretBCPGKey)privPk);

            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                EdSecretBCPGKey eddsaK = (EdSecretBCPGKey)privPk;

                return implGetPrivateKeyPKCS8("EdDSA", new PrivateKeyInfo(
                    new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    new DEROctetString(BigIntegers.asUnsignedByteArray(Ed25519.SECRET_KEY_SIZE, eddsaK.getX()))));
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

            case PublicKeyAlgorithmTags.X25519:
                X25519SecretBCPGKey x25519Priv = (X25519SecretBCPGKey) privPk;
                return implGetPrivateKeyPKCS8("XDH", new PrivateKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519),
                        new DEROctetString(x25519Priv.getKey())));

            case PublicKeyAlgorithmTags.X448:
                X448SecretBCPGKey x448Priv = (X448SecretBCPGKey) privPk;
                return implGetPrivateKeyPKCS8("XDH", new PrivateKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448),
                        new DEROctetString(x448Priv.getKey())));

            case PublicKeyAlgorithmTags.Ed25519:
                Ed25519SecretBCPGKey ed25519Priv = (Ed25519SecretBCPGKey) privPk;
                return implGetPrivateKeyPKCS8("EdDSA", new PrivateKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                        new DEROctetString(ed25519Priv.getKey())));

            case PublicKeyAlgorithmTags.Ed448:
                Ed448SecretBCPGKey ed448Priv = (Ed448SecretBCPGKey) privPk;
                return implGetPrivateKeyPKCS8("EdDSA", new PrivateKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448),
                        new DEROctetString(ed448Priv.getKey())));

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

                if (ecdhK.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    byte[] pEnc = BigIntegers.asUnsignedByteArray(ecdhK.getEncodedPoint());

                    // skip the 0x40 header byte.
                    if (pEnc.length < 1 || 0x40 != pEnc[0])
                    {
                        throw new IllegalArgumentException("Invalid Curve25519 public key");
                    }

                    return implGetPublicKeyX509("XDH", new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519),
                        Arrays.copyOfRange(pEnc, 1, pEnc.length)));
                }
                else
                {
                    return implGetPublicKeyEC("ECDH", ecdhK);
                }
            }

            case PublicKeyAlgorithmTags.ECDSA:
                return implGetPublicKeyEC("ECDSA", (ECDSAPublicBCPGKey)publicPk.getKey());

            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                EdDSAPublicBCPGKey eddsaK = (EdDSAPublicBCPGKey)publicPk.getKey();

                byte[] pEnc = BigIntegers.asUnsignedByteArray(eddsaK.getEncodedPoint());

                // skip the 0x40 header byte.
                if (pEnc.length < 1 || 0x40 != pEnc[0])
                {
                    throw new IllegalArgumentException("Invalid Ed25519 public key");
                }

                return implGetPublicKeyX509("EdDSA", new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    Arrays.copyOfRange(pEnc, 1, pEnc.length)));
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

            case PublicKeyAlgorithmTags.X25519:
                X25519PublicBCPGKey x25519Pub = (X25519PublicBCPGKey) publicPk.getKey();
                return implGetPublicKeyX509("XDH", new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519),
                        x25519Pub.getKey()));

            case PublicKeyAlgorithmTags.X448:
                X448PublicBCPGKey x448Pub = (X448PublicBCPGKey) publicPk.getKey();
                return implGetPublicKeyX509("XDH", new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448),
                        x448Pub.getKey()));

            case PublicKeyAlgorithmTags.Ed25519:
                Ed25519PublicBCPGKey ed25519Pub = (Ed25519PublicBCPGKey) publicPk.getKey();
                return implGetPublicKeyX509("EdDSA", new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                        ed25519Pub.getKey()));

            case PublicKeyAlgorithmTags.Ed448:
                Ed448PublicBCPGKey ed448Pub = (Ed448PublicBCPGKey) publicPk.getKey();
                return implGetPublicKeyX509("EdDSA", new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                        ed448Pub.getKey()));

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
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException
    {
        return getECParameterSpec(curveOid, JcaJcePGPUtil.getX9Parameters(curveOid));
    }

    private ECParameterSpec getECParameterSpec(ASN1ObjectIdentifier curveOid, X9ECParameters x9Params)
        throws InvalidParameterSpecException, NoSuchProviderException, NoSuchAlgorithmException
    {
        AlgorithmParameters params = helper.createAlgorithmParameters("EC");

        params.init(new ECGenParameterSpec(ECNamedCurveTable.getName(curveOid)));

        return params.getParameterSpec(ECParameterSpec.class);
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
                PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());

                try
                {
                    // 'reverse' because the native format for X25519 private keys is little-endian
                    return new ECSecretBCPGKey(new BigInteger(1,
                        Arrays.reverse(ASN1OctetString.getInstance(pInfo.parsePrivateKey()).getOctets())));
                }
                catch (IOException e)
                {
                    throw new PGPException(e.getMessage(), e);
                }
            }
        }

        case PublicKeyAlgorithmTags.ECDSA:
        {
            ECPrivateKey ecK = (ECPrivateKey)privKey;
            return new ECSecretBCPGKey(ecK.getS());
        }

        case PublicKeyAlgorithmTags.EDDSA_LEGACY:
        {
            PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());

            try
            {
                return new EdSecretBCPGKey(
                    new BigInteger(1, ASN1OctetString.getInstance(pInfo.parsePrivateKey()).getOctets()));
            }
            catch (IOException e)
            {
                throw new PGPException(e.getMessage(), e);
            }
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

        case PublicKeyAlgorithmTags.X25519:
            return new X25519SecretBCPGKey(privKey.getEncoded());
        case PublicKeyAlgorithmTags.X448:
            return new X448SecretBCPGKey(privKey.getEncoded());
        case PublicKeyAlgorithmTags.Ed25519:
            return new Ed25519SecretBCPGKey(privKey.getEncoded());
        case PublicKeyAlgorithmTags.Ed448:
            return new Ed448SecretBCPGKey(privKey.getEncoded());

        default:
            throw new PGPException("unknown key class");
        }
    }

    private BCPGKey getPublicBCPGKey(int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey, Date time)
        throws PGPException
    {
        if (pubKey instanceof RSAPublicKey)
        {
            RSAPublicKey rK = (RSAPublicKey)pubKey;
            return new RSAPublicBCPGKey(rK.getModulus(), rK.getPublicExponent());
        }
        else if (pubKey instanceof DSAPublicKey)
        {
            DSAPublicKey dK = (DSAPublicKey)pubKey;
            DSAParams dP = dK.getParams();
            return new DSAPublicBCPGKey(dP.getP(), dP.getQ(), dP.getG(), dK.getY());
        }
        else if (pubKey instanceof DHPublicKey)
        {
            DHPublicKey eK = (DHPublicKey)pubKey;
            DHParameterSpec eS = eK.getParams();
            return new ElGamalPublicBCPGKey(eS.getP(), eS.getG(), eK.getY());
        }
        else if (pubKey instanceof ECPublicKey)
        {
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());

            // TODO: should probably match curve by comparison as well
            ASN1ObjectIdentifier  curveOid = ASN1ObjectIdentifier.getInstance(keyInfo.getAlgorithm().getParameters());

            X9ECParametersHolder params = ECNamedCurveTable.getByOIDLazy(curveOid);

            ASN1OctetString key = new DEROctetString(keyInfo.getPublicKeyData().getBytes());
            X9ECPoint derQ = new X9ECPoint(params.getCurve(), key);

            if (algorithm == PGPPublicKey.ECDH)
            {
                PGPKdfParameters kdfParams = implGetKdfParameters(algorithmParameters);

                return new ECDHPublicBCPGKey(curveOid, derQ.getPoint(), kdfParams.getHashAlgorithm(),
                    kdfParams.getSymmetricWrapAlgorithm());
            }
            else if (algorithm == PGPPublicKey.ECDSA)
            {
                return new ECDSAPublicBCPGKey(curveOid, derQ.getPoint());
            }
            else
            {
                throw new PGPException("unknown EC algorithm");
            }
        }
        else if (pubKey.getAlgorithm().regionMatches(true, 0, "ED2", 0, 3))
        {
            SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());
            byte[] pointEnc = new byte[1 + ED25519_KEY_SIZE];

            pointEnc[0] = 0x40;
            System.arraycopy(pubInfo.getPublicKeyData().getBytes(), 0, pointEnc, 1, pointEnc.length - 1);

            return new EdDSAPublicBCPGKey(GNUObjectIdentifiers.Ed25519, new BigInteger(1, pointEnc));
        }
        else if (pubKey.getAlgorithm().regionMatches(true, 0, "X2", 0, 2))
        {
            SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());
            byte[] pointEnc = new byte[1 + X25519_KEY_SIZE];

            pointEnc[0] = 0x40;
            System.arraycopy(pubInfo.getPublicKeyData().getBytes(), 0, pointEnc, 1, pointEnc.length - 1);

            PGPKdfParameters kdfParams = implGetKdfParameters(algorithmParameters);

            return new ECDHPublicBCPGKey(CryptlibObjectIdentifiers.curvey25519, new BigInteger(1, pointEnc),
                kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
        }
        else
        {
            throw new PGPException("unknown key class");
        }
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

    private PGPKdfParameters implGetKdfParameters(PGPAlgorithmParameters algorithmParameters)
    {
        return null == algorithmParameters ? DEFAULT_KDF_PARAMETERS : (PGPKdfParameters)algorithmParameters;
    }

    private PrivateKey implGetPrivateKeyEC(String keyAlgorithm, ECPublicBCPGKey ecPub, ECSecretBCPGKey ecPriv)
        throws GeneralSecurityException, PGPException
    {
        ECPrivateKeySpec ecPrivSpec = new ECPrivateKeySpec(ecPriv.getX(), getECParameterSpec(ecPub.getCurveOID()));
        return implGeneratePrivate(keyAlgorithm, ecPrivSpec);
    }

    private PrivateKey implGetPrivateKeyPKCS8(String keyAlgorithm, PrivateKeyInfo privateKeyInfo)
        throws GeneralSecurityException, IOException, PGPException
    {
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
        return implGeneratePrivate(keyAlgorithm, pkcs8Spec);
    }

    private PublicKey implGetPublicKeyEC(String keyAlgorithm, ECPublicBCPGKey ecPub) throws GeneralSecurityException, IOException, PGPException
    {
        ASN1ObjectIdentifier curveOID = ecPub.getCurveOID();
        X9ECParameters x9Params = JcaJcePGPUtil.getX9Parameters(curveOID);
        ECPoint ecPubPoint = JcaJcePGPUtil.decodePoint(ecPub.getEncodedPoint(), x9Params.getCurve());
        ECPublicKeySpec ecPubSpec = new ECPublicKeySpec(
            new java.security.spec.ECPoint(
                ecPubPoint.getAffineXCoord().toBigInteger(),
                ecPubPoint.getAffineYCoord().toBigInteger()),
            getECParameterSpec(curveOID, x9Params));
        return implGeneratePublic(keyAlgorithm, ecPubSpec);
    }

    private PublicKey implGetPublicKeyX509(String keyAlgorithm, SubjectPublicKeyInfo subjectPublicKeyInfo)
        throws GeneralSecurityException, IOException, PGPException
    {
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
        return implGeneratePublic(keyAlgorithm, x509Spec);
    }
}
