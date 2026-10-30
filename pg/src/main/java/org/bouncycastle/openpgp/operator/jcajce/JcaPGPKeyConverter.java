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
import java.util.Enumeration;
import java.util.List;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
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
import org.bouncycastle.bcpg.MLDSACompositePublicBCPGKey;
import org.bouncycastle.bcpg.MLDSACompositeSecretBCPGKey;
import org.bouncycastle.bcpg.MLKEMCompositePublicBCPGKey;
import org.bouncycastle.bcpg.MLKEMCompositeSecretBCPGKey;
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
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
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
    private OperatorHelper helper = OperatorUtils.createDefaultHelper();
    private KeyFingerPrintCalculator fingerPrintCalculator = new JcaKeyFingerprintCalculator();

    public JcaPGPKeyConverter setProvider(Provider provider)
    {
        this.helper = OperatorUtils.createProviderHelper(provider);

        return this;
    }

    public JcaPGPKeyConverter setProvider(String providerName)
    {
        this.helper = OperatorUtils.createNamedHelper(providerName);

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
     * Create a version 4 PGPPublicKey from the passed in JCA one.
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
     * @deprecated use versioned {@link #getPGPPublicKey(int, int, PGPAlgorithmParameters, PublicKey, Date)} instead.
     */
    @Deprecated
    @SuppressWarnings("InlineMeSuggester")
    public PGPPublicKey getPGPPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey, Date time)
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
     * @param version             key version.
     * @param algorithm           asymmetric algorithm type representing the public key.
     * @param algorithmParameters additional parameters to be stored against the public key.
     * @param pubKey              actual public key to associate.
     * @param time                date of creation.
     * @throws PGPException on key creation problem.
     */
    public PGPPublicKey getPGPPublicKey(int version, int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey, Date time)
        throws PGPException
    {
        BCPGKey bcpgKey = getPublicBCPGKey(algorithm, algorithmParameters, pubKey);

        return new PGPPublicKey(new PublicKeyPacket(version, algorithm, time, bcpgKey), fingerPrintCalculator);
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
     * @deprecated use versioned {@link #getPGPPublicKey(int, int, PublicKey, Date)} instead.
     */
    @Deprecated
    public PGPPublicKey getPGPPublicKey(int algorithm, PublicKey pubKey, Date time)
        throws PGPException
    {
        return getPGPPublicKey(algorithm, null, pubKey, time);
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
    public PGPPublicKey getPGPPublicKey(int version, int algorithm, PublicKey pubKey, Date time)
        throws PGPException
    {
        return getPGPPublicKey(version, algorithm, null, pubKey, time);
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
                if (JcaJcePGPUtil.isX25519(ecdhPub.getCurveOID()))
                {
                    // 'reverse' because the native format for X25519 private keys is little-endian
                    return implGeneratePrivate("XDH", new Operation()
                    {
                        @Override
                        public PrivateKeyInfo getPrivateKeyInfos()
                            throws IOException
                        {
                            return getPrivateKeyInfo(EdECObjectIdentifiers.id_X25519,
                                Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(((ECSecretBCPGKey)privPk).getX())));
                        }
                    });
                }
                // Legacy X448 (1.3.101.111)
                else if (EdECObjectIdentifiers.id_X448.equals(ecdhPub.getCurveOID()))
                {
                    // 'reverse' because the native format for X448 private keys is little-endian (?)
                    return implGeneratePrivate("XDH", new Operation()
                    {
                        @Override
                        public PrivateKeyInfo getPrivateKeyInfos()
                            throws IOException
                        {
                            return getPrivateKeyInfo(EdECObjectIdentifiers.id_X448,
                                Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(((ECSecretBCPGKey)privPk).getX())));
                        }
                    });
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
                return implGeneratePrivate("XDH", new Operation()
                {
                    @Override
                    public PrivateKeyInfo getPrivateKeyInfos()
                        throws IOException
                    {
                        return getPrivateKeyInfo(EdECObjectIdentifiers.id_X25519,
                            X25519SecretBCPGKey.LENGTH, privPk.getEncoded());
                    }
                });
            }
            // Modern X448 (1.3.101.111)
            case PublicKeyAlgorithmTags.X448:
            {
                return implGeneratePrivate("XDH", new Operation()
                {
                    @Override
                    public PrivateKeyInfo getPrivateKeyInfos()
                        throws IOException
                    {
                        return getPrivateKeyInfo(EdECObjectIdentifiers.id_X448,
                            X448SecretBCPGKey.LENGTH, privPk.getEncoded());
                    }
                });
            }
            case PublicKeyAlgorithmTags.ECDSA:
            {
                return implGetPrivateKeyEC("EC", (ECDSAPublicBCPGKey)pubPk.getKey(), (ECSecretBCPGKey)privPk);
            }
            // Legacy EdDSA (legacy Ed448, legacy Ed25519)
            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                EdDSAPublicBCPGKey eddsaPub = (EdDSAPublicBCPGKey)pubPk.getKey();
                // Legacy Ed448 (1.3.101.113)
                if (EdECObjectIdentifiers.id_Ed448.equals(eddsaPub.getCurveOID()))
                {
                    return implGeneratePrivate("EdDSA", new Operation()
                    {
                        @Override
                        public PrivateKeyInfo getPrivateKeyInfos()
                            throws IOException
                        {
                            return getPrivateKeyInfo(EdECObjectIdentifiers.id_Ed448,
                                BigIntegers.asUnsignedByteArray(Ed448.SECRET_KEY_SIZE, ((EdSecretBCPGKey)privPk).getX()));
                        }
                    });
                }
                // Legacy Ed25519
                // 1.3.6.1.4.1.11591.15.1 & 1.3.101.112
                return implGeneratePrivate("EdDSA", new Operation()
                {
                    @Override
                    public PrivateKeyInfo getPrivateKeyInfos()
                        throws IOException
                    {
                        return getPrivateKeyInfo(EdECObjectIdentifiers.id_Ed25519,
                            BigIntegers.asUnsignedByteArray(Ed25519.SECRET_KEY_SIZE, ((EdSecretBCPGKey)privPk).getX()));
                    }
                });
            }
            // Modern Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
            case PublicKeyAlgorithmTags.Ed25519:
            {
                return implGeneratePrivate("EdDSA", new Operation()
                {
                    @Override
                    public PrivateKeyInfo getPrivateKeyInfos()
                        throws IOException
                    {
                        return getPrivateKeyInfo(EdECObjectIdentifiers.id_Ed25519,
                            Ed25519SecretBCPGKey.LENGTH, privPk.getEncoded());
                    }
                });
            }
            // Modern Ed448 (1.3.101.113)
            case PublicKeyAlgorithmTags.Ed448:
            {
                return implGeneratePrivate("EdDSA", new Operation()
                {
                    @Override
                    public PrivateKeyInfo getPrivateKeyInfos()
                        throws IOException
                    {
                        return getPrivateKeyInfo(EdECObjectIdentifiers.id_Ed448,
                            Ed448SecretBCPGKey.LENGTH, privPk.getEncoded());
                    }
                });
            }
            // RFC 9980 ML-DSA + EdDSA composites: EdDSA secret key || 32 octet ML-DSA seed
            case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            {
                final int algorithm = pubPk.getAlgorithm();
                final MLDSACompositeSecretBCPGKey compPriv = (MLDSACompositeSecretBCPGKey)privPk;
                final ASN1ObjectIdentifier eddsaOid = algorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519
                    ? EdECObjectIdentifiers.id_Ed25519 : EdECObjectIdentifiers.id_Ed448;
                PrivateKey eddsaPriv = implGeneratePrivate("EdDSA", new Operation()
                {
                    @Override
                    public PrivateKeyInfo getPrivateKeyInfos()
                        throws IOException
                    {
                        return getPrivateKeyInfo(eddsaOid, compPriv.getEdDSASecretKey());
                    }
                });
                PrivateKey mldsaPriv = implGeneratePrivate("ML-DSA", new Operation()
                {
                    @Override
                    public PrivateKeyInfo getPrivateKeyInfos()
                        throws IOException
                    {
                        // RFC 9881 sec. 6: the seed-only PKCS#8 form, seed [0] OCTET STRING
                        return getSeedPrivateKeyInfo(getMLDSAOid(algorithm), compPriv.getMLDSASeed());
                    }
                });
                return new CompositePrivateKey(new PrivateKey[]{ eddsaPriv, mldsaPriv });
            }
            // RFC 9980 SLH-DSA: SK.seed || SK.prf || PK.seed || PK.root
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            {
                final int algorithm = pubPk.getAlgorithm();
                return implGeneratePrivate("SLH-DSA", new Operation()
                {
                    @Override
                    public PrivateKeyInfo getPrivateKeyInfos()
                        throws IOException
                    {
                        // RFC 9814 sec. 6: the privateKey OCTET STRING holds the raw SLH-DSA secret key
                        return new PrivateKeyInfo(new AlgorithmIdentifier(getSLHDSAOid(algorithm)), privPk.getEncoded());
                    }
                });
            }
            // RFC 9980 ML-KEM + ECDH composites: ECDH secret key || 64 octet ML-KEM seed d || z
            case PublicKeyAlgorithmTags.MLKEM768_X25519:
            case PublicKeyAlgorithmTags.MLKEM1024_X448:
            {
                final int algorithm = pubPk.getAlgorithm();
                final MLKEMCompositeSecretBCPGKey compPriv = (MLKEMCompositeSecretBCPGKey)privPk;
                final ASN1ObjectIdentifier xdhOid = algorithm == PublicKeyAlgorithmTags.MLKEM768_X25519
                    ? EdECObjectIdentifiers.id_X25519 : EdECObjectIdentifiers.id_X448;
                PrivateKey xdhPriv = implGeneratePrivate("XDH", new Operation()
                {
                    @Override
                    public PrivateKeyInfo getPrivateKeyInfos()
                        throws IOException
                    {
                        return getPrivateKeyInfo(xdhOid, compPriv.getECDHSecretKey());
                    }
                });
                PrivateKey mlkemPriv = implGeneratePrivate("ML-KEM", new Operation()
                {
                    @Override
                    public PrivateKeyInfo getPrivateKeyInfos()
                        throws IOException
                    {
                        // RFC 9935 sec. 6: the seed-only PKCS#8 form, seed [0] OCTET STRING
                        return getSeedPrivateKeyInfo(getMLKEMOid(algorithm), compPriv.getMLKEMSeed());
                    }
                });
                return new CompositePrivateKey(new PrivateKey[]{ xdhPriv, mlkemPriv });
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
                if (JcaJcePGPUtil.isX25519(ecdhK.getCurveOID()))
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
                return implGetPublicKeyEC("EC", (ECDSAPublicBCPGKey)publicPk.getKey());
            }
            // Legacy EdDSA (legacy Ed448, legacy Ed25519)
            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                EdDSAPublicBCPGKey eddsaKey = (EdDSAPublicBCPGKey)publicPk.getKey();
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
            // RFC 9980 ML-DSA + EdDSA composites
            case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            {
                int algorithm = publicPk.getAlgorithm();
                MLDSACompositePublicBCPGKey compK = (MLDSACompositePublicBCPGKey)publicPk.getKey();
                PublicKey eddsaPub = implGetPublicKeyX509(compK.getEdDSAPublicKey(), 0,
                    algorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519 ? EdECObjectIdentifiers.id_Ed25519 : EdECObjectIdentifiers.id_Ed448,
                    "EdDSA");
                PublicKey mldsaPub = implGetPublicKeyX509(compK.getMLDSAPublicKey(), 0, getMLDSAOid(algorithm), "ML-DSA");
                return new CompositePublicKey(new PublicKey[]{ eddsaPub, mldsaPub });
            }
            // RFC 9980 SLH-DSA
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
            case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            {
                return implGetPublicKeyX509(publicPk.getKey().getEncoded(), 0, getSLHDSAOid(publicPk.getAlgorithm()), "SLH-DSA");
            }
            // RFC 9980 ML-KEM + ECDH composites
            case PublicKeyAlgorithmTags.MLKEM768_X25519:
            case PublicKeyAlgorithmTags.MLKEM1024_X448:
            {
                int algorithm = publicPk.getAlgorithm();
                MLKEMCompositePublicBCPGKey compK = (MLKEMCompositePublicBCPGKey)publicPk.getKey();
                PublicKey xdhPub = implGetPublicKeyX509(compK.getECDHPublicKey(), 0,
                    algorithm == PublicKeyAlgorithmTags.MLKEM768_X25519 ? EdECObjectIdentifiers.id_X25519 : EdECObjectIdentifiers.id_X448,
                    "XDH");
                PublicKey mlkemPub = implGetPublicKeyX509(compK.getMLKEMPublicKey(), 0, getMLKEMOid(algorithm), "ML-KEM");
                return new CompositePublicKey(new PublicKey[]{ xdhPub, mlkemPub });
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
        // Resolve via the JCE provider's curve-name registry first; this works with both
        // the BC and JDK 11+ Sun providers. If no name match is available (for example
        // if the OID is for a curve the provider doesn't know by name) fall back to the
        // X9.62 OID-encoded form, which BC accepts directly. See github #1230.
        AlgorithmParameters params = helper.createAlgorithmParameters("EC");
        String curveName = ECNamedCurveTable.getName(curveOid);

        if (curveName != null)
        {
            try
            {
                params.init(new ECGenParameterSpec(curveName));
                return params.getParameterSpec(ECParameterSpec.class);
            }
            catch (InvalidParameterSpecException e)
            {
                // provider didn't recognise the name - retry with the OID encoding.
                params = helper.createAlgorithmParameters("EC");
            }
        }

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
                return getPrivateBCPGKey(privKey, new BCPGKeyOperation()
                {
                    @Override
                    public BCPGKey getBCPGKey(byte[] key)
                    {
                        return new ECSecretBCPGKey(new BigInteger(1, Arrays.reverse(key)));
                    }
                });
            }
        }
        // Modern X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
        case PublicKeyAlgorithmTags.X25519:
        {
            return getPrivateBCPGKey(privKey, new BCPGKeyOperation()
            {
                @Override
                public BCPGKey getBCPGKey(byte[] key)
                {
                    return new X25519SecretBCPGKey(key);
                }
            });
        }
        // Modern X448 (1.3.101.111)
        case PublicKeyAlgorithmTags.X448:
        {
            return getPrivateBCPGKey(privKey, new BCPGKeyOperation()
            {
                @Override
                public BCPGKey getBCPGKey(byte[] key)
                {
                    return new X448SecretBCPGKey(key);
                }
            });
        }
        case PublicKeyAlgorithmTags.ECDSA:
        {
            return new ECSecretBCPGKey(((ECPrivateKey)privKey).getS());
        }
        // Legacy EdDSA (legacy Ed448, legacy Ed25519)
        case PublicKeyAlgorithmTags.EDDSA_LEGACY:
        {
            return getPrivateBCPGKey(privKey, new BCPGKeyOperation()
            {
                @Override
                public BCPGKey getBCPGKey(byte[] key)
                {
                    return new EdSecretBCPGKey(new BigInteger(1, key));
                }
            });
        }
        // Modern Ed25519 (1.3.6.1.4.1.11591.15.1 & 1.3.101.112)
        case PublicKeyAlgorithmTags.Ed25519:
        {
            return getPrivateBCPGKey(privKey, new BCPGKeyOperation()
            {
                @Override
                public BCPGKey getBCPGKey(byte[] key)
                {
                    return new Ed25519SecretBCPGKey(key);
                }
            });
        }
        // Modern Ed448 (1.3.101.113)
        case PublicKeyAlgorithmTags.Ed448:
        {
            return getPrivateBCPGKey(privKey, new BCPGKeyOperation()
            {
                @Override
                public BCPGKey getBCPGKey(byte[] key)
                {
                    return new Ed448SecretBCPGKey(key);
                }
            });
        }
        // RFC 9980 ML-DSA + EdDSA composites
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
        {
            int algorithm = pub.getAlgorithm();
            List<PrivateKey> components = getCompositeComponents(algorithm, privKey);
            byte[] eddsaEnc = getRawPrivateKey(components.get(0), true);
            byte[] seed = getPQCSeed(components.get(1), MLDSACompositeSecretBCPGKey.MLDSA_SEED_LENGTH);
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
            return new SLHDSASecretBCPGKey(pub.getAlgorithm(), getRawPrivateKey(privKey, false));
        }
        // RFC 9980 ML-KEM + ECDH composites
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
        {
            int algorithm = pub.getAlgorithm();
            List<PrivateKey> components = getCompositeComponents(algorithm, privKey);
            byte[] xdhEnc = getRawPrivateKey(components.get(0), true);
            byte[] seed = getPQCSeed(components.get(1), MLKEMCompositeSecretBCPGKey.MLKEM_SEED_LENGTH);
            if (seed == null)
            {
                throw new PGPException("ML-KEM private key carries no seed - RFC 9980 sec. 4.3.2.2 stores the secret key in seed format only");
            }
            return new MLKEMCompositeSecretBCPGKey(algorithm, xdhEnc, seed);
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
            RSAPublicKey rK = (RSAPublicKey)pubKey;
            return new RSAPublicBCPGKey(rK.getModulus(), rK.getPublicExponent());
        }
        case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
        case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
        {
            DHPublicKey egK = (DHPublicKey)pubKey;
            return new ElGamalPublicBCPGKey(egK.getParams().getP(), egK.getParams().getG(), egK.getY());
        }
        case PublicKeyAlgorithmTags.DSA:
        {
            DSAPublicKey dK = (DSAPublicKey)pubKey;
            DSAParams dP = dK.getParams();
            return new DSAPublicBCPGKey(dP.getP(), dP.getQ(), dP.getG(), dK.getY());
        }

        case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
        {
            DHPublicKey eK = (DHPublicKey)pubKey;
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
            return getPublicBCPGKey(pubKey, Ed25519PublicBCPGKey.LENGTH, new BCPGKeyOperation()
            {
                @Override
                public BCPGKey getBCPGKey(byte[] key)
                {
                    return new Ed25519PublicBCPGKey(key);
                }
            });
        }

        // Modern Ed448 (1.3.101.113)
        case PublicKeyAlgorithmTags.Ed448:
        {
            return getPublicBCPGKey(pubKey, Ed448PublicBCPGKey.LENGTH, new BCPGKeyOperation()
            {
                @Override
                public BCPGKey getBCPGKey(byte[] key)
                {
                    return new Ed448PublicBCPGKey(key);
                }
            });
        }

        // Modern X25519 (1.3.6.1.4.1.3029.1.5.1 & 1.3.101.110)
        case PublicKeyAlgorithmTags.X25519:
        {
            return getPublicBCPGKey(pubKey, X25519PublicBCPGKey.LENGTH, new BCPGKeyOperation()
            {
                @Override
                public BCPGKey getBCPGKey(byte[] key)
                {
                    return new X25519PublicBCPGKey(key);
                }
            });
        }
        // Modern X448 (1.3.101.111)
        case PublicKeyAlgorithmTags.X448:
        {
            return getPublicBCPGKey(pubKey, X448PublicBCPGKey.LENGTH, new BCPGKeyOperation()
            {
                @Override
                public BCPGKey getBCPGKey(byte[] key)
                {
                    return new X448PublicBCPGKey(key);
                }
            });
        }

        // RFC 9980 ML-DSA + EdDSA composites
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
        {
            List<PublicKey> components = getCompositeComponents(algorithm, pubKey);
            return new MLDSACompositePublicBCPGKey(algorithm, getRawPublicKey(components.get(0)), getRawPublicKey(components.get(1)));
        }
        // RFC 9980 SLH-DSA
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
        {
            return new SLHDSAPublicBCPGKey(algorithm, getRawPublicKey(pubKey));
        }
        // RFC 9980 ML-KEM + ECDH composites
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
        {
            List<PublicKey> components = getCompositeComponents(algorithm, pubKey);
            return new MLKEMCompositePublicBCPGKey(algorithm, getRawPublicKey(components.get(0)), getRawPublicKey(components.get(1)));
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
        byte[] pubInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()).getPublicKeyData().getBytes();
        byte[] pointEnc = new byte[keySize];
        // refer to getPointEncUncompressed
        System.arraycopy(pubInfo, 0, pointEnc, pointEnc.length - pubInfo.length, pubInfo.length);
        return operation.getBCPGKey(pointEnc);
    }

    private byte[] getPointEncUncompressed(PublicKey pubKey, int publicKeySize)
    {
        byte[] pubInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()).getPublicKeyData().getBytes();
        byte[] pointEnc = new byte[1 + publicKeySize];

        pointEnc[0] = 0x40;
        //offset with pointEnc.length - pubInfo.length to avoid leading zero issue
        System.arraycopy(pubInfo, 0, pointEnc, pointEnc.length - pubInfo.length, pubInfo.length);
        return pointEnc;
    }

    @FunctionalInterface
    private interface Operation
    {
        PrivateKeyInfo getPrivateKeyInfos()
            throws IOException;
    }

    private PrivateKey implGeneratePrivate(String keyAlgorithm, Operation operation)
        throws GeneralSecurityException, PGPException, IOException
    {
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(operation.getPrivateKeyInfos().getEncoded());
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

    /**
     * Return the two component keys of an RFC 9980 composite key, in OpenPGP order (traditional, post-quantum).
     */
    private static List<PublicKey> getCompositeComponents(int algorithm, PublicKey key)
        throws PGPException
    {
        if (!(key instanceof CompositePublicKey) || ((CompositePublicKey)key).getPublicKeys().size() != 2)
        {
            throw new PGPException("public key algorithm " + algorithm + " requires a CompositePublicKey of two component keys");
        }
        return ((CompositePublicKey)key).getPublicKeys();
    }

    private static List<PrivateKey> getCompositeComponents(int algorithm, PrivateKey key)
        throws PGPException
    {
        if (!(key instanceof CompositePrivateKey) || ((CompositePrivateKey)key).getPrivateKeys().size() != 2)
        {
            throw new PGPException("public key algorithm " + algorithm + " requires a CompositePrivateKey of two component keys");
        }
        return ((CompositePrivateKey)key).getPrivateKeys();
    }

    /**
     * The raw key bytes of a key whose SubjectPublicKeyInfo carries them as the bit string: EdDSA, XDH,
     * ML-DSA, ML-KEM and SLH-DSA all do.
     */
    private static byte[] getRawPublicKey(PublicKey key)
    {
        return SubjectPublicKeyInfo.getInstance(key.getEncoded()).getPublicKeyData().getOctets();
    }

    /**
     * The raw key bytes of a private key from its PKCS#8 encoding: for EdDSA and XDH the privateKey OCTET
     * STRING wraps a CurvePrivateKey OCTET STRING (RFC 8410 sec. 7), for SLH-DSA it holds the secret key
     * bytes themselves (RFC 9814 sec. 6).
     */
    private static byte[] getRawPrivateKey(PrivateKey key, boolean curvePrivateKey)
        throws PGPException
    {
        try
        {
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(key.getEncoded());
            if (curvePrivateKey)
            {
                return ASN1OctetString.getInstance(info.parsePrivateKey()).getOctets();
            }
            return info.getPrivateKey().getOctets();
        }
        catch (Exception e)
        {
            throw new PGPException("cannot extract private key: " + e.getMessage(), e);
        }
    }

    /**
     * The seed of an ML-DSA or ML-KEM private key, from the BC key interfaces when available and otherwise
     * from the PKCS#8 encoding of RFC 9881 / RFC 9935: seed [0] OCTET STRING, or the seed element of the
     * "both" SEQUENCE. Null for an expanded-key-only encoding, which RFC 9980 cannot carry.
     */
    private static byte[] getPQCSeed(PrivateKey key, int seedLength)
        throws PGPException
    {
        byte[] seed = null;
        if (key instanceof MLDSAPrivateKey)
        {
            seed = ((MLDSAPrivateKey)key).getSeed();
        }
        else if (key instanceof MLKEMPrivateKey)
        {
            seed = ((MLKEMPrivateKey)key).getSeed();
        }
        else
        {
            try
            {
                PrivateKeyInfo info = PrivateKeyInfo.getInstance(key.getEncoded());
                ASN1Encodable priv = info.parsePrivateKey();
                if (priv instanceof ASN1TaggedObject)
                {
                    seed = ASN1OctetString.getInstance((ASN1TaggedObject)priv, false).getOctets();
                }
                else if (priv instanceof ASN1Sequence)
                {
                    seed = ASN1OctetString.getInstance(((ASN1Sequence)priv).getObjectAt(0)).getOctets();
                }
            }
            catch (Exception e)
            {
                throw new PGPException("cannot extract private key seed: " + e.getMessage(), e);
            }
        }
        if (seed != null && seed.length != seedLength)
        {
            throw new PGPException("unexpected private key seed length: " + seed.length);
        }
        return seed;
    }

    /**
     * The seed-only PKCS#8 form of an ML-DSA (RFC 9881 sec. 6) or ML-KEM (RFC 9935 sec. 6) private key:
     * privateKey is the DER of seed [0] OCTET STRING.
     */
    private static PrivateKeyInfo getSeedPrivateKeyInfo(ASN1ObjectIdentifier algorithm, byte[] seed)
        throws IOException
    {
        return new PrivateKeyInfo(new AlgorithmIdentifier(algorithm), new DERTaggedObject(false, 0, new DEROctetString(seed)));
    }

    /**
     * Return the object identifier of the ML-DSA parameter set of an RFC 9980 ML-DSA + EdDSA composite algorithm.
     *
     * @param algorithm {@link PublicKeyAlgorithmTags#MLDSA65_Ed25519} or {@link PublicKeyAlgorithmTags#MLDSA87_Ed448}
     * @return id-ml-dsa-65 or id-ml-dsa-87
     */
    public static ASN1ObjectIdentifier getMLDSAOid(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            return NISTObjectIdentifiers.id_ml_dsa_65;
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            return NISTObjectIdentifiers.id_ml_dsa_87;
        default:
            throw new IllegalArgumentException("not an ML-DSA composite algorithm: " + algorithm);
        }
    }

    /**
     * Return the object identifier of the SLH-DSA parameter set of an RFC 9980 SLH-DSA algorithm.
     *
     * @param algorithm one of the SLH-DSA code points
     * @return id-slh-dsa-shake-128s, -128f or -256s
     */
    public static ASN1ObjectIdentifier getSLHDSAOid(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
            return NISTObjectIdentifiers.id_slh_dsa_shake_128s;
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
            return NISTObjectIdentifiers.id_slh_dsa_shake_128f;
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            return NISTObjectIdentifiers.id_slh_dsa_shake_256s;
        default:
            throw new IllegalArgumentException("not an SLH-DSA algorithm: " + algorithm);
        }
    }

    /**
     * Return the object identifier of the ML-KEM parameter set of an RFC 9980 ML-KEM + ECDH composite algorithm.
     *
     * @param algorithm {@link PublicKeyAlgorithmTags#MLKEM768_X25519} or {@link PublicKeyAlgorithmTags#MLKEM1024_X448}
     * @return id-alg-ml-kem-768 or id-alg-ml-kem-1024
     */
    public static ASN1ObjectIdentifier getMLKEMOid(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
            return NISTObjectIdentifiers.id_alg_ml_kem_768;
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
            return NISTObjectIdentifiers.id_alg_ml_kem_1024;
        default:
            throw new IllegalArgumentException("not an ML-KEM composite algorithm: " + algorithm);
        }
    }
}
