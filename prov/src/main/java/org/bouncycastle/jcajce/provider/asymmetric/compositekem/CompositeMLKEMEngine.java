package org.bouncycastle.jcajce.provider.asymmetric.compositekem;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.util.Arrays;

/**
 * Composite ML-KEM Engine using JCE for all component operations.
 * Implements Section 3.2 (Encap) and Section 3.3 (Decap) of the draft.
 */
class CompositeMLKEMEngine
{
    private static final OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private final ASN1ObjectIdentifier compositeOID;
    private final SecureRandom random;

    public CompositeMLKEMEngine(ASN1ObjectIdentifier compositeOID)
    {
        this(compositeOID, null);
    }

    public CompositeMLKEMEngine(ASN1ObjectIdentifier compositeOID, SecureRandom random)
    {
        if (!CompositeIndex.isCompositeKEMOID(compositeOID))
        {
            throw new IllegalArgumentException("Not a composite KEM OID: " + compositeOID);
        }
        this.compositeOID = compositeOID;
        this.random = random;
    }

    /**
     * KEM combiner as defined in section 3.4 of draft-ietf-lamps-pq-composite-kem:
     * <pre>
     *   ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)
     * </pre>
     * where Label is the per-algorithm domain separator from {@link CompositeIndex#getKEMLabel}.
     */
    private static byte[] kemCombiner(byte[] mlkemSS, byte[] tradSS, byte[] tradCT,
                                      byte[] tradPK, ASN1ObjectIdentifier compositeOID)
    {
        if (mlkemSS.length != 32)
        {
            throw new IllegalArgumentException("ML-KEM shared secret must be 32 bytes");
        }

        byte[] label = CompositeIndex.getKEMLabel(compositeOID);
        MessageDigest digest;
        try
        {
            digest = MessageDigest.getInstance("SHA3-256");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("SHA3-256 not available", e);
        }
        digest.update(mlkemSS);
        digest.update(tradSS);
        digest.update(tradCT);
        digest.update(tradPK);
        digest.update(label);
        return digest.digest();
    }

    /**
     * Encap(pk) -> (ss, ct) as per Section 3.2.
     */
    public SecretWithEncapsulation encapsulate(CompositePublicKey publicKey)
        throws InvalidKeyException
    {
        List<PublicKey> compKeys = publicKey.getPublicKeys();
        List<Provider> providers = publicKey.getProviders(); // may be null or contain nulls
        if (compKeys.size() != 2)
        {
            throw new InvalidKeyException("Composite key must have exactly 2 components");
        }

        PublicKey mlkemPK = compKeys.get(0);
        PublicKey tradPK = compKeys.get(1);
        Provider mlkemProv = resolveProvider((providers != null && !providers.isEmpty()) ? providers.get(0) : null);
        Provider tradProv = resolveProvider((providers != null && providers.size() > 1) ? providers.get(1) : null);

        byte[] mlkemCT;
        byte[] tradSS = null, tradCT;
        byte[] tradPKBytes;

        try
        {
            // ----- ML-KEM encapsulation using provider-specific KeyGenerator -----
            KeyGenerator kemGen = (mlkemProv == null)
                ? KeyGenerator.getInstance("ML-KEM")
                : KeyGenerator.getInstance("ML-KEM", mlkemProv);
            KEMGenerateSpec genSpec = new KEMGenerateSpec.Builder(mlkemPK, "", 256).withKdfAlgorithm(null).build();
            kemGen.init(genSpec, random);
            SecretKeyWithEncapsulation mlkemResult = (SecretKeyWithEncapsulation)kemGen.generateKey();
            mlkemCT = mlkemResult.getEncapsulation();

            // ----- Traditional KEM encapsulation -----
            String tradAlg = CompositeIndex.getTraditionalAlgorithmName(compositeOID);

            if ("RSA".equals(tradAlg))
            {
                Cipher rsaCipher = (tradProv == null) ? Cipher.getInstance("RSA/NONE/OAEPPadding")
                    : Cipher.getInstance("RSA/NONE/OAEPPadding", tradProv);

                rsaCipher.init(Cipher.ENCRYPT_MODE, tradPK, oaepSpec, random);
                tradSS = new byte[32];
                random.nextBytes(tradSS);
                tradCT = rsaCipher.doFinal(tradSS);
                tradPKBytes = getSubjectPublicKeyBytes(tradPK);
            }
            else if ("ECDH".equals(tradAlg))
            {
                String curveName;
                try
                {
                    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(tradPK.getEncoded());
                    X962Parameters params = X962Parameters.getInstance(spki.getAlgorithm().getParameters());

                    if (params.isNamedCurve())
                    {
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)params.getParameters();
                        curveName = oid.getId();
                    }
                    else
                    {
                        throw new IllegalArgumentException("Curve is not named (implicit parameters)");
                    }
                }
                catch (Exception e)
                {
                    throw new IllegalArgumentException("Cannot determine curve from EC public key: " + e.getMessage(), e);
                }
                KeyPairGenerator ephemKPG = (tradProv == null) ? KeyPairGenerator.getInstance("ECDH")
                    : KeyPairGenerator.getInstance("ECDH", tradProv);
                ephemKPG.initialize(new ECGenParameterSpec(curveName), random);
                KeyPair ephemPair = ephemKPG.generateKeyPair();
                PrivateKey ephemPriv = ephemPair.getPrivate();
                tradCT = getSubjectPublicKeyBytes(ephemPair.getPublic());
                tradPKBytes = getSubjectPublicKeyBytes(tradPK);
                tradSS = getTradSS(tradProv, "ECDH", tradPK, ephemPriv);
            }
            else if ("X25519".equals(tradAlg))
            {
                KeyPair ephemPair = getXDHKeyPair(tradProv, 255, "X25519");
                PrivateKey ephemPriv = ephemPair.getPrivate();
                // draft sec. 4: the ciphertext is the raw RFC 7748 public key, not the SPKI wrapper.
                tradCT = getSubjectPublicKeyBytes(ephemPair.getPublic());
                tradPKBytes = getSubjectPublicKeyBytes(tradPK);
                tradSS = getTradSS(tradProv, tradPKBytes, "X25519", EdECObjectIdentifiers.id_X25519, 32, ephemPriv);
            }
            else if ("X448".equals(tradAlg))
            {
                KeyPair ephemPair = getXDHKeyPair(tradProv, 448, "X448");
                PrivateKey ephemPriv = ephemPair.getPrivate();
                // draft sec. 4: the ciphertext is the raw RFC 7748 public key, not the SPKI wrapper.
                tradCT = getSubjectPublicKeyBytes(ephemPair.getPublic());
                tradPKBytes = getSubjectPublicKeyBytes(tradPK);
                tradSS = getTradSS(tradProv, tradPKBytes, "X448", EdECObjectIdentifiers.id_X448, 56, ephemPriv);
            }
            else
            {
                throw new NoSuchAlgorithmException("Unsupported traditional algorithm: " + tradAlg);
            }

            byte[] compositeCT = Arrays.concatenate(mlkemCT, tradCT);
            return new SecretWithEncapsulationImpl(kemCombiner(mlkemResult.getEncoded(), tradSS, tradCT, tradPKBytes,
                compositeOID), compositeCT);
        }
        catch (Exception e)
        {
            throw new InvalidKeyException("Traditional encapsulation failed: " + e.getMessage(), e);
        }
        finally
        {
            Arrays.clear(tradSS);
        }
    }

    /**
     * Decap(sk, ct) -> ss as per Section 3.3.
     */
    public byte[] decapsulate(CompositePrivateKey privateKey, byte[] ciphertext)
        throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException,
        IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException
    {
        // Deserialize ciphertext
        int mlkemCTSize = CompositeIndex.getAlgorithmName(compositeOID).contains("768") ? 1088 : 1568;
        if (ciphertext.length < mlkemCTSize)
        {
            throw new IllegalArgumentException("Ciphertext too short for ML-KEM component");
        }

        byte[] mlkemCT = new byte[mlkemCTSize];
        byte[] tradCT = new byte[ciphertext.length - mlkemCTSize];
        System.arraycopy(ciphertext, 0, mlkemCT, 0, mlkemCTSize);
        System.arraycopy(ciphertext, mlkemCTSize, tradCT, 0, tradCT.length);

        List<PrivateKey> compKeys = privateKey.getPrivateKeys();
        List<Provider> providers = privateKey.getProviders(); // assume similar getter exists
        if (compKeys.size() != 2)
        {
            throw new InvalidKeyException("Composite key must have exactly 2 components");
        }

        PrivateKey mlkemSK = compKeys.get(0);
        PrivateKey tradSK = compKeys.get(1);
        Provider mlkemProv = resolveProvider((providers != null && !providers.isEmpty()) ? providers.get(0) : null);
        Provider tradProv = resolveProvider((providers != null && providers.size() > 1) ? providers.get(1) : null);

        byte[] tradSS = null;
        byte[] tradPKBytes;

        try
        {
            // ----- ML-KEM decapsulation using provider-specific KeyGenerator -----
            KeyGenerator kemGen = (mlkemProv == null) ? KeyGenerator.getInstance("ML-KEM")
                : KeyGenerator.getInstance("ML-KEM", mlkemProv);
            KEMExtractSpec extSpec = new KEMExtractSpec.Builder(mlkemSK, mlkemCT, "", 256).withKdfAlgorithm(null).build();
            kemGen.init(extSpec);
            SecretKeyWithEncapsulation mlkemResult = (SecretKeyWithEncapsulation)kemGen.generateKey();

            // ----- Traditional KEM decapsulation -----
            String tradAlg = CompositeIndex.getTraditionalAlgorithmName(compositeOID);

            if ("RSA".equals(tradAlg))
            {
                Cipher rsaCipher = (tradProv == null)
                    ? Cipher.getInstance("RSA/NONE/OAEPPadding")
                    : Cipher.getInstance("RSA/NONE/OAEPPadding", tradProv);
                rsaCipher.init(Cipher.DECRYPT_MODE, tradSK, oaepSpec);
                tradSS = rsaCipher.doFinal(tradCT);

                RSAPublicKey rsaPub;
                if (tradSK instanceof RSAPrivateCrtKey)
                {
                    RSAPrivateCrtKey rsaCrt = (RSAPrivateCrtKey)tradSK;
                    rsaPub = new RSAPublicKey(rsaCrt.getModulus(), rsaCrt.getPublicExponent());
                }
                else
                {
                    RSAPrivateKey rsaPriv = RSAPrivateKey.getInstance(PrivateKeyInfo.getInstance(tradSK.getEncoded()).parsePrivateKey());
                    rsaPub = new RSAPublicKey(rsaPriv.getModulus(), rsaPriv.getPublicExponent());
                }
                tradPKBytes = rsaPub.getEncoded(ASN1Encoding.DER);
            }
            else if ("ECDH".equals(tradAlg))
            {
                ECPrivateKey ecPriv = (ECPrivateKey)tradSK;
                ECParameterSpec params = ecPriv.getParams();
                int len = (params.getCurve().getField().getFieldSize() + 7) >>> 3;
                if (tradCT.length != 1 + 2 * len || tradCT[0] != 0x04)
                {
                    throw new IllegalArgumentException("malformed EC point in composite ciphertext");
                }
                byte[] xBytes = new byte[len];
                byte[] yBytes = new byte[len];
                System.arraycopy(tradCT, 1, xBytes, 0, len);
                System.arraycopy(tradCT, 1 + len, yBytes, 0, len);
                java.security.spec.ECPoint point = new java.security.spec.ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
                ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, params);
                tradSS = getTradSS(tradProv, "ECDH", getPublicKey("EC", tradProv, pubSpec), tradSK);
                tradPKBytes = getSubjectPublicKeyBytes(getPublicKeyFromPrivate(tradSK, tradProv));
            }
            else if ("X25519".equals(tradAlg))
            {
                tradSS = getTradSS(tradProv, tradCT, "X25519", EdECObjectIdentifiers.id_X25519, 32, tradSK);
                tradPKBytes = getSubjectPublicKeyBytes(getPublicKeyFromPrivate(tradSK, tradProv));
            }
            else if ("X448".equals(tradAlg))
            {
                tradSS = getTradSS(tradProv, tradCT, "X448", EdECObjectIdentifiers.id_X448, 56, tradSK);
                tradPKBytes = getSubjectPublicKeyBytes(getPublicKeyFromPrivate(tradSK, tradProv));
            }
            else
            {
                throw new NoSuchAlgorithmException("Unsupported traditional algorithm: " + tradAlg);
            }
            return kemCombiner(mlkemResult.getEncoded(), tradSS, tradCT, tradPKBytes, compositeOID);
        }
        finally
        {
            Arrays.clear(tradSS);
        }
    }

    /**
     * Resolve the provider to use for a component operation. Composite ML-KEM is a BouncyCastle
     * feature and its component keys are BC keys, so when a component does not carry an explicit
     * provider we fall back to BouncyCastle rather than the JCE default. The default EC provider
     * (e.g. SunEC) may reject a BC key or an unsupported curve such as the brainpool curves, which
     * is exactly the failure this avoids.
     */
    private static Provider resolveProvider(Provider provider)
    {
        if (provider != null)
        {
            return provider;
        }

        Provider bc = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

        return (bc != null) ? bc : new BouncyCastleProvider();
    }

    private byte[] getSubjectPublicKeyBytes(PublicKey ecPubKey)
    {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ecPubKey.getEncoded());
        return spki.getPublicKeyData().getOctets();
    }

    private PublicKey getPublicKeyFromPrivate(PrivateKey privKey, Provider prov)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException
    {
        String alg = privKey.getAlgorithm();
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(privKey.getEncoded());
        AlgorithmIdentifier algId = pki.getPrivateKeyAlgorithm();
        SubjectPublicKeyInfo spki;
        if (pki.getPublicKeyData() != null)
        {
            spki = new SubjectPublicKeyInfo(algId, pki.getPublicKeyData());
        }
        else
        {
            byte[] rawPub;
            if ("X25519".equals(alg))
            {
                rawPub = new X25519PrivateKeyParameters(
                    ASN1OctetString.getInstance(pki.parsePrivateKey()).getOctets(), 0).generatePublicKey().getEncoded();
            }
            else if ("X448".equals(alg))
            {
                rawPub = new X448PrivateKeyParameters(
                    ASN1OctetString.getInstance(pki.parsePrivateKey()).getOctets(), 0).generatePublicKey().getEncoded();
            }
            else if ("EC".equals(alg) || "ECDH".equals(alg))
            {
                org.bouncycastle.asn1.sec.ECPrivateKey ecKey = org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(pki.parsePrivateKey());
                X962Parameters params = X962Parameters.getInstance(algId.getParameters());
                ECDomainParameters domainParams = ECUtil.getDomainParameters(BouncyCastleProvider.CONFIGURATION, params);
                ECPrivateKeyParameters ecParams = new ECPrivateKeyParameters(ecKey.getKey(), domainParams);
                ECPoint q = domainParams.getG().multiply(ecParams.getD()).normalize();
                rawPub = q.getEncoded(false);
            }
            else
            {
                throw new InvalidKeyException("Cannot extract public key from private key");
            }
            spki = new SubjectPublicKeyInfo(algId, rawPub);
        }
        return getPublicKey(alg, prov, new X509EncodedKeySpec(spki.getEncoded()));
    }

    private PublicKey getPublicKey(String alg, Provider prov, KeySpec pubSpec)
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        KeyFactory kf = (prov == null) ? KeyFactory.getInstance(alg) : KeyFactory.getInstance(alg, prov);
        return kf.generatePublic(pubSpec);
    }

    private byte[] getTradSS(Provider tradProv, byte[] tradPKBytes, String algorithm, ASN1ObjectIdentifier identifier,
                             int keySize, PrivateKey ephemPriv)
        throws NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidKeySpecException
    {
        if (tradPKBytes.length != keySize)
        {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(tradPKBytes);
            tradPKBytes = spki.getPublicKeyData().getOctets();
            if (tradPKBytes.length != keySize)
            {
                throw new IllegalArgumentException("Invalid public key encoding");
            }
        }
        PublicKey receiverPub = getPublicKey(algorithm, tradProv, new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(identifier),
            tradPKBytes).getEncoded(ASN1Encoding.DER)));
        return getTradSS(tradProv, algorithm, receiverPub, ephemPriv);
    }

    private byte[] getTradSS(Provider tradProv, String algorithm, PublicKey receiverPub, PrivateKey ephemPriv)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        KeyAgreement ka = (tradProv == null) ? KeyAgreement.getInstance(algorithm) : KeyAgreement.getInstance(algorithm, tradProv);
        ka.init(ephemPriv);
        ka.doPhase(receiverPub, true);
        return ka.generateSecret();
    }

    private KeyPair getXDHKeyPair(Provider tradProv, int keySize, String algorithm)
        throws NoSuchAlgorithmException
    {
        KeyPairGenerator ephemKPG = (tradProv == null) ? KeyPairGenerator.getInstance(algorithm)
            : KeyPairGenerator.getInstance(algorithm, tradProv);
        ephemKPG.initialize(keySize, random);
        return ephemKPG.generateKeyPair();
    }
}