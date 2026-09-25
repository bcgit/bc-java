package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientIdentifier;
import org.bouncycastle.asn1.cms.OriginatorPublicKey;
import org.bouncycastle.asn1.cms.RecipientEncryptedKey;
import org.bouncycastle.asn1.cms.RecipientKeyIdentifier;
import org.bouncycastle.asn1.cms.ecc.MQVuserKeyingMaterial;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.Gost2814789EncryptedKey;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyAgreeRecipientInfoGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.SecretKeySizeProvider;
import org.bouncycastle.util.Arrays;

public class JceKeyAgreeRecipientInfoGenerator
    extends KeyAgreeRecipientInfoGenerator
{
    private SecretKeySizeProvider keySizeProvider = new DefaultSecretKeySizeProvider();

    private List recipientIDs = new ArrayList();
    private List recipientKeys = new ArrayList();
    private PublicKey senderPublicKey;
    private PrivateKey senderPrivateKey;

    private EnvelopedDataHelper helper = CMSUtils.createDefaultHelper();
    private SecureRandom random;
    private KeyPair ephemeralKP;
    private byte[] userKeyingMaterial;

    public JceKeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID, PrivateKey senderPrivateKey, PublicKey senderPublicKey, ASN1ObjectIdentifier keyEncryptionOID)
    {
        super(keyAgreementOID, SubjectPublicKeyInfo.getInstance(senderPublicKey.getEncoded()), keyEncryptionOID);

        this.senderPublicKey = senderPublicKey;
        this.senderPrivateKey = senderPrivateKey;
    }

    public JceKeyAgreeRecipientInfoGenerator setUserKeyingMaterial(byte[] userKeyingMaterial)
    {
        this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);

        return this;
    }

    public JceKeyAgreeRecipientInfoGenerator setProvider(Provider provider)
    {
        this.helper = CMSUtils.createProviderHelper(provider);

        return this;
    }

    public JceKeyAgreeRecipientInfoGenerator setProvider(String providerName)
    {
        this.helper = CMSUtils.createNamedHelper(providerName);

        return this;
    }

    public JceKeyAgreeRecipientInfoGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    /**
     * Add a recipient based on the passed in certificate's public key and its issuer and serial number.
     * 
     * @param recipientCert recipient's certificate
     * @return the current instance.
     * @throws CertificateEncodingException  if the necessary data cannot be extracted from the certificate.
     */
    public JceKeyAgreeRecipientInfoGenerator addRecipient(X509Certificate recipientCert)
        throws CertificateEncodingException
    {
        recipientIDs.add(new KeyAgreeRecipientIdentifier(CMSUtils.getIssuerAndSerialNumber(recipientCert)));
        recipientKeys.add(recipientCert.getPublicKey());

        return this;
    }

    /**
     * Add a recipient identified by the passed in subjectKeyID and the for the passed in public key.
     *
     * @param subjectKeyID identifier actual recipient will use to match the private key.
     * @param publicKey the public key for encrypting the secret key.
     * @return the current instance.
     * @throws CertificateEncodingException
     */
    public JceKeyAgreeRecipientInfoGenerator addRecipient(byte[] subjectKeyID, PublicKey publicKey)
        throws CertificateEncodingException
    {
        recipientIDs.add(new KeyAgreeRecipientIdentifier(new RecipientKeyIdentifier(subjectKeyID)));
        recipientKeys.add(publicKey);

        return this;
    }

    public ASN1Sequence generateRecipientEncryptedKeys(AlgorithmIdentifier keyAgreeAlgorithm, AlgorithmIdentifier keyEncryptionAlgorithm, GenericKey contentEncryptionKey)
        throws CMSException
    {
        if (recipientIDs.isEmpty())
        {
            throw new CMSException("No recipients associated with generator - use addRecipient()");
        }

        ASN1ObjectIdentifier keyAgreementOID = keyAgreeAlgorithm.getAlgorithm();

        // RFC 3370 sec. 4.1.2 (static-static DH) and RFC 4490 sec. 4.1.1 (GOST): the ukm MUST be present
        // TODO Consider delegating to an OID classifier for static-key agreement schemes
        if (userKeyingMaterial == null
            && (PKCSObjectIdentifiers.id_alg_SSDH.equals(keyAgreementOID) || CMSUtils.isGOST(keyAgreementOID)))
        {
            throw new CMSException("User keying material must be set for static keys.");
        }

        init(keyAgreementOID);

        PrivateKey senderPrivateKey = this.senderPrivateKey;

        ASN1EncodableVector recipientEncryptedKeys = new ASN1EncodableVector();
        for (int i = 0; i != recipientIDs.size(); i++)
        {
            PublicKey recipientPublicKey = (PublicKey)recipientKeys.get(i);
            KeyAgreeRecipientIdentifier karId = (KeyAgreeRecipientIdentifier)recipientIDs.get(i);

            try
            {
                AlgorithmParameterSpec agreementParamSpec = null;

                if (CMSUtils.isMQV(keyAgreementOID))
                {
                    // RFC 5753 sec. 3.2.2 / 7.2: the KDF SharedInfo is DER(ECC-CMS-SharedInfo), with the
                    // addedukm as its entityUInfo, exactly as for ECDH
                    byte[] ukmKeyingMaterial = ecc_cms_Generator.generateKDFMaterial(keyEncryptionAlgorithm, keySizeProvider.getKeySize(keyEncryptionAlgorithm.getAlgorithm()), userKeyingMaterial);

                    agreementParamSpec = new MQVParameterSpec(ephemeralKP, recipientPublicKey, ukmKeyingMaterial);
                }
                else if (CMSUtils.isEC(keyAgreementOID))
                {
                    byte[] ukmKeyingMaterial = ecc_cms_Generator.generateKDFMaterial(keyEncryptionAlgorithm, keySizeProvider.getKeySize(keyEncryptionAlgorithm.getAlgorithm()), userKeyingMaterial);

                    agreementParamSpec = new UserKeyingMaterialSpec(ukmKeyingMaterial);
                }
                else if (CMSUtils.isGOST(keyAgreementOID) ||
                         CMSUtils.isRFC2631(keyAgreementOID))
                {
                    if (userKeyingMaterial != null)
                    {
                        agreementParamSpec = new UserKeyingMaterialSpec(userKeyingMaterial);
                    }
                }
                else
                {
                    throw new CMSException("Unknown key agreement algorithm: " + keyAgreementOID);
                }

                ASN1ObjectIdentifier keyEncryptionOID = keyEncryptionAlgorithm.getAlgorithm();

                // Use key agreement to choose a wrap key for this recipient
                KeyAgreement keyAgreement = helper.createKeyAgreement(keyAgreementOID);
                keyAgreement.init(senderPrivateKey, agreementParamSpec, random);
                keyAgreement.doPhase(recipientPublicKey, true);

                SecretKey keyEncryptionKey = keyAgreement.generateSecret(keyEncryptionOID.getId());

                // Wrap the content encryption key with the agreement key
                Cipher keyEncryptionCipher = helper.createCipher(keyEncryptionOID);

                byte[] encryptedKeyOctets;
                if (CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap.equals(keyEncryptionOID) ||
                    CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap.equals(keyEncryptionOID))
                {
                    keyEncryptionCipher.init(Cipher.WRAP_MODE, keyEncryptionKey,
                        new GOST28147WrapParameterSpec(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet, userKeyingMaterial));

                    byte[] encKeyBytes = keyEncryptionCipher.wrap(helper.getJceKey(contentEncryptionKey));

                    Gost2814789EncryptedKey encKey = new Gost2814789EncryptedKey(
                        Arrays.copyOfRange(encKeyBytes, 0, encKeyBytes.length - 4),
                        Arrays.copyOfRange(encKeyBytes, encKeyBytes.length - 4, encKeyBytes.length));

                    encryptedKeyOctets = encKey.getEncoded(ASN1Encoding.DER);
                }
                else
                {
                    keyEncryptionCipher.init(Cipher.WRAP_MODE, keyEncryptionKey, random);

                    encryptedKeyOctets = keyEncryptionCipher.wrap(helper.getJceKey(contentEncryptionKey));
                }

                recipientEncryptedKeys.add(new RecipientEncryptedKey(karId, new DEROctetString(encryptedKeyOctets)));
            }
            catch (CMSException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new CMSException("Cannot perform agreement step: " + e.getMessage(), e);
            }
        }

        return new DERSequence(recipientEncryptedKeys);
    }

    protected byte[] getUserKeyingMaterial(AlgorithmIdentifier keyAgreeAlg)
        throws CMSException
    {
        init(keyAgreeAlg.getAlgorithm());

        if (ephemeralKP != null)
        {
            OriginatorPublicKey originatorPublicKey = createOriginatorPublicKey(SubjectPublicKeyInfo.getInstance(ephemeralKP.getPublic().getEncoded()));

            try
            {
                if (userKeyingMaterial != null)
                {
                    return new MQVuserKeyingMaterial(originatorPublicKey, new DEROctetString(userKeyingMaterial)).getEncoded();
                }
                else
                {
                    return new MQVuserKeyingMaterial(originatorPublicKey, null).getEncoded();
                }
            }
            catch (IOException e)
            {
                throw new CMSException("unable to encode user keying material: " + e.getMessage(), e);
            }
        }

        return userKeyingMaterial;
    }

    protected void generationComplete()
    {
        // an MQV ephemeral key pair is shared by the recipients of one KeyAgreeRecipientInfo only
        ephemeralKP = null;
    }

    private void init(ASN1ObjectIdentifier keyAgreementOID)
        throws CMSException
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        if (CMSUtils.isMQV(keyAgreementOID))
        {
            if (ephemeralKP == null)
            {
                try
                {
                    SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(senderPublicKey.getEncoded());

                    ECKeyPairGenerator ephemKPG = new ECKeyPairGenerator();
                    ECPublicKeyParameters pubParams = (ECPublicKeyParameters)PublicKeyFactory.createKey(pubInfo);

                    ephemKPG.init(new ECKeyGenerationParameters(pubParams.getParameters(), random));

                    AsymmetricCipherKeyPair kp = ephemKPG.generateKeyPair();

                    KeyFactory kFact = helper.createKeyFactory(keyAgreementOID);

                    ephemeralKP = new KeyPair(
                        kFact.generatePublic(new X509EncodedKeySpec(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()).getEncoded())),
                        kFact.generatePrivate(new PKCS8EncodedKeySpec(PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()).getEncoded())));
                }
                catch (Exception e)
                {
                    throw new CMSException(
                        "cannot determine MQV ephemeral key pair parameters from public key: " + e, e);
                }
            }
        }
    }

    private static KeyMaterialGenerator ecc_cms_Generator = new RFC5753KeyMaterialGenerator();
}
