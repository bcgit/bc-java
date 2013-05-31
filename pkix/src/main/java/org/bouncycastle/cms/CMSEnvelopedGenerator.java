package org.bouncycastle.cms;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;

/**
 * General class for generating a CMS enveloped-data message.
 */
public class CMSEnvelopedGenerator
{
    public static final String  DES_EDE3_CBC    = PKCSObjectIdentifiers.des_EDE3_CBC.getId();
    public static final String  RC2_CBC         = PKCSObjectIdentifiers.RC2_CBC.getId();
    public static final String  IDEA_CBC        = "1.3.6.1.4.1.188.7.1.1.2";
    public static final String  CAST5_CBC       = "1.2.840.113533.7.66.10";
    public static final String  AES128_CBC      = NISTObjectIdentifiers.id_aes128_CBC.getId();
    public static final String  AES192_CBC      = NISTObjectIdentifiers.id_aes192_CBC.getId();
    public static final String  AES256_CBC      = NISTObjectIdentifiers.id_aes256_CBC.getId();
    public static final String  CAMELLIA128_CBC = NTTObjectIdentifiers.id_camellia128_cbc.getId();
    public static final String  CAMELLIA192_CBC = NTTObjectIdentifiers.id_camellia192_cbc.getId();
    public static final String  CAMELLIA256_CBC = NTTObjectIdentifiers.id_camellia256_cbc.getId();
    public static final String  SEED_CBC        = KISAObjectIdentifiers.id_seedCBC.getId();

    public static final String  DES_EDE3_WRAP   = PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId();
    public static final String  AES128_WRAP     = NISTObjectIdentifiers.id_aes128_wrap.getId();
    public static final String  AES192_WRAP     = NISTObjectIdentifiers.id_aes192_wrap.getId();
    public static final String  AES256_WRAP     = NISTObjectIdentifiers.id_aes256_wrap.getId();
    public static final String  CAMELLIA128_WRAP = NTTObjectIdentifiers.id_camellia128_wrap.getId();
    public static final String  CAMELLIA192_WRAP = NTTObjectIdentifiers.id_camellia192_wrap.getId();
    public static final String  CAMELLIA256_WRAP = NTTObjectIdentifiers.id_camellia256_wrap.getId();
    public static final String  SEED_WRAP       = KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId();

    public static final String  ECDH_SHA1KDF    = X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.getId();
    public static final String  ECMQV_SHA1KDF   = X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme.getId();

    final List oldRecipientInfoGenerators = new ArrayList();
    final List recipientInfoGenerators = new ArrayList();

    protected CMSAttributeTableGenerator unprotectedAttributeGenerator = null;

    final SecureRandom rand;
    protected OriginatorInfo originatorInfo;

    /**
     * base constructor
     */
    public CMSEnvelopedGenerator()
    {
        this(new SecureRandom());
    }

    /**
     * constructor allowing specific source of randomness
     * @param rand instance of SecureRandom to use
     */
    public CMSEnvelopedGenerator(
        SecureRandom rand)
    {
        this.rand = rand;
    }

    public void setUnprotectedAttributeGenerator(CMSAttributeTableGenerator unprotectedAttributeGenerator)
    {
        this.unprotectedAttributeGenerator = unprotectedAttributeGenerator;
    }


    public void setOriginatorInfo(OriginatorInformation originatorInfo)
    {
        this.originatorInfo = originatorInfo.toASN1Structure();
    }

    /**
     * add a recipient.
     *
     * @deprecated use the addRecipientGenerator and JceKeyTransRecipientInfoGenerator
     * @param cert recipient's public key certificate
     * @exception IllegalArgumentException if there is a problem with the certificate
     */
    public void addKeyTransRecipient(
        X509Certificate cert)
        throws IllegalArgumentException
    {
        try
        {
            oldRecipientInfoGenerators.add(new JceKeyTransRecipientInfoGenerator(cert));
        }
        catch (CertificateEncodingException e)
        {
            throw new IllegalArgumentException("unable to encode certificate: " + e.getMessage());
        }
    }

    /**
     * add a recipient
     *
     * @deprecated use the addRecipientGenerator and JceKeyTransRecipientInfoGenerator
     * @param key the public key used by the recipient
     * @param subKeyId the identifier for the recipient's public key
     * @exception IllegalArgumentException if there is a problem with the key
     */
    public void addKeyTransRecipient(
        PublicKey   key,
        byte[]      subKeyId)
        throws IllegalArgumentException
    {
        oldRecipientInfoGenerators.add(new JceKeyTransRecipientInfoGenerator(subKeyId, key));
    }

    /**
     * add a KEK recipient.
     *
     * @deprecated use the addRecipientGenerator and JceKEKRecipientInfoGenerator
     * @param key the secret key to use for wrapping
     * @param keyIdentifier the byte string that identifies the key
     */
    public void addKEKRecipient(
        SecretKey   key,
        byte[]      keyIdentifier)
    {
        addKEKRecipient(key, new KEKIdentifier(keyIdentifier, null, null));
    }

    /**
     * add a KEK recipient.
     *
     * @deprecated use the addRecipientGenerator and JceKEKRecipientInfoGenerator
     * @param key the secret key to use for wrapping
     * @param kekIdentifier a KEKIdentifier structure (identifies the key)
     */
    public void addKEKRecipient(
        SecretKey       key,
        KEKIdentifier   kekIdentifier)
    {
        oldRecipientInfoGenerators.add(new JceKEKRecipientInfoGenerator(kekIdentifier, key));
    }

    /**
     * @deprecated use addRecipientGenerator and JcePasswordRecipientInfoGenerator
     * @param pbeKey PBE key
     * @param kekAlgorithmOid key encryption algorithm to use.
     */
    public void addPasswordRecipient(
        CMSPBEKey pbeKey,
        String    kekAlgorithmOid)
    {
        oldRecipientInfoGenerators.add(new JcePasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(kekAlgorithmOid), pbeKey.getPassword())
            .setSaltAndIterationCount(pbeKey.getSalt(), pbeKey.getIterationCount())
            .setPasswordConversionScheme((pbeKey instanceof PKCS5Scheme2UTF8PBEKey) ? PasswordRecipient.PKCS5_SCHEME2_UTF8 : PasswordRecipient.PKCS5_SCHEME2));
    }

    /**
     * Add a key agreement based recipient.
     *
     * @deprecated use the addRecipientGenerator and JceKeyAgreeRecipientInfoGenerator
     * @param agreementAlgorithm key agreement algorithm to use.
     * @param senderPrivateKey private key to initialise sender side of agreement with.
     * @param senderPublicKey sender public key to include with message.
     * @param recipientCert recipient's public key certificate.
     * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
     * @param provider provider to use for the agreement calculation.
     * @exception NoSuchProviderException if the specified provider cannot be found
     * @exception NoSuchAlgorithmException if the algorithm requested cannot be found
     * @exception InvalidKeyException if the keys are inappropriate for the algorithm specified
     */
    public void addKeyAgreementRecipient(
        String           agreementAlgorithm,
        PrivateKey       senderPrivateKey,
        PublicKey        senderPublicKey,
        X509Certificate  recipientCert,
        String           cekWrapAlgorithm,
        String           provider)
        throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException
    {
        addKeyAgreementRecipient(agreementAlgorithm, senderPrivateKey, senderPublicKey, recipientCert,  cekWrapAlgorithm, CMSUtils.getProvider(provider));
    }

    /**
     * Add a key agreement based recipient.
     *
     * @deprecated use the addRecipientGenerator and JceKeyAgreeRecipientInfoGenerator
     * @param agreementAlgorithm key agreement algorithm to use.
     * @param senderPrivateKey private key to initialise sender side of agreement with.
     * @param senderPublicKey sender public key to include with message.
     * @param recipientCert recipient's public key certificate.
     * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
     * @param provider provider to use for the agreement calculation.
     * @exception NoSuchAlgorithmException if the algorithm requested cannot be found
     * @exception InvalidKeyException if the keys are inappropriate for the algorithm specified
     */
    public void addKeyAgreementRecipient(
        String           agreementAlgorithm,
        PrivateKey       senderPrivateKey,
        PublicKey        senderPublicKey,
        X509Certificate  recipientCert,
        String           cekWrapAlgorithm,
        Provider         provider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        List recipients = new ArrayList();

        recipients.add(recipientCert);

        addKeyAgreementRecipients(agreementAlgorithm, senderPrivateKey, senderPublicKey,
            recipients, cekWrapAlgorithm, provider);
    }

    /**
     * Add multiple key agreement based recipients (sharing a single KeyAgreeRecipientInfo structure).
     *
     * @deprecated use the addRecipientGenerator and JceKeyAgreeRecipientInfoGenerator
     * @param agreementAlgorithm key agreement algorithm to use.
     * @param senderPrivateKey private key to initialise sender side of agreement with.
     * @param senderPublicKey sender public key to include with message.
     * @param recipientCerts recipients' public key certificates.
     * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
     * @param provider provider to use for the agreement calculation.
     * @exception NoSuchAlgorithmException if the algorithm requested cannot be found
     * @exception InvalidKeyException if the keys are inappropriate for the algorithm specified
     */
    public void addKeyAgreementRecipients(
        String           agreementAlgorithm,
        PrivateKey       senderPrivateKey,
        PublicKey        senderPublicKey,
        Collection       recipientCerts,
        String           cekWrapAlgorithm,
        String           provider)
        throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException
    {
        addKeyAgreementRecipients(agreementAlgorithm, senderPrivateKey, senderPublicKey, recipientCerts, cekWrapAlgorithm, CMSUtils.getProvider(provider));
    }

    /**
     * Add multiple key agreement based recipients (sharing a single KeyAgreeRecipientInfo structure).
     *
     * @deprecated use the addRecipientGenerator and JceKeyAgreeRecipientInfoGenerator
     * @param agreementAlgorithm key agreement algorithm to use.
     * @param senderPrivateKey private key to initialise sender side of agreement with.
     * @param senderPublicKey sender public key to include with message.
     * @param recipientCerts recipients' public key certificates.
     * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
     * @param provider provider to use for the agreement calculation.
     * @exception NoSuchAlgorithmException if the algorithm requested cannot be found
     * @exception InvalidKeyException if the keys are inappropriate for the algorithm specified
     */
    public void addKeyAgreementRecipients(
        String           agreementAlgorithm,
        PrivateKey       senderPrivateKey,
        PublicKey        senderPublicKey,
        Collection       recipientCerts,
        String           cekWrapAlgorithm,
        Provider         provider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        JceKeyAgreeRecipientInfoGenerator recipientInfoGenerator = new JceKeyAgreeRecipientInfoGenerator(new ASN1ObjectIdentifier(agreementAlgorithm), senderPrivateKey, senderPublicKey, new ASN1ObjectIdentifier(cekWrapAlgorithm)).setProvider(provider);

        for (Iterator it = recipientCerts.iterator(); it.hasNext();)
        {
            try
            {
                recipientInfoGenerator.addRecipient((X509Certificate)it.next());
            }
            catch (CertificateEncodingException e)
            {
                throw new IllegalArgumentException("unable to encode certificate: " + e.getMessage());
            }
        }

        oldRecipientInfoGenerators.add(recipientInfoGenerator);
    }

    /**
     * Add a generator to produce the recipient info required.
     * 
     * @param recipientGenerator a generator of a recipient info object.
     */
    public void addRecipientInfoGenerator(RecipientInfoGenerator recipientGenerator)
    {
        recipientInfoGenerators.add(recipientGenerator);
    }

    protected AlgorithmIdentifier getAlgorithmIdentifier(String encryptionOID, AlgorithmParameters params) throws IOException
    {
        ASN1Encodable asn1Params;
        if (params != null)
        {
            asn1Params = ASN1Primitive.fromByteArray(params.getEncoded("ASN.1"));
        }
        else
        {
            asn1Params = DERNull.INSTANCE;
        }

        return new AlgorithmIdentifier(
            new ASN1ObjectIdentifier(encryptionOID),
            asn1Params);
    }

    protected void convertOldRecipients(SecureRandom rand, Provider provider)
    {
        for (Iterator it = oldRecipientInfoGenerators.iterator(); it.hasNext();)
        {
            Object recipient = it.next();

            if (recipient instanceof JceKeyTransRecipientInfoGenerator)
            {
                JceKeyTransRecipientInfoGenerator recip = (JceKeyTransRecipientInfoGenerator)recipient;

                if (provider != null)
                {
                    recip.setProvider(provider);
                }

                recipientInfoGenerators.add(recip);
            }
            else if (recipient instanceof KEKRecipientInfoGenerator)
            {
                JceKEKRecipientInfoGenerator recip = (JceKEKRecipientInfoGenerator)recipient;

                if (provider != null)
                {
                    recip.setProvider(provider);
                }

                recip.setSecureRandom(rand);

                recipientInfoGenerators.add(recip);
            }
            else if (recipient instanceof JcePasswordRecipientInfoGenerator)
            {
                JcePasswordRecipientInfoGenerator recip = (JcePasswordRecipientInfoGenerator)recipient;

                if (provider != null)
                {
                    recip.setProvider(provider);
                }

                recip.setSecureRandom(rand);

                recipientInfoGenerators.add(recip);
            }
            else if (recipient instanceof JceKeyAgreeRecipientInfoGenerator)
            {
                JceKeyAgreeRecipientInfoGenerator recip = (JceKeyAgreeRecipientInfoGenerator)recipient;

                if (provider != null)
                {
                    recip.setProvider(provider);
                }

                recip.setSecureRandom(rand);

                recipientInfoGenerators.add(recip);
            }
        }

        oldRecipientInfoGenerators.clear();
    }
}
