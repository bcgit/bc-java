package org.bouncycastle.operator.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jcajce.util.AlgorithmParametersUtils;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Integers;

class OperatorHelper
{
    private static final Map oids = new HashMap();
    private static final Map asymmetricWrapperAlgNames = new HashMap();
    private static final Map symmetricWrapperAlgNames = new HashMap();
    private static final Map symmetricKeyAlgNames = new HashMap();
    private static final Map symmetricWrapperKeySizes = new HashMap();

    static
    {
        //
        // reverse mappings
        //
        oids.put(EdECObjectIdentifiers.id_Ed25519, "Ed25519");
        oids.put(EdECObjectIdentifiers.id_Ed448, "Ed448");
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "SHA1WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
        oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256WITHECGOST3410-2012-256");
        oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512WITHECGOST3410-2012-512");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");
        oids.put(IsaraObjectIdentifiers.id_alg_xmss, "XMSS");
        oids.put(IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");

        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "MD5WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "MD2WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "SHA1WITHDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
        oids.put(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
        oids.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");

        oids.put(OIWObjectIdentifiers.idSHA1, "SHA1");
        oids.put(NISTObjectIdentifiers.id_sha224, "SHA224");
        oids.put(NISTObjectIdentifiers.id_sha256, "SHA256");
        oids.put(NISTObjectIdentifiers.id_sha384, "SHA384");
        oids.put(NISTObjectIdentifiers.id_sha512, "SHA512");
        oids.put(TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");
        oids.put(TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160");
        oids.put(TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");

        asymmetricWrapperAlgNames.put(PKCSObjectIdentifiers.rsaEncryption, "RSA/ECB/PKCS1Padding");

        asymmetricWrapperAlgNames.put(CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410");

        symmetricWrapperAlgNames.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap, "DESEDEWrap");
        symmetricWrapperAlgNames.put(PKCSObjectIdentifiers.id_alg_CMSRC2wrap, "RC2Wrap");
        symmetricWrapperAlgNames.put(NISTObjectIdentifiers.id_aes128_wrap, "AESWrap");
        symmetricWrapperAlgNames.put(NISTObjectIdentifiers.id_aes192_wrap, "AESWrap");
        symmetricWrapperAlgNames.put(NISTObjectIdentifiers.id_aes256_wrap, "AESWrap");
        symmetricWrapperAlgNames.put(NTTObjectIdentifiers.id_camellia128_wrap, "CamelliaWrap");
        symmetricWrapperAlgNames.put(NTTObjectIdentifiers.id_camellia192_wrap, "CamelliaWrap");
        symmetricWrapperAlgNames.put(NTTObjectIdentifiers.id_camellia256_wrap, "CamelliaWrap");
        symmetricWrapperAlgNames.put(KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap, "SEEDWrap");
        symmetricWrapperAlgNames.put(PKCSObjectIdentifiers.des_EDE3_CBC, "DESede");

        symmetricWrapperKeySizes.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap, Integers.valueOf(192));
        symmetricWrapperKeySizes.put(NISTObjectIdentifiers.id_aes128_wrap, Integers.valueOf(128));
        symmetricWrapperKeySizes.put(NISTObjectIdentifiers.id_aes192_wrap, Integers.valueOf(192));
        symmetricWrapperKeySizes.put(NISTObjectIdentifiers.id_aes256_wrap, Integers.valueOf(256));
        symmetricWrapperKeySizes.put(NTTObjectIdentifiers.id_camellia128_wrap, Integers.valueOf(128));
        symmetricWrapperKeySizes.put(NTTObjectIdentifiers.id_camellia192_wrap, Integers.valueOf(192));
        symmetricWrapperKeySizes.put(NTTObjectIdentifiers.id_camellia256_wrap, Integers.valueOf(256));
        symmetricWrapperKeySizes.put(KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap, Integers.valueOf(128));
        symmetricWrapperKeySizes.put(PKCSObjectIdentifiers.des_EDE3_CBC, Integers.valueOf(192));

        symmetricKeyAlgNames.put(NISTObjectIdentifiers.aes, "AES");
        symmetricKeyAlgNames.put(NISTObjectIdentifiers.id_aes128_CBC, "AES");
        symmetricKeyAlgNames.put(NISTObjectIdentifiers.id_aes192_CBC, "AES");
        symmetricKeyAlgNames.put(NISTObjectIdentifiers.id_aes256_CBC, "AES");
        symmetricKeyAlgNames.put(PKCSObjectIdentifiers.des_EDE3_CBC, "DESede");
        symmetricKeyAlgNames.put(PKCSObjectIdentifiers.RC2_CBC, "RC2");
    }

    private JcaJceHelper helper;

    OperatorHelper(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    String getWrappingAlgorithmName(ASN1ObjectIdentifier algOid)
    {
        return (String)symmetricWrapperAlgNames.get(algOid);
    }

    int getKeySizeInBits(ASN1ObjectIdentifier algOid)
    {
        return ((Integer)symmetricWrapperKeySizes.get(algOid)).intValue();
    }

    KeyPairGenerator createKeyPairGenerator(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        try
        {
            String agreementName = null; //(String)BASE_CIPHER_NAMES.get(algorithm);

            if (agreementName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return helper.createKeyPairGenerator(agreementName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return helper.createKeyPairGenerator(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot create key agreement: " + e.getMessage(), e);
        }
    }

    Cipher createCipher(ASN1ObjectIdentifier algorithm)
        throws OperatorCreationException
    {
        try
        {
            return helper.createCipher(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    KeyAgreement createKeyAgreement(ASN1ObjectIdentifier algorithm)
        throws OperatorCreationException
    {
        try
        {
            String agreementName = null; //(String)BASE_CIPHER_NAMES.get(algorithm);

            if (agreementName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return helper.createKeyAgreement(agreementName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return helper.createKeyAgreement(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException("cannot create key agreement: " + e.getMessage(), e);
        }
    }

    Cipher createAsymmetricWrapper(ASN1ObjectIdentifier algorithm, Map extraAlgNames)
        throws OperatorCreationException
    {
        try
        {
            String cipherName = null;

            if (!extraAlgNames.isEmpty())
            {
                cipherName = (String)extraAlgNames.get(algorithm);
            }

            if (cipherName == null)
            {
                cipherName = (String)asymmetricWrapperAlgNames.get(algorithm);
            }

            if (cipherName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return helper.createCipher(cipherName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // try alternate for RSA
                    if (cipherName.equals("RSA/ECB/PKCS1Padding"))
                    {
                        try
                        {
                            return helper.createCipher("RSA/NONE/PKCS1Padding");
                        }
                        catch (NoSuchAlgorithmException ex)
                        {
                            // Ignore
                        }
                    }
                    // Ignore
                }
            }

            return helper.createCipher(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    Cipher createSymmetricWrapper(ASN1ObjectIdentifier algorithm)
        throws OperatorCreationException
    {
        try
        {
            String cipherName = (String)symmetricWrapperAlgNames.get(algorithm);

            if (cipherName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return helper.createCipher(cipherName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // Ignore
                }
            }
            return helper.createCipher(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    AlgorithmParameters createAlgorithmParameters(AlgorithmIdentifier cipherAlgId)
        throws OperatorCreationException
    {
        AlgorithmParameters parameters;

        if (cipherAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption))
        {
            return null;
        }

        try
        {
            parameters = helper.createAlgorithmParameters(cipherAlgId.getAlgorithm().getId());
        }
        catch (NoSuchAlgorithmException e)
        {
            return null;   // There's a good chance there aren't any!
        }
        catch (NoSuchProviderException e)
        {
            throw new OperatorCreationException("cannot create algorithm parameters: " + e.getMessage(), e);
        }

        try
        {
            parameters.init(cipherAlgId.getParameters().toASN1Primitive().getEncoded());
        }
        catch (IOException e)
        {
            throw new OperatorCreationException("cannot initialise algorithm parameters: " + e.getMessage(), e);
        }

        return parameters;
    }

    MessageDigest createDigest(AlgorithmIdentifier digAlgId)
        throws GeneralSecurityException
    {
        MessageDigest dig;

        try
        {
            if (digAlgId.getAlgorithm().equals(NISTObjectIdentifiers.id_shake256_len))
            {
                dig = helper.createMessageDigest("SHAKE256-" + ASN1Integer.getInstance(digAlgId.getParameters()).getValue());
            }
            else
            {
                dig = helper.createMessageDigest(MessageDigestUtils.getDigestName(digAlgId.getAlgorithm()));
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            //
            // try an alternate
            //
            if (oids.get(digAlgId.getAlgorithm()) != null)
            {
                String digestAlgorithm = (String)oids.get(digAlgId.getAlgorithm());

                dig = helper.createMessageDigest(digestAlgorithm);
            }
            else
            {
                throw e;
            }
        }

        return dig;
    }

    Signature createSignature(AlgorithmIdentifier sigAlgId)
        throws GeneralSecurityException
    {
        String sigName = getSignatureName(sigAlgId);
        Signature sig;

        try
        {
            sig = helper.createSignature(sigName);
        }
        catch (NoSuchAlgorithmException e)
        {
            //
            // try an alternate
            //
            if (sigName.endsWith("WITHRSAANDMGF1"))
            {
                String signatureAlgorithm =
                    sigName.substring(0, sigName.indexOf('W')) + "WITHRSASSA-PSS";

                sig = helper.createSignature(signatureAlgorithm);
            }
            else if (oids.get(sigAlgId.getAlgorithm()) != null)
            {
                String signatureAlgorithm = (String)oids.get(sigAlgId.getAlgorithm());

                sig = helper.createSignature(signatureAlgorithm);
            }
            else
            {
                throw e;
            }
        }

        if (sigAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(sigAlgId.getParameters());

            if (notDefaultPSSParams(seq))
            {
                try
                {
                    AlgorithmParameters algParams = helper.createAlgorithmParameters("PSS");

                    algParams.init(seq.getEncoded());

                    sig.setParameter(algParams.getParameterSpec(PSSParameterSpec.class));
                }
                catch (IOException e)
                {
                    throw new GeneralSecurityException("unable to process PSS parameters: " + e.getMessage());
                }
            }
        }

        return sig;
    }

    public Signature createRawSignature(AlgorithmIdentifier algorithm)
    {
        Signature sig;

        try
        {
            String algName = getSignatureName(algorithm);

            algName = "NONE" + algName.substring(algName.indexOf("WITH"));

            sig = helper.createSignature(algName);

            // RFC 4056
            // When the id-RSASSA-PSS algorithm identifier is used for a signature,
            // the AlgorithmIdentifier parameters field MUST contain RSASSA-PSS-params.
            if (algorithm.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
            {
                AlgorithmParameters params = helper.createAlgorithmParameters(algName);

                AlgorithmParametersUtils.loadParameters(params, algorithm.getParameters());

                PSSParameterSpec spec = (PSSParameterSpec)params.getParameterSpec(PSSParameterSpec.class);
                sig.setParameter(spec);
            }
        }
        catch (Exception e)
        {
            return null;
        }

        return sig;
    }

    private static String getSignatureName(
        AlgorithmIdentifier sigAlgId)
    {
        ASN1Encodable params = sigAlgId.getParameters();

        if (params != null && !DERNull.INSTANCE.equals(params))
        {
            if (sigAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
            {
                RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(params);
                return getDigestName(rsaParams.getHashAlgorithm().getAlgorithm()) + "WITHRSAANDMGF1";
            }
        }

        if (oids.containsKey(sigAlgId.getAlgorithm()))
        {
            return (String)oids.get(sigAlgId.getAlgorithm());
        }

        return sigAlgId.getAlgorithm().getId();
    }

    // we need to remove the - to create a correct signature name
    private static String getDigestName(ASN1ObjectIdentifier oid)
    {
        String name = MessageDigestUtils.getDigestName(oid);

        int dIndex = name.indexOf('-');
        if (dIndex > 0 && !name.startsWith("SHA3"))
        {
            return name.substring(0, dIndex) + name.substring(dIndex + 1);
        }

        return name;
    }

    public X509Certificate convertCertificate(X509CertificateHolder certHolder)
        throws CertificateException
    {
        try
        {
            CertificateFactory certFact = helper.createCertificateFactory("X.509");

            return (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
        }
        catch (IOException e)
        {
            throw new OpCertificateException("cannot get encoded form of certificate: " + e.getMessage(), e);
        }
        catch (NoSuchProviderException e)
        {
            throw new OpCertificateException("cannot find factory provider: " + e.getMessage(), e);
        }
    }

    public PublicKey convertPublicKey(SubjectPublicKeyInfo publicKeyInfo)
        throws OperatorCreationException
    {
        try
        {
            KeyFactory keyFact = helper.createKeyFactory(publicKeyInfo.getAlgorithm().getAlgorithm().getId());

            return keyFact.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
        }
        catch (IOException e)
        {
            throw new OperatorCreationException("cannot get encoded form of key: " + e.getMessage(), e);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new OperatorCreationException("cannot create key factory: " + e.getMessage(), e);
        }
        catch (NoSuchProviderException e)
        {
            throw new OperatorCreationException("cannot find factory provider: " + e.getMessage(), e);
        }
        catch (InvalidKeySpecException e)
        {
            throw new OperatorCreationException("cannot create key factory: " + e.getMessage(), e);
        }
    }

    // TODO: put somewhere public so cause easily accessed
    private static class OpCertificateException
        extends CertificateException
    {
        private Throwable cause;

        public OpCertificateException(String msg, Throwable cause)
        {
            super(msg);

            this.cause = cause;
        }

        public Throwable getCause()
        {
            return cause;
        }
    }

    String getKeyAlgorithmName(ASN1ObjectIdentifier oid)
    {

        String name = (String)symmetricKeyAlgNames.get(oid);

        if (name != null)
        {
            return name;
        }

        return oid.getId();
    }

    // for our purposes default includes varient digest with salt the same size as digest
    private boolean notDefaultPSSParams(ASN1Sequence seq)
        throws GeneralSecurityException
    {
        if (seq == null || seq.size() == 0)
        {
            return false;
        }

        RSASSAPSSparams pssParams = RSASSAPSSparams.getInstance(seq);

        if (!pssParams.getMaskGenAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.id_mgf1))
        {
            return true;
        }

        // same digest for sig and MGF1
        if (!pssParams.getHashAlgorithm().equals(AlgorithmIdentifier.getInstance(pssParams.getMaskGenAlgorithm().getParameters())))
        {
            return true;
        }

        MessageDigest digest = createDigest(pssParams.getHashAlgorithm());

        return pssParams.getSaltLength().intValue() != digest.getDigestLength();
    }
}
