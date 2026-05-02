package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jcajce.util.AlgorithmParametersUtils;
import org.bouncycastle.jcajce.util.AnnotatedPrivateKey;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorCreationException;

class CMSUtils
{
    private static final Map asymmetricWrapperAlgNames = new HashMap();

    private static Map<ASN1ObjectIdentifier,String> wrapAlgNames = new HashMap();

    static
    {
       wrapAlgNames.put(CMSAlgorithm.AES128_WRAP, "AESWRAP");
       wrapAlgNames.put(CMSAlgorithm.AES192_WRAP, "AESWRAP");
       wrapAlgNames.put(CMSAlgorithm.AES256_WRAP, "AESWRAP");
       wrapAlgNames.put(CMSAlgorithm.AES128_WRAP_PAD, "AES-KWP");
       wrapAlgNames.put(CMSAlgorithm.AES192_WRAP_PAD, "AES-KWP");
       wrapAlgNames.put(CMSAlgorithm.AES256_WRAP_PAD, "AES-KWP");
    }

    static
    {
        asymmetricWrapperAlgNames.put(PKCSObjectIdentifiers.rsaEncryption, "RSA/ECB/PKCS1Padding");
        asymmetricWrapperAlgNames.put(OIWObjectIdentifiers.elGamalAlgorithm, "Elgamal/ECB/PKCS1Padding");
        asymmetricWrapperAlgNames.put(PKCSObjectIdentifiers.id_RSAES_OAEP, "RSA/ECB/OAEPPadding");
        asymmetricWrapperAlgNames.put(CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410");
        asymmetricWrapperAlgNames.put(ISOIECObjectIdentifiers.id_kem_rsa, "RSA-KTS-KEM-KWS");
    }

    static String getWrapAlgorithmName(ASN1ObjectIdentifier oid)
    {
        return (String)wrapAlgNames.get(oid);
    }

    static PrivateKey cleanPrivateKey(PrivateKey key)
    {
        if (key instanceof AnnotatedPrivateKey)
        {
            return cleanPrivateKey(((AnnotatedPrivateKey)key).getKey());
        }
        else
        {
            return key;
        }
    }

    static IssuerAndSerialNumber getIssuerAndSerialNumber(X509Certificate cert)
        throws CertificateEncodingException
    {
        Certificate certStruct = Certificate.getInstance(cert.getEncoded());

        return new IssuerAndSerialNumber(certStruct.getIssuer(), cert.getSerialNumber());
    }

    static byte[] getSubjectKeyId(X509Certificate cert)
    {
        byte[] ext = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());

        if (ext != null)
        {
            return ASN1OctetString.getInstance(ASN1OctetString.getInstance(ext).getOctets()).getOctets();
        }
        else
        {
            return null;
        }
    }

    static EnvelopedDataHelper createContentHelper(Provider provider)
    {
        if (provider != null)
        {
            return new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
        }
        else
        {
            return new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
        }
    }

    static EnvelopedDataHelper createContentHelper(String providerName)
    {
        if (providerName != null)
        {
            return new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
        }
        else
        {
            return new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
        }
    }

    static ASN1Encodable extractParameters(AlgorithmParameters params)
        throws CMSException
    {
        try
        {
            return AlgorithmParametersUtils.extractParameters(params);
        }
        catch (IOException e)
        {
            throw new CMSException("cannot extract parameters: " + e.getMessage(), e);
        }
    }

    static void loadParameters(AlgorithmParameters params, ASN1Encodable sParams)
        throws CMSException
    {
        try
        {
            AlgorithmParametersUtils.loadParameters(params, sParams);
        }
        catch (IOException e)
        {
            throw new CMSException("error encoding algorithm parameters.", e);
        }
    }

    static Key getJceKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof Key)
        {
            return (Key)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new SecretKeySpec((byte[])key.getRepresentation(), "ENC");
        }

        throw new IllegalArgumentException("unknown generic key type");
    }

    static Cipher createAsymmetricWrapper(JcaJceHelper helper, ASN1ObjectIdentifier algorithm, Map extraAlgNames)
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

    public static int getKekSize(ASN1ObjectIdentifier symWrapAlg)
    {
        // TODO: add table
        if (symWrapAlg.equals(CMSAlgorithm.AES256_WRAP) || symWrapAlg.equals(CMSAlgorithm.AES256_WRAP_PAD))
        {
            return 32;
        }
        else if (symWrapAlg.equals(CMSAlgorithm.AES128_WRAP) || symWrapAlg.equals(CMSAlgorithm.AES128_WRAP_PAD))
        {
            return  16;
        }
        else if (symWrapAlg.equals(CMSAlgorithm.AES192_WRAP) || symWrapAlg.equals(CMSAlgorithm.AES192_WRAP_PAD))
        {
            return  24;
        }
        else
        {
            throw new IllegalArgumentException("unknown wrap algorithm");
        }
    }
}