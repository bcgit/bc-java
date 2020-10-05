package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jcajce.util.AlgorithmParametersUtils;
import org.bouncycastle.jcajce.util.AnnotatedPrivateKey;

class CMSUtils
{
    private static final Set mqvAlgs = new HashSet();
    private static final Set ecAlgs = new HashSet();
    private static final Set gostAlgs = new HashSet();

    static
    {
        mqvAlgs.add(X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme);

        ecAlgs.add(X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme);
        ecAlgs.add(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme);

        gostAlgs.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_ESDH);
        gostAlgs.add(CryptoProObjectIdentifiers.gostR3410_2001);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512);
    }

    static boolean isMQV(ASN1ObjectIdentifier algorithm)
    {
        return mqvAlgs.contains(algorithm);
    }

    static boolean isEC(ASN1ObjectIdentifier algorithm)
    {
        return ecAlgs.contains(algorithm);
    }

    static boolean isGOST(ASN1ObjectIdentifier algorithm)
    {
        return gostAlgs.contains(algorithm);
    }

    static boolean isRFC2631(ASN1ObjectIdentifier algorithm)
    {
        return algorithm.equals(PKCSObjectIdentifiers.id_alg_ESDH) || algorithm.equals(PKCSObjectIdentifiers.id_alg_SSDH);
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
}