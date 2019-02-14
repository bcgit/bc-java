package org.bouncycastle.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.AttCertIssuer;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.V2AttributeCertificateInfoGenerator;
import org.bouncycastle.operator.ContentSigner;

/**
 * class to produce an X.509 Version 2 AttributeCertificate.
 */
public class X509v2AttributeCertificateBuilder
{
    private V2AttributeCertificateInfoGenerator   acInfoGen;
    private ExtensionsGenerator extGenerator;

    /**
     * Base constructor.
     *
     * @param holder holder certificate details
     * @param issuer issuer of this attribute certificate.
     * @param serialNumber serial number of this attribute certificate.
     * @param notBefore the date before which the certificate is not valid.
     * @param notAfter the date after which the certificate is not valid.
     */
    public X509v2AttributeCertificateBuilder(AttributeCertificateHolder holder, AttributeCertificateIssuer  issuer, BigInteger serialNumber, Date notBefore, Date notAfter)
    {
        acInfoGen = new V2AttributeCertificateInfoGenerator();
        extGenerator = new ExtensionsGenerator();

        acInfoGen.setHolder(holder.holder);
        acInfoGen.setIssuer(AttCertIssuer.getInstance(issuer.form));
        acInfoGen.setSerialNumber(new ASN1Integer(serialNumber));
        acInfoGen.setStartDate(new ASN1GeneralizedTime(notBefore));
        acInfoGen.setEndDate(new ASN1GeneralizedTime(notAfter));
    }

    /**
     * Base constructor with locale for interpreting dates. You may need to use this constructor if the default locale
     * doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible with other ASN.1 implementations.
     *
     * @param holder holder certificate details
     * @param issuer issuer of this attribute certificate.
     * @param serialNumber serial number of this attribute certificate.
     * @param notBefore the date before which the certificate is not valid.
     * @param notAfter the date after which the certificate is not valid.
     * @param dateLocale locale to be used for date interpretation.
     */
    public X509v2AttributeCertificateBuilder(AttributeCertificateHolder holder, AttributeCertificateIssuer  issuer, BigInteger serialNumber, Date notBefore, Date notAfter, Locale dateLocale)
    {
        acInfoGen = new V2AttributeCertificateInfoGenerator();
        extGenerator = new ExtensionsGenerator();

        acInfoGen.setHolder(holder.holder);
        acInfoGen.setIssuer(AttCertIssuer.getInstance(issuer.form));
        acInfoGen.setSerialNumber(new ASN1Integer(serialNumber));
        acInfoGen.setStartDate(new ASN1GeneralizedTime(notBefore, dateLocale));
        acInfoGen.setEndDate(new ASN1GeneralizedTime(notAfter, dateLocale));
    }

    /**
     * Create a builder for a version 2 attribute certificate, initialised with another certificate.
     *
     * @param template template certificate to base the new one on.
     */
    public X509v2AttributeCertificateBuilder(X509AttributeCertificateHolder template)
    {
        acInfoGen = new V2AttributeCertificateInfoGenerator();
        acInfoGen.setSerialNumber(new ASN1Integer(template.getSerialNumber()));
        acInfoGen.setIssuer(AttCertIssuer.getInstance(template.getIssuer().form));
        acInfoGen.setStartDate(new ASN1GeneralizedTime(template.getNotBefore()));
        acInfoGen.setEndDate(new ASN1GeneralizedTime(template.getNotAfter()));
        acInfoGen.setHolder(template.getHolder().holder);
        boolean[] uniqueID = template.getIssuerUniqueID();
        if (uniqueID != null)
        {
            acInfoGen.setIssuerUniqueID(CertUtils.booleanToBitString(uniqueID));
        }
        
        Attribute[] attr = template.getAttributes();

        for (int i = 0; i != attr.length; i++)
        {
            acInfoGen.addAttribute(attr[i]);
        }

        extGenerator = new ExtensionsGenerator();

        Extensions exts = template.getExtensions();

        for (Enumeration en = exts.oids(); en.hasMoreElements();)
        {
            extGenerator.addExtension(exts.getExtension((ASN1ObjectIdentifier)en.nextElement()));
        }
    }

    /**
     * Return if the extension indicated by OID is present.
     *
     * @param oid the OID for the extension of interest.
     * @return the Extension, or null if it is not present.
     */
    public boolean hasExtension(ASN1ObjectIdentifier oid)
    {
         return doGetExtension(oid) != null;
    }

    /**
     * Return the current value of the extension for OID.
     *
     * @param oid the OID for the extension we want to fetch.
     * @return true if a matching extension is present, false otherwise.
     */
    public Extension getExtension(ASN1ObjectIdentifier oid)
    {
         return doGetExtension(oid);
    }

    private Extension doGetExtension(ASN1ObjectIdentifier oid)
    {
        Extensions exts = extGenerator.generate();

        return exts.getExtension(oid);
    }

    /**
     * Add an attribute to the certification request we are building.
     *
     * @param attrType the OID giving the type of the attribute.
     * @param attrValue the ASN.1 structure that forms the value of the attribute.
     * @return this builder object.
     */
    public X509v2AttributeCertificateBuilder addAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
    {
        acInfoGen.addAttribute(new Attribute(attrType, new DERSet(attrValue)));

        return this;
    }

    /**
     * Add an attribute with multiple values to the certification request we are building.
     *
     * @param attrType the OID giving the type of the attribute.
     * @param attrValues an array of ASN.1 structures that form the value of the attribute.
     * @return this builder object.
     */
    public X509v2AttributeCertificateBuilder addAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable[] attrValues)
    {
        acInfoGen.addAttribute(new Attribute(attrType, new DERSet(attrValues)));

        return this;
    }

    public void setIssuerUniqueId(
        boolean[] iui)
    {
        acInfoGen.setIssuerUniqueID(CertUtils.booleanToBitString(iui));
    }

    /**
     * Add a given extension field for the standard extensions tag made up of the passed in parameters.
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param value the ASN.1 structure that forms the extension's value.
     * @return this builder object.
     */
    public X509v2AttributeCertificateBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean isCritical,
        ASN1Encodable value)
        throws CertIOException
    {
        CertUtils.addExtension(extGenerator, oid, isCritical, value);

        return this;
    }

    /**
     * Add a given extension field for the standard extensions using a byte encoding of the
     * extension value.
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param encodedValue a byte array representing the encoding of the extension value.
     * @return this builder object.
     */
    public X509v2AttributeCertificateBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean isCritical,
        byte[] encodedValue)
        throws CertIOException
    {
        extGenerator.addExtension(oid, isCritical, encodedValue);

        return this;
    }

    /**
     * Add a given extension field for the standard extensions.
     *
     * @param extension the full extension value.
     * @return this builder object.
     */
    public X509v2AttributeCertificateBuilder addExtension(
        Extension extension)
        throws CertIOException
    {
        extGenerator.addExtension(extension);

        return this;
    }

    /**
     * Replace the extension field for the passed in extension's extension ID
     * with a new version.
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param value the ASN.1 structure that forms the extension's value.
     * @return this builder object.
     * @throws CertIOException if there is an issue with the new extension value.
     * @throws IllegalArgumentException if the extension to be replaced is not present.
     */
    public X509v2AttributeCertificateBuilder replaceExtension(
        ASN1ObjectIdentifier oid,
        boolean isCritical,
        ASN1Encodable value)
        throws CertIOException
    {
        try
        {
            extGenerator = CertUtils.doReplaceExtension(extGenerator, new Extension(oid, isCritical, value.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
        }
        catch (IOException e)
        {
            throw new CertIOException("cannot encode extension: " + e.getMessage(), e);
        }

        return this;
    }

    /**
     * Replace the extension field for the passed in extension's extension ID
     * with a new version.
     *
     * @param extension the full extension value.
     * @return this builder object.
     * @throws CertIOException if there is an issue with the new extension value.
     * @throws IllegalArgumentException if the extension to be replaced is not present.
     */
    public X509v2AttributeCertificateBuilder replaceExtension(
        Extension extension)
        throws CertIOException
    {
        extGenerator = CertUtils.doReplaceExtension(extGenerator, extension);

        return this;
    }

    /**
     * Replace a given extension field for the standard extensions tag (tag 3) with the passed in
     * byte encoded extension value.
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param encodedValue a byte array representing the encoding of the extension value.
     * @return this builder object.
     * @throws CertIOException if there is an issue with the new extension value.
     * @throws IllegalArgumentException if the extension to be replaced is not present.
     */
    public X509v2AttributeCertificateBuilder replaceExtension(
        ASN1ObjectIdentifier oid,
        boolean isCritical,
        byte[] encodedValue)
        throws CertIOException
    {
        extGenerator = CertUtils.doReplaceExtension(extGenerator, new Extension(oid, isCritical, encodedValue));

        return this;
    }

    /**
     * Remove the extension indicated by OID.
     *
     * @param oid the OID of the extension to be removed.
     * @return this builder object.
     * @throws IllegalArgumentException if the extension to be removed is not present.
     */
    public X509v2AttributeCertificateBuilder removeExtension(ASN1ObjectIdentifier oid)
    {
        extGenerator = CertUtils.doRemoveExtension(extGenerator, oid);

        return this;
    }

   /**
     * Generate an X509 certificate, based on the current issuer and subject
     * using the passed in signer.
     *
     * @param signer the content signer to be used to generate the signature validating the certificate.
     * @return a holder containing the resulting signed certificate.
     */
    public X509AttributeCertificateHolder build(
        ContentSigner signer)
    {
        acInfoGen.setSignature(signer.getAlgorithmIdentifier());

        if (!extGenerator.isEmpty())
        {
            acInfoGen.setExtensions(extGenerator.generate());
        }

        return CertUtils.generateFullAttrCert(signer, acInfoGen.generateAttributeCertificateInfo());
    }
}
