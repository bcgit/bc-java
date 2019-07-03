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
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
import org.bouncycastle.operator.ContentSigner;

/**
 * class to produce an X.509 Version 2 CRL.
 */
public class X509v2CRLBuilder
{
    private V2TBSCertListGenerator      tbsGen;
    private ExtensionsGenerator         extGenerator;

    /**
     * Basic constructor.
     *
     * @param issuer the issuer this CRL is associated with.
     * @param thisUpdate  the date of this update.
     */
    public X509v2CRLBuilder(
        X500Name issuer,
        Date     thisUpdate)
    {
        tbsGen = new V2TBSCertListGenerator();
        extGenerator = new ExtensionsGenerator();

        tbsGen.setIssuer(issuer);
        tbsGen.setThisUpdate(new Time(thisUpdate));
    }

    /**
     * Basic constructor with Locale. You may need to use this constructor if the default locale
     * doesn't use a Gregorian calender so that the Time produced is compatible with other ASN.1 implementations.
     *
     * @param issuer the issuer this CRL is associated with.
     * @param thisUpdate  the date of this update.
     * @param dateLocale locale to be used for date interpretation.
     */
    public X509v2CRLBuilder(
        X500Name issuer,
        Date     thisUpdate,
        Locale   dateLocale)
    {
        tbsGen = new V2TBSCertListGenerator();
        extGenerator = new ExtensionsGenerator();

        tbsGen.setIssuer(issuer);
        tbsGen.setThisUpdate(new Time(thisUpdate, dateLocale));
    }

    /**
     * Basic constructor.
     *
     * @param issuer the issuer this CRL is associated with.
     * @param thisUpdate  the Time of this update.
     */
    public X509v2CRLBuilder(
        X500Name issuer,
        Time     thisUpdate)
    {
        tbsGen = new V2TBSCertListGenerator();
        extGenerator = new ExtensionsGenerator();

        tbsGen.setIssuer(issuer);
        tbsGen.setThisUpdate(thisUpdate);
    }

    /**
     * Create a builder for a version 2 CRL, initialised with another CRL.
     *
     * @param template template CRL to base the new one on.
     */
    public X509v2CRLBuilder(X509CRLHolder template)
    {
        tbsGen = new V2TBSCertListGenerator();
        tbsGen.setIssuer(template.getIssuer());
        tbsGen.setThisUpdate(new Time(template.getThisUpdate()));
        Date nextUpdate = template.getNextUpdate();
        if (nextUpdate != null)
        {
            tbsGen.setNextUpdate(new Time(nextUpdate));
        }

        addCRL(template);

        extGenerator = new ExtensionsGenerator();

        Extensions exts = template.getExtensions();
        if (exts != null)
        {
            for (Enumeration en = exts.oids(); en.hasMoreElements(); )
            {
                extGenerator.addExtension(exts.getExtension((ASN1ObjectIdentifier)en.nextElement()));
            }
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
     * Set the date by which the next CRL will become available.
     *
     * @param date  date of next CRL update.
     * @return the current builder.
     */
    public X509v2CRLBuilder setNextUpdate(
        Date    date)
    {
        return this.setNextUpdate(new Time(date));
    }

    /**
     * Set the date by which the next CRL will become available.
     *
     * @param date  date of next CRL update.
     * @param dateLocale locale to be used for date interpretation.
     * @return the current builder.
     */
    public X509v2CRLBuilder setNextUpdate(
        Date    date,
        Locale  dateLocale)
    {
        return this.setNextUpdate(new Time(date, dateLocale));
    }

    /**
     * Set the date by which the next CRL will become available.
     *
     * @param date  date of next CRL update.
     * @return the current builder.
     */
    public X509v2CRLBuilder setNextUpdate(
        Time    date)
    {
        tbsGen.setNextUpdate(date);

        return this;
    }

    /**
     * Add a CRL entry with the just reasonCode extension.
     *
     * @param userCertificateSerial serial number of revoked certificate.
     * @param revocationDate date of certificate revocation.
     * @param reason the reason code, as indicated in CRLReason, i.e CRLReason.keyCompromise, or 0 if not to be used.
     * @return the current builder.
     */
    public X509v2CRLBuilder addCRLEntry(BigInteger userCertificateSerial, Date revocationDate, int reason)
    {
        tbsGen.addCRLEntry(new ASN1Integer(userCertificateSerial), new Time(revocationDate), reason);

        return this;
    }

    /**
     * Add a CRL entry with an invalidityDate extension as well as a reasonCode extension. This is used
     * where the date of revocation might be after issues with the certificate may have occurred.
     *
     * @param userCertificateSerial serial number of revoked certificate.
     * @param revocationDate date of certificate revocation.
     * @param reason the reason code, as indicated in CRLReason, i.e CRLReason.keyCompromise, or 0 if not to be used.
     * @param invalidityDate the date on which the private key for the certificate became compromised or the certificate otherwise became invalid.
     * @return the current builder.
     */
    public X509v2CRLBuilder addCRLEntry(BigInteger userCertificateSerial, Date revocationDate, int reason, Date invalidityDate)
    {
        tbsGen.addCRLEntry(new ASN1Integer(userCertificateSerial), new Time(revocationDate), reason, new ASN1GeneralizedTime(invalidityDate));

        return this;
    }

    /**
     * Add a CRL entry with extensions.
     *
     * @param userCertificateSerial serial number of revoked certificate.
     * @param revocationDate date of certificate revocation.
     * @param extensions extension set to be associated with this CRLEntry.
     * @return the current builder.
     */
    public X509v2CRLBuilder addCRLEntry(BigInteger userCertificateSerial, Date revocationDate, Extensions extensions)
    {
        tbsGen.addCRLEntry(new ASN1Integer(userCertificateSerial), new Time(revocationDate), extensions);

        return this;
    }

    /**
     * Add the CRLEntry objects contained in a previous CRL.
     * 
     * @param other the X509CRLHolder to source the other entries from.
     * @return the current builder.
     */
    public X509v2CRLBuilder addCRL(X509CRLHolder other)
    {
        TBSCertList revocations = other.toASN1Structure().getTBSCertList();

        if (revocations != null)
        {
            for (Enumeration en = revocations.getRevokedCertificateEnumeration(); en.hasMoreElements();)
            {
                tbsGen.addCRLEntry(ASN1Sequence.getInstance(((ASN1Encodable)en.nextElement()).toASN1Primitive()));
            }
        }

        return this;
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3)
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param value the ASN.1 structure that forms the extension's value.
     * @return this builder object.
     */
    public X509v2CRLBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean isCritical,
        ASN1Encodable value)
        throws CertIOException
    {
        CertUtils.addExtension(extGenerator, oid, isCritical, value);

        return this;
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3) using a byte encoding of the
     * extension value.
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param encodedValue a byte array representing the encoding of the extension value.
     * @return this builder object.
     */
    public X509v2CRLBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean isCritical,
        byte[] encodedValue)
        throws CertIOException
    {
        extGenerator.addExtension(oid, isCritical, encodedValue);

        return this;
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3).
     *
     * @param extension the full extension value.
     * @return this builder object.
     */
    public X509v2CRLBuilder addExtension(
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
    public X509v2CRLBuilder replaceExtension(
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
    public X509v2CRLBuilder replaceExtension(
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
    public X509v2CRLBuilder replaceExtension(
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
    public X509v2CRLBuilder removeExtension(ASN1ObjectIdentifier oid)
    {
        extGenerator = CertUtils.doRemoveExtension(extGenerator, oid);

        return this;
    }

    /**
     * Generate an X.509 CRL, based on the current issuer and subject
     * using the passed in signer.
     *
     * @param signer the content signer to be used to generate the signature validating the certificate.
     * @return a holder containing the resulting signed certificate.
     */
    public X509CRLHolder build(
        ContentSigner signer)
    {
        tbsGen.setSignature(signer.getAlgorithmIdentifier());

        if (!extGenerator.isEmpty())
        {
            tbsGen.setExtensions(extGenerator.generate());
        }

        return CertUtils.generateFullCRL(signer, tbsGen.generateTBSCertList());
    }
}
