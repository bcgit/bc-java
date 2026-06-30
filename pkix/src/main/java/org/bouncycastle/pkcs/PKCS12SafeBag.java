package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CRLBag;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.pkcs.SecretBag;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Holding class for a PKCS#12 SafeBag (RFC 7292). {@link #getBagValue()} returns a typed view
 * of the payload appropriate to {@link #getType()}.
 */
public class PKCS12SafeBag
{
    /** Standard {@code pkcs-9-at-friendlyName} attribute OID. */
    public static final ASN1ObjectIdentifier friendlyNameAttribute = PKCSObjectIdentifiers.pkcs_9_at_friendlyName;
    /** Standard {@code pkcs-9-at-localKeyId} attribute OID. */
    public static final ASN1ObjectIdentifier localKeyIdAttribute = PKCSObjectIdentifiers.pkcs_9_at_localKeyId;

    private SafeBag safeBag;

    /**
     * Wrap an existing parsed SafeBag ASN.1 structure.
     *
     * @param safeBag the underlying SafeBag.
     */
    public PKCS12SafeBag(SafeBag safeBag)
    {
        this.safeBag = safeBag;
    }

    /**
     * Return the underlying ASN.1 structure for this safe bag.
     *
     * @return a SafeBag
     */
    public SafeBag toASN1Structure()
    {
        return safeBag;
    }

    /**
     * Return the BagId giving the type of content in the bag.
     *
     * @return the bagId
     */
    public ASN1ObjectIdentifier getType()
    {
        return safeBag.getBagId();
    }

    /**
     * Return the bag attributes (e.g. friendlyName, localKeyId) attached to this bag.
     *
     * @return the attributes as an array, or {@code null} if none are present.
     */
    public Attribute[] getAttributes()
    {
        ASN1Set attrs = safeBag.getBagAttributes();

        if (attrs == null)
        {
            return null;
        }

        Attribute[] attributes = new Attribute[attrs.size()];
        for (int i = 0; i != attrs.size(); i++)
        {
            attributes[i] = Attribute.getInstance(attrs.getObjectAt(i));
        }

        return attributes;
    }

    /**
     * Return the bag value as a typed object appropriate to {@link #getType()}:
     * pkcs8ShroudedKeyBag → {@link PKCS8EncryptedPrivateKeyInfo}, certBag →
     * {@link X509CertificateHolder}, keyBag → {@link org.bouncycastle.asn1.pkcs.PrivateKeyInfo},
     * crlBag → {@link X509CRLHolder}, secretBag → {@link PKCS12SecretBag}. Other types are
     * returned as their raw ASN.1 encoding.
     *
     * @return a typed view of this bag's value.
     */
    public Object getBagValue()
    {
        if (getType().equals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag))
        {
            return new PKCS8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo.getInstance(safeBag.getBagValue()));
        }
        if (getType().equals(PKCSObjectIdentifiers.certBag))
        {
            CertBag certBag = CertBag.getInstance(safeBag.getBagValue());

            return new X509CertificateHolder(Certificate.getInstance(ASN1OctetString.getInstance(certBag.getCertValue()).getOctets()));
        }
        if (getType().equals(PKCSObjectIdentifiers.keyBag))
        {
            return PrivateKeyInfo.getInstance(safeBag.getBagValue());
        }
        if (getType().equals(PKCSObjectIdentifiers.crlBag))
        {
            CRLBag crlBag = CRLBag.getInstance(safeBag.getBagValue());

            return new X509CRLHolder(CertificateList.getInstance(ASN1OctetString.getInstance(crlBag.getCrlValue()).getOctets()));
        }
        if (getType().equals(PKCSObjectIdentifiers.secretBag))
        {
            return new PKCS12SecretBag(SecretBag.getInstance(safeBag.getBagValue()));
        }

        return safeBag.getBagValue();
    }
}
