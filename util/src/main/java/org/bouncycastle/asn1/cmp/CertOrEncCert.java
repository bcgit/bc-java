package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1Util;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.EncryptedValue;

/**
 * CertOrEncCert ::= CHOICE {
 * certificate     [0] CMPCertificate,
 * encryptedCert   [1] EncryptedKey
 * }
 */
public class CertOrEncCert
    extends ASN1Object
    implements ASN1Choice
{
    private CMPCertificate certificate;
    private EncryptedKey encryptedCert;

    private CertOrEncCert(ASN1TaggedObject tagged)
    {
        if (tagged.hasContextTag(0))
        {
            certificate = CMPCertificate.getInstance(tagged.getExplicitBaseObject());
        }
        else if (tagged.hasContextTag(1))
        {
            encryptedCert = EncryptedKey.getInstance(tagged.getExplicitBaseObject());
        }
        else
        {
            throw new IllegalArgumentException("unknown tag: " + ASN1Util.getTagText(tagged));
        }
    }

    public CertOrEncCert(CMPCertificate certificate)
    {
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }

        this.certificate = certificate;
    }

    public CertOrEncCert(EncryptedValue encryptedValue)
    {
        if (encryptedValue == null)
        {
            throw new IllegalArgumentException("'encryptedCert' cannot be null");
        }

        this.encryptedCert = new EncryptedKey(encryptedValue);
    }

    public CertOrEncCert(EncryptedKey encryptedKey)
    {
        if (encryptedKey == null)
        {
            throw new IllegalArgumentException("'encryptedCert' cannot be null");
        }

        this.encryptedCert = encryptedKey;
    }

    public static CertOrEncCert getInstance(Object o)
    {
        if (o instanceof CertOrEncCert)
        {
            return (CertOrEncCert)o;
        }

        if (o instanceof ASN1TaggedObject)
        {
            return new CertOrEncCert(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }

    public boolean hasEncryptedCertificate()
    {
        return encryptedCert != null;
    }

    public CMPCertificate getCertificate()
    {
        return certificate;
    }

    public EncryptedKey getEncryptedCert()
    {
        return encryptedCert;
    }

    /**
     * <pre>
     * CertOrEncCert ::= CHOICE {
     *                      certificate     [0] CMPCertificate,
     *                      encryptedCert   [1] EncryptedKey
     *           }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (certificate != null)
        {
            return new DERTaggedObject(true, 0, certificate);
        }

        return new DERTaggedObject(true, 1, encryptedCert);
    }
}
