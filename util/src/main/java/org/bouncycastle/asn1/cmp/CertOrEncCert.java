package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.EncryptedValue;

public class CertOrEncCert
    extends ASN1Object
    implements ASN1Choice
{
    private CMPCertificate certificate;
    private EncryptedKey encryptedKey;

    private CertOrEncCert(ASN1TaggedObject tagged)
    {
        if (tagged.getTagNo() == 0)
        {
            certificate = CMPCertificate.getInstance(tagged.getObject());
        }
        else if (tagged.getTagNo() == 1)
        {
            encryptedKey = EncryptedKey.getInstance(tagged.getObject());
        }
        else
        {
            throw new IllegalArgumentException("unknown tag: " + tagged.getTagNo());
        }
    }

    public static CertOrEncCert getInstance(Object o)
    {
        if (o instanceof CertOrEncCert)
        {
            return (CertOrEncCert)o;
        }

        if (o instanceof ASN1TaggedObject)
        {
            return new CertOrEncCert((ASN1TaggedObject)o);
        }

        return null;
    }

    public CertOrEncCert(CMPCertificate certificate)
    {
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }

        this.certificate = certificate;
    }

    public CertOrEncCert(EncryptedValue encryptedCert)
    {
        if (encryptedCert == null)
        {
            throw new IllegalArgumentException("'encryptedCert' cannot be null");
        }

        this.encryptedKey = new EncryptedKey(encryptedCert);
    }

    public CertOrEncCert(EncryptedKey encryptedKey)
    {
        if (encryptedKey == null)
        {
            throw new IllegalArgumentException("'encryptedKey' cannot be null");
        }

        this.encryptedKey = encryptedKey;
    }

    public CMPCertificate getCertificate()
    {
        return certificate;
    }

    public EncryptedKey getEncryptedCert()
    {
        return encryptedKey;
    }

    /**
     * <pre>
     * CertOrEncCert ::= CHOICE {
     *                      certificate     [0] CMPCertificate,
     *                      encryptedCert   [1] EncryptedKey
     *           }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (certificate != null)
        {
            return new DERTaggedObject(true, 0, certificate);
        }

        return new DERTaggedObject(true, 1, encryptedKey);
    }
}
