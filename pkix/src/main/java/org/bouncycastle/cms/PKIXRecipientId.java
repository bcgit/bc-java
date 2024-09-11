package org.bouncycastle.cms;

import java.math.BigInteger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;

public class PKIXRecipientId
    extends RecipientId
{
    protected final X509CertificateHolderSelector baseSelector;

    protected PKIXRecipientId(int type, X509CertificateHolderSelector baseSelector)
    {
        super(type);

        this.baseSelector = baseSelector;
    }

    protected PKIXRecipientId(int type, X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId)
    {
        this(type, new X509CertificateHolderSelector(issuer, serialNumber, subjectKeyId));
    }

    public X500Name getIssuer()
    {
        return baseSelector.getIssuer();
    }

    public BigInteger getSerialNumber()
    {
        return baseSelector.getSerialNumber();
    }

    public byte[] getSubjectKeyIdentifier()
    {
        return baseSelector.getSubjectKeyIdentifier();
    }

    public Object clone()
    {
        return new PKIXRecipientId(getType(), baseSelector);
    }

    public int hashCode()
    {
        return baseSelector.hashCode();
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof PKIXRecipientId))
        {
            return false;
        }

        PKIXRecipientId id = (PKIXRecipientId)o;

        return this.baseSelector.equals(id.baseSelector);
    }

    public boolean match(Object obj)
    {
        return baseSelector.match(obj);
    }
}
