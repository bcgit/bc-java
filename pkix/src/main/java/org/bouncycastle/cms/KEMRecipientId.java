package org.bouncycastle.cms;

import java.math.BigInteger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;

public class KEMRecipientId
    extends PKIXRecipientId
{
    private KEMRecipientId(X509CertificateHolderSelector baseSelector)
    {
        super(kem, baseSelector);
    }

    /**
     * Construct a key trans recipient ID with the value of a public key's subjectKeyId.
     *
     * @param subjectKeyId a subjectKeyId
     */
    public KEMRecipientId(byte[] subjectKeyId)
    {
        super(kem, null, null, subjectKeyId);
    }

    /**
     * Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated
     * certificate.
     *
     * @param issuer the issuer of the recipient's associated certificate.
     * @param serialNumber the serial number of the recipient's associated certificate.
     */
    public KEMRecipientId(X500Name issuer, BigInteger serialNumber)
    {
        super(kem, issuer, serialNumber, null);
    }

    /**
     * Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated
     * certificate.
     *
     * @param issuer the issuer of the recipient's associated certificate.
     * @param serialNumber the serial number of the recipient's associated certificate.
     * @param subjectKeyId the subject key identifier to use to match the recipients associated certificate.
     */
    public KEMRecipientId(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId)
    {
        super(kem, issuer, serialNumber, subjectKeyId);
    }

    public Object clone()
    {
        return new KEMRecipientId(this.baseSelector);
    }

    public boolean match(Object obj)
    {
        if (obj instanceof KEMRecipientInformation)
        {
            return ((KEMRecipientInformation)obj).getRID().equals(this);
        }

        return super.match(obj);
    }

    public boolean equals(
        Object  o)
    {
        // Strict type check, mirroring KeyTransRecipientId / KeyAgreeRecipientId: without it this
        // would inherit PKIXRecipientId.equals (which only checks instanceof PKIXRecipientId), so
        // a KEMRecipientId could equal a KeyTrans/KeyAgree id sharing the same issuer+serial,
        // making equality asymmetric across recipient-id kinds in a RecipientInformationStore.
        if (!(o instanceof KEMRecipientId))
        {
            return false;
        }

        KEMRecipientId id = (KEMRecipientId)o;

        return this.baseSelector.equals(id.baseSelector);
    }
}
