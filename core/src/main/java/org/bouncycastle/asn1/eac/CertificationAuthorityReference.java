package org.bouncycastle.asn1.eac;

/**
 * @deprecated use org.bouncycastle.eac.asn1.CertificationAuthorityReference
 */
public class CertificationAuthorityReference
    extends CertificateHolderReference
{
    public CertificationAuthorityReference(String countryCode, String holderMnemonic, String sequenceNumber)
    {
        super(countryCode, holderMnemonic, sequenceNumber);
    }

    CertificationAuthorityReference(byte[] contents)
    {
        super(contents);
    }
}
