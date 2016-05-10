package com.github.gv2011.bcasn.asn1.eac;

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
