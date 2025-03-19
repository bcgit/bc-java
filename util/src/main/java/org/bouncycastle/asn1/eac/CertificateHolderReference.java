package org.bouncycastle.asn1.eac;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class CertificateHolderReference
{
    private static final Charset ReferenceEncoding = StandardCharsets.ISO_8859_1;

    private final String countryCode;
    private final String holderMnemonic;
    private final String sequenceNumber;

    public CertificateHolderReference(String countryCode, String holderMnemonic, String sequenceNumber)
    {
        this.countryCode = countryCode;
        this.holderMnemonic = holderMnemonic;
        this.sequenceNumber = sequenceNumber;
    }

    CertificateHolderReference(byte[] contents)
    {
        String concat = new String(contents, ReferenceEncoding);

        this.countryCode = concat.substring(0, 2);
        this.holderMnemonic = concat.substring(2, concat.length() - 5);

        this.sequenceNumber = concat.substring(concat.length() - 5);
    }

    public String getCountryCode()
    {
        return countryCode;
    }

    public String getHolderMnemonic()
    {
        return holderMnemonic;
    }

    public String getSequenceNumber()
    {
        return sequenceNumber;
    }


    public byte[] getEncoded()
    {
        String ref = countryCode + holderMnemonic + sequenceNumber;

        return ref.getBytes(ReferenceEncoding);
    }
}
