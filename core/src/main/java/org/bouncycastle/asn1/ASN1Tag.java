package org.bouncycastle.asn1;

final class ASN1Tag
{
    static ASN1Tag create(int tagClass, int tagNumber)
    {
        return new ASN1Tag(tagClass, tagNumber);
    }

    private final int tagClass;
    private final int tagNumber;

    private ASN1Tag(int tagClass, int tagNumber)
    {
        this.tagClass = tagClass;
        this.tagNumber = tagNumber;
    }

    int getTagClass()
    {
        return tagClass;
    }

    int getTagNumber()
    {
        return tagNumber;
    }
}
