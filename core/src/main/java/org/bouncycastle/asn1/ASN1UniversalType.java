package org.bouncycastle.asn1;

import java.io.IOException;

abstract class ASN1UniversalType
    extends ASN1Type
{
    final ASN1Tag tag;

    ASN1UniversalType(Class javaClass, int tagNumber)
    {
        super(javaClass);

        this.tag = ASN1Tag.create(BERTags.UNIVERSAL, tagNumber);
    }

    final ASN1Primitive checkedCast(ASN1Primitive primitive)
    {
        if (javaClass.isInstance(primitive))
        {
            return primitive;
        }

        throw new IllegalStateException("unexpected object: " + primitive.getClass().getName());
    }

    ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
    {
        throw new IllegalStateException("unexpected implicit primitive encoding");
    }

    ASN1Primitive fromImplicitConstructed(ASN1Sequence sequence)
    {
        throw new IllegalStateException("unexpected implicit constructed encoding");
    }

    final ASN1Primitive fromByteArray(byte[] bytes) throws IOException
    {
        return checkedCast(ASN1Primitive.fromByteArray(bytes));
    }

    final ASN1Primitive getContextInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        if (BERTags.CONTEXT_SPECIFIC != taggedObject.getTagClass())
        {
            throw new IllegalStateException("this method only valid for CONTEXT_SPECIFIC tags");
        }

        return checkedCast(taggedObject.getBaseUniversal(declaredExplicit, this));
    }

    final ASN1Tag getTag()
    {
        return tag;
    }
}
