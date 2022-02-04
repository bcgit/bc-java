package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 *     Ieee1609Dot2Content ::= CHOICE {
 *         unsecuredData Opaque,
 *         signedData SignedData,
 *         encryptedData EncryptedData,
 *         signedCertificateRequest Opaque,
 *         ...
 *     }
 * </pre>
 */
public class Ieee1609Dot2Content
    extends ASN1Object
    implements ASN1Choice
{
    public static final int unsecuredData = 0;
    public static final int signedData = 1;
    public static final int encryptedData = 2;
    public static final int signedCertificateRequest = 3;
    public static final int extension = 4;

    private final int choice;
    private final ASN1Encodable content;

    public Ieee1609Dot2Content(int choice, ASN1Encodable object)
    {
        this.choice = choice;
        this.content = object;
    }

    private Ieee1609Dot2Content(ASN1TaggedObject to)
    {
        choice = to.getTagNo();
        switch (choice)
        {
        case unsecuredData:
        case signedCertificateRequest:
        case extension:
            content = ASN1OctetString.getInstance(to.getObject());
            return;
        case signedData:
            content = SignedData.getInstance(to.getObject());
            return;
        case encryptedData:
            content = EncryptedData.getInstance(to.getObject());
            return;
        default:
            throw new IllegalArgumentException("invalid choice value " + to.getTagNo());
        }
    }


    public static Ieee1609Dot2Content getInstance(Object src)
    {
        if (src instanceof Ieee1609Dot2Content)
        {
            return (Ieee1609Dot2Content)src;
        }

        if (src != null)
        {
            return new Ieee1609Dot2Content(ASN1TaggedObject.getInstance(src));
        }
        return null;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, content);
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getContent()
    {
        return content;
    }

    public static class Builder
    {
        private int choice;
        private ASN1Encodable object;

        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder setObject(ASN1Encodable object)
        {
            this.object = object;
            return this;
        }

        public Builder unsecuredData(ASN1OctetString octetString)
        {
            this.object = octetString;
            this.choice = unsecuredData;
            return this;
        }

        public Builder signedData(SignedData signedData)
        {
            this.object = signedData;
            this.choice = Ieee1609Dot2Content.signedData;
            return this;
        }

        public Builder encryptedData(EncryptedData encryptedData)
        {
            this.object = encryptedData;
            this.choice = Ieee1609Dot2Content.encryptedData;
            return this;
        }

        public Builder signedCertificateRequest(ASN1OctetString octetString)
        {
            this.object = octetString;
            this.choice = signedCertificateRequest;
            return this;
        }

        public Builder extension(byte[] value)
        {
            this.object = new DEROctetString(value);
            this.choice = extension;
            return this;
        }

        public Ieee1609Dot2Content build()
        {
            return new Ieee1609Dot2Content(choice, object);
        }
    }

}
