package org.bouncycastle.asn1.tsp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DLSequence;

/**
 * Implementation of the EncryptionInfo element defined in RFC 4998:
 * <p>
 * 1988 ASN.1 EncryptionInfo
 * <p>
 * EncryptionInfo       ::=     SEQUENCE {
 * encryptionInfoType     OBJECT IDENTIFIER,
 * encryptionInfoValue    ANY DEFINED BY encryptionInfoType
 * }
 * <p>
 * 1997-ASN.1 EncryptionInfo
 * <p>
 * EncryptionInfo       ::=     SEQUENCE {
 * encryptionInfoType   ENCINFO-TYPE.&id
 * ({SupportedEncryptionAlgorithms}),
 * encryptionInfoValue  ENCINFO-TYPE.&Type
 * ({SupportedEncryptionAlgorithms}{@encryptionInfoType})
 * }
 * <p>
 * ENCINFO-TYPE ::= TYPE-IDENTIFIER
 * <p>
 * SupportedEncryptionAlgorithms ENCINFO-TYPE ::= {...}
 */
public class EncryptionInfo
    extends ASN1Object
{

    /**
     * The OID for EncryptionInfo type.
     */
    private ASN1ObjectIdentifier encryptionInfoType;

    /**
     * The value of EncryptionInfo
     */
    private ASN1Encodable encryptionInfoValue;

    public static EncryptionInfo getInstance(final ASN1Object obj)
    {
        if (obj instanceof EncryptionInfo)
        {
            return (EncryptionInfo)obj;
        }
        else if (obj != null)
        {
            return new EncryptionInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static EncryptionInfo getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private EncryptionInfo(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("wrong sequence size in constructor: " + sequence.size());
        }

        this.encryptionInfoType = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
        this.encryptionInfoValue = sequence.getObjectAt(1);
    }

    public EncryptionInfo(ASN1ObjectIdentifier encryptionInfoType,
                          ASN1Encodable encryptionInfoValue)
    {
        this.encryptionInfoType = encryptionInfoType;
        this.encryptionInfoValue = encryptionInfoValue;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(encryptionInfoType);
        v.add(encryptionInfoValue);

        return new DLSequence(v);
    }
}
