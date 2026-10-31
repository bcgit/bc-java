package org.bouncycastle.asn1.icao;


import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * The DataGroupHash object.
 * <pre>
 * DataGroupHash  ::=  SEQUENCE {
 *      dataGroupNumber         DataGroupNumber,
 *      dataGroupHashValue     OCTET STRING }
 *
 * DataGroupNumber ::= INTEGER {
 *         dataGroup1    (1),
 *         dataGroup1    (2),
 *         dataGroup1    (3),
 *         dataGroup1    (4),
 *         dataGroup1    (5),
 *         dataGroup1    (6),
 *         dataGroup1    (7),
 *         dataGroup1    (8),
 *         dataGroup1    (9),
 *         dataGroup1    (10),
 *         dataGroup1    (11),
 *         dataGroup1    (12),
 *         dataGroup1    (13),
 *         dataGroup1    (14),
 *         dataGroup1    (15),
 *         dataGroup1    (16) }
 *
 * </pre>
 */
public class DataGroupHash
    extends ASN1Object
{
    ASN1Integer dataGroupNumber;
    ASN1OctetString    dataGroupHashValue;

    public static DataGroupHash getInstance(
        Object obj)
    {
        if (obj instanceof DataGroupHash)
        {
            return (DataGroupHash)obj;
        }
        else if (obj != null)
        {
            return new DataGroupHash(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private DataGroupHash(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        dataGroupNumber = ASN1Integer.getInstance(seq.getObjectAt(0));
        dataGroupHashValue = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public DataGroupHash(
        int dataGroupNumber,
        ASN1OctetString     dataGroupHashValue)
    {
        this.dataGroupNumber = ASN1Integer.valueOf(dataGroupNumber);
        this.dataGroupHashValue = dataGroupHashValue;
    }

    public int getDataGroupNumber()
    {
        return dataGroupNumber.intValueExact();
    }

    public ASN1OctetString getDataGroupHashValue()
    {
        return dataGroupHashValue;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(dataGroupNumber, dataGroupHashValue);
    }
}
