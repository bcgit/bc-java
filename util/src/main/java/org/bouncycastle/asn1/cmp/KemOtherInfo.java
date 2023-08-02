package org.bouncycastle.asn1.cmp;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/*
 * <pre>
 * KemOtherInfo ::= SEQUENCE {
 *   staticString      PKIFreeText,  -- MUST be "CMP-KEM"
 *   transactionID [0] OCTET STRING     OPTIONAL,
 *   senderNonce   [1] OCTET STRING     OPTIONAL,
 *   recipNonce    [2] OCTET STRING     OPTIONAL,
 *   len               INTEGER (1..MAX),
 *   mac               AlgorithmIdentifier{MAC-ALGORITHM, {...}}
 *   ct                OCTET STRING
 * }
 * </pre>
 */
public class KemOtherInfo
    extends ASN1Object
{
    private static final PKIFreeText DEFAULT_staticString = new PKIFreeText("CMP-KEM");

    private final PKIFreeText staticString;
    private ASN1OctetString transactionID;
    private ASN1OctetString senderNonce;
    private ASN1OctetString recipNonce;
    private final ASN1Integer len;
    private final AlgorithmIdentifier mac;
    private final ASN1OctetString ct;

    public KemOtherInfo(
        ASN1OctetString transactionID,
        ASN1OctetString senderNonce,
        ASN1OctetString recipNonce,
        ASN1Integer len,
        AlgorithmIdentifier mac,
        ASN1OctetString ct)
    {
        this.staticString = DEFAULT_staticString;
        this.transactionID = transactionID;
        this.senderNonce = senderNonce;
        this.recipNonce = recipNonce;
        this.len = len;
        this.mac = mac;
        this.ct = ct;
    }

    public KemOtherInfo(
        ASN1OctetString transactionID,
        ASN1OctetString senderNonce,
        ASN1OctetString recipNonce,
        long len,
        AlgorithmIdentifier mac,
        ASN1OctetString ct)
    {
        this(transactionID, senderNonce, recipNonce, new ASN1Integer(len), mac, ct);
    }

    private KemOtherInfo(ASN1Sequence seq)
    {
        if (seq.size() < 4 || seq.size() > 7)
        {
            throw new IllegalArgumentException("sequence size should be between 4 and 7 inclusive");
        }

        Enumeration en = seq.getObjects();

        staticString = PKIFreeText.getInstance(en.nextElement());
        if (!staticString.equals(DEFAULT_staticString))
        {
            throw new IllegalArgumentException("staticString field should be " + DEFAULT_staticString);
        }

        ASN1Object next = null;
        while (en.hasMoreElements())
        {
            next = (ASN1Object)en.nextElement();
            if (!(next instanceof ASN1TaggedObject))
            {
                break;
            }
            ASN1TaggedObject tagged = (ASN1TaggedObject)next;
            switch (tagged.getTagNo())
            {
            case 0:
                transactionID = ASN1OctetString.getInstance(tagged, true);
                break;
            case 1:
                senderNonce = ASN1OctetString.getInstance(tagged, true);
                break;
            case 2:
                recipNonce = ASN1OctetString.getInstance(tagged, true);
            default:
                throw new IllegalArgumentException("unknown tag number: " + tagged.getTagNo());
            }
        }
        len = ASN1Integer.getInstance(next);
        mac = AlgorithmIdentifier.getInstance(en.nextElement());
        ct = ASN1OctetString.getInstance(en.nextElement());
    }

    public static KemOtherInfo getInstance(Object o)
    {
        if (o instanceof KemOtherInfo)
        {
            return (KemOtherInfo)o;
        }

        if (o != null)
        {
            return new KemOtherInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1OctetString getTransactionID()
    {
        return transactionID;
    }

    public ASN1OctetString getSenderNonce()
    {
        return senderNonce;
    }

    public ASN1OctetString getRecipNonce()
    {
        return recipNonce;
    }

    public ASN1Integer getLen()
    {
        return len;
    }

    public AlgorithmIdentifier getMac()
    {
        return mac;
    }

    public ASN1OctetString getCt()
    {
        return ct;
    }

    /**
     * <pre>
     * KemOtherInfo ::= SEQUENCE {
     *   staticString      PKIFreeText,   -- MUST be "CMP-KEM"
     *   transactionID [0] OCTET STRING     OPTIONAL,
     *   senderNonce   [1] OCTET STRING     OPTIONAL,
     *   recipNonce    [2] OCTET STRING     OPTIONAL,
     *   len               INTEGER (1..MAX),
     *   mac               AlgorithmIdentifier{MAC-ALGORITHM, {...}}
     *   ct                OCTET STRING
     * }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(7);

        v.add(staticString);
        addOptional(v, 0, transactionID);
        addOptional(v, 1, senderNonce);
        addOptional(v, 2, recipNonce);
        v.add(len);
        v.add(mac);
        v.add(ct);

        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }
}
