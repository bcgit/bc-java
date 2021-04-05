package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * <pre>
 * SinglePubInfo ::= SEQUENCE {
 *        pubMethod    INTEGER {
 *           dontCare    (0),
 *           x500        (1),
 *           web         (2),
 *           ldap        (3) },
 *       pubLocation  GeneralName OPTIONAL }
 * </pre>
 */
public class SinglePubInfo
    extends ASN1Object
{
    public static final ASN1Integer dontCare = new ASN1Integer(0);
    public static final ASN1Integer x500 = new ASN1Integer(1);
    public static final ASN1Integer web = new ASN1Integer(2);
    public static final ASN1Integer ldap = new ASN1Integer(3);

    private ASN1Integer pubMethod;
    private GeneralName pubLocation;

    private SinglePubInfo(ASN1Sequence seq)
    {
        pubMethod = ASN1Integer.getInstance(seq.getObjectAt(0));

        if (seq.size() == 2)
        {
            pubLocation = GeneralName.getInstance(seq.getObjectAt(1));
        }
    }

    public static SinglePubInfo getInstance(Object o)
    {
        if (o instanceof SinglePubInfo)
        {
            return (SinglePubInfo)o;
        }

        if (o != null)
        {
            return new SinglePubInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public SinglePubInfo(ASN1Integer pubMethod, GeneralName pubLocation)
    {
        this.pubMethod = pubMethod;
        this.pubLocation = pubLocation;
    }

    public ASN1Integer getPubMethod()
    {
        return pubMethod;
    }

    public GeneralName getPubLocation()
    {
        return pubLocation;
    }

    /**
     * Return the primitive representation of SinglePubInfo.
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(pubMethod);

        if (pubLocation != null)
        {
            v.add(pubLocation);
        }

        return new DERSequence(v);
    }
}
