package org.bouncycastle.asn1.x509.qualified;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * The QcType statementInfo defined by ETSI EN 319 412-5 sec. 4.2.3, used inside
 * a QCStatement whose statementId is {@link ETSIQCObjectIdentifiers#id_etsi_qcs_QcType}.
 * <pre>
 * QcType ::= SEQUENCE OF OBJECT IDENTIFIER
 * </pre>
 * The OIDs are drawn from {@link ETSIQCObjectIdentifiers#id_etsi_qct_esign},
 * {@link ETSIQCObjectIdentifiers#id_etsi_qct_eseal} and
 * {@link ETSIQCObjectIdentifiers#id_etsi_qct_web}.
 */
public class QcType
    extends ASN1Object
{
    private final ASN1ObjectIdentifier[] types;

    public static QcType getInstance(Object obj)
    {
        if (obj instanceof QcType)
        {
            return (QcType)obj;
        }
        if (obj != null)
        {
            return new QcType(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private QcType(ASN1Sequence seq)
    {
        this.types = new ASN1ObjectIdentifier[seq.size()];
        for (int i = 0; i != types.length; i++)
        {
            types[i] = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(i));
        }
    }

    public QcType(ASN1ObjectIdentifier type)
    {
        this.types = new ASN1ObjectIdentifier[]{ type };
    }

    public QcType(ASN1ObjectIdentifier[] types)
    {
        this.types = (ASN1ObjectIdentifier[])types.clone();
    }

    public ASN1ObjectIdentifier[] getTypes()
    {
        return (ASN1ObjectIdentifier[])types.clone();
    }

    /**
     * Return true if the supplied QcType OID is one of the declared types.
     */
    public boolean hasType(ASN1ObjectIdentifier type)
    {
        for (int i = 0; i != types.length; i++)
        {
            if (types[i].equals(type))
            {
                return true;
            }
        }
        return false;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(types.length);
        for (int i = 0; i != types.length; i++)
        {
            v.add(types[i]);
        }
        return new DERSequence(v);
    }
}
