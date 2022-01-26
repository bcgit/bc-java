package org.bouncycastle.oer.its;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.HeaderInfoContributorId;

/**
 * Ieee1609Dot2HeaderInfoContributedExtensions
 * IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION ::= {
 * {EtsiOriginatingHeaderInfoExtension IDENTIFIED BY etsiHeaderInfoContributorId},
 * ...
 * }
 */
public class EtsiOriginatingHeaderInfoExtension
    extends ASN1Object
{

    private final HeaderInfoContributorId etsiHeaderInfoContributorId;
    private final ASN1OctetString extension;


    public EtsiOriginatingHeaderInfoExtension(HeaderInfoContributorId etsiHeaderInfoContributorId, ASN1OctetString extension)
    {
        this.etsiHeaderInfoContributorId = etsiHeaderInfoContributorId;
        this.extension = extension;
    }

    public static EtsiOriginatingHeaderInfoExtension getInstance(Object src)
    {
        if (src instanceof EtsiOriginatingHeaderInfoExtension)
        {
            return (EtsiOriginatingHeaderInfoExtension)src;
        }


        Iterator<ASN1Encodable> items = ASN1Sequence.getInstance(src).iterator();
        HeaderInfoContributorId id = HeaderInfoContributorId.getInstance(items.next());

        // TODO not sure this is correct.
        if (items.hasNext())
        {
            return new EtsiOriginatingHeaderInfoExtension(id, ASN1OctetString.getInstance(items.next()));
        }

        return new EtsiOriginatingHeaderInfoExtension(id, null);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(etsiHeaderInfoContributorId, extension);
    }

    public HeaderInfoContributorId getEtsiHeaderInfoContributorId()
    {
        return etsiHeaderInfoContributorId;
    }

    public ASN1OctetString getExtension()
    {
        return extension;
    }
}
