package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.EtsiOriginatingHeaderInfoExtension;
import org.bouncycastle.oer.its.ItsUtils;

/**
 * ContributedExtensionBlock ::= SEQUENCE {
 * contributorId IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.
 * &id({Ieee1609Dot2HeaderInfoContributedExtensions}),
 * extns   SEQUENCE (SIZE(1..MAX)) OF IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.
 * &Extn({Ieee1609Dot2HeaderInfoContributedExtensions}{@.contributorId})
 * }
 */
public class ContributedExtensionBlock
    extends ASN1Object
{
    private final HeaderInfoContributorId contributorId;
    private final List<EtsiOriginatingHeaderInfoExtension> extns;

    public ContributedExtensionBlock(HeaderInfoContributorId contributorId, List<EtsiOriginatingHeaderInfoExtension> extns)
    {
        this.contributorId = contributorId;
        this.extns = extns;
    }

    private ContributedExtensionBlock(ASN1Sequence sequence)
    {

        Iterator<ASN1Encodable> items = sequence.iterator();

        HeaderInfoContributorId id = HeaderInfoContributorId.getInstance(items.next());
        List<EtsiOriginatingHeaderInfoExtension> extns = new ArrayList<EtsiOriginatingHeaderInfoExtension>();

        while (items.hasNext())
        {
            extns.add(EtsiOriginatingHeaderInfoExtension.getInstance(items.next()));
        }

        contributorId = null;
        this.extns = null;

//        return new ContributedExtensionBlock(id, extns);

    }

    public static ContributedExtensionBlock getInstance(Object src)
    {
        if (src instanceof ContributedExtensionBlock)
        {
            return (ContributedExtensionBlock)src;
        }

        if (src != null)
        {
            return new ContributedExtensionBlock(ASN1Sequence.getInstance(src));
        }

        return null;


    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(contributorId, ItsUtils.toSequence(extns));
    }

    public HeaderInfoContributorId getContributorId()
    {
        return contributorId;
    }

    public List<EtsiOriginatingHeaderInfoExtension> getExtns()
    {
        return extns;
    }
}
