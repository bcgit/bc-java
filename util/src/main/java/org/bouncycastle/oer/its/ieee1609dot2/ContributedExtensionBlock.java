package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.etsi103097.extension.EtsiOriginatingHeaderInfoExtension;

/**
 * ContributedExtensionBlock ::= SEQUENCE {
 * contributorId IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.
 * &amp;id({Ieee1609Dot2HeaderInfoContributedExtensions}),
 * extns   SEQUENCE (SIZE(1..MAX)) OF IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.
 * &amp;Extn({Ieee1609Dot2HeaderInfoContributedExtensions}{&#64;.contributorId})
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

        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }


        contributorId = HeaderInfoContributorId.getInstance(sequence.getObjectAt(0));

        Iterator<ASN1Encodable> items = ASN1Sequence.getInstance(sequence.getObjectAt(1)).iterator();
        List<EtsiOriginatingHeaderInfoExtension> extns = new ArrayList<EtsiOriginatingHeaderInfoExtension>();

        while (items.hasNext())
        {
            extns.add(EtsiOriginatingHeaderInfoExtension.getInstance(items.next()));
        }

        this.extns = Collections.unmodifiableList(extns);


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
