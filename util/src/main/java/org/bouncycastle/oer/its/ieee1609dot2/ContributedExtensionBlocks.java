package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ContributedExtensionBlocks
    extends ASN1Object
{
    private final List<ContributedExtensionBlock> contributedExtensionBlocks;

    public ContributedExtensionBlocks(List<ContributedExtensionBlock> extensionBlocks)
    {
        this.contributedExtensionBlocks = Collections.unmodifiableList(extensionBlocks);
    }

    private ContributedExtensionBlocks(ASN1Sequence sequence)
    {
        List<ContributedExtensionBlock> blocks = new ArrayList<ContributedExtensionBlock>();
        for (Iterator<ASN1Encodable> it = sequence.iterator(); it.hasNext(); )
        {
            blocks.add(ContributedExtensionBlock.getInstance(it.next()));
        }
        contributedExtensionBlocks = Collections.unmodifiableList(blocks);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public List<ContributedExtensionBlock> getContributedExtensionBlocks()
    {
        return contributedExtensionBlocks;
    }

    public int size()
    {
        return contributedExtensionBlocks.size();
    }

    public static ContributedExtensionBlocks getInstance(Object o)
    {
        if (o instanceof ContributedExtensionBlocks)
        {
            return (ContributedExtensionBlocks)o;
        }

        if (o != null)
        {
            return new ContributedExtensionBlocks(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(contributedExtensionBlocks.toArray(new ContributedExtensionBlock[0]));
    }

    public static class Builder
    {
        private final List<ContributedExtensionBlock> extensionBlocks = new ArrayList<ContributedExtensionBlock>();

        public Builder add(ContributedExtensionBlock... blocks)
        {
            extensionBlocks.addAll(Arrays.asList(blocks));
            return this;
        }

        public ContributedExtensionBlocks build()
        {
            return new ContributedExtensionBlocks(extensionBlocks);
        }

    }

}
