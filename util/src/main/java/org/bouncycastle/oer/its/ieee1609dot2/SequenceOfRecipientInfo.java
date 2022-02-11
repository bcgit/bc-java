package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     SequenceOfRecipientInfo ::= SEQUENCE OF RecipientInfo
 * </pre>
 */
public class SequenceOfRecipientInfo
    extends ASN1Object
{
    private final List<RecipientInfo> recipientInfos;

    public SequenceOfRecipientInfo(List<RecipientInfo> recipientInfos)
    {
        this.recipientInfos = Collections.unmodifiableList(recipientInfos);
    }

    private SequenceOfRecipientInfo(ASN1Sequence sequence)
    {
        ArrayList<RecipientInfo> infoArrayList = new ArrayList<RecipientInfo>();
        for (Iterator<ASN1Encodable> it = sequence.iterator(); it.hasNext(); )
        {
            infoArrayList.add(RecipientInfo.getInstance(it.next()));
        }
        recipientInfos = Collections.unmodifiableList(infoArrayList);
    }

    public static SequenceOfRecipientInfo getInstance(Object object)
    {

        if (object instanceof SequenceOfRecipientInfo)
        {
            return (SequenceOfRecipientInfo)object;
        }

        if (object != null)
        {
            return new SequenceOfRecipientInfo(ASN1Sequence.getInstance(object));
        }
        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (RecipientInfo info : recipientInfos)
        {
            v.add(info);
        }
        return new DERSequence(v);
    }

    public List<RecipientInfo> getRecipientInfos()
    {
        return recipientInfos;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {

        private List<RecipientInfo> recipientInfos;

        public Builder setRecipientInfos(List<RecipientInfo> recipientInfos)
        {
            this.recipientInfos = recipientInfos;
            return this;
        }

        public Builder addRecipients(RecipientInfo... items)
        {
            if (recipientInfos == null)
            {
                recipientInfos = new ArrayList<RecipientInfo>();
            }
            recipientInfos.addAll(Arrays.asList(items));
            return this;
        }


        public SequenceOfRecipientInfo createSequenceOfRecipientInfo()
        {
            return new SequenceOfRecipientInfo(recipientInfos);
        }
    }

}
