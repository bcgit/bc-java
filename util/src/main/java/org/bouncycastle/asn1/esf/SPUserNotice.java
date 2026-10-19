package org.bouncycastle.asn1.esf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.NoticeReference;

public class SPUserNotice
    extends ASN1Object
{
    private NoticeReference noticeRef;
    private DisplayText     explicitText;

    public static SPUserNotice getInstance(
        Object obj)
    {
        if (obj instanceof SPUserNotice)
        {
            return (SPUserNotice)obj;
        }
        else if (obj != null)
        {
            return new SPUserNotice(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private SPUserNotice(
        ASN1Sequence seq)
    {
        // noticeRef NoticeReference OPTIONAL, then explicitText DisplayText OPTIONAL
        int count = seq.size(), pos = 0;
        if (pos < count && (seq.getObjectAt(pos) instanceof NoticeReference || seq.getObjectAt(pos) instanceof ASN1Sequence))
        {
            noticeRef = NoticeReference.getInstance(seq.getObjectAt(pos++));
        }
        if (pos < count && (seq.getObjectAt(pos) instanceof DisplayText || seq.getObjectAt(pos) instanceof ASN1String))
        {
            explicitText = DisplayText.getInstance(seq.getObjectAt(pos++));
        }
        if (pos != count)
        {
            throw new IllegalArgumentException("unexpected element at position " + pos);
        }
    }

    public SPUserNotice(
        NoticeReference noticeRef,
        DisplayText     explicitText)
    {
        this.noticeRef = noticeRef;
        this.explicitText = explicitText;
    }

    public NoticeReference getNoticeRef()
    {
        return noticeRef;
    }

    public DisplayText getExplicitText()
    {
        return explicitText;
    }

    /**
     * <pre>
     * SPUserNotice ::= SEQUENCE {
     *     noticeRef NoticeReference OPTIONAL,
     *     explicitText DisplayText OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        if (noticeRef != null)
        {
            v.add(noticeRef);
        }

        if (explicitText != null)
        {
            v.add(explicitText);
        }

        return new DERSequence(v);
    }
}
