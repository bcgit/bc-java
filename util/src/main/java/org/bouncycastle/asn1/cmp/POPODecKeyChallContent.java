package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * POPODecKeyChallContent ::= SEQUENCE OF Challenge
 * -- One Challenge per encryption key certification request (in the
 * -- same order as these requests appear in CertReqMessages).
 */
public class POPODecKeyChallContent
    extends ASN1Object
{
    private final ASN1Sequence content;

    private POPODecKeyChallContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static POPODecKeyChallContent getInstance(Object o)
    {
        if (o instanceof POPODecKeyChallContent)
        {
            return (POPODecKeyChallContent)o;
        }

        if (o != null)
        {
            return new POPODecKeyChallContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public POPODecKeyChallContent(Challenge... challenges)
    {
        content = new DERSequence(challenges);
    }

    public Challenge[] toChallengeArray()
    {
        Challenge[] result = new Challenge[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = Challenge.getInstance(content.getObjectAt(i));
        }

        return result;
    }


    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
