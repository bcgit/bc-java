package org.bouncycastle.asn1.cmc;

import java.util.Vector;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 * PKIData ::= SEQUENCE {
 * controlSequence    SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
 * reqSequence        SEQUENCE SIZE(0..MAX) OF TaggedRequest,
 * cmsSequence        SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
 * otherMsgSequence   SEQUENCE SIZE(0..MAX) OF OtherMsg
 * }
 * </pre>
 */
public class PKIData extends ASN1Object
{
    private Vector controlSequence;
    private Vector reqSequence;


    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
