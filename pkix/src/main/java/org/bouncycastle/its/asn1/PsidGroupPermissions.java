package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     PsidGroupPermissions ::= SEQUENCE {
 *         subjectPermissions SubjectPermissions,
 *         minChainLength INTEGER DEFAULT 1,
 *         chainLengthRange INTEGER DEFAULT 0,
 *         eeType EndEntityType DEFAULT (app)
 *     }
 * </pre>
 */
public class PsidGroupPermissions
    extends ASN1Object
{
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
