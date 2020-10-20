package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     Duration ::= CHOICE {
 *         microseconds Uint16,
 *         milliseconds Uint16,
 *         seconds Uint16,
 *         minutes Uint16,
 *         hours Uint16,
 *         sixtyHours Uint16,
 *         years Uint16
 *     }
 * </pre>
 */
public class Duration
    extends ASN1Object
    implements ASN1Choice
{
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
