package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * <pre>
 * EDIPartyName ::= Sequence {
 *      nameAssigner            [0]     DirectoryString OPTIONAL,
 *      partyName               [1]     DirectoryString }
 * </pre>
 */
public class EDIPartyName
    extends ASN1Object
{
    public static EDIPartyName getInstance(Object obj)
    {
        if (obj instanceof EDIPartyName)
        {
            return (EDIPartyName)obj;
        }
        else if (obj != null)
        {
            return new EDIPartyName(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static EDIPartyName getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new EDIPartyName(ASN1Sequence.getTagged(taggedObject, declaredExplicit));
    }

    private final DirectoryString nameAssigner;
    private final DirectoryString partyName;

    private EDIPartyName(ASN1Sequence seq)
    {
        int count = seq.size(), pos = 0;
        if (count < 1 || count > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }

        // DirectoryString is a CHOICE type, so use explicit tagging despite IMPLICIT TAGS

        // nameAssigner [0] DirectoryString OPTIONAL
        DirectoryString nameAssigner = null;
        if (pos < count)
        {
            ASN1TaggedObject tag0 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 0);
            if (tag0 != null)
            {
                pos++;
                nameAssigner = DirectoryString.getTagged(tag0, true);
            }
        }
        this.nameAssigner = nameAssigner;

        ASN1TaggedObject tag1 = ASN1TaggedObject.getContextInstance(seq.getObjectAt(pos++), 1);        
        this.partyName = DirectoryString.getTagged(tag1, true);

        if (pos != count)
        {
            throw new IllegalArgumentException("Unexpected elements in sequence");
        }
    }

    public EDIPartyName(DirectoryString nameAssigner, DirectoryString partyName)
    {
        if (partyName == null)
        {
            throw new NullPointerException("'partyName' cannot be null");
        }

        this.nameAssigner = nameAssigner;
        this.partyName = partyName;
    }

    public DirectoryString getNameAssigner()
    {
        return nameAssigner;
    }

    public DirectoryString getPartyName()
    {
        return partyName;
    }

    public ASN1Primitive toASN1Primitive()
    {
        // DirectoryString is a CHOICE type, so the [0] and [1] tags are explicit despite the
        // IMPLICIT TAGS of the RFC 5280 module - the same reasoning the decoder above applies.
        // Emitting the DirectoryStrings untagged left the encoder unable to parse its own output.
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        if (nameAssigner != null)
        {
            v.add(new DERTaggedObject(true, 0, nameAssigner));
        }
        v.add(new DERTaggedObject(true, 1, partyName));

        return new DERSequence(v);
    }
}
