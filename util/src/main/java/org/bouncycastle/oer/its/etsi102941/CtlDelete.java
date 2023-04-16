package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/**
 * CtlDelete ::= CHOICE {
 * cert  HashedId8,
 * dc    DcDelete,
 * ...
 * }
 */
public class CtlDelete
    extends ASN1Object
    implements ASN1Choice
{

    public static final int cert = 0;
    public static final int dc = 1;

    private final int choice;
    private final ASN1Encodable ctlDelete;

    public static CtlDelete cert(HashedId8 value)
    {
        return new CtlDelete(cert, value);
    }

    public static CtlDelete dc(DcDelete value)
    {
        return new CtlDelete(dc, value);
    }


    public CtlDelete(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        switch (choice)
        {
        case cert:
            ctlDelete = HashedId8.getInstance(value);
            return;
        case dc:
            ctlDelete = DcDelete.getInstance(value);
            return;
        }
        throw new IllegalArgumentException("invalid choice value " + choice);
    }

    private CtlDelete(ASN1TaggedObject value)
    {
        this(value.getTagNo(), value.getExplicitBaseObject());
    }

    public static CtlDelete getInstance(Object o)
    {
        if (o instanceof CtlDelete)
        {
            return (CtlDelete)o;
        }

        if (o != null)
        {
            return new CtlDelete(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }
        return null;
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getCtlDelete()
    {
        return ctlDelete;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, ctlDelete);
    }
}
