package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * CtlCommand ::= CHOICE {
 * add CtlEntry,
 * delete  CtlDelete,
 * ...
 * }
 */
public class CtlCommand
    extends ASN1Object
    implements ASN1Choice
{
    private final int choice;
    private final ASN1Encodable ctlCommand;

    public static final int add = 0;
    public static final int delete = 1;


    public CtlCommand(int choice, ASN1Encodable ctlCommand)
    {
        this.choice = choice;
        this.ctlCommand = ctlCommand;
    }

    private CtlCommand(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        switch (choice)
        {
        case add:
            ctlCommand = CtlEntry.getInstance(ato.getExplicitBaseObject());
            return;
        case delete:
            ctlCommand = CtlDelete.getInstance(ato.getExplicitBaseObject());
            return;
        }

        throw new IllegalArgumentException("invalid choice value " + choice);
    }

    public static CtlCommand getInstance(Object o)
    {
        if (o instanceof CtlCommand)
        {
            return (CtlCommand)o;
        }

        if (o != null)
        {
            return new CtlCommand(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }

    public static CtlCommand add(CtlEntry add)
    {
        return new CtlCommand(CtlCommand.add, add);
    }

    public static CtlCommand delete(CtlDelete delete)
    {
        return new CtlCommand(CtlCommand.delete, delete);
    }


    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getCtlCommand()
    {
        return ctlCommand;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, ctlCommand);
    }
}
