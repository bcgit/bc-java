package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * CtlEntry ::= CHOICE {
 * rca   RootCaEntry,
 * ea    EaEntry,
 * aa    AaEntry,
 * dc    DcEntry,
 * tlm   TlmEntry,
 * ...
 * }
 */
public class CtlEntry
    extends ASN1Object
    implements ASN1Choice
{
    public static final int rca = 0;
    public static final int ea = 1;
    public static final int aa = 2;
    public static final int dc = 3;
    public static final int tlm = 4;

    private final int choice;
    private final ASN1Encodable ctlEntry;

    public CtlEntry(int choice, ASN1Encodable ctlEntry)
    {
        this.choice = choice;
        this.ctlEntry = ctlEntry;
    }


    private CtlEntry(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        switch (choice)
        {
        case rca:
            ctlEntry = RootCaEntry.getInstance(ato.getExplicitBaseObject());
            return;
        case ea:
            ctlEntry = EaEntry.getInstance(ato.getExplicitBaseObject());
            return;
        case aa:
            ctlEntry = AaEntry.getInstance(ato.getExplicitBaseObject());
            return;
        case dc:
            ctlEntry = DcEntry.getInstance(ato.getExplicitBaseObject());
            return;
        case tlm:
            ctlEntry = TlmEntry.getInstance(ato.getExplicitBaseObject());
            return;
        }

        throw new IllegalArgumentException("invalid choice value " + choice);

    }


    public static CtlEntry getInstance(Object o)
    {
        if (o instanceof CtlEntry)
        {
            return (CtlEntry)o;
        }

        if (o != null)
        {
            return new CtlEntry(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }
        return null;
    }

    public static CtlEntry rca(RootCaEntry rca)
    {
        return new CtlEntry(CtlEntry.rca, rca);
    }

    public static CtlEntry ea(EaEntry ea)
    {
        return new CtlEntry(CtlEntry.ea, ea);
    }

    public static CtlEntry aa(AaEntry aa)
    {
        return new CtlEntry(CtlEntry.aa, aa);
    }

    public static CtlEntry dc(DcEntry dc)
    {
        return new CtlEntry(CtlEntry.dc, dc);
    }

    public static CtlEntry tlm(TlmEntry tlm)
    {
        return new CtlEntry(CtlEntry.tlm, tlm);
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getCtlEntry()
    {
        return ctlEntry;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, ctlEntry);
    }
}
