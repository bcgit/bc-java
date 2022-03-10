package org.bouncycastle.oer.its.etsi102941;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;


public class SequenceOfCtlCommand
    extends ASN1Object
{
    private final List<CtlCommand> ctlCommands;

    public SequenceOfCtlCommand(List<CtlCommand> hashedId8s)
    {
        this.ctlCommands = Collections.unmodifiableList(hashedId8s);
    }

    private SequenceOfCtlCommand(ASN1Sequence sequence)
    {
        List<CtlCommand> items = new ArrayList<CtlCommand>();
        for (Iterator<ASN1Encodable> it = sequence.iterator(); it.hasNext(); )
        {
            items.add(CtlCommand.getInstance(it.next()));
        }
        this.ctlCommands = Collections.unmodifiableList(items);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static SequenceOfCtlCommand getInstance(Object o)
    {
        if (o instanceof SequenceOfCtlCommand)
        {
            return (SequenceOfCtlCommand)o;
        }
        if (o != null)
        {
            return new SequenceOfCtlCommand(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public List<CtlCommand> getCtlCommands()
    {
        return ctlCommands;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(ctlCommands.toArray(new ASN1Encodable[0]));
    }

    public static class Builder
    {
        private final List<CtlCommand> items = new ArrayList<CtlCommand>();

        public Builder addHashId8(CtlCommand... items)
        {
            this.items.addAll(Arrays.asList(items));
            return this;
        }

        public SequenceOfCtlCommand build()
        {
            return new SequenceOfCtlCommand(items);
        }
    }

}
