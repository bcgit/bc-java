package org.bouncycastle.mls.codec;

import java.io.IOException;

public class ProposalOrRef
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProposalOrRefType type;
    Proposal proposal;

    byte[] reference;

    public ProposalOrRefType getType()
    {
        return type;
    }

    public Proposal getProposal()
    {
        return proposal;
    }

    public byte[] getReference()
    {
        return reference;
    }


    static public ProposalOrRef forRef(byte[] ref)
    {
        return new ProposalOrRef(ProposalOrRefType.REFERENCE, null, ref);
    }

    static public ProposalOrRef forProposal(Proposal proposal)
    {
        return new ProposalOrRef(ProposalOrRefType.PROPOSAL, proposal, null);
    }

    public ProposalOrRef(ProposalOrRefType type, Proposal proposal, byte[] reference)
    {
        this.type = type;
        this.proposal = proposal;
        this.reference = reference;
    }

    @SuppressWarnings("unused")
    ProposalOrRef(MLSInputStream stream)
        throws IOException
    {
        this.type = ProposalOrRefType.values()[(byte)stream.read(byte.class)];
        switch (type)
        {
        case PROPOSAL:
            proposal = (Proposal)stream.read(Proposal.class);
            break;
        case REFERENCE:
            reference = stream.readOpaque();
            break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(type);
        switch (type)
        {
        case PROPOSAL:
            stream.write(proposal);
            break;
        case REFERENCE:
            stream.writeOpaque(reference);
            break;
        }
    }
}
