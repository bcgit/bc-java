package org.bouncycastle.mls.codec;

import java.io.IOException;

public class ProposalOrRef
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    public ProposalOrRefType type;
    public Proposal proposal;

    //opaque HashReference<V>;
    //HashReference ProposalRef;
    //MakeProposalRef(value)   = RefHash("MLS 1.0 Proposal Reference", value)
    //RefHash(label, value) = Hash(RefHashInput)
    //For a ProposalRef, the value input is the AuthenticatedContent carrying the proposal.

    // opaque reference = RefHash("MLS 1.0 Proposal Reference", auth.proposal
    public byte[] reference; // TODO ProposalRef

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

    ProposalOrRef(MLSInputStream stream) throws IOException
    {
        this.type = ProposalOrRefType.values()[(byte) stream.read(byte.class)];
        switch (type)
        {
            case PROPOSAL:
                proposal = (Proposal) stream.read(Proposal.class);
                break;
            case REFERENCE:
                reference = stream.readOpaque();
                break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
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
