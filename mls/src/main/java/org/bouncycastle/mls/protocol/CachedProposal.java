package org.bouncycastle.mls.protocol;

import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.codec.Sender;
import org.bouncycastle.util.Arrays;

public class CachedProposal
{
    byte[] proposalRef;
    Proposal proposal;
    LeafIndex sender;

    public CachedProposal(byte[] proposalRef, Proposal proposal, LeafIndex sender)
    {
        this.proposalRef = proposalRef;
        this.proposal = proposal;
        this.sender = sender;
    }
}
