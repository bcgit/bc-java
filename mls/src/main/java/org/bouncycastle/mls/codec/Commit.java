package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Commit
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    List<ProposalOrRef> proposals;
    UpdatePath updatePath;

    public List<ProposalOrRef> getProposals()
    {
        return proposals;
    }

    public void setUpdatePath(UpdatePath updatePath)
    {
        this.updatePath = updatePath;
    }

    public UpdatePath getUpdatePath()
    {
        return updatePath;
    }

    public byte[] validityExternal()
    {
        // External Commits MUST contain a path field (and is therefore a "full"
        // Commit). The joiner is added at the leftmost free leaf node (just as if
        // they were added with an Add proposal), and the path is calculated relative
        // to that leaf node.

        // The Commit MUST NOT include any proposals by reference, since an external
        // joiner cannot determine the validity of proposals sent within the group
        for (ProposalOrRef p : proposals)
        {
            if (p.type == ProposalOrRefType.REFERENCE)
            {
                return null;
            }
        }
        if (updatePath == null)
        {
            return null;
        }

        int extIndex;
        for (extIndex = 0; extIndex < proposals.size(); extIndex++)
        {
            if (proposals.get(extIndex).proposal.getProposalType() == ProposalType.EXTERNAL_INIT)
            {
                break;
            }
        }
        if (extIndex == proposals.size())
        {
            return null;
        }

        return proposals.get(extIndex).proposal.externalInit.kemOutput;
    }

    public Commit()
    {
        this.proposals = new ArrayList<ProposalOrRef>();
    }

    @SuppressWarnings("unused")
    Commit(MLSInputStream stream)
        throws IOException
    {
        proposals = new ArrayList<ProposalOrRef>();
        stream.readList(proposals, ProposalOrRef.class);

        updatePath = (UpdatePath)stream.readOptional(UpdatePath.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.writeList(proposals);
        stream.writeOptional(updatePath);
    }
}
