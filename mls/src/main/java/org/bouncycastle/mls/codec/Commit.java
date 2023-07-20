package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.List;

public class Commit
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    List<ProposalOrRef> proposals;

    byte[] proposalsBytes;
    UpdatePath updatePath;

    Commit(MLSInputStream stream) throws IOException
    {
//        proposals = new ArrayList<>();
//        stream.readList(proposals ,ProposalOrRef.class);
        proposalsBytes = stream.readOpaque();
        updatePath = (UpdatePath) stream.readOptional(UpdatePath.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(proposalsBytes);
//        stream.writeList(proposals);
        stream.writeOptional(updatePath);
    }
}
