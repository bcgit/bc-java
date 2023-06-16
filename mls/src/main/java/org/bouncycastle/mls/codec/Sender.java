package org.bouncycastle.mls.codec;

import java.io.IOException;

public class Sender
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    SenderType senderType;
    int node_index; // leaf or sender

    public Sender(SenderType senderType, int node_index)
    {
        this.senderType = senderType;
        this.node_index = node_index;
    }

    public Sender(MLSInputStream stream) throws IOException
    {
        this.senderType = SenderType.values()[(byte) stream.read(byte.class)];
        switch (senderType)
        {

            case MEMBER:
            case EXTERNAL:
                node_index = (int) stream.read(int.class);
                break;
            case NEW_MEMBER_PROPOSAL:
            case NEW_MEMBER_COMMIT:
                break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(senderType);
        switch (senderType)
        {
            case MEMBER:
            case EXTERNAL:
                stream.write(node_index);
                break;
            case NEW_MEMBER_PROPOSAL:
            case NEW_MEMBER_COMMIT:
                break;
        }
    }
}
