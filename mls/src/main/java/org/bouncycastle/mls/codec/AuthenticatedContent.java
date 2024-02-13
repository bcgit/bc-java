package org.bouncycastle.mls.codec;

import java.io.IOException;

import org.bouncycastle.mls.crypto.MlsCipherSuite;

public class AuthenticatedContent
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    WireFormat wireFormat;

    FramedContent content;
    FramedContentAuthData auth;

    public FramedContent getContent()
    {
        return content;
    }

    public WireFormat getWireFormat()
    {
        return wireFormat;
    }

    public void setConfirmationTag(byte[] tag)
    {
        auth.confirmation_tag = tag;
    }

    public byte[] getConfirmationTag()
    {
        return auth.confirmation_tag;
    }

    public byte[] getConfirmedTranscriptHashInput()
        throws IOException
    {
        return MLSOutputStream.encode(new ConfirmedTranscriptHashInput(wireFormat, content, auth.signature));
    }

    public byte[] getInterimTranscriptHashInput()
        throws IOException
    {
        return MLSOutputStream.encode(new InterimTranscriptHashInput(auth.confirmation_tag));
    }

    public AuthenticatedContent(WireFormat wireFormat, FramedContent content, FramedContentAuthData auth) throws Exception
    {
        this.wireFormat = wireFormat;
        this.content = content;
        this.auth = auth;

        if (auth.contentType == ContentType.APPLICATION)
        {
            if (wireFormat != WireFormat.mls_private_message)
            {
                throw new Exception("Unencrypted application message");
            }
            else if (content.sender.senderType != SenderType.MEMBER)
            {
                throw new Exception("sender must be a member");
            }
        }
    }

    public static AuthenticatedContent sign(WireFormat wireFormat, FramedContent content, MlsCipherSuite suite, byte[] sigPriv, byte[] groupContext)
        throws Exception
    {
        if (wireFormat == WireFormat.mls_public_message &&
            content.contentType == ContentType.APPLICATION)
        {
            throw new Exception("Application data cannot be sent as PublicMessage");
        }
        FramedContentTBS tbs = new FramedContentTBS(wireFormat, content, groupContext);
        byte[] signature = suite.signWithLabel(sigPriv, "FramedContentTBS", MLSOutputStream.encode(tbs));
        FramedContentAuthData auth = new FramedContentAuthData(content.contentType, signature, null);
        return new AuthenticatedContent(wireFormat, content, auth);
    }

    public boolean verify(MlsCipherSuite suite, byte[] sigPub, byte[] context)
        throws IOException
    {
        if (wireFormat == WireFormat.mls_public_message &&
            content.contentType == ContentType.APPLICATION)
        {
            return false;
        }

        FramedContentTBS tbs = new FramedContentTBS(wireFormat, content, context);
        return suite.verifyWithLabel(sigPub, "FramedContentTBS", MLSOutputStream.encode(tbs), auth.signature);
    }

    @SuppressWarnings("unused")
    public AuthenticatedContent(MLSInputStream stream)
        throws IOException
    {
        this.wireFormat = WireFormat.values()[(short)stream.read(short.class)];
        content = (FramedContent)stream.read(FramedContent.class);
        auth = new FramedContentAuthData(stream, content.contentType);
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(wireFormat);
        stream.write(content);
        stream.write(auth);
    }
}

class ConfirmedTranscriptHashInput
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    WireFormat wireFormat;
    FramedContent content;
    byte[] signature;

    public ConfirmedTranscriptHashInput(WireFormat wireFormat, FramedContent content, byte[] signature)
    {
        this.wireFormat = wireFormat;
        this.content = content;
        this.signature = signature;
    }

    @SuppressWarnings("unused")
    public ConfirmedTranscriptHashInput(MLSInputStream stream)
        throws IOException
    {
        this.wireFormat = WireFormat.values()[(short)stream.read(short.class)];
        content = (FramedContent)stream.read(FramedContent.class);
        signature = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(wireFormat);
        stream.write(content);
        stream.writeOpaque(signature);
    }
}

class InterimTranscriptHashInput
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] confirmation_tag;

    public InterimTranscriptHashInput(byte[] confirmation_tag)
    {
        this.confirmation_tag = confirmation_tag;
    }

    @SuppressWarnings("unused")
    public InterimTranscriptHashInput(MLSInputStream stream)
        throws IOException
    {
        confirmation_tag = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.writeOpaque(confirmation_tag);
    }
}
