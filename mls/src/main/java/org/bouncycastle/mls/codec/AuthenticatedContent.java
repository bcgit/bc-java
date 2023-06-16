package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.crypto.CipherSuite;

import java.io.IOException;

public class AuthenticatedContent
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    WireFormat wireFormat;
    public FramedContent content;
    FramedContentAuthData auth;

    public void setConfirmationTag(byte[] tag)
    {
        auth.confirmation_tag = tag;
    }
    public AuthenticatedContent(WireFormat wireFormat, FramedContent content, FramedContentAuthData auth)
    {
        this.wireFormat = wireFormat;
        this.content = content;
        this.auth = auth;

        //TODO move elsewhere?
        if (auth.contentType == ContentType.COMMIT && auth.confirmation_tag == null)
        {
            //TODO
//            throw new MissingConfirmationTag()
        }

        if (auth.contentType == ContentType.APPLICATION)
        {
            if (wireFormat != WireFormat.mls_private_message)
            {
//                throw new UnencryptedApplicationMessage()
            }
            else if (content.sender.senderType != SenderType.MEMBER)
            {
//                throw new Exception("sender must be a member")
            }
        }
    }

    public static AuthenticatedContent sign(WireFormat wireFormat, FramedContent content, CipherSuite suite, byte[] sigPriv, byte[] groupContext) throws Exception
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

    public boolean verify(CipherSuite suite, byte[] sigPub, byte[] context) throws IOException
    {
        if (wireFormat == WireFormat.mls_public_message &&
                content.contentType == ContentType.APPLICATION)
        {
            return false;
        }

        FramedContentTBS tbs = new FramedContentTBS(wireFormat, content, context);
        return suite.verifyWithLabel(sigPub, "FramedContentTBS", MLSOutputStream.encode(tbs), auth.signature);
    }

    public AuthenticatedContent(MLSInputStream stream) throws IOException
    {
        this.wireFormat = WireFormat.values()[(short) stream.read(short.class)];
        content = (FramedContent) stream.read(FramedContent.class);
        auth = new FramedContentAuthData(stream, content.contentType);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(wireFormat);
        stream.write(content);
        stream.write(auth);
    }
}
