package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

public class PublicMessage
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    FramedContent content;
    FramedContentAuthData auth;
    byte[] membership_tag;

    @SuppressWarnings("unused")
    public PublicMessage(MLSInputStream stream) throws IOException
    {
        content = (FramedContent) stream.read(FramedContent.class);
        auth = new FramedContentAuthData(stream, content.contentType);

        switch (content.sender.senderType)
        {

            case RESERVED:
            case EXTERNAL:
            case NEW_MEMBER_PROPOSAL:
            case NEW_MEMBER_COMMIT:
                break;
            case MEMBER:
                membership_tag = stream.readOpaque();
                break;
        }
    }


    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(content);
        stream.write(auth);

        switch (content.sender.senderType)
        {

            case RESERVED:
            case EXTERNAL:
            case NEW_MEMBER_PROPOSAL:
            case NEW_MEMBER_COMMIT:
                break;
            case MEMBER:
                stream.writeOpaque(membership_tag);
                break;
        }
    }


    public PublicMessage(FramedContent content, FramedContentAuthData auth, byte[] membership_tag)
    {
        this.content = content;
        this.auth = auth;
        switch (content.sender.senderType)
        {

            case RESERVED:
            case NEW_MEMBER_COMMIT:
            case EXTERNAL:
            case NEW_MEMBER_PROPOSAL:
                break;
            case MEMBER:
                this.membership_tag = membership_tag;
                break;
        }
    }

    static public PublicMessage protect(AuthenticatedContent authContent, CipherSuite suite,
                                        byte[] membershipKeyBytes, byte[] groupContextBytes) throws IOException
    {
        PublicMessage pt = new PublicMessage(authContent.content, authContent.auth, null);
        if (pt.content.sender.senderType == SenderType.MEMBER)
        {
            GroupContext context = (GroupContext) MLSInputStream.decode(groupContextBytes, GroupContext.class);
            Secret membershipKey = new Secret(membershipKeyBytes);
            pt.membership_tag = pt.membershipMac(suite, membershipKey, context);
        }
        return pt;
    }
    public AuthenticatedContent unprotect(CipherSuite suite, Secret membership_key, GroupContext context) throws IOException
    {
        if (content.sender.senderType == SenderType.MEMBER)
        {
            byte[] membershipTag = membershipMac(suite, membership_key, context);
            if (!Arrays.areEqual(membershipTag, membership_tag))
            {
                // throw tagMisMatch error!
                throw new IOException("incorrect membership tag");
            }
        }
        return new AuthenticatedContent(WireFormat.mls_public_message, content, auth);
    }

    public byte[] membershipMac(CipherSuite suite, Secret membershipKey, GroupContext context) throws IOException
    {
        // MAC(membership_key, AuthenticatedContentTBM)
        FramedContentTBS tbs = new FramedContentTBS(
                WireFormat.mls_public_message,
                content,
                context);
        AuthenticatedContentTBM tbm = new AuthenticatedContentTBM(tbs, auth);
        Secret ikm = new Secret(MLSOutputStream.encode(tbm));
        Secret membership_tag = Secret.extract(suite, membershipKey, ikm);
        return membership_tag.value();
    }
}
