package org.bouncycastle.mls.codec;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.mls.GroupKeySet;
import org.bouncycastle.mls.KeyGeneration;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

public class PrivateMessage
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] group_id;
    long epoch;
    ContentType content_type;
    byte[] authenticated_data;
    byte[] encrypted_sender_data;
    byte[] ciphertext;

    PrivateMessage(MLSInputStream stream) throws IOException
    {
        group_id = stream.readOpaque();
        epoch = (long) stream.read(long.class);
        content_type = ContentType.values()[(byte) stream.read(byte.class)];
        authenticated_data = stream.readOpaque();
        encrypted_sender_data = stream.readOpaque();
        ciphertext = stream.readOpaque();
    }

    public AuthenticatedContent unprotect(CipherSuite suite, GroupKeySet keys, byte[] senderDataSecretBytes) throws IOException, InvalidCipherTextException, IllegalAccessException
    {
        // Decrypt and parse the sender data
        Secret senderDataSecret = new Secret(senderDataSecretBytes);
        int sampleSize = suite.getKDF().getHashLength();
        byte[] sample = Arrays.copyOf(ciphertext, sampleSize);
        int keySize = suite.getAEAD().getKeySize();
        int nonceSize = suite.getAEAD().getNonceSize();
        Secret key = senderDataSecret.expandWithLabel(suite, "key", sample, keySize);
        Secret nonce = senderDataSecret.expandWithLabel(suite, "nonce", sample, nonceSize);

        SenderDataAAD senderDataAAD = new SenderDataAAD(group_id, epoch, content_type);
        byte[] senderDataPt = suite.getAEAD().open(
                key.value(),
                nonce.value(),
                MLSOutputStream.encode(senderDataAAD),
                encrypted_sender_data
        );
        SenderData senderData = (SenderData) MLSInputStream.decode(senderDataPt, SenderData.class);
        if (!keys.hasLeaf(senderData.sender))
        {
            return null;
        }

        // Decrypt the content
        KeyGeneration contentKeys = keys.get(content_type, senderData.sender, senderData.generation, senderData.reuseGuard);

        PrivateContentAAD contentAAD = new PrivateContentAAD(group_id, epoch, content_type, authenticated_data);
        byte[] contentPtBytes = suite.getAEAD().open(
                contentKeys.key,
                contentKeys.nonce,
                MLSOutputStream.encode(contentAAD),
                ciphertext
        );

        //TODO: check if erase is working properly also check when to erase
        keys.erase(content_type, senderData.sender, senderData.generation);

        // Parse Content
        FramedContent content = new FramedContent(
                group_id,
                epoch,
                new Sender(SenderType.MEMBER, (int)senderData.sender.value()),
                authenticated_data,
                null,
                content_type,
                null,
                null
        );

        FramedContentAuthData auth = new FramedContentAuthData(
                content_type,
                null,
                null
        );
        deserializeContentPt(contentPtBytes, content, auth);

        return new AuthenticatedContent(
                WireFormat.mls_private_message,
                content,
                auth
        );
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(group_id);
        stream.write(epoch);
        stream.write(content_type);
        stream.writeOpaque(authenticated_data);
        stream.writeOpaque(encrypted_sender_data);
        stream.writeOpaque(ciphertext);
    }

    private void deserializeContentPt(byte[] contentPt, FramedContent content, FramedContentAuthData auth) throws IOException
    {
        MLSInputStream stream = new MLSInputStream(contentPt);
        switch (content_type)
        {
            case APPLICATION:
                content.application_data = stream.readOpaque();
                break;
            case PROPOSAL:
                content.proposal = (Proposal) stream.read(Proposal.class);
                break;
            case COMMIT:
                content.commit = (Commit) stream.read(Commit.class);
                break;
        }
        auth.signature = stream.readOpaque();
        switch (content_type)
        {
            case APPLICATION:
            case PROPOSAL:
                break;
            case COMMIT:
                auth.confirmation_tag = stream.readOpaque();
                break;
        }
    }
}
