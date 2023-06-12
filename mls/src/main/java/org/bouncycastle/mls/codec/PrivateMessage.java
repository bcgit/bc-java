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
        System.out.println("keySize: " + keySize);
        System.out.println("nonceSize: " + nonceSize);
        Secret key = senderDataSecret.expandWithLabel(suite, "key", sample, keySize);
        Secret nonce = senderDataSecret.expandWithLabel(suite, "nonce", sample, nonceSize);


        SenderDataAAD senderDataAAD = new SenderDataAAD(group_id, epoch, content_type);
        byte[] senderDataPt = suite.getAEAD().open(
                key.value(),
                nonce.value(),
                MLSOutputStream.encode(senderDataAAD),
                ciphertext
        );
        SenderData senderData = (SenderData) MLSInputStream.decode(senderDataPt, SenderData.class);

        if (!keys.hasLeaf(senderData.sender))
        {
            return null;
        }

        // Decrypt the content
        KeyGeneration contentKeys = keys.get(content_type, senderData.sender, senderData.generation, senderData.reuseGuard);
        keys.erase(content_type, senderData.sender, senderData.generation);

        PrivateContentAAD contentAAD = new PrivateContentAAD(group_id, epoch, content_type, authenticated_data);
        byte[] contentPt = suite.getAEAD().open(
                contentKeys.key,
                contentKeys.nonce,
                MLSOutputStream.encode(contentAAD),
                ciphertext
        );

        System.out.println(Hex.toHexString(contentPt));

        // Parse Content
//        FramedContent content = new FramedContent(
//                group_id,
//                epoch,
//                new Sender(SenderType.MEMBER, (int)senderData.sender.value()),
//                authenticated_data,
//
//        )
//
//        AuthenticatedContent res = new AuthenticatedContent(
//                WireFormat.mls_private_message,
//
//
//        )


        return null;
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
}
