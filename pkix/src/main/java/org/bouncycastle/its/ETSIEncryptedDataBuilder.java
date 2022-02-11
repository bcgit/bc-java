package org.bouncycastle.its;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.its.operator.ETSIDataEncryptor;
import org.bouncycastle.oer.its.ieee1609dot2.AesCcmCiphertext;
import org.bouncycastle.oer.its.ieee1609dot2.EncryptedData;
import org.bouncycastle.oer.its.ieee1609dot2.SequenceOfRecipientInfo;
import org.bouncycastle.oer.its.ieee1609dot2.SymmetricCiphertext;

public class ETSIEncryptedDataBuilder
{

    private final SecureRandom random;


    private final List<ETSIRecipientInfoBuilder> recipientInfoBuilders = new ArrayList<ETSIRecipientInfoBuilder>();

    public ETSIEncryptedDataBuilder()
    {
        this.random = new SecureRandom(); // TODO: remove
    }

    public void addRecipientInfoBuilder(ETSIRecipientInfoBuilder recipientInfoBuilder)
    {
        recipientInfoBuilders.add(recipientInfoBuilder);
    }

    public ETSIEncryptedData build(ETSIDataEncryptor encryptor, byte[] content)
    {

        byte[] key = new byte[16];
        random.nextBytes(key);

        byte[] opaque = encryptor.encrypt(key, content);
        byte[] nonce = encryptor.getNonce();

        SequenceOfRecipientInfo.Builder builder = SequenceOfRecipientInfo.builder();
        for (ETSIRecipientInfoBuilder recipientInfoBuilder : recipientInfoBuilders)
        {
            builder.addRecipients(recipientInfoBuilder.build(key));
        }

        // Encryption goes here

        return new ETSIEncryptedData(EncryptedData.builder()
            .setRecipients(builder.createSequenceOfRecipientInfo())
            .setCiphertext(SymmetricCiphertext.aes128ccm(AesCcmCiphertext.builder()
                .setOpaque(opaque)
                .setNonce(nonce)
                .createAesCcmCiphertext())).createEncryptedData()
        );
    }

}
