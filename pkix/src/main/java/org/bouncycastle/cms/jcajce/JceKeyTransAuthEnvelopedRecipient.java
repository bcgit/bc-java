package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.InputStreamWithMAC;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.operator.InputAEADDecryptor;

public class JceKeyTransAuthEnvelopedRecipient
    extends JceKeyTransRecipient
{
    public JceKeyTransAuthEnvelopedRecipient(PrivateKey recipientKey)
    {
        super(recipientKey);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        final Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputAEADDecryptor()
        {
            private InputStream inputStream;

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataIn)
            {
                inputStream = dataIn;
                return new CipherInputStream(dataIn, dataCipher);
            }

            public OutputStream getAADStream()
            {
                return new AADStream(dataCipher);
            }

            public byte[] getMAC()
            {
                if (inputStream instanceof InputStreamWithMAC)
                {
                    return ((InputStreamWithMAC)inputStream).getMAC();
                }
                return null;
            }
        });
    }

    private static class AADStream
        extends OutputStream
    {
        private Cipher cipher;
        private byte[] oneByte = new byte[1];

        public AADStream(Cipher cipher)
        {
            this.cipher = cipher;
        }

        public void write(byte[] buf, int off, int len)
            throws IOException
        {
            cipher.updateAAD(buf, off, len);
        }

        public void write(int b)
            throws IOException
        {
            oneByte[0] = (byte)b;

            cipher.updateAAD(oneByte);
        }
    }
}
