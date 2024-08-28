package org.bouncycastle.cms;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.jcajce.JceKEKAuthEnvelopedRecipient;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.operator.InputAEADDecryptor;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class CMSInputAEADDecryptor
        implements InputAEADDecryptor
{
    final AlgorithmIdentifier contentEncryptionAlgorithm;

    final Cipher dataCipher;

    private InputStream inputStream;

    public CMSInputAEADDecryptor(AlgorithmIdentifier contentEncryptionAlgorithm, Cipher dataCipher)
    {
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        this.dataCipher = dataCipher;
    }

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
