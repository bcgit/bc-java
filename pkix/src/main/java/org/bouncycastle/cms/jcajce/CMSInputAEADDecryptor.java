package org.bouncycastle.cms.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.InputStreamWithMAC;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.operator.InputAEADDecryptor;

class CMSInputAEADDecryptor
    implements InputAEADDecryptor
{
    private final AlgorithmIdentifier contentEncryptionAlgorithm;

    private final Cipher dataCipher;

    private InputStream inputStream;

    CMSInputAEADDecryptor(AlgorithmIdentifier contentEncryptionAlgorithm, Cipher dataCipher)
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
        if (checkForAEAD())
        {
            return new JceAADStream(dataCipher);
        }

        return null; // TODO: okay this is awful, we could use AEADParameterSpec for earlier JDKs.
    }

    public byte[] getMAC()
    {
        if (inputStream instanceof InputStreamWithMAC)
        {
            return ((InputStreamWithMAC)inputStream).getMAC();
        }
        return null;
    }

    private static boolean checkForAEAD()
    {
        return (Boolean)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                try
                {
                    return Cipher.class.getMethod("updateAAD", byte[].class) != null;
                }
                catch (Exception ignore)
                {
                    // TODO[logging] Log the fact that we are falling back to BC-specific class
                    return Boolean.FALSE;
                }
            }
        });
    }
}
