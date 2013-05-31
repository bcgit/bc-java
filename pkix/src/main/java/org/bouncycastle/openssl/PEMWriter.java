package org.bouncycastle.openssl;

import java.io.IOException;
import java.io.Writer;
import java.security.SecureRandom;

import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * General purpose writer for OpenSSL PEM objects.
 */
public class PEMWriter
    extends PemWriter
{
    private String provider;

    /**
     * Base constructor.
     * 
     * @param out output stream to use.
     */
    public PEMWriter(Writer out)
    {
        this(out, "BC");
    }

    /**
     * @deprecated use constructor that just takes out, and writeObject(PEMEncryptor)
     * @param out
     * @param provider
     */
    public PEMWriter(
        Writer  out,
        String  provider)
    {
        super(out);

        this.provider = provider;
    }

    public void writeObject(
            Object  obj)
            throws IOException
    {
        writeObject(obj, null);
    }

    public void writeObject(
        Object  obj,
        PEMEncryptor encryptor)
        throws IOException
    {
        try
        {
            super.writeObject(new JcaMiscPEMGenerator(obj, encryptor));
        }
        catch (PemGenerationException e)
        {
            if (e.getCause() instanceof IOException)
            {
                throw (IOException)e.getCause();
            }

            throw e;
        }
    }

    public void writeObject(
        PemObjectGenerator obj)
        throws IOException
    {
        super.writeObject(obj);
    }

    /**
     * @deprecated use writeObject(obj, PEMEncryptor)
     */
    public void writeObject(
        Object       obj,
        String       algorithm,
        char[]       password,
        SecureRandom random)
        throws IOException
    {
        this.writeObject(obj, new JcePEMEncryptorBuilder(algorithm).setSecureRandom(random).setProvider(provider).build(password));
    }
}
