package org.bouncycastle.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

public class BCLoadStoreParameter
    implements KeyStore.LoadStoreParameter
{
    private final InputStream in;
    private final OutputStream out;
    private final KeyStore.ProtectionParameter protectionParameter;

    /**
     * Base constructor for
     *
     * @param out
     * @param password
     */
    public BCLoadStoreParameter(OutputStream out, char[] password)
    {
        this(out, new KeyStore.PasswordProtection(password));
    }

    public BCLoadStoreParameter(InputStream in, char[] password)
    {
        this(in, new KeyStore.PasswordProtection(password));
    }

    public BCLoadStoreParameter(InputStream in, KeyStore.ProtectionParameter protectionParameter)
    {
        this(in, null, protectionParameter);
    }

    public BCLoadStoreParameter(OutputStream out, KeyStore.ProtectionParameter protectionParameter)
    {
        this(null, out, protectionParameter);
    }

    BCLoadStoreParameter(InputStream in, OutputStream out, KeyStore.ProtectionParameter protectionParameter)
    {
        this.in = in;
        this.out = out;
        this.protectionParameter = protectionParameter;
    }

    public KeyStore.ProtectionParameter getProtectionParameter()
    {
        return protectionParameter;
    }

    public OutputStream getOutputStream()
    {
        if (out == null)
        {
            throw new UnsupportedOperationException("parameter not configured for storage - no OutputStream");
        }

        return out;
    }

    public InputStream getInputStream()
    {
        if (out != null)
        {
            throw new UnsupportedOperationException("parameter configured for storage OutputStream present");
        }

        return in;
    }
}
