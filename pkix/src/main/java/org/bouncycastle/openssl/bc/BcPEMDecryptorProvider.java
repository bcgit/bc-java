package org.bouncycastle.openssl.bc;

import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PasswordException;

public class BcPEMDecryptorProvider
    implements PEMDecryptorProvider
{
    private final char[] password;

    public BcPEMDecryptorProvider(char[] password)
    {
        this.password = password;
    }

    public PEMDecryptor get(final String dekAlgName)
    {
        return new PEMDecryptor()
        {
            public byte[] decrypt(byte[] keyBytes, byte[] iv)
                throws PEMException
            {
                if (password == null)
                {
                    throw new PasswordException("Password is null, but a password is required");
                }

                return PEMUtilities.crypt(false, keyBytes, password, dekAlgName, iv);
            }
        };
    }
}
