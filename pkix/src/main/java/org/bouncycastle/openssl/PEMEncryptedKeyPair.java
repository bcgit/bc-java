package org.bouncycastle.openssl;

import java.io.IOException;

import org.bouncycastle.operator.OperatorCreationException;

public class PEMEncryptedKeyPair
{
    private final String dekAlgName;
    private final byte[] iv;
    private final byte[] keyBytes;
    private final PEMKeyPairParser parser;

    PEMEncryptedKeyPair(String dekAlgName, byte[] iv, byte[] keyBytes, PEMKeyPairParser parser)
    {
        this.dekAlgName = dekAlgName;
        this.iv = iv;
        this.keyBytes = keyBytes;
        this.parser = parser;
    }

    /**
     * Return the key encryption algorithm name that was in the original DEK-Info field.
     *
     * @return the key encryption algorithm name.
     */
    public String getDekAlgName()
    {
        return dekAlgName;
    }

    public PEMKeyPair decryptKeyPair(PEMDecryptorProvider keyDecryptorProvider)
        throws IOException
    {
        try
        {
            PEMDecryptor keyDecryptor = keyDecryptorProvider.get(dekAlgName);

            return parser.parse(keyDecryptor.decrypt(keyBytes, iv));
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (OperatorCreationException e)
        {
            throw new PEMException("cannot create extraction operator: " + e.getMessage(), e);
        }
        catch (Exception e)
        {
            throw new PEMException("exception processing key pair: " + e.getMessage(), e);
        }
    }
}
