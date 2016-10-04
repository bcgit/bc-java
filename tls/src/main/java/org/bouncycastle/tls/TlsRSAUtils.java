package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * RSA Utility methods.
 */
public abstract class TlsRSAUtils
{
    private TlsRSAUtils()
    {
    }

    /*
     * Generate a pre_master_secret and send it encrypted to the server
     */
    public static TlsSecret generateEncryptedPreMasterSecret(TlsContext context, TlsEncryptor encryptor,
        OutputStream output) throws IOException
    {
        TlsSecret preMasterSecret = context.getCrypto().generateRSAPreMasterSecret(context.getClientVersion());

        byte[] encryptedPreMasterSecret = preMasterSecret.encrypt(encryptor);

        if (TlsUtils.isSSL(context))
        {
            // TODO Do any SSLv3 servers actually expect the length?
            output.write(encryptedPreMasterSecret);
        }
        else
        {
            TlsUtils.writeOpaque16(encryptedPreMasterSecret, output);
        }

        return preMasterSecret;
    }
}
