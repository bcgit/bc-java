package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * RSA Utility methods.
 */
class TlsRSAUtils
{
    private TlsRSAUtils()
    {
    }

    /*
     * Generate a pre_master_secret and send it encrypted to the server
     */
    public static TlsSecret generateEncryptedPreMasterSecret(TlsContext context, TlsCertificate rsaServerCert,
        OutputStream output) throws IOException
    {
        TlsSecret preMasterSecret = context.getCrypto().generateRandomSecret(48);

        // add version details
        byte[] encodedSecret = preMasterSecret.extract();

        TlsUtils.writeVersion(context.getClientVersion(), encodedSecret, 0);

        // repackage for encryption and send.
        preMasterSecret = context.getCrypto().createSecret(encodedSecret);

        TlsEncryptor encryptor = context.getCrypto().createEncryptor(rsaServerCert);

        byte[] encryptedPreMasterSecret = preMasterSecret.extract(encryptor);

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
