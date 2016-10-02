package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsSecret;

public class TlsRSAUtils
{
    public static TlsSecret generateEncryptedPreMasterSecret(TlsContext context, TlsCertificate rsaServerCert,
        OutputStream output) throws IOException
    {
        // TODO[tls-ops] RSA pre_master_secret generation should be delegated to TlsCrypto

        /*
         * Choose a pre_master_secret and send it encrypted to the server
         */
        TlsSecret preMasterSecret = context.getCrypto().generateRandomSecret(48);

        byte[] encodedSecret = preMasterSecret.extract();

        TlsUtils.writeVersion(context.getClientVersion(), encodedSecret, 0);

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
