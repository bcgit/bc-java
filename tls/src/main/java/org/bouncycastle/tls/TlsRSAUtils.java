package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsCertificate;
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
    public static TlsSecret generateEncryptedPreMasterSecret(TlsContext context, TlsCertificate certificate,
        OutputStream output) throws IOException
    {
        TlsSecret preMasterSecret = context.getCrypto()
            .generateRSAPreMasterSecret(context.getRSAPreMasterSecretVersion());

        byte[] encryptedPreMasterSecret = preMasterSecret.encrypt(certificate);
        TlsUtils.writeEncryptedPMS(context, encryptedPreMasterSecret, output);

        return preMasterSecret;
    }
}
