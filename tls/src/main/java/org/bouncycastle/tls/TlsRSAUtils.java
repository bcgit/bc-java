package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCertificateRole;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * RSA utility methods.
 */
public abstract class TlsRSAUtils
{
    /**
     * Generate a pre_master_secret and send it encrypted to the server.
     * 
     * @deprecated Use
     *             {@link TlsUtils#generateEncryptedPreMasterSecret(TlsContext, TlsEncryptor, OutputStream)}
     *             instead.
     */
    public static TlsSecret generateEncryptedPreMasterSecret(TlsContext context, TlsCertificate certificate,
        OutputStream output) throws IOException
    {
        TlsEncryptor encryptor = certificate.createEncryptor(TlsCertificateRole.RSA_ENCRYPTION);

        return TlsUtils.generateEncryptedPreMasterSecret(context, encryptor, output);
    }
}
