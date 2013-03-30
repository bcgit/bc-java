package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class AbstractTlsCipherFactory implements TlsCipherFactory {

    public TlsCipher createCipher(TlsContext context, int encryptionAlgorithm, int macAlgorithm)
        throws IOException {

        return createCipher(context, encryptionAlgorithm, macAlgorithm, PRFAlgorithm.tls_prf_legacy);
    }

    public TlsCipher createCipher(TlsContext context, int encryptionAlgorithm, int macAlgorithm,
        int prfAlgorithm) throws IOException {

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
