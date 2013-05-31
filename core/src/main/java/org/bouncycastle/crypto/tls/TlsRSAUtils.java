package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class TlsRSAUtils
{
    public static byte[] generateEncryptedPreMasterSecret(TlsContext context, RSAKeyParameters rsaServerPublicKey,
                                                          OutputStream output)
        throws IOException
    {
        /*
         * Choose a PremasterSecret and send it encrypted to the server
         */
        byte[] premasterSecret = new byte[48];
        context.getSecureRandom().nextBytes(premasterSecret);
        TlsUtils.writeVersion(context.getClientVersion(), premasterSecret, 0);

        PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
        encoding.init(true, new ParametersWithRandom(rsaServerPublicKey, context.getSecureRandom()));

        try
        {
            byte[] encryptedPreMasterSecret = encoding.processBlock(premasterSecret, 0, premasterSecret.length);

            if (context.getServerVersion().isSSL())
            {
                // TODO Do any SSLv3 servers actually expect the length?
                output.write(encryptedPreMasterSecret);
            }
            else
            {
                TlsUtils.writeOpaque16(encryptedPreMasterSecret, output);
            }
        }
        catch (InvalidCipherTextException e)
        {
            /*
             * This should never happen, only during decryption.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return premasterSecret;
    }
}
