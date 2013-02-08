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
    public static byte[] generateEncryptedPreMasterSecret(TlsClientContext context,
        RSAKeyParameters rsaServerPublicKey, OutputStream os) throws IOException
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
            boolean isTls = context.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
            byte[] keData = encoding.processBlock(premasterSecret, 0, premasterSecret.length);

            if (isTls)
            {
                TlsUtils.writeOpaque16(keData, os);
            }
            else
            {
                os.write(keData);
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
