package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public abstract class TlsRsaKeyExchange
{
    private TlsRsaKeyExchange()
    {
    }

    public static byte[] decryptPreMasterSecret(byte[] encryptedPreMasterSecret, RSAKeyParameters privateKey,
        int protocolVersion, SecureRandom secureRandom)
    {
        /*
         * Generate 48 random bytes we can use as a Pre-Master-Secret, if the PKCS1 padding check should fail.
         */
        byte[] fallback = new byte[48];
        secureRandom.nextBytes(fallback);

        byte[] M = Arrays.clone(fallback);
        try
        {
            PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine(), fallback);
            encoding.init(false, new ParametersWithRandom(privateKey, secureRandom));

            M = encoding.processBlock(encryptedPreMasterSecret, 0, encryptedPreMasterSecret.length);
        }
        catch (Exception e)
        {
            /*
             * This should never happen since the decryption should never throw an exception and return a
             * random value instead.
             *
             * In any case, a TLS server MUST NOT generate an alert if processing an RSA-encrypted premaster
             * secret message fails, or the version number is not as expected. Instead, it MUST continue the
             * handshake with a randomly generated premaster secret.
             */
        }

        /*
         * Compare the version number in the decrypted Pre-Master-Secret with the legacy_version field from
         * the ClientHello. If they don't match, continue the handshake with the randomly generated 'fallback'
         * value.
         *
         * NOTE: The comparison and replacement must be constant-time.
         */
        int mask = (Pack.bigEndianToShort(M, 0) ^ protocolVersion) & 0xFFFF;

        // 'mask' will be all 1s if the versions matched, or else all 0s.
        mask = (mask - 1) >> 31;

        for (int i = 0; i < 48; i++)
        {
            M[i] = (byte)((M[i] & mask) | (fallback[i] & ~mask));
        }

        return M;
    }
}
