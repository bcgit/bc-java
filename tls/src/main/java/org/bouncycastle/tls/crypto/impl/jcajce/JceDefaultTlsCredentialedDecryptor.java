package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.Cipher;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.TlsImplUtils;
import org.bouncycastle.util.Arrays;

/**
 * Credentialed class decrypting RSA encrypted secrets sent from a peer for our end of the TLS connection using the JCE.
 */
public class JceDefaultTlsCredentialedDecryptor
    implements TlsCredentialedDecryptor
{
    protected JcaTlsCrypto crypto;
    protected Certificate certificate;
    protected PrivateKey privateKey;

    public JceDefaultTlsCredentialedDecryptor(JcaTlsCrypto crypto, Certificate certificate,
                                              PrivateKey privateKey)
    {
        if (crypto == null)
        {
            throw new IllegalArgumentException("'crypto' cannot be null");
        }
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty())
        {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }

        if (privateKey instanceof RSAPrivateKey || "RSA".equals(privateKey.getAlgorithm()))
        {
            this.crypto = crypto;
            this.certificate = certificate;
            this.privateKey = privateKey;
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: "
                + privateKey.getClass().getName());
        }
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public TlsSecret decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext) throws IOException
    {
        // TODO Keep only the decryption itself here - move error handling outside 
        return safeDecryptPreMasterSecret(cryptoParams, privateKey, ciphertext);
    }

    /*
     * TODO[tls-ops] Probably need to make RSA encryption/decryption into TlsCrypto functions so
     * that users can implement "generic" encryption credentials externally
     */
    protected TlsSecret safeDecryptPreMasterSecret(TlsCryptoParameters cryptoParams, PrivateKey rsaServerPrivateKey,
                                                   byte[] encryptedPreMasterSecret)
    {
        SecureRandom secureRandom = crypto.getSecureRandom();

        /*
         * RFC 5246 7.4.7.1.
         */
        ProtocolVersion expectedVersion = cryptoParams.getRSAPreMasterSecretVersion();

        // TODO Provide as configuration option?
        boolean versionNumberCheckDisabled = false;

        /*
         * Generate 48 random bytes we can use as a Pre-Master-Secret, if the
         * PKCS1 padding check should fail.
         */
        byte[] fallback = new byte[48];
        secureRandom.nextBytes(fallback);

        byte[] M = Arrays.clone(fallback);
        try
        {
            Cipher c = crypto.createRSAEncryptionCipher();
            c.init(Cipher.DECRYPT_MODE, rsaServerPrivateKey);
            byte[] m = c.doFinal(encryptedPreMasterSecret);
            if (m != null && m.length == 48)
            {
                M = m;
            }
        }
        catch (Exception e)
        {
            /*
             * A TLS server MUST NOT generate an alert if processing an
             * RSA-encrypted premaster secret message fails, or the version number is not as
             * expected. Instead, it MUST continue the handshake with a randomly generated
             * premaster secret.
             */
        }

        /*
         * If ClientHello.legacy_version is TLS 1.1 or higher, server implementations MUST check the
         * version number [..].
         */
        if (versionNumberCheckDisabled && !TlsImplUtils.isTLSv11(expectedVersion))
        {
            /*
             * If the version number is TLS 1.0 or earlier, server implementations SHOULD check the
             * version number, but MAY have a configuration option to disable the check.
             */
        }
        else
        {
            /*
             * Compare the version number in the decrypted Pre-Master-Secret with the legacy_version
             * field from the ClientHello. If they don't match, continue the handshake with the
             * randomly generated 'fallback' value.
             *
             * NOTE: The comparison and replacement must be constant-time.
             */
            int mask = (expectedVersion.getMajorVersion() ^ (M[0] & 0xFF))
                     | (expectedVersion.getMinorVersion() ^ (M[1] & 0xFF));

            // 'mask' will be all 1s if the versions matched, or else all 0s.
            mask = (mask - 1) >> 31;

            for (int i = 0; i < 48; i++)
            {
                M[i] = (byte)((M[i] & mask) | (fallback[i] & ~mask));
            }
        }

        return crypto.createSecret(M);
    }
}
