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
        ProtocolVersion clientVersion = cryptoParams.getClientVersion();

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
            M = c.doFinal(encryptedPreMasterSecret);
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
         * If ClientHello.client_version is TLS 1.1 or higher, server implementations MUST
         * check the version number [..].
         */
        if (versionNumberCheckDisabled && clientVersion.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv10))
        {
            /*
             * If the version number is TLS 1.0 or earlier, server
             * implementations SHOULD check the version number, but MAY have a
             * configuration option to disable the check.
             *
             * So there is nothing to do here.
             */
        }
        else
        {
            /*
             * OK, we need to compare the version number in the decrypted Pre-Master-Secret with the
             * clientVersion received during the handshake. If they don't match, we replace the
             * decrypted Pre-Master-Secret with a random one.
             */
            int correct = (clientVersion.getMajorVersion() ^ (M[0] & 0xff))
                | (clientVersion.getMinorVersion() ^ (M[1] & 0xff));
            correct |= correct >> 1;
            correct |= correct >> 2;
            correct |= correct >> 4;
            int mask = ~((correct & 1) - 1);

            /*
             * mask will be all bits set to 0xff if the version number differed.
             */
            for (int i = 0; i < 48; i++)
            {
                M[i] = (byte)((M[i] & (~mask)) | (fallback[i] & mask));
            }
        }
        return crypto.createSecret(M);
    }
}
