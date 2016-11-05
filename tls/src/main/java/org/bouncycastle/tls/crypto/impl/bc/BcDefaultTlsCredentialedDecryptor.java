package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * Credentialed class decrypting RSA encrypted secrets sent from a peer for our end of the TLS connection using the BC light-weight API.
 */
public class BcDefaultTlsCredentialedDecryptor
    implements TlsCredentialedDecryptor
{
    protected BcTlsCrypto crypto;
    protected Certificate certificate;
    protected AsymmetricKeyParameter privateKey;

    public BcDefaultTlsCredentialedDecryptor(BcTlsCrypto crypto, Certificate certificate,
                                           AsymmetricKeyParameter privateKey)
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
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("'privateKey' must be private");
        }

        if (privateKey instanceof RSAKeyParameters)
        {
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: "
                + privateKey.getClass().getName());
        }

        this.crypto = crypto;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public TlsSecret decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext) throws IOException
    {
        // TODO Keep only the decryption itself here - move error handling outside 
        return safeDecryptPreMasterSecret(cryptoParams, (RSAKeyParameters)privateKey, ciphertext);
    }

    /*
     * TODO[tls-ops] Probably need to make RSA encryption/decryption into TlsCrypto functions so
     * that users can implement "generic" encryption credentials externally
     */
    protected TlsSecret safeDecryptPreMasterSecret(TlsCryptoParameters cryptoParams, RSAKeyParameters rsaServerPrivateKey,
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
            PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine(), fallback);
            encoding.init(false, new ParametersWithRandom(rsaServerPrivateKey, secureRandom));

            M = encoding.processBlock(encryptedPreMasterSecret, 0, encryptedPreMasterSecret.length);
        }
        catch (Exception e)
        {
            /*
             * This should never happen since the decryption should never throw an exception
             * and return a random value instead.
             *
             * In any case, a TLS server MUST NOT generate an alert if processing an
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
