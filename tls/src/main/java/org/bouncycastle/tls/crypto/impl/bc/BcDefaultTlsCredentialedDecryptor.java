package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;

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
     * TODO[tls-ops] Probably need to make RSA encryption/decryption into TlsCrypto functions so that users
     * can implement "generic" encryption credentials externally
     */
    protected TlsSecret safeDecryptPreMasterSecret(TlsCryptoParameters cryptoParams,
        RSAKeyParameters rsaServerPrivateKey, byte[] encryptedPreMasterSecret)
    {
        ProtocolVersion expectedVersion = cryptoParams.getRSAPreMasterSecretVersion();

        byte[] preMasterSecret = org.bouncycastle.crypto.tls.TlsRsaKeyExchange.decryptPreMasterSecret(
            encryptedPreMasterSecret, 0, encryptedPreMasterSecret.length, rsaServerPrivateKey,
            expectedVersion.getFullVersion(), crypto.getSecureRandom());

        return crypto.createSecret(preMasterSecret);
    }
}
