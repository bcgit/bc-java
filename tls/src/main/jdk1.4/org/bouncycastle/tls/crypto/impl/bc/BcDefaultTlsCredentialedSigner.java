package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;

/**
 * Credentialed class for generating signatures based on the use of primitives from the BC light-weight API.
 */
public class BcDefaultTlsCredentialedSigner
    extends DefaultTlsCredentialedSigner
{
    private static TlsSigner makeSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey, Certificate certificate)
    {
        TlsSigner signer;
        if (privateKey instanceof RSAKeyParameters)
        {
            signer = new BcTlsRSASigner(crypto, (RSAKeyParameters)privateKey);
        }
        else if (privateKey instanceof DSAPrivateKeyParameters)
        {
            signer = new BcTlsDSASigner(crypto, (DSAPrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            signer = new BcTlsECDSASigner(crypto, (ECPrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof Ed25519PrivateKeyParameters)
        {
            try
            {
                signer = new BcTlsEd25519Signer(crypto, (Ed25519PrivateKeyParameters)privateKey,
                    BcTlsCertificate.convert(crypto, certificate.getCertificateAt(0)).getPubKeyEd25519());
            }
            catch (IOException e)
            {
                throw new org.bouncycastle.tls.exceptions.IllegalArgumentException(e);
            }
        }
        else if (privateKey instanceof Ed448PrivateKeyParameters)
        {
            try
            {
                signer = new BcTlsEd448Signer(crypto, (Ed448PrivateKeyParameters)privateKey,
                    BcTlsCertificate.convert(crypto, certificate.getCertificateAt(0)).getPubKeyEd448());
            }
            catch (IOException e)
            {
                throw new org.bouncycastle.tls.exceptions.IllegalArgumentException(e);
            }
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }

        return signer;
    }

    public BcDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, BcTlsCrypto crypto, AsymmetricKeyParameter privateKey,
        Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        super(cryptoParams, makeSigner(crypto, privateKey, certificate), certificate, signatureAndHashAlgorithm);
    }
}
