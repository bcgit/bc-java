package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;

/**
 * Credentialed class for generating signatures based on the use of primitives from the BC light-weight API.
 */
public class BcDefaultTlsCredentialedSigner
    extends DefaultTlsCredentialedSigner
{
    private static TlsSigner makeSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey, Certificate certificate,
        SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        if (privateKey instanceof RSAKeyParameters)
        {
            RSAKeyParameters privKeyRSA = (RSAKeyParameters)privateKey;

            if (signatureAndHashAlgorithm != null)
            {
                int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isRSAPSS(signatureScheme))
                {
                    return new BcTlsRSAPSSSigner(crypto, privKeyRSA, signatureScheme);
                }
            }

            return new BcTlsRSASigner(crypto, privKeyRSA);
        }
        else if (privateKey instanceof DSAPrivateKeyParameters)
        {
            return new BcTlsDSASigner(crypto, (DSAPrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            ECPrivateKeyParameters privKeyEC = (ECPrivateKeyParameters)privateKey;

            if (signatureAndHashAlgorithm != null)
            {
                // TODO[RFC 8998]
//                short signatureAlgorithm = signatureAndHashAlgorithm.getSignature();
//                switch (signatureAlgorithm)
//                {
//                case SignatureAlgorithm.sm2:
//                    return new BcTlsSM2Signer(crypto, privKeyEC, Strings.toByteArray("TLSv1.3+GM+Cipher+Suite"));
//                }

                int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isECDSA(signatureScheme))
                {
                    return new BcTlsECDSA13Signer(crypto, privKeyEC, signatureScheme);
                }
            }

            return new BcTlsECDSASigner(crypto, privKeyEC);
        }
        else if (privateKey instanceof Ed25519PrivateKeyParameters)
        {
            return new BcTlsEd25519Signer(crypto, (Ed25519PrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof Ed448PrivateKeyParameters)
        {
            return new BcTlsEd448Signer(crypto, (Ed448PrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof MLDSAPrivateKeyParameters)
        {
            if (signatureAndHashAlgorithm != null)
            {
                TlsSigner signer = BcTlsMLDSASigner.create(crypto, (MLDSAPrivateKeyParameters)privateKey,
                    SignatureScheme.from(signatureAndHashAlgorithm));
                if (signer != null)
                {
                    return signer;
                }
            }

            throw new IllegalArgumentException("ML-DSA private key of wrong type for signature algorithm");
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }
    }

    public BcDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, BcTlsCrypto crypto,
        AsymmetricKeyParameter privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        super(cryptoParams, makeSigner(crypto, privateKey, certificate, signatureAndHashAlgorithm), certificate,
            signatureAndHashAlgorithm);
    }
}
