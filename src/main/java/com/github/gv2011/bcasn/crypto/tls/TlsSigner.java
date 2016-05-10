package com.github.gv2011.bcasn.crypto.tls;

import com.github.gv2011.bcasn.crypto.CryptoException;
import com.github.gv2011.bcasn.crypto.Signer;
import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;

public interface TlsSigner
{
    void init(TlsContext context);

    byte[] generateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1)
        throws CryptoException;

    byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm,
        AsymmetricKeyParameter privateKey, byte[] hash)
        throws CryptoException;

    boolean verifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] md5AndSha1)
        throws CryptoException;

    boolean verifyRawSignature(SignatureAndHashAlgorithm algorithm, byte[] sigBytes,
        AsymmetricKeyParameter publicKey, byte[] hash)
        throws CryptoException;

    Signer createSigner(AsymmetricKeyParameter privateKey);

    Signer createSigner(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey);

    Signer createVerifyer(AsymmetricKeyParameter publicKey);

    Signer createVerifyer(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter publicKey);

    boolean isValidPublicKey(AsymmetricKeyParameter publicKey);
}
