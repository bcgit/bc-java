package org.bouncycastle.mls.crypto;

import java.io.IOException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface MlsSigner
{
    int ecdsa_secp256r1_sha256 = 3;
    int ecdsa_secp521r1_sha512 = 4;
    int ecdsa_secp384r1_sha384 = 5;
    int ed25519 = 7;
    int ed448 = 8;
    // ML-DSA (FIPS 204, pure, empty context) by the TLS SignatureScheme code points of draft-ietf-tls-mldsa,
    // as used by the post-quantum cipher suites of draft-ietf-mls-pq-ciphersuites
    int mldsa44 = 0x0904;
    int mldsa65 = 0x0905;
    int mldsa87 = 0x0906;

    AsymmetricCipherKeyPair generateSignatureKeyPair();

    byte[] serializePublicKey(AsymmetricKeyParameter key);

    byte[] serializePrivateKey(AsymmetricKeyParameter key);

    byte[] signWithLabel(byte[] priv, String label, byte[] content)
        throws IOException, CryptoException;

    boolean verifyWithLabel(byte[] pub, String label, byte[] content, byte[] signature)
        throws IOException;

    AsymmetricCipherKeyPair deserializePrivateKey(byte[] priv);

    AsymmetricKeyParameter deserializePublicKey(byte[] pub);
}
