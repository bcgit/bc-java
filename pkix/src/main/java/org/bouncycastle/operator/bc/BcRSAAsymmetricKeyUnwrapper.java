package org.bouncycastle.operator.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Lightweight unwrapper for RSA PKCS#1 v1.5 ({@code rsaEncryption}) key transport, used by the
 * BC CMS / PKIX recipient implementations.
 * <p>
 * <b>Bleichenbacher/Marvin note:</b> PKCS#1 v1.5 RSA decryption is inherently vulnerable to
 * adaptive chosen-ciphertext (Bleichenbacher / Marvin) attacks whenever an attacker can submit
 * ciphertexts and distinguish a padding failure from a success -- including only by timing or
 * observable behaviour. This unwrapper reports a decryption/padding failure by throwing (an
 * {@link org.bouncycastle.operator.OperatorException}) rather than returning a random key of the
 * expected length, so a service that decrypts attacker-supplied key-transport blobs with a static
 * RSA private key and exposes the outcome (a distinguishable error, or a response-time difference)
 * acts as such an oracle. The lightweight {@link PKCS1Encoding} offers a constant-time
 * random-fallback mode (return a random key of the expected length on bad padding instead of
 * throwing); the BC TLS stack wires it for the RSA key-exchange pre-master secret, but it is not
 * applied here, so padding-oracle resistance for CMS/PKIX key transport is left to the protocol or
 * application layer. Where this unwrapper backs an online decryption oracle, prefer RSA-KEM or
 * RSA-OAEP key transport over PKCS#1 v1.5.
 * </p>
 */
public class BcRSAAsymmetricKeyUnwrapper
    extends BcAsymmetricKeyUnwrapper
{
    public BcRSAAsymmetricKeyUnwrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter privateKey)
    {
        super(encAlgId, privateKey);
    }

    protected AsymmetricBlockCipher createAsymmetricUnwrapper(ASN1ObjectIdentifier algorithm)
    {
        return new PKCS1Encoding(new RSABlindedEngine());
    }
}
