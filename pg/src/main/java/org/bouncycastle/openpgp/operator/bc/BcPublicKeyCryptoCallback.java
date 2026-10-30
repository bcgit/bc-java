package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.openpgp.PGPException;

/**
 * Callback isolating the raw public-key operations performed while recovering an OpenPGP session key.
 * <p>
 * {@link BcPublicKeyDataDecryptorFactory} performs all packet parsing, length checking and KDF/key-unwrap
 * work itself and delegates only the private-key operation - an RSA or ElGamal decryption, an
 * ECDH / X25519 / X448 agreement, or an ML-KEM decapsulation - to an instance of this class. A subclass may
 * therefore route that one operation to a hardware device (a smart card or HSM) without reimplementing any
 * of the session-key recovery logic.
 * <p>
 * For the RFC 9980 ML-KEM + ECDH composites the factory makes two calls: {@link #decrypt(int, AsymmetricKeyParameter)}
 * with {@link org.bouncycastle.bcpg.PublicKeyAlgorithmTags#X25519} or {@link org.bouncycastle.bcpg.PublicKeyAlgorithmTags#X448}
 * and the sender's ephemeral public key, returning the ECDH key share, and {@link #decrypt(int, byte[][])}
 * with the composite algorithm ID and the ML-KEM ciphertext as the single element of the array, returning
 * the ML-KEM key share. See {@code org.bouncycastle.openpgp.api.operator.bc.BcExternalPublicKeyDataDecryptorFactory}
 * for the externally-backed-key base class built on this seam.
 * <p>
 * This is the lightweight (<code>.bc</code>) binding: keys are passed as
 * {@link AsymmetricKeyParameter}. It deliberately lives in the <code>.bc</code> subpackage rather than
 * alongside {@link org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory}, because the
 * top-level <code>operator</code> package is JCA-free <em>and</em> lightweight-crypto-free.
 */
public abstract class BcPublicKeyCryptoCallback
{
    public abstract byte[] decrypt(int keyAlgorithm,
                                   byte[][] pEnc)
        throws PGPException, InvalidCipherTextException;

    public abstract byte[] decrypt(int keyAlgorithm,
                                   AsymmetricKeyParameter peerKey)
        throws PGPException, InvalidCipherTextException;
}
