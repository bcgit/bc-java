package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.openpgp.PGPException;

/**
 * Callback isolating the raw public-key operations performed while recovering an OpenPGP session key.
 * <p>
 * {@link BcPublicKeyDataDecryptorFactory} performs all packet parsing, length checking and KDF/key-unwrap
 * work itself and delegates only the private-key operation - an RSA or ElGamal decryption, or an
 * ECDH / X25519 / X448 agreement - to an instance of this class. A subclass may therefore route that one
 * operation to a hardware device (a smart card or HSM) without reimplementing any of the session-key
 * recovery logic. See {@code org.bouncycastle.openpgp.api.operator.bc.BcExternalPublicKeyDataDecryptorFactory}
 * for the externally-backed-key base class built on this seam.
 * <p>
 * This is the lightweight (<code>.bc</code>) binding: keys are passed as
 * {@link AsymmetricKeyParameter}. It deliberately lives in the <code>.bc</code> subpackage rather than
 * alongside {@link org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory}, because the
 * top-level <code>operator</code> package is JCA-free <em>and</em> lightweight-crypto-free.
 */
public abstract class BcPublicKeyCryptoCallback
{
    /**
     * Perform RSA decryption of an encrypted session key.
     *
     * @param keyAlgorithm public key algorithm
     * @param pEnc encrypted session key
     * @param privKey RSA private key
     * @return decrypted session key
     * @throws PGPException if the message cannot be decrypted
     * @throws InvalidCipherTextException if the ciphertext is invalid
     */
    public abstract byte[] decryptRSA(int keyAlgorithm,
                                      byte[] pEnc,
                                      AsymmetricKeyParameter privKey)
        throws PGPException, InvalidCipherTextException;

    /**
     * Perform ElGamal decryption of an encrypted session key.
     *
     * @param keyAlgorithm public key algorithm
     * @param secKeyData encrypted session key data
     * @param privKey ElGamal private key
     * @return decrypted session key
     * @throws InvalidCipherTextException if the ciphertext is invalid
     * @throws PGPException if the message cannot be decrypted
     */
    public abstract byte[] decryptElGamal(int keyAlgorithm,
                                          byte[][] secKeyData,
                                          AsymmetricKeyParameter privKey)
        throws InvalidCipherTextException, PGPException;

    /**
     * Perform an ECDH agreement to calculate a shared secret.
     *
     * @param pubKey our ECDH public key
     * @param ephemeralKeyBytes encoded ephemeral public key
     * @param privKey private ECDH key
     * @return shared secret
     * @throws PGPException if the message cannot be decrypted
     */
    public abstract byte[] decryptECDH(ECDHPublicBCPGKey pubKey,
                                       byte[] ephemeralKeyBytes,
                                       AsymmetricKeyParameter privKey)
        throws PGPException;

    /**
     * Perform an X25519 agreement to calculate a shared secret.
     *
     * @param privKey private X25519 key
     * @param ephemeralKey encoded ephemeral X25519 public key
     * @return shared secret
     * @throws PGPException if the message cannot be decrypted
     */
    public abstract byte[] decryptX25519(AsymmetricKeyParameter privKey,
                                         byte[] ephemeralKey)
        throws PGPException;

    /**
     * Perform an X448 agreement to calculate a shared secret.
     *
     * @param privKey private X448 key
     * @param ephemeralKey encoded ephemeral X448 public key
     * @return shared secret
     * @throws PGPException if the message cannot be decrypted
     */
    public abstract byte[] decryptX448(AsymmetricKeyParameter privKey,
                                       byte[] ephemeralKey)
        throws PGPException;
}
