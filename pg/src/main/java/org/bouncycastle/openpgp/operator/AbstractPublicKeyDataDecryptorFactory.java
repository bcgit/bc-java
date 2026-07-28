package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.bcpg.X448PublicBCPGKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.Arrays;

public abstract class AbstractPublicKeyDataDecryptorFactory
        implements PublicKeyDataDecryptorFactory
{
    @Override
    public final byte[] recoverSessionData(PublicKeyEncSessionPacket pkesk, InputStreamPacket encData)
            throws PGPException
    {
        byte[] sessionData = recoverSessionData(pkesk.getAlgorithm(), pkesk.getEncSessionKey(), pkesk.getVersion());
        return prependSKAlgorithmToSessionData(pkesk, encData, sessionData);
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
        throws PGPException
    {
        return recoverSessionData(keyAlgorithm, secKeyData, PublicKeyEncSessionPacket.VERSION_3);
    }

    protected byte[] prependSKAlgorithmToSessionData(PublicKeyEncSessionPacket pkesk,
                                                   InputStreamPacket encData,
                                                   byte[] decryptedSessionData)
            throws PGPException
    {
        // V6 PKESK packets do not include the session key algorithm, so source it from the SEIPD2 instead
        if (!containsSKAlg(pkesk.getVersion()))
        {
            if (!(encData instanceof SymmetricEncIntegrityPacket) ||
                    ((SymmetricEncIntegrityPacket) encData).getVersion() != SymmetricEncIntegrityPacket.VERSION_2)
            {
                throw new PGPException("v6 PKESK packet MUST precede v2 SEIPD packet");
            }

            SymmetricEncIntegrityPacket seipd2 = (SymmetricEncIntegrityPacket) encData;
            return Arrays.prepend(decryptedSessionData,
                    (byte) (seipd2.getCipherAlgorithm() & 0xff));
        }
        // V3 PKESK does store the session key algorithm either encrypted or unencrypted, depending on the PK algorithm
        else
        {
            switch (pkesk.getAlgorithm())
            {
                case PublicKeyAlgorithmTags.X25519:
                    // X25519 does not encrypt SK algorithm
                    return Arrays.prepend(decryptedSessionData,
                            pkesk.getEncSessionKey()[0][X25519PublicBCPGKey.LENGTH + 1]);
                case PublicKeyAlgorithmTags.X448:
                    // X448 does not encrypt SK algorithm
                    return Arrays.prepend(decryptedSessionData,
                            pkesk.getEncSessionKey()[0][X448PublicBCPGKey.LENGTH + 1]);
                default:
                    // others already prepended session key algorithm to session key
                    return decryptedSessionData;
            }
        }
    }

    protected boolean containsSKAlg(int pkeskVersion)
    {
        return pkeskVersion != PublicKeyEncSessionPacket.VERSION_6;
    }

    protected static void checkRange(int pLen, byte[] enc)
            throws PGPException
    {
        if (pLen > enc.length)
        {
            throw new PGPException("encoded length out of range");
        }
    }

    /**
     * Return a callback to perform low-level public-key cryptographic operations.
     * @return callback
     */
    protected abstract PublicKeyCryptoCallback getCryptoCallback();

    /**
     * Callback for low-level PK crypto operations.
     *
     */
    public static abstract class PublicKeyCryptoCallback
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
         * Perform an ECDH handshake to calculate a shared secret.
         *
         * @param pubKey our ECDH public key
         * @param ephemeralKeyBytes encoded ephemeral key pair
         * @param privKey private ECDH key
         * @return shared secret
         * @throws PGPException if the message cannot be decrypted
         */
        public abstract byte[] decryptECDH(ECDHPublicBCPGKey pubKey,
                                           byte[] ephemeralKeyBytes,
                                           AsymmetricKeyParameter privKey)
                throws PGPException;

        /**
         * Perform an X25519 handshake to calculate a shared secret.
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
         * Perform an X448 handshake to calculate a shared secret.
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
}
