package org.bouncycastle.openpgp.api.operator;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.bcpg.X448PublicBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.RFC6637Utils;
import org.bouncycastle.util.Arrays;

/**
 * Base class for a {@link PublicKeyDataDecryptorFactory} whose private key material is held outside
 * the OpenPGP key - typically on a hardware token - as described by
 * <a href="https://datatracker.ietf.org/doc/draft-dkg-openpgp-external-secrets/">OpenPGP External Secret
 * Keys</a> and signalled by {@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_EXTERNAL}.
 * <p>
 * The session-key recovery flow - packet parsing, length checking, the RFC 6637 KDF and the RFC 9580
 * HKDF/key-unwrap sequencing - lives here, expressed entirely over byte arrays, so it is tied to no
 * crypto stack. A subclass binds the primitive operations: the raw private-key operation (an RSA or
 * ElGamal decryption, or an ECDH / X25519 / X448 agreement, routed to wherever the key is held) and
 * the two symmetric primitives (HKDF and key unwrap), plus the {@link PGPDataDecryptor} creation the
 * {@link PublicKeyDataDecryptorFactory} interface requires.
 * <p>
 * The JCA/JCE binding is built by
 * {@code org.bouncycastle.openpgp.api.operator.jcajce.JceExternalPublicKeyDataDecryptorFactoryBuilder}.
 * On the lightweight side {@code org.bouncycastle.openpgp.api.operator.bc.BcExternalPublicKeyDataDecryptorFactory}
 * predates this class and inherits the equivalent flow from
 * {@code org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory} instead; the packet
 * parsing is shared with both through {@link AbstractPublicKeyDataDecryptorFactory}'s parse methods.
 */
public abstract class AbstractExternalPublicKeyDataDecryptorFactory
    extends AbstractPublicKeyDataDecryptorFactory
{
    private final PGPPublicKey pubKey;
    private final KeyFingerPrintCalculator fingerPrintCalculator;
    private final PGPDigestCalculatorProvider digestCalculatorProvider;

    /**
     * Base constructor.
     *
     * @param pubKey the public half of the key being decrypted for
     * @param fingerPrintCalculator calculator for the key fingerprint carried in the RFC 6637 user
     *        keying material
     * @param digestCalculatorProvider source of the digest the RFC 6637 KDF runs on
     */
    protected AbstractExternalPublicKeyDataDecryptorFactory(PGPPublicKey pubKey,
        KeyFingerPrintCalculator fingerPrintCalculator, PGPDigestCalculatorProvider digestCalculatorProvider)
    {
        this.pubKey = pubKey;
        this.fingerPrintCalculator = fingerPrintCalculator;
        this.digestCalculatorProvider = digestCalculatorProvider;
    }

    /**
     * Return the public half of the key this factory decrypts for.
     *
     * @return public key
     */
    protected PGPPublicKey getPublicKey()
    {
        return pubKey;
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion)
        throws PGPException
    {
        try
        {
            if (keyAlgorithm == PublicKeyAlgorithmTags.X25519)
            {
                return recoverXDHSessionData(secKeyData, pkeskVersion, X25519PublicBCPGKey.LENGTH,
                    HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128, "OpenPGP X25519", false);
            }
            else if (keyAlgorithm == PublicKeyAlgorithmTags.X448)
            {
                return recoverXDHSessionData(secKeyData, pkeskVersion, X448PublicBCPGKey.LENGTH,
                    HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256, "OpenPGP X448", true);
            }
            else if (keyAlgorithm == PublicKeyAlgorithmTags.ECDH)
            {
                return recoverECDHSessionData(secKeyData);
            }
            else if (keyAlgorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT
                || keyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL)
            {
                return decryptRSA(keyAlgorithm, Arrays.copyOfRange(secKeyData[0], 2, secKeyData[0].length));
            }
            else
            {
                return decryptElGamal(keyAlgorithm, secKeyData);
            }
        }
        catch (IOException e)
        {
            throw new PGPException("exception creating user keying material: " + e.getMessage(), e);
        }
    }

    private byte[] recoverXDHSessionData(byte[][] secKeyData, int pkeskVersion, int pLen,
        int hashAlgorithm, int kekAlgorithm, String hkdfInfo, boolean x448)
        throws PGPException, IOException
    {
        byte[][] ephemeralKeyAndKeyEnc = parseXDHEncSessionKey(secKeyData[0], pLen, containsSKAlg(pkeskVersion));
        byte[] ephemeralKey = ephemeralKeyAndKeyEnc[0];
        byte[] keyEnc = ephemeralKeyAndKeyEnc[1];

        byte[] secret = x448 ? agreeX448(ephemeralKey) : agreeX25519(ephemeralKey);

        byte[] hkdfOut = generateHKDFBytes(hashAlgorithm,
            Arrays.concatenate(ephemeralKey, pubKey.getPublicKeyPacket().getKey().getEncoded(), secret),
            hkdfInfo, getKeyLen(kekAlgorithm));

        return unwrapSessionData(keyEnc, SymmetricKeyAlgorithmTags.AES_128, hkdfOut);
    }

    private byte[] recoverECDHSessionData(byte[][] secKeyData)
        throws PGPException, IOException
    {
        byte[][] pEncAndKeyEnc = parseECDHEncSessionKey(secKeyData[0]);
        byte[] pEnc = pEncAndKeyEnc[0];
        byte[] keyEnc = pEncAndKeyEnc[1];

        PublicKeyPacket pubKeyPacket = pubKey.getPublicKeyPacket();
        ECDHPublicBCPGKey ecPubKey = (ECDHPublicBCPGKey)pubKeyPacket.getKey();

        byte[] secret;
        // XDH
        if (ecPubKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
        {
            if (pEnc.length != 1 + X25519PublicBCPGKey.LENGTH || 0x40 != pEnc[0])
            {
                throw new IllegalArgumentException("Invalid Curve25519 public key");
            }
            // skip the 0x40 header byte.
            secret = agreeX25519(Arrays.copyOfRange(pEnc, 1, pEnc.length));
        }
        else if (ecPubKey.getCurveOID().equals(EdECObjectIdentifiers.id_X448))
        {
            if (pEnc.length != 1 + X448PublicBCPGKey.LENGTH || 0x40 != pEnc[0])
            {
                throw new IllegalArgumentException("Invalid Curve448 public key");
            }
            // skip the 0x40 header byte.
            secret = agreeX448(Arrays.copyOfRange(pEnc, 1, pEnc.length));
        }
        else
        {
            secret = agreeECDH(ecPubKey, pEnc);
        }

        int hashAlgorithm = ecPubKey.getHashAlgorithm();
        int symmetricKeyAlgorithm = ecPubKey.getSymmetricKeyAlgorithm();
        byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pubKeyPacket, fingerPrintCalculator);

        byte[] key = rfc6637KDF(digestCalculatorProvider.get(hashAlgorithm), symmetricKeyAlgorithm,
            secret, userKeyingMaterial);

        byte[] unwrapped = unwrapSessionData(keyEnc, symmetricKeyAlgorithm, key);

        return PGPPad.unpadSessionData(unwrapped);
    }

    // RFC 6637 - Section 7
    //   MB = Hash ( 00 || 00 || 00 || 01 || ZB || Param );
    //   return oBits leftmost bits of MB.
    private static byte[] rfc6637KDF(PGPDigestCalculator digCalc, int keyAlgorithm, byte[] secret,
        byte[] userKeyingMaterial)
        throws PGPException
    {
        try
        {
            OutputStream dOut = digCalc.getOutputStream();

            dOut.write(0x00);
            dOut.write(0x00);
            dOut.write(0x00);
            dOut.write(0x01);
            dOut.write(secret);
            dOut.write(userKeyingMaterial);

            byte[] digest = digCalc.getDigest();

            byte[] key = new byte[getKeyLen(keyAlgorithm)];

            System.arraycopy(digest, 0, key, 0, key.length);

            return key;
        }
        catch (IOException e)
        {
            throw new PGPException("Exception performing KDF: " + e.getMessage(), e);
        }
    }

    private static int getKeyLen(int algID)
        throws PGPException
    {
        switch (algID)
        {
        case SymmetricKeyAlgorithmTags.AES_128:
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
            return 16;
        case SymmetricKeyAlgorithmTags.AES_192:
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
            return 24;
        case SymmetricKeyAlgorithmTags.AES_256:
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            return 32;
        default:
            throw new PGPException("unknown symmetric algorithm ID: " + algID);
        }
    }

    /**
     * Perform RSA decryption of an encrypted session key.
     *
     * @param keyAlgorithm public key algorithm
     * @param sessionKey encrypted session key, with the MPI length octets already removed
     * @return decrypted session key
     * @throws PGPException if the session key cannot be decrypted
     */
    protected abstract byte[] decryptRSA(int keyAlgorithm, byte[] sessionKey)
        throws PGPException;

    /**
     * Perform ElGamal decryption of an encrypted session key.
     *
     * @param keyAlgorithm public key algorithm
     * @param secKeyData encrypted session key data
     * @return decrypted session key
     * @throws PGPException if the session key cannot be decrypted
     */
    protected abstract byte[] decryptElGamal(int keyAlgorithm, byte[][] secKeyData)
        throws PGPException;

    /**
     * Perform an ECDH agreement against the sender's ephemeral point and return the shared secret.
     *
     * @param pubKey our ECDH public key
     * @param ephemeralKeyBytes the sender's encoded ephemeral point
     * @return shared secret
     * @throws PGPException if the agreement cannot be performed
     */
    protected abstract byte[] agreeECDH(ECDHPublicBCPGKey pubKey, byte[] ephemeralKeyBytes)
        throws PGPException;

    /**
     * Perform an X25519 agreement against the sender's ephemeral key and return the shared secret.
     *
     * @param ephemeralKey the sender's ephemeral X25519 public key (32 octets, no header byte)
     * @return shared secret
     * @throws PGPException if the agreement cannot be performed
     */
    protected abstract byte[] agreeX25519(byte[] ephemeralKey)
        throws PGPException;

    /**
     * Perform an X448 agreement against the sender's ephemeral key and return the shared secret.
     *
     * @param ephemeralKey the sender's ephemeral X448 public key (56 octets, no header byte)
     * @return shared secret
     * @throws PGPException if the agreement cannot be performed
     */
    protected abstract byte[] agreeX448(byte[] ephemeralKey)
        throws PGPException;

    /**
     * Derive key material with HKDF as RFC 9580 sections 5.1.6 and 5.1.7 prescribe for the X25519
     * and X448 encrypted session keys: no salt, the given info string, output truncated to keyLen.
     *
     * @param hashAlgorithm the hash algorithm underlying the HKDF (SHA256 or SHA512)
     * @param ikm input keying material
     * @param info the HKDF info string ("OpenPGP X25519" / "OpenPGP X448")
     * @param keyLen number of octets of output keying material
     * @return derived key material
     * @throws PGPException if the derivation cannot be performed
     */
    protected abstract byte[] generateHKDFBytes(int hashAlgorithm, byte[] ikm, String info, int keyLen)
        throws PGPException;

    /**
     * Unwrap a wrapped (RFC 3394) session key.
     *
     * @param keyEnc the wrapped session key
     * @param symmetricKeyAlgorithm the wrapping algorithm
     * @param key the key-encryption key
     * @return the unwrapped session key
     * @throws PGPException if the session key cannot be unwrapped
     */
    protected abstract byte[] unwrapSessionData(byte[] keyEnc, int symmetricKeyAlgorithm, byte[] key)
        throws PGPException;
}
