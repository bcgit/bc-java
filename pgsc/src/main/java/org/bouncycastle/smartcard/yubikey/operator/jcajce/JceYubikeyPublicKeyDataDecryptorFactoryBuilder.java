package org.bouncycastle.smartcard.yubikey.operator.jcajce;

import com.yubico.yubikit.core.application.InvalidPinException;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JceExternalPublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.smartcard.card.CardException;
import org.bouncycastle.smartcard.yubikey.YubikeyOpenPGPSmartCard;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.PublicKey;

public class JceYubikeyPublicKeyDataDecryptorFactoryBuilder
        extends JceExternalPublicKeyDataDecryptorFactoryBuilder
{
    private final KeyPassphraseProvider userPinProvider;
    private final YubikeyOpenPGPSmartCard yubikey;

    public JceYubikeyPublicKeyDataDecryptorFactoryBuilder(YubikeyOpenPGPSmartCard yubikey,
                                                          KeyPassphraseProvider userPinProvider)
    {
        this.userPinProvider = userPinProvider;
        this.yubikey = yubikey;
    }

    private static PGPKeyPair unlock(OpenPGPKey.OpenPGPSecretKey secretKey)
            throws PGPException
    {
        OpenPGPKey.OpenPGPPrivateKey privKey = secretKey.unlock();
        if (privKey == null)
        {
            return new PGPKeyPair(secretKey.getPGPPublicKey(), null);
        }
        return privKey.getKeyPair();
    }

    @Override
    public PublicKeyDataDecryptorFactory build(OpenPGPKey.OpenPGPSecretKey secretKey)
            throws PGPException
    {
        return build(unlock(secretKey), new PublicKeyCryptoCallback()
        {
            @Override
            public byte[] decryptRSA(int keyAlgorithm, byte[] pEnc)
                    throws PGPException
            {
                char[] pin = requireUserPin(userPinProvider, secretKey);

                try (OpenPgpSession openPgpSession = yubikey.openSession())
                {
                    openPgpSession.verifyUserPin(pin, true);
                    System.out.println("JCYK: pEnc: " + Hex.toHexString(pEnc));
                    byte[] decryptedSessionKey = openPgpSession.decrypt(pEnc);
                    System.out.println("JCYK: decEnc: " + Hex.toHexString(decryptedSessionKey));
                    return decryptedSessionKey;
                }
                catch (ApduException | CardException | IOException e)
                {
                    throw new PGPException("Cannot decrypt message", e);
                }
                catch (InvalidPinException e)
                {
                    throw new KeyPassphraseException(secretKey, e);
                }
            }

            @Override
            public byte[] decryptElGamal(int keyAlgorithm, byte[][] secKeyData)
                    throws PGPException
            {
                throw new PGPException("ElGamal not supported on YubiKey.");
            }

            @Override
            public byte[] decryptECDH(ECDHPublicBCPGKey pubKey, PublicKey ephemeralKeyBytes)
                    throws PGPException
            {
                char[] pin = requireUserPin(userPinProvider, secretKey);

                String curveName = ECUtil.getCurveName(pubKey.getCurveOID());
                switch (curveName)
                {
                    case "secp256r1":
                    case "prime256v1":
                    case "secp256k1":
                    case "secp384r1":
                    case "secp521r1":
                    case "brainpoolP256r1":
                    case "brainpoolP384r1":
                    case "brainpoolP512r1":
                    case "curve25519":
                        break;
                    default:
                        throw new PGPException("Unsupported EC curve: " + ECUtil.getCurveName(pubKey.getCurveOID()) + " (" + pubKey.getCurveOID() + ")");
                }

                PublicKeyValues ephemeralPublicKey = PublicKeyValues.fromPublicKey(ephemeralKeyBytes);

                try (OpenPgpSession openPgpSession = yubikey.openSession())
                {
                    openPgpSession.verifyUserPin(pin, true);
                    // Perform ECDH handshake to generate shared secret
                    System.out.println("JCYK: ephKey: " + Hex.toHexString(ephemeralPublicKey.getEncoded()));
                    byte[] sharedSecret = openPgpSession.decrypt(ephemeralPublicKey);
                    System.out.println("JCYK: decSes: " + Hex.toHexString(sharedSecret));
                    return sharedSecret;
                }
                catch (ApduException | IOException | CardException e)
                {
                    throw new PGPException("Cannot decrypt message", e);
                }
                catch (InvalidPinException e)
                {
                    throw new KeyPassphraseException(secretKey, e);
                }
            }

            @Override
            public byte[] decryptX25519(PublicKey ephemeralKey)
                    throws PGPException
            {
                char[] pin = requireUserPin(userPinProvider, secretKey);

                PublicKeyValues peerKey = PublicKeyValues.fromPublicKey(ephemeralKey);

                try (OpenPgpSession openPgpSession = yubikey.openSession())
                {
                    openPgpSession.verifyUserPin(pin, true);
                    System.out.println("JCYK: ephKey: " + Hex.toHexString(peerKey.getEncoded()));
                    byte[] decryptedSessionKey = openPgpSession.decrypt(peerKey);
                    System.out.println("JCYK: decSes: " + Hex.toHexString(decryptedSessionKey));
                    return decryptedSessionKey;
                }
                catch (ApduException | IOException | CardException e)
                {
                    throw new PGPException("Cannot decrypt message", e);
                }
                catch (InvalidPinException e)
                {
                    throw new KeyPassphraseException(secretKey, e);
                }
            }

            @Override
            public byte[] decryptX448(PublicKey ephemeralKey)
                    throws PGPException
            {
                throw new PGPException("X448 not supported by YubiKey.");
            }
        });
    }

    private char[] requireUserPin(KeyPassphraseProvider userPinProvider,
                                  OpenPGPKey.OpenPGPSecretKey key)
            throws KeyPassphraseException
    {
        char[] pin = userPinProvider.getKeyPassword(key);
        if (pin == null || pin.length == 0)
        {
            throw new KeyPassphraseException(key, new IllegalStateException("PIN required."));
        }
        return pin;
    }
}
