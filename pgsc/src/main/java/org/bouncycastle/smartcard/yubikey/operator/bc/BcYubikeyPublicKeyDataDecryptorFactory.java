package org.bouncycastle.smartcard.yubikey.operator.bc;

import com.yubico.yubikit.core.application.InvalidPinException;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.bc.BcExternalPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.smartcard.card.CardException;
import org.bouncycastle.smartcard.yubikey.YubikeyOpenPGPSmartCard;
import org.bouncycastle.smartcard.yubikey.YubikeySmartCardBackend;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.Date;

public class BcYubikeyPublicKeyDataDecryptorFactory
        extends BcExternalPublicKeyDataDecryptorFactory
{
    private final KeyPassphraseProvider userPinProvider;
    private final YubikeyOpenPGPSmartCard yubikey;

    public BcYubikeyPublicKeyDataDecryptorFactory(OpenPGPKey.OpenPGPSecretKey secretKey,
                                                  YubikeyOpenPGPSmartCard yubikey,
                                                  KeyPassphraseProvider userPinProvider)
            throws PGPException
    {
        super(secretKey);
        this.yubikey = yubikey;
        this.userPinProvider = userPinProvider;
    }

    @Override
    protected PublicKeyCryptoCallback getCryptoCallback()
    {
        return getExternalKeyCryptoCallback();
    }

    @Override
    public PublicKeyCryptoCallback getExternalKeyCryptoCallback()
    {
        return new PublicKeyCryptoCallback()
        {
            @Override
            public byte[] decryptRSA(int keyAlgorithm,
                                     byte[] pEnc,
                                     AsymmetricKeyParameter privKey)
                    throws PGPException
            {
                char[] pin = requireUserPin(userPinProvider, getSecretKey());
                try (OpenPgpSession openPgpSession = yubikey.openSession())
                {
                    openPgpSession.verifyUserPin(pin, true);
                    System.out.println("BCYK: pEnc: " + Hex.toHexString(pEnc));
                    byte[] decryptedSessionKey = openPgpSession.decrypt(pEnc);
                    System.out.println("BCYK: decSes: " + Hex.toHexString(decryptedSessionKey));
                    return decryptedSessionKey;
                }
                catch (ApduException | CardException | IOException e)
                {
                    throw new PGPException("Cannot decrypt message", e);
                }
                catch (InvalidPinException e)
                {
                    throw new KeyPassphraseException(getSecretKey(), e);
                }
            }

            @Override
            public byte[] decryptElGamal(int keyAlgorithm,
                                         byte[][] secKeyData,
                                         AsymmetricKeyParameter privKey)
                    throws PGPException
            {
                throw new PGPException("ElGamal not supported on YubiKey.");
            }

            @Override
            public byte[] decryptECDH(ECDHPublicBCPGKey pubKey,
                                      byte[] ephemeralKeyBytes,
                                      AsymmetricKeyParameter privKey)
                    throws PGPException
            {
                char[] pin = requireUserPin(userPinProvider, getSecretKey());

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

                ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);
                ECPoint publicPoint = params.getCurve().decodePoint(ephemeralKeyBytes);

                // Here, in order to convert the public point into a PublicKey, we unfortunately need
                //  to take a detour, creating a temporary PGPPublicKey, which we then convert into a
                //  PublicKey via the JcaPGPKeyConverter.
                // This was the easiest way I found to construct the PublicKey, please improve :)
                PublicKeyValues ephemeralPublicKey = yubikey.convertPublicKey(
                        new PGPPublicKey(new PublicKeyPacket(
                                4,
                                PublicKeyAlgorithmTags.ECDH,
                                new Date(),
                                new ECDHPublicBCPGKey(
                                        pubKey.getCurveOID(),
                                        publicPoint,
                                        pubKey.getHashAlgorithm(),
                                        pubKey.getSymmetricKeyAlgorithm()
                                )
                        ),
                                new BcKeyFingerprintCalculator())
                );

                try (OpenPgpSession openPgpSession = yubikey.openSession())
                {
                    openPgpSession.verifyUserPin(pin, true);
                    // Perform ECDH handshake to generate shared secret
                    byte[] sharedSecret = openPgpSession.decrypt(ephemeralPublicKey);
                    return sharedSecret;
                }
                catch (ApduException | IOException | CardException e)
                {
                    throw new PGPException("Cannot decrypt message", e);
                }
                catch (InvalidPinException e)
                {
                    throw new KeyPassphraseException(getSecretKey(), e);
                }
            }

            @Override
            public byte[] decryptX25519(AsymmetricKeyParameter privKey, byte[] ephemeralKey)
                    throws PGPException
            {
                char[] pin = requireUserPin(userPinProvider, getSecretKey());
                X25519PublicKeyParameters pub = new X25519PublicKeyParameters(ephemeralKey, 0);
                PGPPublicKey k = new BcPGPKeyConverter().getPGPPublicKey(4, PublicKeyAlgorithmTags.ECDH, null, pub, new Date());

                PublicKeyValues peerKey = yubikey.convertPublicKey(k);

                try (OpenPgpSession openPgpSession = yubikey.openSession())
                {
                    openPgpSession.verifyUserPin(pin, true);
                    System.out.println("BCYK: pEnc: " + Hex.toHexString(ephemeralKey));
                    byte[] decryptedSessionKey = openPgpSession.decrypt(peerKey);
                    System.out.println("BCYK: decSes: " + Hex.toHexString(decryptedSessionKey));
                    return decryptedSessionKey;
                }
                catch (ApduException | IOException | CardException e)
                {
                    throw new PGPException("Cannot decrypt message", e);
                }
                catch (InvalidPinException e)
                {
                    throw new KeyPassphraseException(getSecretKey(), e);
                }
            }

            @Override
            public byte[] decryptX448(AsymmetricKeyParameter privKey, byte[] ephemeralKey)
                    throws PGPException
            {
                throw new PGPException("X448 not supported by YubiKey.");
                /*
                char[] pin = requireUserPin(userPinProvider, getSecretKey());
                PublicKeyValues peerKey = PublicKeyValues.fromPublicKey(toPublicKey("X448", ephemeralKey));

                try (OpenPgpSession openPgpSession = yubikey.openSession())
                {
                    openPgpSession.verifyUserPin(pin, true);
                    byte[] decryptedSessionKey = openPgpSession.decrypt(peerKey);
                    return decryptedSessionKey;
                }
                catch (ApduException | IOException | CardException e)
                {
                    throw new PGPException("Cannot decrypt message", e);
                }
                catch (InvalidPinException e)
                {
                    throw new KeyPassphraseException(getSecretKey(), e);
                }
                 */
            }
        };
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
