package org.bouncycastle.openpgp.smartcard.yubikey.operator;

import com.yubico.yubikit.core.application.InvalidPinException;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.bc.BcExternalPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyCryptoCallback;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyOpenPGPSmartCard;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.util.Date;

/**
 * {@link BcExternalPublicKeyDataDecryptorFactory} routing the private-key operation of OpenPGP session-key
 * recovery to a YubiKey's OpenPGP applet.
 * <p>
 * The card performs the RSA decryption or the ECDH / X25519 agreement; all packet parsing, KDF and key
 * unwrap work stays in {@link org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory}.
 * ElGamal and X448 are not supported by the applet and are rejected.
 */
public class YubikeyPublicKeyDataDecryptorFactory
    extends BcExternalPublicKeyDataDecryptorFactory
{
    private final KeyPassphraseProvider userPinProvider;
    private final YubikeyOpenPGPSmartCard yubikey;

    public YubikeyPublicKeyDataDecryptorFactory(OpenPGPKey.OpenPGPSecretKey secretKey,
                                                YubikeyOpenPGPSmartCard yubikey,
                                                KeyPassphraseProvider userPinProvider)
        throws PGPException
    {
        super(secretKey);
        this.yubikey = yubikey;
        this.userPinProvider = userPinProvider;
    }

    @Override
    public BcPublicKeyCryptoCallback getExternalKeyCryptoCallback()
    {
        return new BcPublicKeyCryptoCallback()
        {
            public byte[] decryptRSA(int keyAlgorithm,
                                     byte[] pEnc,
                                     AsymmetricKeyParameter privKey)
                throws PGPException
            {
                char[] pin = requireUserPin();
                try (OpenPgpSession openPgpSession = yubikey.openSession())
                {
                    openPgpSession.verifyUserPin(pin, true);
                    return openPgpSession.decrypt(pEnc);
                }
                catch (ApduException | CardException | IOException e)
                {
                    throw new PGPException("Cannot decrypt message", e);
                }
                catch (InvalidPinException e)
                {
                    throw new KeyPassphraseException(getSecretKey(), e);
                }
                finally
                {
                    Arrays.fill(pin, (char)0);
                }
            }

            public byte[] decryptElGamal(int keyAlgorithm,
                                         byte[][] secKeyData,
                                         AsymmetricKeyParameter privKey)
                throws PGPException
            {
                throw new PGPException("ElGamal not supported on YubiKey.");
            }

            public byte[] decryptECDH(ECDHPublicBCPGKey pubKey,
                                      byte[] ephemeralKeyBytes,
                                      AsymmetricKeyParameter privKey)
                throws PGPException
            {
                PublicKeyValues ephemeralPublicKey = toEphemeralPublicKey(pubKey, ephemeralKeyBytes);

                char[] pin = requireUserPin();
                try (OpenPgpSession openPgpSession = yubikey.openSession())
                {
                    openPgpSession.verifyUserPin(pin, true);
                    // the card performs the ECDH agreement and returns the shared secret
                    return openPgpSession.decrypt(ephemeralPublicKey);
                }
                catch (ApduException | IOException | CardException e)
                {
                    throw new PGPException("Cannot decrypt message", e);
                }
                catch (InvalidPinException e)
                {
                    throw new KeyPassphraseException(getSecretKey(), e);
                }
                finally
                {
                    Arrays.fill(pin, (char)0);
                }
            }

            public byte[] decryptX25519(AsymmetricKeyParameter privKey, byte[] ephemeralKey)
                throws PGPException
            {
                if (ephemeralKey == null || ephemeralKey.length != X25519PublicKeyParameters.KEY_SIZE)
                {
                    throw new PGPException("Invalid X25519 ephemeral key length");
                }

                X25519PublicKeyParameters pub = new X25519PublicKeyParameters(ephemeralKey, 0);
                PGPPublicKey k = new BcPGPKeyConverter().getPGPPublicKey(
                    PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.ECDH, null, pub, new Date());
                PublicKeyValues peerKey = yubikey.convertPublicKey(k);

                char[] pin = requireUserPin();
                try (OpenPgpSession openPgpSession = yubikey.openSession())
                {
                    openPgpSession.verifyUserPin(pin, true);
                    return openPgpSession.decrypt(peerKey);
                }
                catch (ApduException | IOException | CardException e)
                {
                    throw new PGPException("Cannot decrypt message", e);
                }
                catch (InvalidPinException e)
                {
                    throw new KeyPassphraseException(getSecretKey(), e);
                }
                finally
                {
                    Arrays.fill(pin, (char)0);
                }
            }

            public byte[] decryptX448(AsymmetricKeyParameter privKey, byte[] ephemeralKey)
                throws PGPException
            {
                throw new PGPException("X448 not supported by YubiKey.");
            }
        };
    }

    /**
     * Convert the sender's ephemeral point into the form the applet expects, validating it first.
     * <p>
     * The point arrives from the message, so it is attacker-supplied: reject anything that is not a
     * valid, non-infinity point of the recipient key's curve before handing it to the card, which will
     * otherwise multiply it by the card-held private scalar (an invalid-curve attack against the token).
     */
    private PublicKeyValues toEphemeralPublicKey(ECDHPublicBCPGKey pubKey, byte[] ephemeralKeyBytes)
        throws PGPException
    {
        ASN1ObjectIdentifier curveOid = pubKey.getCurveOID();
        String curveName = ECUtil.getCurveName(curveOid);
        if (curveName == null || !isSupportedCurve(curveName))
        {
            throw new PGPException("Unsupported EC curve: " + curveName + " (" + curveOid + ")");
        }

        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);
        ECPoint publicPoint;
        try
        {
            publicPoint = ECAlgorithms.cleanPoint(params.getCurve(), params.getCurve().decodePoint(ephemeralKeyBytes));
        }
        catch (IllegalArgumentException e)
        {
            throw new PGPException("Invalid ephemeral EC point", e);
        }
        if (publicPoint.isInfinity())
        {
            throw new PGPException("Invalid ephemeral EC point: point at infinity");
        }

        // yubikit takes the peer key as a java.security PublicKey, and the only conversion BC offers from
        // a raw point runs through a PGPPublicKey - hence the throwaway packet. Only the point is used;
        // the creation date never leaves this method.
        return yubikey.convertPublicKey(new PGPPublicKey(
            new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.ECDH,
                new Date(),
                new ECDHPublicBCPGKey(
                    curveOid,
                    publicPoint,
                    pubKey.getHashAlgorithm(),
                    pubKey.getSymmetricKeyAlgorithm())),
            new BcKeyFingerprintCalculator()));
    }

    private static boolean isSupportedCurve(String curveName)
    {
        return "secp256r1".equals(curveName)
            || "prime256v1".equals(curveName)
            || "secp256k1".equals(curveName)
            || "secp384r1".equals(curveName)
            || "secp521r1".equals(curveName)
            || "brainpoolP256r1".equals(curveName)
            || "brainpoolP384r1".equals(curveName)
            || "brainpoolP512r1".equals(curveName)
            || "curve25519".equals(curveName);
    }

    /**
     * Fetch the card's user PIN. The returned array is the caller's to zeroize once the card has
     * verified it.
     */
    private char[] requireUserPin()
        throws KeyPassphraseException
    {
        char[] pin = userPinProvider.getKeyPassword(getSecretKey());
        if (pin == null || pin.length == 0)
        {
            throw new KeyPassphraseException(getSecretKey(), new IllegalStateException("PIN required."));
        }
        return pin;
    }
}
