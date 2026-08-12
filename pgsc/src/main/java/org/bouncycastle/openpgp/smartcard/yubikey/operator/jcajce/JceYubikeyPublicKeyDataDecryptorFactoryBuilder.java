package org.bouncycastle.openpgp.smartcard.yubikey.operator.jcajce;

import com.yubico.yubikit.core.application.InvalidPinException;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.api.operator.jcajce.JceExternalPublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyOpenPGPSmartCard;
import org.bouncycastle.util.Arrays;

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
                    byte[] decryptedSessionKey = openPgpSession.decrypt(pEnc);
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
                finally
                {
                    Arrays.fill(pin, (char) 0);
                }
            }

            @Override
            public byte[] decryptElGamal(int keyAlgorithm, byte[][] secKeyData)
                    throws PGPException
            {
                throw new PGPException("ElGamal not supported on YubiKey.");
            }

            @Override
            public byte[] decryptECDH(ECDHPublicBCPGKey pubKey, PublicKey ephemeralKey)
                    throws PGPException
            {
                // validate the curve and convert the ephemeral key before fetching the PIN, so no
                // failure on this path can leave the PIN unzeroized
                ASN1ObjectIdentifier curveOid = pubKey.getCurveOID();
                String curveName = ECUtil.getCurveName(curveOid);
                if (curveName == null || !isSupportedCurve(curveName))
                {
                    throw new PGPException("Unsupported EC curve: " + curveName + " (" + curveOid + ")");
                }

                PublicKeyValues ephemeralPublicKey = PublicKeyValues.fromPublicKey(ephemeralKey);

                char[] pin = requireUserPin(userPinProvider, secretKey);

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
                    throw new KeyPassphraseException(secretKey, e);
                }
                finally
                {
                    Arrays.fill(pin, (char) 0);
                }
            }

            @Override
            public byte[] decryptX25519(PublicKey ephemeralKey)
                    throws PGPException
            {
                // convert the ephemeral key before fetching the PIN - see decryptECDH
                PublicKeyValues peerKey = PublicKeyValues.fromPublicKey(ephemeralKey);

                char[] pin = requireUserPin(userPinProvider, secretKey);

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
                    throw new KeyPassphraseException(secretKey, e);
                }
                finally
                {
                    Arrays.fill(pin, (char) 0);
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
