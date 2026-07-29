package org.bouncycastle.smartcard.yubikey;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.DeviceInfo;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.smartcard.card.CardException;
import org.bouncycastle.smartcard.yubikey.operator.YubikeyPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.Arrays;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class YubikeySmartCardBackend
        extends OpenPGPSmartCardBackend<YubikeyOpenPGPSmartCard>
{
    private final JcaPGPKeyConverter converter;
    private final JcaKeyFingerprintCalculator fingerprintCalculator;
    private final Set<Integer> allowedCardSerials = new HashSet<>();
    private final YubiKitManager manager;

    public static YubikeySmartCardBackend createInstance()
    {
        return createInstance(new YubiKitManager());
    }

    public static YubikeySmartCardBackend createInstance(YubiKitManager yubiKitManager)
    {
        return createInstance(yubiKitManager, new BouncyCastleProvider());
    }

    public static YubikeySmartCardBackend createInstance(YubiKitManager yubiKitManager,
                                                         BouncyCastleProvider provider)
    {
        return new YubikeySmartCardBackend(yubiKitManager,
                new JcaPGPKeyConverter().setProvider(provider),
                new JcaKeyFingerprintCalculator().setProvider(provider));
    }

    public YubikeySmartCardBackend(YubiKitManager yubiKitManager,
                                   JcaPGPKeyConverter keyConverter,
                                   JcaKeyFingerprintCalculator fingerprintCalculator)
    {
        this.manager = yubiKitManager;
        this.converter = keyConverter;
        this.fingerprintCalculator = fingerprintCalculator;
    }

    @Override
    public String getName()
    {
        return "Yubikit";
    }

    @Override
    public List<YubikeyOpenPGPSmartCard> listSmartCards()
            throws CardException
    {
        Map<YubiKeyDevice, DeviceInfo> allDevices;
        try
        {
            allDevices = manager.listAllDevices();
        }
        catch (RuntimeException e)
        {
            return new ArrayList<>(); // no hardware devices
        }

        List<YubikeyOpenPGPSmartCard> allowedDevices = new ArrayList<>();
        for (Map.Entry<YubiKeyDevice, DeviceInfo> entry : allDevices.entrySet())
        {
            YubikeyOpenPGPSmartCard yubikey = new YubikeyOpenPGPSmartCard(this, entry.getValue(), entry.getKey());
            if (allowedCardSerials.contains(yubikey.getSerialNumber()))
            {
                allowedDevices.add(yubikey);
            }
        }
        return allowedDevices;
    }

    @Override
    public PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPKey.OpenPGPSecretKey secretKey,
            YubikeyOpenPGPSmartCard card,
            KeyPassphraseProvider userPinProvider)
            throws PGPException
    {
        return new YubikeyPublicKeyDataDecryptorFactory(secretKey, card, userPinProvider);
    }

    public YubikeySmartCardBackend addAllowedCardSerial(Integer number)
    {
        allowedCardSerials.add(number);
        return this;
    }

    PrivateKeyValues convertPrivateKey(PGPKeyPair keyPair)
            throws PGPException
    {
        PGPPrivateKey pgpPrivateKey = keyPair.getPrivateKey();
        PrivateKey converted = converter.getPrivateKey(pgpPrivateKey);
        boolean isLegacyX25519 = PublicKeyUtils.isX25519Key(keyPair.getPublicKey());
        if (isLegacyX25519)
        {
            return PrivateKeyValues.fromPrivateKey(new PrivateKey()
            {
                @Override
                public String getAlgorithm()
                {
                    return converted.getAlgorithm();
                }

                @Override
                public String getFormat()
                {
                    return converted.getFormat();
                }

                @Override
                public byte[] getEncoded()
                {
                    // YubiKey expects x25519 private key in big-endian format
                    byte[] orig = converted.getEncoded();
                    Arrays.reverseInPlace(orig, orig.length - 32, 32);
                    return orig;
                }
            });
        }
        return PrivateKeyValues.fromPrivateKey(converter.getPrivateKey(pgpPrivateKey));
    }

    PublicKeyValues convertPublicKey(PGPPublicKey pgpPublicKey)
            throws PGPException
    {
        try
        {
            return PublicKeyValues.fromPublicKey(converter.getPublicKey(pgpPublicKey));
        }
        catch (IllegalStateException e)
        {
            throw new PGPException("Cannot convert PGPPublicKey to PublicKeyValues", e);
        }
    }

    /**
     * Convert the key from {@link PublicKeyValues} into a bare {@link PGPPublicKey}, brute-forcing the
     * algorithm id.
     * Brute-forcing is done by comparing the fingerprint of the reconstructed PGP key to the fingerprint
     * stored on the key.
     *
     * @param pkVal Yubikey PublicKeyValues
     * @param storedFingerprint fingerprint as it is stored on the Yubikey device
     * @param creationTime creation time as it is stored on the Yubikey device
     * @return converted PGP public key
     *
     * @throws PGPException if the key cannot be reconstructed
     * @throws NoSuchAlgorithmException if no Provider supports an implementation for the PublicKeyValues algorithm
     * @throws InvalidKeySpecException if the PublicKeyValues specification is inappropriate to produce a public key
     */
    public PGPPublicKey convertPublicKey(PublicKeyValues pkVal,
                                    byte[] storedFingerprint,
                                    Date creationTime)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        PublicKey pk = pkVal.toPublicKey();
        PGPPublicKey pgpKey = null;
        String alg = pk.getAlgorithm();
        switch (alg)
        {
            case "RSA":
                pgpKey = bruteForcePublicKey(pk, creationTime, storedFingerprint,
                        PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_ENCRYPT, PublicKeyAlgorithmTags.RSA_SIGN);
                break;
            case "EC":
                pgpKey = bruteForcePublicKey(pk, creationTime, storedFingerprint,
                        PublicKeyAlgorithmTags.ECDSA, PublicKeyAlgorithmTags.ECDH);
                break;
            case "EdDSA":
                pgpKey = bruteForcePublicKey(pk, creationTime, storedFingerprint,
                        PublicKeyAlgorithmTags.EDDSA_LEGACY, PublicKeyAlgorithmTags.Ed25519, PublicKeyAlgorithmTags.Ed448);
                break;
            case "XDH":
                pgpKey = bruteForcePublicKey(pk, creationTime, storedFingerprint,
                        PublicKeyAlgorithmTags.ECDH, PublicKeyAlgorithmTags.X25519);
                break;
        }

        if (pgpKey != null)
        {
            return pgpKey;
        }
        throw new PGPException("Cannot reconstruct public " + alg + " PGP key.");
    }

    private PGPPublicKey bruteForcePublicKey(PublicKey pk, Date creationTime,
                                             byte[] storedFingerprint,
                                             int... plausibleAlgorithms)
            throws PGPException
    {
        for (int algorithm : plausibleAlgorithms)
        {
            BCPGKey bcKey = converter.getPublicBCPGKey(algorithm, null, pk);
            PGPPublicKey pgpKey = new PGPPublicKey(
                    new PublicKeyPacket(4, algorithm, creationTime, bcKey),
                    fingerprintCalculator);
            if (fingerprintMatches(storedFingerprint, pgpKey.getFingerprint()))
            {
                return pgpKey;
            }
        }
        return null;
    }
}
