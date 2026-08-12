package org.bouncycastle.openpgp.smartcard.yubikey;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.DeviceInfo;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.yubikey.operator.bc.BcYubikeyPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.yubikey.operator.jcajce.JceYubikeyPublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Arrays;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class YubikeySmartCardBackend
        extends OpenPGPSmartCardBackend<YubikeyOpenPGPSmartCard>
{
    private static final int X25519_SCALAR_SIZE = 32;

    private final YubikeyDecryptorFactoryProvider decryptorFactoryProvider;
    private final JcaPGPKeyConverter converter;
    private final JcaKeyFingerprintCalculator fingerprintCalculator;
    private final Set<Integer> allowedCardSerials = new HashSet<>();
    private final YubiKitManager manager;

    public static YubikeySmartCardBackend createInstance()
    {
        return createInstance(bcImpl());
    }

    public static YubikeySmartCardBackend createInstance(YubikeyDecryptorFactoryProvider decryptorFactoryProvider)
    {
        return createInstance(new YubiKitManager(),
                decryptorFactoryProvider);
    }

    public static YubikeySmartCardBackend createInstance(YubiKitManager yubiKitManager,
                                                         YubikeyDecryptorFactoryProvider decryptorFactoryProvider)
    {
        return createInstance(yubiKitManager,
                new BouncyCastleProvider(),
                decryptorFactoryProvider);
    }

    public static YubikeySmartCardBackend createInstance(YubiKitManager yubiKitManager,
                                                         BouncyCastleProvider provider,
                                                         YubikeyDecryptorFactoryProvider decryptorFactoryProvider)
    {
        return new YubikeySmartCardBackend(
                yubiKitManager,
                new JcaPGPKeyConverter().setProvider(provider),
                new JcaKeyFingerprintCalculator().setProvider(provider),
                decryptorFactoryProvider);
    }

    public YubikeySmartCardBackend(YubiKitManager yubiKitManager,
                                   JcaPGPKeyConverter keyConverter,
                                   JcaKeyFingerprintCalculator fingerprintCalculator,
                                   YubikeyDecryptorFactoryProvider decryptorFactoryProvider)
    {
        this.manager = yubiKitManager;
        this.converter = keyConverter;
        this.fingerprintCalculator = fingerprintCalculator;
        this.decryptorFactoryProvider = decryptorFactoryProvider;
    }

    @Override
    public String getName()
    {
        return "Yubikit " + decryptorFactoryProvider.getName();
    }

    /**
     * Return the connected YubiKey devices whose serial number has been allow-listed with
     * {@link #addAllowedCardSerial(Integer)}. Devices that have not been allow-listed are never opened,
     * so no APDU is exchanged with a device the caller did not nominate; a backend with an empty
     * allow-list therefore always returns an empty list.
     *
     * @return allow-listed smart cards
     * @throws CardException if the device layer cannot be queried, or a nominated device cannot be read
     */
    @Override
    public List<YubikeyOpenPGPSmartCard> listSmartCards()
            throws CardException
    {
        if (allowedCardSerials.isEmpty())
        {
            return new ArrayList<YubikeyOpenPGPSmartCard>();
        }

        Map<YubiKeyDevice, DeviceInfo> allDevices;
        try
        {
            allDevices = manager.listAllDevices();
        }
        catch (RuntimeException e)
        {
            // the desktop backend throws unchecked when no PC/SC service or reader is available; that is
            // "nothing plugged in", but it is also how a genuine fault surfaces, so keep the cause.
            throw new CardException("Cannot enumerate YubiKey devices.", e);
        }

        List<YubikeyOpenPGPSmartCard> allowedDevices = new ArrayList<YubikeyOpenPGPSmartCard>();
        for (Iterator<Map.Entry<YubiKeyDevice, DeviceInfo>> it = allDevices.entrySet().iterator(); it.hasNext();)
        {
            Map.Entry<YubiKeyDevice, DeviceInfo> entry = it.next();
            // check the allow-list against the serial the device layer already reported, before opening
            // a session against the card
            if (!allowedCardSerials.contains(entry.getValue().getSerialNumber()))
            {
                continue;
            }
            allowedDevices.add(new YubikeyOpenPGPSmartCard(this, entry.getValue(), entry.getKey()));
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
        return decryptorFactoryProvider.provide(secretKey, card, userPinProvider);
    }

    /**
     * Nominate a device serial number this backend is permitted to open. Nothing is enumerated until at
     * least one serial has been added - see {@link #listSmartCards()}.
     *
     * @param number device serial number
     * @return this
     */
    public YubikeySmartCardBackend addAllowedCardSerial(Integer number)
    {
        allowedCardSerials.add(number);
        return this;
    }

    PrivateKeyValues convertPrivateKey(PGPKeyPair keyPair)
            throws PGPException
    {
        final PrivateKey converted = converter.getPrivateKey(keyPair.getPrivateKey());
        if (!PublicKeyUtils.isX25519Key(keyPair.getPublicKey().getPublicKeyPacket()))
        {
            return PrivateKeyValues.fromPrivateKey(converted);
        }

        return PrivateKeyValues.fromPrivateKey(new PrivateKey()
        {
            public String getAlgorithm()
            {
                return converted.getAlgorithm();
            }

            public String getFormat()
            {
                return converted.getFormat();
            }

            public byte[] getEncoded()
            {
                // the YubiKey expects the X25519 scalar big-endian, the reverse of the PKCS#8 encoding.
                // Copy first: getEncoded() is not contractually required to hand back a fresh array, and
                // reversing in place would corrupt the source key for any provider that shares one.
                byte[] encoding = Arrays.clone(converted.getEncoded());
                if (encoding == null || encoding.length < X25519_SCALAR_SIZE)
                {
                    throw new IllegalStateException("X25519 private key encoding too short to contain a scalar");
                }
                Arrays.reverseInPlace(encoding, encoding.length - X25519_SCALAR_SIZE, X25519_SCALAR_SIZE);
                return encoding;
            }
        });
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
        String alg = pk.getAlgorithm();
        int[] candidates;
        if ("RSA".equals(alg))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_ENCRYPT,
                PublicKeyAlgorithmTags.RSA_SIGN};
        }
        else if ("EC".equals(alg))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.ECDSA, PublicKeyAlgorithmTags.ECDH};
        }
        else if ("EdDSA".equals(alg))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.EDDSA_LEGACY, PublicKeyAlgorithmTags.Ed25519,
                PublicKeyAlgorithmTags.Ed448};
        }
        else if ("XDH".equals(alg))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.ECDH, PublicKeyAlgorithmTags.X25519};
        }
        else
        {
            throw new PGPException("Cannot reconstruct public " + alg + " PGP key.");
        }

        PGPPublicKey pgpKey = bruteForcePublicKey(pk, creationTime, storedFingerprint, candidates);
        if (pgpKey == null)
        {
            throw new PGPException("Cannot reconstruct public " + alg + " PGP key.");
        }
        return pgpKey;
    }

    private PGPPublicKey bruteForcePublicKey(PublicKey pk, Date creationTime,
                                             byte[] storedFingerprint,
                                             int[] plausibleAlgorithms)
    {
        for (int i = 0; i != plausibleAlgorithms.length; i++)
        {
            int algorithm = plausibleAlgorithms[i];
            PGPPublicKey pgpKey;
            try
            {
                pgpKey = converter.getPGPPublicKey(PublicKeyPacket.VERSION_4, algorithm, pk, creationTime);
            }
            catch (PGPException e)
            {
                // this candidate algorithm cannot represent the key at all (e.g. an Ed448 tag over an
                // Ed25519 key) - that is a miss, not a failure of the whole search.
                continue;
            }

            if (fingerprintMatches(storedFingerprint, pgpKey.getFingerprint()))
            {
                return pgpKey;
            }
        }
        return null;
    }

    public interface YubikeyDecryptorFactoryProvider
    {
        PublicKeyDataDecryptorFactory provide(OpenPGPKey.OpenPGPSecretKey secretKey,
                                              YubikeyOpenPGPSmartCard card,
                                              KeyPassphraseProvider userPinProvider)
                throws PGPException;

        String getName();
    }

    public static YubikeyDecryptorFactoryProvider bcImpl()
    {
        return new YubikeyDecryptorFactoryProvider()
        {
            @Override
            public PublicKeyDataDecryptorFactory provide(OpenPGPKey.OpenPGPSecretKey secretKey,
                                                         YubikeyOpenPGPSmartCard card,
                                                         KeyPassphraseProvider userPinProvider)
                    throws PGPException
            {
                return new BcYubikeyPublicKeyDataDecryptorFactory(secretKey, card, userPinProvider);
            }

            @Override
            public String getName()
            {
                return "BCYK";
            }
        };
    }

    public static YubikeyDecryptorFactoryProvider jceImpl()
    {
        return new YubikeyDecryptorFactoryProvider()
        {
            @Override
            public PublicKeyDataDecryptorFactory provide(OpenPGPKey.OpenPGPSecretKey secretKey,
                                                         YubikeyOpenPGPSmartCard card,
                                                         KeyPassphraseProvider userPinProvider)
                    throws PGPException
            {
                return new JceYubikeyPublicKeyDataDecryptorFactoryBuilder(card, userPinProvider)
                        .setProvider(new BouncyCastleProvider())
                        .build(secretKey);
            }

            @Override
            public String getName()
            {
                return "JCYK";
            }
        };
    }
}
