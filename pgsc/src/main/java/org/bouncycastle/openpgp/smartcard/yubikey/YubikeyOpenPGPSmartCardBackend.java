package org.bouncycastle.openpgp.smartcard.yubikey;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.openpgp.OpenPgpCurve;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.card.CardException;
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

public class YubikeyOpenPGPSmartCardBackend
        extends OpenPGPSmartCardBackend<YubikeyOpenPGPSmartCard>
{
    private static final int X25519_SCALAR_SIZE = 32;

    private boolean useAllowList = true;
    private final Set<Integer> allowedCardSerials = new HashSet<>();
    private final YubiKitManager manager;

    public static YubikeyOpenPGPSmartCardBackend createInstance()
    {
        return createInstance(new BcOpenPGPSmartCardImplementation());
    }

    public static YubikeyOpenPGPSmartCardBackend createInstance(OpenPGPSmartCardImplementation implementation)
    {
        return createInstance(new YubiKitManager(),
                implementation);
    }

    public static YubikeyOpenPGPSmartCardBackend createInstance(YubiKitManager yubiKitManager,
                                                                OpenPGPSmartCardImplementation implementation)
    {
        return createInstance(yubiKitManager,
                new BouncyCastleProvider(),
                implementation);
    }

    public static YubikeyOpenPGPSmartCardBackend createInstance(YubiKitManager yubiKitManager,
                                                                BouncyCastleProvider provider,
                                                                OpenPGPSmartCardImplementation implementation)
    {
        return new YubikeyOpenPGPSmartCardBackend(
                yubiKitManager,
                new JcaPGPKeyConverter().setProvider(provider),
                implementation);
    }

    public YubikeyOpenPGPSmartCardBackend(YubiKitManager yubiKitManager,
                                          JcaPGPKeyConverter keyConverter,
                                          OpenPGPSmartCardImplementation implementation)
    {
        super(implementation, keyConverter);
        this.manager = yubiKitManager;
    }

    @Override
    public String getName()
    {
        return implementation.getName() + "+Yubikit";
    }

    /**
     * Return the connected YubiKey devices whose serial number has been allow-listed with
     * {@link #addAllowedCardSerial(Integer)}. Devices that have not been allow-listed are never opened,
     * so no APDU is exchanged with a device the caller did not nominate; a backend with an empty
     * allow-list therefore always returns an empty list.
     * Note: The allow-list can be disabled with {@link #setEnableAllowList(boolean)} passing in <pre>false</pre>.
     * If the allow-list is disabled, any device can be opened, regardless of whether it was allow-listed.
     *
     * @return allow-listed smart cards
     * @throws CardException if the device layer cannot be queried, or a nominated device cannot be read
     */
    @Override
    public List<YubikeyOpenPGPSmartCard> listSmartCards()
            throws CardException
    {
        if (useAllowList && allowedCardSerials.isEmpty())
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
            if (useAllowList && !allowedCardSerials.contains(entry.getValue().getSerialNumber()))
            {
                continue;
            }
            allowedDevices.add(new YubikeyOpenPGPSmartCard(this, entry.getValue(), entry.getKey()));
        }
        return allowedDevices;
    }

    /**
     * Nominate a device serial number this backend is permitted to open. Nothing is enumerated until at
     * least one serial has been added - see {@link #listSmartCards()}.
     *
     * @param number device serial number
     * @return this
     */
    public YubikeyOpenPGPSmartCardBackend addAllowedCardSerial(Integer number)
    {
        allowedCardSerials.add(number);
        return this;
    }

    /**
     * Configure the backend to limit the set of permitted devices to those on the allow-list.
     * If the allow-list is disabled by passing in <pre>false</pre> any device will be permitted to be opened.
     *
     * @return this
     */
    public YubikeyOpenPGPSmartCardBackend setEnableAllowList(boolean enableAllowList)
    {
        useAllowList = enableAllowList;
        return this;
    }

    PrivateKeyValues convertPrivateKey(PGPKeyPair keyPair)
            throws PGPException
    {
        final PrivateKey converted = converter.getPrivateKey(keyPair.getPrivateKey());

        if (PublicKeyUtils.isX25519Key(keyPair.getPublicKey().getPublicKeyPacket()))
        {
            // the YubiKey expects the X25519 scalar big-endian, the reverse of the PKCS#8 encoding.
            // Copy first: getEncoded() is not contractually required to hand back a fresh array, and
            // reversing in place would corrupt the source key for any provider that shares one.
            return PrivateKeyValues.fromPrivateKey(bigEndian(converted));
        }
        return PrivateKeyValues.fromPrivateKey(converted);
    }

    private PrivateKey bigEndian(PrivateKey privateKey)
    {
        return new PrivateKey()
        {
            public String getAlgorithm()
            {
                return privateKey.getAlgorithm();
            }

            public String getFormat()
            {
                return privateKey.getFormat();
            }

            public byte[] getEncoded()
            {
                byte[] encoding = Arrays.clone(privateKey.getEncoded());
                if (encoding == null || encoding.length < X25519_SCALAR_SIZE)
                {
                    throw new IllegalStateException("X25519 private key encoding too short to contain a scalar");
                }
                Arrays.reverseInPlace(encoding, encoding.length - X25519_SCALAR_SIZE, X25519_SCALAR_SIZE);
                return encoding;
            }
        };
    }

    PublicKeyValues convertPublicKeyValues(PGPPublicKey pgpPublicKey)
            throws PGPException
    {
        try
        {
            return PublicKeyValues.fromPublicKey(convertPublicKey(pgpPublicKey));
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
        return convertPublicKey(pk, storedFingerprint, creationTime);
    }

    public PGPPublicKey convertPublicKey(PublicKeyValues pkVals,
                                 int keyVersion,
                                 int publicKeyAlgorithmTag,
                                 Date creationTime,
                                 boolean subkey)
            throws NoSuchAlgorithmException, InvalidKeySpecException, PGPException
    {
        PublicKey pk = pkVals.toPublicKey();
        return convertPublicKey(pk, keyVersion, publicKeyAlgorithmTag, creationTime, subkey);
    }

    OpenPgpCurve curveFromOID(ASN1ObjectIdentifier oid)
    {
        // Again, since OpenPgpCurve members are private or package-private, we need to manually map known entries.
        if (oid.equals(X9ObjectIdentifiers.prime256v1) || oid.equals(SECObjectIdentifiers.secp256r1))
        {
            return OpenPgpCurve.SECP256R1;
        }
        if (oid.equals(SECObjectIdentifiers.secp384r1))
        {
            return OpenPgpCurve.SECP384R1;
        }
        if (oid.equals(SECObjectIdentifiers.secp521r1))
        {
            return OpenPgpCurve.SECP521R1;
        }
        if (oid.equals(SECObjectIdentifiers.secp256k1))
        {
            return OpenPgpCurve.SECP256K1;
        }
        if (oid.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return OpenPgpCurve.BrainpoolP256R1;
        }
        if (oid.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return OpenPgpCurve.BrainpoolP384R1;
        }
        if (oid.equals(TeleTrusTObjectIdentifiers.brainpoolP512r1))
        {
            return OpenPgpCurve.BrainpoolP512R1;
        }
        if (oid.equals(GNUObjectIdentifiers.Ed25519) || oid.equals(EdECObjectIdentifiers.id_Ed25519))
        {
            return OpenPgpCurve.Ed25519;
        }
        if (oid.equals(CryptlibObjectIdentifiers.curvey25519) || oid.equals(EdECObjectIdentifiers.id_X25519))
        {
            return OpenPgpCurve.X25519;
        }
        throw new IllegalArgumentException("Unknown OID: " + oid);
    }
}
