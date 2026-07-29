package org.bouncycastle.smartcard.yubikey;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.application.InvalidPinException;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.openpgp.AlgorithmAttributes;
import com.yubico.yubikit.openpgp.DiscretionaryDataObjects;
import com.yubico.yubikit.openpgp.KeyRef;
import com.yubico.yubikit.openpgp.KeyStatus;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.smartcard.OpenPGPHardwareKey;
import org.bouncycastle.smartcard.OpenPGPSmartCard;
import org.bouncycastle.smartcard.card.CardException;
import org.bouncycastle.smartcard.card.SupportedAlgorithms;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class YubikeyOpenPGPSmartCard
        extends OpenPGPSmartCard
{

    private final DeviceInfo deviceInfo;
    private final YubiKeyDevice device;
    private final Map<KeyRef, List<AlgorithmAttributes>> supportedAlgorithms;

    public YubikeyOpenPGPSmartCard(YubikeySmartCardBackend backend,
                                   DeviceInfo deviceInfo,
                                   YubiKeyDevice device)
            throws CardException
    {
        super(backend);
        this.deviceInfo = deviceInfo;
        this.device = device;

        try (OpenPgpSession session = openSession())
        {
            supportedAlgorithms = session.getAlgorithmInformation();
            readMetadata(session);
        }
        catch (ApduException | IOException | BadResponseException e)
        {
            throw new CardException("Cannot perform initial read from Yubikey", e);
        }
    }

    private void readMetadata(OpenPgpSession session)
            throws CardException
    {
        keys.clear();
        DiscretionaryDataObjects discretionary = getDiscretionary(session);

        for (KeyRef keyRef : KeyRef.values())
        {
            KeyStatus keyStatus = discretionary.getKeyStatus(keyRef);
            if (keyStatus == null || keyStatus == KeyStatus.NONE)
            {
                continue;
            }

            byte[] fingerprint = discretionary.getFingerprint(keyRef);
            Date generationTime = new Date(discretionary.getGenerationTime(keyRef) * 1000L);
            keys.put(keyRef.getValue(), new OpenPGPHardwareKey(
                    this,
                    keyRef.getValue(),
                    keyStatus.value,
                    fingerprint,
                    generationTime));
        }
    }

    public OpenPgpSession openSession()
            throws IOException, ApduException, CardException
    {
        try
        {
            return new OpenPgpSession(device.openConnection(SmartCardConnection.class));
        }
        catch (ApplicationNotAvailableException e)
        {
            throw new CardException("Cannot open OpenPGP session on smartcard " +getSerialNumber() + " (" + getCardType() + " " + getVersion() + ")");
        }
    }

    @Override
    public Integer getSerialNumber()
    {
        return deviceInfo.getSerialNumber();
    }

    @Override
    public String getVersion()
    {
        return deviceInfo.getVersionName();
    }

    @Override
    public boolean isKeySupported(byte keyRef, OpenPGPCertificate.OpenPGPComponentKey key)
            throws CardException
    {
        return getSupportedAlgorithms(keyRef).supports(key);
    }

    /**
     * Return all supported key algorithms of the slot identified by keyRef.
     *
     * @param keyRef key reference
     * @return {@link SupportedAlgorithms}
     */
    public SupportedAlgorithms getSupportedAlgorithms(byte keyRef)
    {
        List<AlgorithmAttributes> attributes = supportedAlgorithms.get(from(keyRef));
        if (attributes == null)
        {
            return new SupportedAlgorithms(new ArrayList<>()); // or throw?
        }

        List< SupportedAlgorithms.Algorithm> algs = new ArrayList<>(attributes.size());
        String keyAlgId = "algorithmId=";
        for (AlgorithmAttributes attribute : attributes)
        {
            String s = attribute.toString();

            int idxAlgId = s.indexOf(keyAlgId);
            String strAlgId = s.substring(idxAlgId + keyAlgId.length(), s.indexOf(",", idxAlgId + keyAlgId.length()));
            int algId = Integer.parseInt(strAlgId);

            // RSA
            if (s.startsWith("Rsa{"))
            {
                String keyNLen = "nLen=";
                int idxNLen = s.indexOf(keyNLen);
                String strNLen = s.substring(idxNLen + keyNLen.length(), s.indexOf(",", idxNLen + keyNLen.length()));
                int nLen = Integer.parseInt(strNLen);
                algs.add(new SupportedAlgorithms.RSA(keyRef, algId, nLen));
            }
            // ECDH, ECDSA, X25519
            else if (s.startsWith("Ec{"))
            {
                String keyCurve = "curve=";
                int idxCurve = s.indexOf(keyCurve);
                String strCurve = s.substring(idxCurve + keyCurve.length(), s.indexOf(",", idxCurve + keyCurve.length()));
                ASN1ObjectIdentifier curve = ECUtil.getNamedCurveOid(strCurve);
                if (curve == null)
                {
                    if (strCurve.equals("X25519"))
                    {
                        curve = CryptlibObjectIdentifiers.curvey25519;
                    }
                    else if (strCurve.equals("Ed25519"))
                    {
                        curve = EdECObjectIdentifiers.id_Ed25519;
                    }
                }
                algs.add(new SupportedAlgorithms.EC(keyRef, algId, curve));
            }
        }
        return new SupportedAlgorithms(algs);
    }

    @Override
    public YubikeyOpenPGPSmartCard reset()
            throws CardException
    {
        try(OpenPgpSession session = openSession())
        {
            session.reset();
            keys.clear();
            readMetadata(session);
        }
        catch (ApduException | IOException e)
        {
            throw new CardException("Cannot reset Yubikey " + getSerialNumber(), e);
        }
        return this;
    }

    @Override
    public YubikeySmartCardBackend getBackend()
    {
        return (YubikeySmartCardBackend) super.getBackend();
    }

    @Override
    public YubikeyOpenPGPSmartCard uploadKey(byte keyRefByte,
                                             OpenPGPKey.OpenPGPPrivateKey key,
                                             char[] adminPin)
            throws CardException, PGPException
    {
        if (!isKeySupported(keyRefByte, key.getPublicKey()))
        {
            throw new CardException("Key type not supported for keyRef " + keyRefByte);
        }

        return uploadKey(keyRefByte, key.getKeyPair(), adminPin);
    }

    public YubikeyOpenPGPSmartCard uploadKey(byte keyRefByte,
                                             PGPKeyPair keyPair,
                                             char[] adminPin)
            throws CardException, PGPException
    {
        try (OpenPgpSession session = openSession())
        {
            KeyRef keyRef = from(keyRefByte);
            session.verifyAdminPin(adminPin);

            // write private key
            PrivateKeyValues privVal = getBackend().convertPrivateKey(keyPair);
            session.putKey(keyRef, privVal);
            // write fingerprint
            session.setFingerprint(keyRef, keyPair.getPublicKey().getFingerprint());

            // write creation time
            int time = (int) (keyPair.getPublicKey().getCreationTime().getTime() / 1000);
            session.setGenerationTime(keyRef, time);

            readMetadata(session);
        }
        catch (ApduException | IOException | BadResponseException e)
        {
            throw new CardException("Cannot upload key to Yubikey " + getSerialNumber() + ", slot " + keyRefByte, e);
        }
        catch (InvalidPinException e)
        {
            throw new CardException("Invalid Admin PIN.", e);
        }

        return this;
    }

    @Override
    public String getCardType()
    {
        return "YubikeySmartCard";
    }

    private DiscretionaryDataObjects getDiscretionary()
            throws CardException
    {
        try (OpenPgpSession session = openSession())
        {
            return getDiscretionary(session);
        }
        catch (IOException | ApduException e)
        {
            throw new CardException("Cannot get discretionary data objects", e);
        }
    }

    private DiscretionaryDataObjects getDiscretionary(OpenPgpSession session)
            throws CardException
    {
        try
        {
            return session
                    .getApplicationRelatedData()
                    .getDiscretionary();
        }
        catch (ApduException | IOException e)
        {
            throw new CardException("Cannot get discretionary data objects", e);
        }
    }

    private KeyRef from(byte k)
    {
        for (KeyRef ref : KeyRef.values())
        {
            if (ref.getValue() == k)
            {
                return ref;
            }
        }
        throw new IllegalArgumentException("unknown key ref: " + k);
    }

    public PublicKeyValues convertPublicKey(PGPPublicKey pgpPublicKey)
            throws PGPException
    {
        return getBackend().convertPublicKey(pgpPublicKey);
    }

    @Override
    public PGPPublicKey reconstructPGPPublicKey(byte keyRefByte)
            throws CardException, PGPException
    {
        KeyRef keyRef = from(keyRefByte);
        DiscretionaryDataObjects ddo = getDiscretionary();
        if (ddo.getKeyStatus(keyRef) ==  KeyStatus.NONE)
        {
            return null;
        }
        byte[] fingerprint = ddo.getFingerprint(keyRef);
        Date creationTime = new Date(1000L + ddo.getGenerationTime(keyRef));
        PublicKeyValues pkVal = getPublicKeyValue(keyRef);

        try
        {
            return getBackend().convertPublicKey(pkVal, fingerprint, creationTime);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            throw new PGPException("Cannot convert public key", e);
        }
    }

    private PublicKeyValues getPublicKeyValue(KeyRef keyRef)
            throws CardException
    {
        try (OpenPgpSession session = openSession())
        {
            return session.getPublicKey(keyRef);
        }
        catch (BadResponseException | IOException | ApduException e)
        {
            throw new CardException("Cannot extract public key value for " + keyRef, e);
        }
    }
}
