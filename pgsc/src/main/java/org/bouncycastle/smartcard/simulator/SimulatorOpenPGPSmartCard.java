package org.bouncycastle.smartcard.simulator;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.smartcard.OpenPGPHardwareKey;
import org.bouncycastle.smartcard.OpenPGPSmartCard;
import org.bouncycastle.smartcard.card.CardException;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class SimulatorOpenPGPSmartCard
        extends OpenPGPSmartCard
{
    private static final Random unsafeRandom = new Random();
    private final Integer serialNumber;

    private final Map<Byte, OpenPGPKey.OpenPGPSecretKey> secretKeys = new HashMap<>();

    public SimulatorOpenPGPSmartCard(SimulatorSmartCardBackend backend,
                                     Integer serialNumber)
    {
        super(backend);
        this.serialNumber = serialNumber;
    }

    public static SimulatorOpenPGPSmartCard createSimulatedCardFrom(SimulatorSmartCardBackend backend,
                                                                    OpenPGPKey softwareKey)
            throws PGPException
    {
        return createSimulatedCardFrom(backend, unsafeRandom.nextInt(), softwareKey);
    }

    public static SimulatorOpenPGPSmartCard createSimulatedCardFrom(SimulatorSmartCardBackend backend,
                                                                    Integer serialNumber,
                                                                    OpenPGPKey softwareKey)
            throws PGPException
    {
        SimulatorOpenPGPSmartCard card = new SimulatorOpenPGPSmartCard(backend, serialNumber);

        List<OpenPGPCertificate.OpenPGPComponentKey> signingKeys = softwareKey.getSigningKeys();
        if (!signingKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = softwareKey.getSecretKey(signingKeys.get(0));
            card.uploadKey(OpenPGPHardwareKey.KEY_REF_SIGNATURE, secretKey.unlock(), null);
        }

        List<OpenPGPCertificate.OpenPGPComponentKey> decryptionKeys = softwareKey.getEncryptionKeys();
        if (!decryptionKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = softwareKey.getSecretKey(decryptionKeys.get(0));
            card.uploadKey(OpenPGPHardwareKey.KEY_REF_DECRYPTION, secretKey.unlock(), null);
        }

        List<OpenPGPCertificate.OpenPGPComponentKey> authenticationKeys = softwareKey.getComponentKeysWithFlag(new Date(), KeyFlags.AUTHENTICATION);
        if (!authenticationKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = softwareKey.getSecretKey(authenticationKeys.get(0));
            card.uploadKey(OpenPGPHardwareKey.KEY_REF_AUTHENTICATION, secretKey.unlock(), null);
        }

        return card;
    }

    private static OpenPGPHardwareKey asHardwareKey(OpenPGPSmartCard card,
                                                    OpenPGPKey.OpenPGPSecretKey key,
                                                    byte keyRef,
                                                    byte state)
    {
        return new OpenPGPHardwareKey(
                card,
                keyRef,
                state,
                key.getPGPPublicKey().getFingerprint(),
                key.getPGPPublicKey().getCreationTime());
    }

    @Override
    public Integer getSerialNumber()
    {
        return serialNumber;
    }

    @Override
    public String getVersion()
    {
        return "1.0";
    }

    @Override
    public boolean isKeySupported(byte keyRef, OpenPGPCertificate.OpenPGPComponentKey key)
    {
        return true;
    }

    @Override
    public SimulatorOpenPGPSmartCard reset()
    {
        keys.clear();
        secretKeys.clear();
        return this;
    }

    @Override
    public SimulatorOpenPGPSmartCard uploadKey(byte keyRef,
                                               OpenPGPKey.OpenPGPPrivateKey key,
                                               char[] adminPin)
    {
        secretKeys.put(keyRef, key.getSecretKey());
        keys.put(keyRef, asHardwareKey(this, key.getSecretKey(), keyRef, OpenPGPHardwareKey.STATE_IMPORTED));
        return this;
    }

    @Override
    public PGPPublicKey reconstructPGPPublicKey(byte keyRef)
    {
        return secretKeys.get(keyRef).getPublicKey().getPGPPublicKey();
    }

    public PGPPrivateKey getSoftwareKey(OpenPGPCertificate.OpenPGPComponentKey key,
                                        KeyPassphraseProvider passphraseProvider)
            throws PGPException
    {
        for (OpenPGPKey.OpenPGPSecretKey k : secretKeys.values())
        {
            if (k.getKeyIdentifier().matchesExplicit(key.getKeyIdentifier()))
            {
                return k.unlock(passphraseProvider).getKeyPair().getPrivateKey();
            }
        }
        return null;
    }

    @Override
    public String getCardType()
    {
        return "SimulatorSmartCard";
    }
}
