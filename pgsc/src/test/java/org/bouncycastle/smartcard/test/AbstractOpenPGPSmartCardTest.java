package org.bouncycastle.smartcard.test;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation;
import org.bouncycastle.smartcard.OpenPGPHardwareKey;
import org.bouncycastle.smartcard.OpenPGPSmartCard;
import org.bouncycastle.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.smartcard.card.CardException;
import org.bouncycastle.util.test.SimpleTest;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public abstract class AbstractOpenPGPSmartCardTest
        extends SimpleTest
{
    protected final OpenPGPImplementation implementation = new BcOpenPGPImplementation();
    protected final OpenPGPApi api = new BcOpenPGPApi(implementation);

    protected final OpenPGPSmartCardManager manager;
    protected final SmartCardTestProperties properties;

    public AbstractOpenPGPSmartCardTest(OpenPGPSmartCardManager manager,
                                        SmartCardTestProperties properties)
    {
        this.manager = manager;
        this.properties = properties;
    }

    public void keyToCard(OpenPGPKey key, OpenPGPSmartCard card)
            throws PGPException, CardException
    {
        card.reset();
        List<OpenPGPCertificate.OpenPGPComponentKey> signingKeys = key.getSigningKeys();
        if (!signingKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = key.getSecretKey(signingKeys.get(0));
            card.uploadKey(OpenPGPHardwareKey.KEY_REF_SIGNATURE, secretKey.unlock(), properties.getAdminPin());
        }

        List<OpenPGPCertificate.OpenPGPComponentKey> decryptionKeys = key.getEncryptionKeys();
        if (!decryptionKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = key.getSecretKey(decryptionKeys.get(0));
            card.uploadKey(OpenPGPHardwareKey.KEY_REF_DECRYPTION, secretKey.unlock(), properties.getAdminPin());
        }

        List<OpenPGPCertificate.OpenPGPComponentKey> authenticationKeys = key.getComponentKeysWithFlag(new Date(), KeyFlags.AUTHENTICATION);
        if (!authenticationKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = key.getSecretKey(authenticationKeys.get(0));
            card.uploadKey(OpenPGPHardwareKey.KEY_REF_AUTHENTICATION, secretKey.unlock(), properties.getAdminPin());
        }
    }

    public OpenPGPKey toExternalKey(OpenPGPKey key, KeyIdentifier componentKey, byte[] locatorHint)
    {
        List<OpenPGPKey.OpenPGPSecretKey> secretKeys = new ArrayList<>();
        for (OpenPGPKey.OpenPGPSecretKey sk : key.getSecretKeys().values())
        {
            if (sk.getKeyIdentifier().matchesExplicit(componentKey))
            {
                secretKeys.add(new OpenPGPKey.OpenPGPSecretKey(
                        sk.getPublicKey(),
                        toExternalKey(sk.getPGPSecretKey(), locatorHint),
                        implementation.pbeSecretKeyDecryptorBuilderProvider()));
            }
            else
            {
                secretKeys.add(sk);
            }
        }
        return new OpenPGPKey(secretKeys, implementation);
    }

    public OpenPGPKey toExternalKey(OpenPGPKey key, byte[] locatorHint)
    {
        List<OpenPGPKey.OpenPGPSecretKey> secretKeys = new ArrayList<>();
        for (OpenPGPKey.OpenPGPSecretKey sk : key.getSecretKeys().values())
        {
            secretKeys.add(new OpenPGPKey.OpenPGPSecretKey(
                    sk.getPublicKey(),
                    toExternalKey(sk.getPGPSecretKey(), locatorHint),
                    implementation.pbeSecretKeyDecryptorBuilderProvider()));
        }
        return new OpenPGPKey(secretKeys, implementation);
    }

    public OpenPGPKey.OpenPGPSecretKey toExternalKey(OpenPGPKey.OpenPGPSecretKey key, byte[] locatorHint)
    {
        PGPSecretKey externalKey = toExternalKey(key.getPGPSecretKey(), locatorHint);
        return new OpenPGPKey.OpenPGPSecretKey(key.getPublicKey(), externalKey, implementation.pbeSecretKeyDecryptorBuilderProvider());
    }

    public PGPSecretKey toExternalKey(PGPSecretKey secretKey, byte[] locatorHint)
    {
        if (secretKey.isMasterKey())
        {
            return new PGPSecretKey(
                    new SecretKeyPacket(
                            secretKey.getPublicKey().getPublicKeyPacket(),
                            locatorHint),
                    secretKey.getPublicKey());
        }
        else
        {
            return new PGPSecretKey(
                    new SecretSubkeyPacket(
                            (PublicSubkeyPacket) secretKey.getPublicKey().getPublicKeyPacket(),
                            locatorHint),
                    secretKey.getPublicKey());
        }
    }
}
