package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.JcaOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestInstanceProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SmartCardWithV6KeysTest
        extends AbstractOpenPGPSmartCardTest
{
    public SmartCardWithV6KeysTest(OpenPGPSmartCardManager manager, TestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public String getName()
    {
        return "SmartCardWithV6Keys";
    }

    @Override
    public void performTest()
            throws Exception
    {
        String V6_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
                "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
                "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
                "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
                "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
                "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
                "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
                "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
                "k0mXubZvyl4GBg==\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        byte[] V6_PRIMARY_FP = Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
        byte[] SHORTENED_V6_PRIMARY_FP = Hex.decode("000000000000000000000006cb186c4f0609a697");
        byte[] V6_ENCRYPTION_FP = Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885");
        byte[] SHORTENED_V6_ENCRYPTION_FP = Hex.decode("00000000000000000000000612c83f1e706f6308");

        OpenPGPKey key = api.readKeyOrCertificate().parseKey(V6_KEY);
        OpenPGPKey.OpenPGPSecretKey signingKey = key.getSecretKey(key.getSigningKeys().get(0));
        OpenPGPKey.OpenPGPSecretKey encryptionKey = key.getSecretKey(key.getEncryptionKeys().get(0));

        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        card.reset();

        card.uploadSigningKey(signingKey.unlock(), k -> properties.getAdminPin());
        isTrue(card.hasKeyWithFingerprint(V6_PRIMARY_FP));
        isTrue(card.hasKeyWithFingerprint(SHORTENED_V6_PRIMARY_FP));
        OpenPGPHardwareKey hwSignatureKey = card.getSignatureKey();
        isEquals("Signature key KeyRef mismatch", OpenPGPHardwareKey.KEY_REF_SIGNATURE, hwSignatureKey.getKeyRef());
        isTrue("Signature key MUST be imported", hwSignatureKey.isImported());
        isTrue("Signature key MUST NOT be generated", !hwSignatureKey.isGenerated());
        isTrue("Shortened signing key fingerprint mismatch",
                Arrays.areEqual(SHORTENED_V6_PRIMARY_FP, hwSignatureKey.getFingerprint()));
        isTrue("Reconstructed signing key fingerprint mismatch",
                Arrays.areEqual(V6_PRIMARY_FP, hwSignatureKey.getFullKeyIdentifier().getFingerprint()));

        card.uploadDecryptionKey(encryptionKey.unlock(), k -> properties.getAdminPin());
        isTrue(card.hasKeyWithFingerprint(V6_ENCRYPTION_FP));
        isTrue(card.hasKeyWithFingerprint(SHORTENED_V6_ENCRYPTION_FP));
        OpenPGPHardwareKey hwDecryptionKey = card.getKeyByFingerprint(V6_ENCRYPTION_FP);
        isEquals("Decryption key KeyRef mismatch", OpenPGPHardwareKey.KEY_REF_DECRYPTION, hwDecryptionKey.getKeyRef());
        isTrue("Decryption key MUST be imported", hwDecryptionKey.isImported());
        isTrue("Decryption key MUST NOT be generated", !hwDecryptionKey.isGenerated());
        isEquals("Decryption key creation time mismatch",
                encryptionKey.getCreationTime(), hwDecryptionKey.getCreationTime());
        isTrue("Shortened decryption key fingerprint mismatch",
                Arrays.areEqual(SHORTENED_V6_ENCRYPTION_FP, hwDecryptionKey.getFingerprint()));
        isTrue("Reconstructed decryption key fingerprint mismatch",
                Arrays.areEqual(
                        V6_ENCRYPTION_FP,
                        hwDecryptionKey.getFullKeyIdentifier().getFingerprint()));
    }

    public static void main(String[] args)
    {
        OpenPGPSmartCardManager m;
        TestProperties p;

        try
        {
            p = YubikeyTestInstanceProvider.defaultProperties();

            // BCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, new BcOpenPGPSmartCardImplementation()));
            runTest(new SmartCardWithV6KeysTest(m, p));

            // JCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, new JcaOpenPGPSmartCardImplementation()));
            runTest(new SmartCardWithV6KeysTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of SmartCardWithV6KeysTest on Yubikey: " + e.getMessage());
        }

        p = new TestProperties(1312);
        SimulatorOpenPGPSmartCardBackend sim = new SimulatorOpenPGPSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, p.getSerialNumber()));
        m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        runTest(new SmartCardWithV6KeysTest(m, p));
    }
}
