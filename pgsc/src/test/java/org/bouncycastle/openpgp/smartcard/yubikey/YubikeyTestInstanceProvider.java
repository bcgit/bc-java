package org.bouncycastle.openpgp.smartcard.yubikey;


import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.test.SmartCardTestProperties;

public class YubikeyTestInstanceProvider
{

    public static OpenPGPSmartCardManager prepareOneYubikeySmartCardManager(
            SmartCardTestProperties testProperties)
            throws YubikeySetupException, CardException
    {
        return prepareOneYubikeySmartCardManager(testProperties, YubikeySmartCardBackend.bcImpl());
    }

    public static OpenPGPSmartCardManager prepareOneYubikeySmartCardManager(
            SmartCardTestProperties testProperties,
            YubikeySmartCardBackend.YubikeyDecryptorFactoryProvider decryptorFactoryProvider)
            throws YubikeySetupException, CardException
    {
        if (testProperties.getSerialNumber() == null)
        {
            throw new YubikeySetupException("Missing yubikey.properties file.");
        }

        YubikeySmartCardBackend backend = YubikeySmartCardBackend.createInstance(decryptorFactoryProvider)
                .addAllowedCardSerial(testProperties.getSerialNumber());
        if (backend.listSmartCards().isEmpty())
        {
            throw new YubikeySetupException("No allowed Yubikey devices present. Did you add your device serial number to the yubikey.properties file?");
        }
        return new OpenPGPSmartCardManager()
                .addBackend(backend);
    }

    public static class YubikeySetupException extends Exception
    {
        public YubikeySetupException(String message)
        {
            super(message);
        }
    }
}
