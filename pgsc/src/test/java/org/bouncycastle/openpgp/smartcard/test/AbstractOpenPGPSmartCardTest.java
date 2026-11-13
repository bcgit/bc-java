package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.api.ExternalOpenPGPKeyUtils;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.List;
import java.util.Properties;

public abstract class AbstractOpenPGPSmartCardTest
        extends SimpleTest
{
    protected final OpenPGPImplementation implementation = new BcOpenPGPImplementation();
    protected final OpenPGPApi api = new BcOpenPGPApi(implementation);
    protected final ExternalOpenPGPKeyUtils cardUtils = new ExternalOpenPGPKeyUtils(implementation);

    protected final OpenPGPSmartCardManager manager;
    protected final TestProperties properties;

    public AbstractOpenPGPSmartCardTest(OpenPGPSmartCardManager manager,
                                        TestProperties properties)
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
            card.uploadSigningKey(secretKey.unlock(), k -> properties.getAdminPin());
        }

        List<OpenPGPCertificate.OpenPGPComponentKey> decryptionKeys = key.getEncryptionKeys();
        if (!decryptionKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = key.getSecretKey(decryptionKeys.get(0));
            card.uploadDecryptionKey(secretKey.unlock(), k -> properties.getAdminPin());
        }

        List<OpenPGPCertificate.OpenPGPComponentKey> authenticationKeys = key.getComponentKeysWithFlag(new Date(), KeyFlags.AUTHENTICATION);
        if (!authenticationKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = key.getSecretKey(authenticationKeys.get(0));
            card.uploadAuthenticationKey(secretKey.unlock(), k -> properties.getAdminPin());
        }
    }

    public static class TestProperties
    {
        public static final char[] DEFAULT_ADMIN_PIN = "12345678".toCharArray();
        public static final char[] DEFAULT_USER_PIN = "123456".toCharArray();

        private final Integer serialNumber;
        private final char[] adminPin;
        private final char[] userPin;

        public TestProperties(Integer serialNumber)
        {
            this(serialNumber, DEFAULT_ADMIN_PIN, DEFAULT_USER_PIN);
        }

        public TestProperties(Integer serialNumber,
                              char[] adminPin,
                              char[] userPin)
        {
            this.serialNumber = serialNumber;
            this.adminPin = adminPin;
            this.userPin = userPin;
        }

        public Integer getSerialNumber()
        {
            return serialNumber;
        }

        public char[] getAdminPin()
        {
            return Arrays.clone(adminPin);
        }

        public char[] getUserPin()
        {
            return Arrays.clone(userPin);
        }

        public static TestProperties fromFile(String fileName)
                throws FileNotFoundException
        {
            Properties properties = loadProperties(fileName);
            return fromProperties(properties);
        }

        public static TestProperties fromProperties(Properties properties)
        {
            return new TestProperties(
                    getInteger(properties, "DEVICE_SERIAL"),
                    getCharArray(properties, "ADMIN_PIN"),
                    getCharArray(properties, "USER_PIN"));
        }

        private static Properties loadProperties(String propFileName)
                throws FileNotFoundException
        {
            try (InputStream in = AbstractOpenPGPSmartCardTest.class.getClassLoader()
                    .getResourceAsStream(propFileName))
            {
                if (in == null)
                {
                    throw new FileNotFoundException("Missing file '" + propFileName + "'.");
                }

                Properties p = new Properties();
                p.load(in);
                return p;
            }
            catch (FileNotFoundException e)
            {
                throw e;
            }
            catch (IOException e)
            {
                throw new RuntimeException("Cannot parse properties from file '" + propFileName + "'.", e);
            }
        }

        private static Integer getInteger(Properties properties, String key)
        {
            if (properties == null)
            {
                return null;
            }

            String val = properties.getProperty(key);
            if (val == null)
            {
                return null;
            }

            return Integer.parseInt(val);
        }

        private static char[] getCharArray(Properties properties, String key)
        {
            if (properties == null)
            {
                return null;
            }
            String val = properties.getProperty(key);
            if (val == null)
            {
                return null;
            }
            return val.toCharArray();
        }
    }
}
