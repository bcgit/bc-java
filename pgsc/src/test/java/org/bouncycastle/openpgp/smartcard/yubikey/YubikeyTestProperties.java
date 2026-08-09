package org.bouncycastle.openpgp.smartcard.yubikey;

import org.bouncycastle.openpgp.smartcard.test.SmartCardTestProperties;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class YubikeyTestProperties
        extends SmartCardTestProperties
{

    public YubikeyTestProperties()
    {
        this(getProperties());
    }

    public YubikeyTestProperties(Properties properties)
    {
        super(getInteger(properties, "DEVICE_SERIAL"), getCharArray(properties, "ADMIN_PIN"), getCharArray(properties, "USER_PIN"));
    }

    private static Properties getProperties()
    {
        // yubikey.properties is deliberately gitignored: it names a specific device and carries its
        // PINs. Without it getResourceAsStream returns null, and Properties.load(null) throws an
        // unchecked NullPointerException that the IOException catch below cannot see - so check the
        // stream explicitly and let the caller take the "no hardware configured, skip" path.
        try (InputStream in = YubikeyTestProperties.class.getClassLoader()
                .getResourceAsStream("yubikey.properties"))
        {
            if (in == null)
            {
                return null;
            }

            Properties p = new Properties();
            p.load(in);
            return p;
        }
        catch (IOException e)
        {
            return null;
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
