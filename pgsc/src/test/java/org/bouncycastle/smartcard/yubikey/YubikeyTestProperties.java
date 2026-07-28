package org.bouncycastle.smartcard.yubikey;

import org.bouncycastle.smartcard.test.SmartCardTestProperties;

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
        Properties p;
        try (InputStream in = YubikeyTestProperties.class.getClassLoader()
                .getResourceAsStream("yubikey.properties"))
        {
            p = new Properties();
            p.load(in);
        }
        catch (IOException e)
        {
            p = null;
        }
        return p;
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
