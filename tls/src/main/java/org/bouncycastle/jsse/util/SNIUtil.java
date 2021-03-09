package org.bouncycastle.jsse.util;

import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.util.IPAddress;

public class SNIUtil
{
    private static final Logger LOG = Logger.getLogger(SNIUtil.class.getName());

    public static BCSNIHostName getBCSNIHostName(URL url)
    {
        if (null != url)
        {
            String host = url.getHost();
            if (null != host && host.indexOf('.') > 0 && !IPAddress.isValid(host))
            {
                try
                {
                    return new BCSNIHostName(host);
                }
                catch (Exception e)
                {
                    LOG.log(Level.FINER, "Failed to parse BCSNIHostName from URL: " + url, e);
                }
            }
        }
        return null;
    }
}
