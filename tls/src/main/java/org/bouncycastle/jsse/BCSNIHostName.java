package org.bouncycastle.jsse;

import java.io.UnsupportedEncodingException;
import java.util.Locale;
import java.util.regex.Pattern;

public final class BCSNIHostName extends BCSNIServerName
{
    public static BCSNIMatcher createSNIMatcher(String regex)
    {
        if (regex == null)
        {
            throw new NullPointerException("'regex' cannot be null");
        }

        return new BCSNIHostNameMatcher(regex);
    }

    private final String hostName;

    private static String fromAscii(byte[] bs)
    {
        try
        {
            return new String(bs, "ASCII");
        }
        catch (UnsupportedEncodingException e)
        {
            throw new RuntimeException(e);
        }
    }

    private static byte[] toAscii(String s)
    {
        try
        {
            return s.getBytes("ASCII");
        }
        catch (UnsupportedEncodingException e)
        {
            throw new RuntimeException(e);
        }
    }

    public BCSNIHostName(String hostName)
    {
        super(BCStandardConstants.SNI_HOST_NAME, toAscii(hostName));

        this.hostName = hostName;
    }

    public BCSNIHostName(byte[] asciiEncoding)
    {
        super(BCStandardConstants.SNI_HOST_NAME, asciiEncoding);

        this.hostName = fromAscii(asciiEncoding);
    }

    public String getAsciiName()
    {
        return hostName;
    }

    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof BCSNIHostName))
        {
            return false;
        }
        BCSNIHostName other = (BCSNIHostName)obj;
        return hostName.equalsIgnoreCase(other.hostName);
    }

    public int hashCode()
    {
        return hostName.toUpperCase(Locale.ENGLISH).hashCode();
    }

    private static final class BCSNIHostNameMatcher
        extends BCSNIMatcher
    {
        private final Pattern pattern;

        BCSNIHostNameMatcher(String regex)
        {
            super(BCStandardConstants.SNI_HOST_NAME);

            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        }

        public boolean matches(BCSNIServerName serverName)
        {
            if (serverName == null || serverName.getType() != BCStandardConstants.SNI_HOST_NAME)
            {
                return false;
            }

            String hostName = fromAscii(serverName.getEncoded());

            return pattern.matcher(hostName).matches();
        }
    }
}
