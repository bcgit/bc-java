package org.bouncycastle.jsse;

import java.util.Locale;
import java.util.regex.Pattern;

import org.bouncycastle.jsse.provider.IDNUtil;
import org.bouncycastle.tls.NameType;
import org.bouncycastle.util.Strings;

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

    public BCSNIHostName(String hostName)
    {
        super(BCStandardConstants.SNI_HOST_NAME, Strings.toByteArray(hostName = normalizeHostName(hostName)));

        this.hostName = hostName;
    }

    public BCSNIHostName(byte[] utf8Encoding)
    {
        super(BCStandardConstants.SNI_HOST_NAME, utf8Encoding);

        this.hostName = normalizeHostName(Strings.fromUTF8ByteArray(utf8Encoding));
    }

    public String getAsciiName()
    {
        return hostName;
    }

    @Override
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

    @Override
    public int hashCode()
    {
        return hostName.toUpperCase(Locale.ENGLISH).hashCode();
    }

    @Override
    public String toString()
    {
        return "{type=" + NameType.getText(NameType.host_name) + ", value=" + hostName + "}";
    }

    private static String normalizeHostName(String hostName)
    {
        if (null == hostName)
        {
            throw new NullPointerException("'hostName' cannot be null");
        }

        hostName = IDNUtil.toASCII(hostName, IDNUtil.USE_STD3_ASCII_RULES);

        if (hostName.length() < 1)
        {
            throw new IllegalArgumentException("SNI host_name cannot be empty");
        }
        if (hostName.endsWith("."))
        {
            throw new IllegalArgumentException("SNI host_name cannot end with a separator");
        }

        return hostName;
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
            if (null == serverName)
            {
                throw new NullPointerException("'serverName' cannot be null");
            }

            if (BCStandardConstants.SNI_HOST_NAME != serverName.getType())
            {
                return false;
            }

            String asciiName;
            try
            {
                asciiName = getAsciiHostName(serverName);
            }
            catch (RuntimeException e)
            {
                return false;
            }

            if (pattern.matcher(asciiName).matches())
            {
                return true;
            }

            String unicodeName = IDNUtil.toUnicode(asciiName, 0);
            if (!asciiName.equals(unicodeName)
                && pattern.matcher(unicodeName).matches())
            {
                return true;
            }

            return false;
        }

        private String getAsciiHostName(BCSNIServerName serverName)
        {
            if (serverName instanceof BCSNIHostName)
            {
                return ((BCSNIHostName)serverName).getAsciiName();
            }

            return normalizeHostName(Strings.fromUTF8ByteArray(serverName.getEncoded()));
        }
    }
}
