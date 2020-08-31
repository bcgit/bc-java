package org.bouncycastle.tls;

import java.util.Vector;

import org.bouncycastle.util.Strings;

public final class ProtocolVersion
{
    public static final ProtocolVersion SSLv3 = new ProtocolVersion(0x0300, "SSL 3.0");
    public static final ProtocolVersion TLSv10 = new ProtocolVersion(0x0301, "TLS 1.0");
    public static final ProtocolVersion TLSv11 = new ProtocolVersion(0x0302, "TLS 1.1");
    public static final ProtocolVersion TLSv12 = new ProtocolVersion(0x0303, "TLS 1.2");
    public static final ProtocolVersion TLSv13 = new ProtocolVersion(0x0304, "TLS 1.3");
    public static final ProtocolVersion DTLSv10 = new ProtocolVersion(0xFEFF, "DTLS 1.0");
    public static final ProtocolVersion DTLSv12 = new ProtocolVersion(0xFEFD, "DTLS 1.2");

    static final ProtocolVersion CLIENT_EARLIEST_SUPPORTED_DTLS = DTLSv10;
    static final ProtocolVersion CLIENT_EARLIEST_SUPPORTED_TLS = SSLv3;
    static final ProtocolVersion CLIENT_LATEST_SUPPORTED_DTLS = DTLSv12;
    static final ProtocolVersion CLIENT_LATEST_SUPPORTED_TLS = TLSv13;

    static final ProtocolVersion SERVER_EARLIEST_SUPPORTED_DTLS = DTLSv10;
    static final ProtocolVersion SERVER_EARLIEST_SUPPORTED_TLS = SSLv3;
    static final ProtocolVersion SERVER_LATEST_SUPPORTED_DTLS = DTLSv12;
    static final ProtocolVersion SERVER_LATEST_SUPPORTED_TLS = TLSv13;

    public static boolean contains(ProtocolVersion[] versions, ProtocolVersion version)
    {
        if (versions != null && version != null)
        {
            for (int i = 0; i < versions.length; ++i)
            {
                if (version.equals(versions[i]))
                {
                    return true;
                }
            }
        }
        return false;
    }

    public static ProtocolVersion getEarliestDTLS(ProtocolVersion[] versions)
    {
        ProtocolVersion earliest = null;
        if (null != versions)
        {
            for (int i = 0; i < versions.length; ++i)
            {
                ProtocolVersion next = versions[i];
                if (null != next && next.isDTLS())
                {
                    if (null == earliest || next.getMinorVersion() > earliest.getMinorVersion())
                    {
                        earliest = next;
                    }
                }
            }
        }
        return earliest;
    }

    public static ProtocolVersion getEarliestTLS(ProtocolVersion[] versions)
    {
        ProtocolVersion earliest = null;
        if (null != versions)
        {
            for (int i = 0; i < versions.length; ++i)
            {
                ProtocolVersion next = versions[i];
                if (null != next && next.isTLS())
                {
                    if (null == earliest || next.getMinorVersion() < earliest.getMinorVersion())
                    {
                        earliest = next;
                    }
                }
            }
        }
        return earliest;
    }

    public static ProtocolVersion getLatestDTLS(ProtocolVersion[] versions)
    {
        ProtocolVersion latest = null;
        if (null != versions)
        {
            for (int i = 0; i < versions.length; ++i)
            {
                ProtocolVersion next = versions[i];
                if (null != next && next.isDTLS())
                {
                    if (null == latest || next.getMinorVersion() < latest.getMinorVersion())
                    {
                        latest = next;
                    }
                }
            }
        }
        return latest;
    }

    public static ProtocolVersion getLatestTLS(ProtocolVersion[] versions)
    {
        ProtocolVersion latest = null;
        if (null != versions)
        {
            for (int i = 0; i < versions.length; ++i)
            {
                ProtocolVersion next = versions[i];
                if (null != next && next.isTLS())
                {
                    if (null == latest || next.getMinorVersion() > latest.getMinorVersion())
                    {
                        latest = next;
                    }
                }
            }
        }
        return latest;
    }

    static boolean isSupportedDTLSVersionClient(ProtocolVersion version)
    {
        return null != version
            && version.isEqualOrLaterVersionOf(CLIENT_EARLIEST_SUPPORTED_DTLS)
            && version.isEqualOrEarlierVersionOf(CLIENT_LATEST_SUPPORTED_DTLS);
    }

    static boolean isSupportedDTLSVersionServer(ProtocolVersion version)
    {
        return null != version
            && version.isEqualOrLaterVersionOf(SERVER_EARLIEST_SUPPORTED_DTLS)
            && version.isEqualOrEarlierVersionOf(SERVER_LATEST_SUPPORTED_DTLS);
    }

    static boolean isSupportedTLSVersionClient(ProtocolVersion version)
    {
        if (null == version)
        {
            return false;
        }

        int fullVersion = version.getFullVersion();

        return fullVersion >= CLIENT_EARLIEST_SUPPORTED_TLS.getFullVersion()
            && fullVersion <= CLIENT_LATEST_SUPPORTED_TLS.getFullVersion();
    }

    static boolean isSupportedTLSVersionServer(ProtocolVersion version)
    {
        if (null == version)
        {
            return false;
        }

        int fullVersion = version.getFullVersion();

        return fullVersion >= SERVER_EARLIEST_SUPPORTED_TLS.getFullVersion()
            && fullVersion <= SERVER_LATEST_SUPPORTED_TLS.getFullVersion();
    }

    private int version;
    private String name;

    private ProtocolVersion(int v, String name)
    {
        this.version = v & 0xFFFF;
        this.name = name;
    }

    public ProtocolVersion[] downTo(ProtocolVersion min)
    {
        if (!isEqualOrLaterVersionOf(min))
        {
            throw new IllegalArgumentException("'min' must be an equal or earlier version of this one");
        }

        Vector result = new Vector();
        result.addElement(this);

        ProtocolVersion current = this;
        while (!current.equals(min))
        {
            current = current.getPreviousVersion();
            result.addElement(current);
        }

        ProtocolVersion[] versions = new ProtocolVersion[result.size()];
        for (int i = 0; i < result.size(); ++i)
        {
            versions[i] = (ProtocolVersion)result.elementAt(i);
        }
        return versions;
    }

    public int getFullVersion()
    {
        return version;
    }

    public int getMajorVersion()
    {
        return version >> 8;
    }

    public int getMinorVersion()
    {
        return version & 0xFF;
    }

    public String getName()
    {
        return name;
    }

    public boolean isDTLS()
    {
        return getMajorVersion() == 0xFE;
    }

    public boolean isSSL()
    {
        return this == SSLv3;
    }

    public boolean isTLS()
    {
        return getMajorVersion() == 0x03;
    }

    public ProtocolVersion getEquivalentTLSVersion()
    {
        switch (getMajorVersion())
        {
        case 0x03:  return this;
        case 0xFE:
            switch(getMinorVersion())
            {
            case 0xFF:  return TLSv11;
            case 0xFD:  return TLSv12;
            default:    return null;
            }
        default:    return null;
        }
    }

    public ProtocolVersion getNextVersion()
    {
        int major = getMajorVersion(), minor = getMinorVersion();
        switch (major)
        {
        case 0x03:
            switch (minor)
            {
            case 0xFF: return null;
            default  : return get(major, minor + 1);
            }
        case 0xFE:
            switch(minor)
            {
            case 0x00: return null;
            case 0xFF: return DTLSv12;
            default  : return get(major, minor - 1);
            }
        default:    return null;
        }
    }

    public ProtocolVersion getPreviousVersion()
    {
        int major = getMajorVersion(), minor = getMinorVersion();
        switch (major)
        {
        case 0x03:
            switch (minor)
            {
            case 0x00: return null;
            default  : return get(major, minor - 1);
            }
        case 0xFE:
            switch(minor)
            {
            case 0xFF: return null;
            case 0xFD: return DTLSv10;
            default  : return get(major, minor + 1);
            }
        default:    return null;
        }
    }

    public boolean isEarlierVersionOf(ProtocolVersion version)
    {
        if (null == version || getMajorVersion() != version.getMajorVersion())
        {
            return false;
        }
        int diffMinorVersion = getMinorVersion() - version.getMinorVersion();
        return isDTLS() ? diffMinorVersion > 0 : diffMinorVersion < 0;
    }

    public boolean isEqualOrEarlierVersionOf(ProtocolVersion version)
    {
        if (null == version || getMajorVersion() != version.getMajorVersion())
        {
            return false;
        }
        int diffMinorVersion = getMinorVersion() - version.getMinorVersion();
        return isDTLS() ? diffMinorVersion >= 0 : diffMinorVersion <= 0;
    }

    public boolean isEqualOrLaterVersionOf(ProtocolVersion version)
    {
        if (null == version || getMajorVersion() != version.getMajorVersion())
        {
            return false;
        }
        int diffMinorVersion = getMinorVersion() - version.getMinorVersion();
        return isDTLS() ? diffMinorVersion <= 0 : diffMinorVersion >= 0;
    }

    public boolean isLaterVersionOf(ProtocolVersion version)
    {
        if (null == version || getMajorVersion() != version.getMajorVersion())
        {
            return false;
        }
        int diffMinorVersion = getMinorVersion() - version.getMinorVersion();
        return isDTLS() ? diffMinorVersion < 0 : diffMinorVersion > 0;
    }

    public boolean equals(Object other)
    {
        return this == other || (other instanceof ProtocolVersion && equals((ProtocolVersion)other));
    }

    public boolean equals(ProtocolVersion other)
    {
        return other != null && this.version == other.version;
    }

    public int hashCode()
    {
        return version;
    }

    public static ProtocolVersion get(int major, int minor)
    {
        switch (major)
        {
        case 0x03:
        {
            switch (minor)
            {
            case 0x00:
                return SSLv3;
            case 0x01:
                return TLSv10;
            case 0x02:
                return TLSv11;
            case 0x03:
                return TLSv12;
            case 0x04:
                return TLSv13;
            }
            return getUnknownVersion(major, minor, "TLS");
        }
        case 0xFE:
        {
            switch (minor)
            {
            case 0xFF:
                return DTLSv10;
            case 0xFE:
                throw new IllegalArgumentException("{0xFE, 0xFE} is a reserved protocol version");
            case 0xFD:
                return DTLSv12;
            }
            return getUnknownVersion(major, minor, "DTLS");
        }
        default:
        {
            return getUnknownVersion(major, minor, "UNKNOWN");
        }
        }
    }

    public ProtocolVersion[] only()
    {
        return new ProtocolVersion[]{ this };
    }

    public String toString()
    {
        return name;
    }

    private static void checkUint8(int versionOctet)
    {
        if (!TlsUtils.isValidUint8(versionOctet))
        {
            throw new IllegalArgumentException("'versionOctet' is not a valid octet");
        }
    }

    private static ProtocolVersion getUnknownVersion(int major, int minor, String prefix)
    {
        checkUint8(major);
        checkUint8(minor);

        int v = (major << 8) | minor;
        String hex = Strings.toUpperCase(Integer.toHexString(0x10000 | v).substring(1));
        return new ProtocolVersion(v, prefix + " 0x" + hex);
    }
}
