package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class ProtocolVersion
{
    public static final ProtocolVersion SSLv3 = new ProtocolVersion(0x0300);
    public static final ProtocolVersion TLSv10 = new ProtocolVersion(0x0301);
    public static final ProtocolVersion TLSv11 = new ProtocolVersion(0x0302);
    public static final ProtocolVersion TLSv12 = new ProtocolVersion(0x0303);

    private int version;

    private ProtocolVersion(int v)
    {
        version = v & 0xffff;
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
        return version & 0xff;
    }

    public boolean equals(Object obj)
    {
        return this == obj;
    }

    public int hashCode()
    {
        return version;
    }

    public static ProtocolVersion get(int major, int minor) throws IOException
    {
        switch (major)
        {
            case 3:
                switch (minor)
                {
                    case 0:
                        return SSLv3;
                    case 1:
                        return TLSv10;
                    case 2:
                        return TLSv11;
                    case 3:
                        return TLSv12;
                }
        }

        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
    }
}
