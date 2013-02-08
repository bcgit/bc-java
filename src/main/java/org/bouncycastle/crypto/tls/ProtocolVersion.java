package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class ProtocolVersion
{
    public static final ProtocolVersion SSLv3 = new ProtocolVersion(0x0300);
    public static final ProtocolVersion TLSv10 = new ProtocolVersion(0x0301);
    public static final ProtocolVersion TLSv11 = new ProtocolVersion(0x0302);
    public static final ProtocolVersion TLSv12 = new ProtocolVersion(0x0303);
    public static final ProtocolVersion DTLSv10 = new ProtocolVersion(0xFEFF);
    public static final ProtocolVersion DTLSv12 = new ProtocolVersion(0xFEFD);

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
	return getMajorVersion() == 0x03 && !isSSL();
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
            case 0x03:
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
                }
            case 0xFE:
                switch (minor)
                {
                    case 0xFF:
                        return DTLSv10;
                    case 0xFD:
                        return DTLSv12;
                }
        }

        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
    }
}
