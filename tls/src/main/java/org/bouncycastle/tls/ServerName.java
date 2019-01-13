package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Strings;

public final class ServerName
{
    private final short nameType;
    private final byte[] nameData;

    /**
     * @deprecated Use {{@link #ServerName(short, byte[])} instead.
     */
    public ServerName(short nameType, Object name)
    {
        if (null == name)
        {
            throw new NullPointerException("'name' cannot be null");
        }

        byte[] nameData;
        switch (nameType)
        {
        case NameType.host_name:
        {
            if (name instanceof byte[])
            {
                nameData = (byte[])name;
                if (TlsUtils.containsNonAscii(nameData))
                {
                    throw new IllegalArgumentException("'name' must be ASCII for host_name");
                }
            }
            else if (name instanceof String)
            {
                String s = (String)name;
                if (TlsUtils.containsNonAscii(s))
                {
                    throw new IllegalArgumentException("'name' must be ASCII for host_name");
                }
                nameData = Strings.toByteArray(s);
            }
            else
            {
                throw new IllegalArgumentException("'name' is not an instance of a supported type");
            }
            break;
        }
        default:
            throw new IllegalArgumentException("'nameType' is an unsupported NameType");
        }

        if (nameData.length < 1 || !TlsUtils.isValidUint16(nameData.length))
        {
            throw new IllegalArgumentException("'name' must have length from 1 to 65535");
        }

        this.nameType = nameType;
        this.nameData = nameData;
    }

    public ServerName(short nameType, byte[] nameData)
    {
        if (null == nameData)
        {
            throw new NullPointerException("'nameData' cannot be null");
        }
        if (nameData.length < 1 || !TlsUtils.isValidUint16(nameData.length))
        {
            throw new IllegalArgumentException("'nameData' must have length from 1 to 65535");
        }

        switch (nameType)
        {
        case NameType.host_name:
        {
            if (TlsUtils.containsNonAscii(nameData))
            {
                throw new IllegalArgumentException("'nameData' must be ASCII for host_name");
            }
            break;
        }
        default:
            throw new IllegalArgumentException("'nameType' is an unsupported NameType");
        }

        this.nameType = nameType;
        this.nameData = nameData;
    }

    public short getNameType()
    {
        return nameType;
    }

    public byte[] getNameData()
    {
        return nameData;
    }

    /**
     * A convenience method for returning a host_name as an ASCII string. Note that this method does
     * not attempt to recognize Internationalized Domain Names (see RFC 5890); further processing
     * may be required to support them.
     * 
     * @deprecated Use {{@link #getNameData()} instead.
     */
    public String getHostName()
    {
        if (NameType.host_name != nameType)
        {
            throw new IllegalStateException("Not of type host_name");
        }

        return Strings.fromByteArray(nameData);
    }

    /**
     * Encode this {@link ServerName} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint8(nameType, output);

        switch (nameType)
        {
        case NameType.host_name:
            TlsUtils.writeOpaque16(nameData, output);
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    /**
     * Parse a {@link ServerName} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link ServerName} object.
     * @throws IOException
     */
    public static ServerName parse(InputStream input) throws IOException
    {
        short name_type = TlsUtils.readUint8(input);
        byte[] nameData;

        switch (name_type)
        {
        case NameType.host_name:
        {
            nameData = TlsUtils.readOpaque16(input, 1);
            if (TlsUtils.containsNonAscii(nameData))
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
            break;
        }
        default:
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return new ServerName(name_type, nameData);
    }
}
