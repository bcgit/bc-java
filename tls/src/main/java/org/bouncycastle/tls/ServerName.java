package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Strings;

/**
 * RFC 6066 3. Server Name Indication
 *
 * Current implementation uses this guidance: "For backward compatibility, all future data
 * structures associated with new NameTypes MUST begin with a 16-bit length field. TLS MAY treat
 * provided server names as opaque data and pass the names and types to the application."
 * 
 * RFC 6066 specifies ASCII encoding for host_name (possibly using A-labels for IDNs), but note that
 * the previous version (RFC 4366) specified UTF-8 encoding (see RFC 6066 Appendix A). For maximum
 * compatibility, it is recommended that client code tolerate receiving UTF-8 from the peer, but
 * only generate ASCII itself.
 */
public final class ServerName
{
    private final short nameType;
    private final byte[] nameData;

    public ServerName(short nameType, byte[] nameData)
    {
        if (!TlsUtils.isValidUint8(nameType))
        {
            throw new IllegalArgumentException("'nameType' must be from 0 to 255");
        }
        if (null == nameData)
        {
            throw new NullPointerException("'nameData' cannot be null");
        }
        if (nameData.length < 1 || !TlsUtils.isValidUint16(nameData.length))
        {
            throw new IllegalArgumentException("'nameData' must have length from 1 to 65535");
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
     * Encode this {@link ServerName} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint8(nameType, output);
        TlsUtils.writeOpaque16(nameData, output);
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
        byte[] nameData = TlsUtils.readOpaque16(input, 1);
        return new ServerName(name_type, nameData);
    }
}
