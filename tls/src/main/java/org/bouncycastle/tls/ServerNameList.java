package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class ServerNameList
{
    protected Vector serverNameList;

    /**
     * @param serverNameList a {@link Vector} of {@link ServerName}.
     */
    public ServerNameList(Vector serverNameList)
    {
        if (null == serverNameList)
        {
            throw new NullPointerException("'serverNameList' cannot be null");
        }

        this.serverNameList = serverNameList;
    }

    /**
     * @return a {@link Vector} of {@link ServerName}.
     */
    public Vector getServerNameList()
    {
        return serverNameList;
    }

    /**
     * Encode this {@link ServerNameList} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        short[] nameTypesSeen = TlsUtils.EMPTY_SHORTS;
        for (int i = 0; i < serverNameList.size(); ++i)
        {
            ServerName entry = (ServerName)serverNameList.elementAt(i);

            nameTypesSeen = checkNameType(nameTypesSeen, entry.getNameType());
            if (null == nameTypesSeen)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            entry.encode(buf);
        }

        TlsUtils.checkUint16(buf.size());
        TlsUtils.writeUint16(buf.size(), output);
        Streams.writeBufTo(buf, output);
    }

    /**
     * Parse a {@link ServerNameList} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link ServerNameList} object.
     * @throws IOException
     */
    public static ServerNameList parse(InputStream input) throws IOException
    {
        byte[] data = TlsUtils.readOpaque16(input, 1);

        ByteArrayInputStream buf = new ByteArrayInputStream(data);

        short[] nameTypesSeen = TlsUtils.EMPTY_SHORTS;
        Vector server_name_list = new Vector();
        while (buf.available() > 0)
        {
            ServerName entry = ServerName.parse(buf);

            nameTypesSeen = checkNameType(nameTypesSeen, entry.getNameType());
            if (null == nameTypesSeen)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            server_name_list.addElement(entry);
        }

        return new ServerNameList(server_name_list);
    }

    private static short[] checkNameType(short[] nameTypesSeen, short nameType)
    {
         // RFC 6066 3. The ServerNameList MUST NOT contain more than one name of the same NameType.
        if (Arrays.contains(nameTypesSeen, nameType))
        {
            return null;
        }
        return Arrays.append(nameTypesSeen, nameType);
    }
}
