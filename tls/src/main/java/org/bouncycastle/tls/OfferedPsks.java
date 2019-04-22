package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

public class OfferedPsks
{
    protected Vector identities;
    protected Vector binders;

    public OfferedPsks(Vector identities, Vector binders)
    {
        if (null == identities || identities.isEmpty())
        {
            throw new IllegalArgumentException("'identities' cannot be null or empty");
        }
        if (null == binders || identities.size() != binders.size())
        {
            throw new IllegalArgumentException("'binders' must be non-null and the same length as 'identities'");
        }

        this.identities = identities;
        this.binders = binders;
    }

    public Vector getBinders()
    {
        return binders;
    }

    public Vector getIdentities()
    {
        return identities;
    }

    public void encode(OutputStream output) throws IOException
    {
        // identities
        {
            int totalLengthIdentities = 0;
            for (int i = 0; i < identities.size(); ++i)
            {
                PskIdentity identity = (PskIdentity)identities.elementAt(i);
                totalLengthIdentities += 2 + identity.getIdentity().length + 4;
            }

            TlsUtils.checkUint16(totalLengthIdentities);
            TlsUtils.writeUint16(totalLengthIdentities, output);

            for (int i = 0; i < identities.size(); ++i)
            {
                PskIdentity identity = (PskIdentity)identities.elementAt(i);
                identity.encode(output);
            }
        }

        // binders
        {
            int totalLengthBinders = 0;
            for (int i = 0; i < binders.size(); ++i)
            {
                byte[] binder = (byte[])binders.elementAt(i);
                totalLengthBinders += 1 + binder.length;
            }

            TlsUtils.checkUint16(totalLengthBinders);
            TlsUtils.writeUint16(totalLengthBinders, output);

            for (int i = 0; i < binders.size(); ++i)
            {
                byte[] binder = (byte[])binders.elementAt(i);
                TlsUtils.writeOpaque8(binder, output);
            }
        }
    }

    public static OfferedPsks parse(InputStream input) throws IOException
    {
        Vector identities = new Vector();
        {
            int totalLengthIdentities = TlsUtils.readUint16(input);
            if (totalLengthIdentities < 7)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            byte[] identitiesData = TlsUtils.readFully(totalLengthIdentities, input);
            ByteArrayInputStream buf = new ByteArrayInputStream(identitiesData);
            do
            {
                PskIdentity identity = PskIdentity.parse(buf);
                identities.add(identity);
            }
            while (buf.available() > 0);
        }

        Vector binders = new Vector();
        {
            int totalLengthBinders = TlsUtils.readUint16(input);
            if (totalLengthBinders < 33)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            byte[] bindersData = TlsUtils.readFully(totalLengthBinders, input);
            ByteArrayInputStream buf = new ByteArrayInputStream(bindersData);
            do
            {
                byte[] binder = TlsUtils.readOpaque8(input, 32);
                binders.add(binder);
            }
            while (buf.available() > 0);
        }

        return new OfferedPsks(identities, binders);
    }
}
