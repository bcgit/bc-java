package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.Strings;

public abstract class TlsCryptoUtils
{
    public static TlsSecret hkdfExpandLabel(TlsSecret secret, short hashAlgorithm, String label, byte[] context, int length)
        throws IOException
    {
        byte[] expandedLabel = Strings.toByteArray("tls13 " + label);

        byte[] hkdfLabel = new byte[2 + (1 + expandedLabel.length) + (1 + context.length)];

        TlsUtils.checkUint16(length);
        TlsUtils.writeUint16(length, hkdfLabel, 0);

        TlsUtils.writeOpaque8(expandedLabel, hkdfLabel, 2);

        TlsUtils.writeOpaque8(context, hkdfLabel, 2 + (1 + expandedLabel.length));

        return secret.hkdfExpand(hashAlgorithm, hkdfLabel, length);
    }
}
