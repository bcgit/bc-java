package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;

public abstract class TlsCryptoUtils
{
    // "tls13 "
    private static final byte[] TLS13_PREFIX = new byte[]{ 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20 };

    public static TlsSecret hkdfExpandLabel(TlsSecret secret, short hashAlgorithm, String label, byte[] context, int length)
        throws IOException
    {
        int labelLength = label.length();
        if (labelLength < 1)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        int contextLength = context.length;
        int expandedLabelLength = TLS13_PREFIX.length + labelLength;

        byte[] hkdfLabel = new byte[2 + (1 + expandedLabelLength) + (1 + contextLength)];

        // uint16 length
        {
            TlsUtils.checkUint16(length);
            TlsUtils.writeUint16(length, hkdfLabel, 0);
        }

        // opaque label<7..255>
        {
            TlsUtils.checkUint8(expandedLabelLength);
            TlsUtils.writeUint8(expandedLabelLength, hkdfLabel, 2);

            System.arraycopy(TLS13_PREFIX, 0, hkdfLabel, 2 + 1, TLS13_PREFIX.length);

            int labelPos = 2 + (1 + TLS13_PREFIX.length);
            for (int i = 0; i < labelLength; ++i)
            {
                char c = label.charAt(i);
                hkdfLabel[labelPos + i] = (byte)c;
            }
        }

        // context
        {
            TlsUtils.writeOpaque8(context, hkdfLabel, 2 + (1 + expandedLabelLength));
        }

        return secret.hkdfExpand(hashAlgorithm, hkdfLabel, length);
    }
}
