package org.bouncycastle.cert.ct;

import org.bouncycastle.util.Arrays;

/**
 * One {@code Extension} entry inside the {@code sct_extensions} list of an
 * RFC 9162 (CT v2) {@link SignedCertificateTimestampDataV2}.
 *
 * <pre>
 *     struct {
 *         ExtensionType extension_type;          // uint16
 *         opaque extension_data&lt;0..2^16-1&gt;;
 *     } Extension;
 * </pre>
 *
 * No ExtensionType values are assigned by RFC 9162 itself; the registry was
 * established under section 10.2.4 for future extensions.
 */
public class SctExtension
{
    private final int extensionType;
    private final byte[] extensionData;

    public SctExtension(int extensionType, byte[] extensionData)
    {
        if ((extensionType & ~0xFFFF) != 0)
        {
            throw new IllegalArgumentException("extensionType must fit in a uint16");
        }
        if (extensionData == null)
        {
            throw new NullPointerException("'extensionData' cannot be null");
        }

        this.extensionType = extensionType;
        this.extensionData = Arrays.clone(extensionData);
    }

    public int getExtensionType()
    {
        return extensionType;
    }

    public byte[] getExtensionData()
    {
        return Arrays.clone(extensionData);
    }
}
