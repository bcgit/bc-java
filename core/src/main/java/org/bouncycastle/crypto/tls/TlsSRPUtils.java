package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Hashtable;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;

public class TlsSRPUtils
{
    public static final Integer EXT_SRP = Integers.valueOf(ExtensionType.srp);

    public static void addSRPExtension(Hashtable extensions, byte[] identity) throws IOException
    {
        extensions.put(EXT_SRP, createSRPExtension(identity));
    }

    public static byte[] getSRPExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_SRP);
        return extensionData == null ? null : readSRPExtension(extensionData);
    }

    public static byte[] createSRPExtension(byte[] identity) throws IOException
    {
        if (identity == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return TlsUtils.encodeOpaque8(identity);
    }

    public static byte[] readSRPExtension(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);
        byte[] identity = TlsUtils.readOpaque8(buf);

        TlsProtocol.assertEmpty(buf);

        return identity;
    }

    public static BigInteger readSRPParameter(InputStream input) throws IOException
    {
        return new BigInteger(1, TlsUtils.readOpaque16(input));
    }

    public static void writeSRPParameter(BigInteger x, OutputStream output) throws IOException
    {
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(x), output);
    }

    public static boolean isSRPCipherSuite(int cipherSuite)
    {
        switch (cipherSuite)
        {
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            return true;

        default:
            return false;
        }
    }
}
