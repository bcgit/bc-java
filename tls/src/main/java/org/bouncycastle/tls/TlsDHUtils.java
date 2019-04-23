package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.DHStandardGroups;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class TlsDHUtils
{
    public static TlsDHConfig createNamedDHConfig(TlsContext context, int namedGroup)
    {
        if (namedGroup < 0 || NamedGroup.getFiniteFieldBits(namedGroup) < 1)
        {
            return null;
        }

        boolean padded = TlsUtils.isTLSv13(context);
        return new TlsDHConfig(namedGroup, padded);
    }

    public static DHGroup getDHGroup(TlsDHConfig dhConfig)
    {
        int namedGroup = dhConfig.getNamedGroup();
        if (namedGroup >= 0)
        {
            return getNamedDHGroup(namedGroup); 
        }

        return dhConfig.getExplicitGroup();
    }

    public static DHGroup getNamedDHGroup(int namedGroup)
    {
        switch (namedGroup)
        {
        case NamedGroup.ffdhe2048:
            return DHStandardGroups.rfc7919_ffdhe2048;
        case NamedGroup.ffdhe3072:
            return DHStandardGroups.rfc7919_ffdhe3072;
        case NamedGroup.ffdhe4096:
            return DHStandardGroups.rfc7919_ffdhe4096;
        case NamedGroup.ffdhe6144:
            return DHStandardGroups.rfc7919_ffdhe6144;
        case NamedGroup.ffdhe8192:
            return DHStandardGroups.rfc7919_ffdhe8192;
        default:
            return null;
        }
    }

    public static int getMinimumFiniteFieldBits(int cipherSuite)
    {
        /*
         * NOTE: An equivalent mechanism was added to support a minimum bit-size requirement for ECC
         * mooted in early drafts of RFC 8442. This requirement was removed in later drafts, so that
         * mechanism is currently somewhat trivial, and this similarly so.
         */
        return isDHCipherSuite(cipherSuite) ? 1 : 0;
    }

    public static boolean isDHCipherSuite(int cipherSuite)
    {
        switch (TlsUtils.getKeyExchangeAlgorithm(cipherSuite))
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_PSK:
        case KeyExchangeAlgorithm.DHE_RSA:
            return true;

        default:
            return false;
        }
    }

    public static int getNamedGroupForDHParameters(BigInteger p, BigInteger g)
    {
        int[] namedGroups = new int[]{ NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096,
            NamedGroup.ffdhe6144, NamedGroup.ffdhe8192 };

        for (int i = 0; i < namedGroups.length; ++i)
        {
            int namedGroup = namedGroups[i];
            DHGroup dhGroup = getNamedDHGroup(namedGroup);
            if (dhGroup != null && dhGroup.getP().equals(p) && dhGroup.getG().equals(g))
            {
                return namedGroup;
            }
        }

        return -1;
    }

    public static TlsDHConfig receiveDHConfig(TlsContext context, TlsDHGroupVerifier dhGroupVerifier,
        InputStream input) throws IOException
    {
        BigInteger p = readDHParameter(input);
        BigInteger g = readDHParameter(input);

        int namedGroup = getNamedGroupForDHParameters(p, g);
        if (namedGroup < 0)
        {
            DHGroup dhGroup = new DHGroup(p, null, g, 0);
            if (!dhGroupVerifier.accept(dhGroup))
            {
                throw new TlsFatalAlert(AlertDescription.insufficient_security);
            }
            return new TlsDHConfig(dhGroup);
        }

        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (null == clientSupportedGroups || Arrays.contains(clientSupportedGroups, namedGroup))
        {
            return new TlsDHConfig(namedGroup, false);
        }

        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
    }

    public static BigInteger readDHParameter(InputStream input) throws IOException
    {
        return new BigInteger(1, TlsUtils.readOpaque16(input, 1));
    }

    public static void writeDHConfig(TlsDHConfig dhConfig, OutputStream output)
        throws IOException
    {
        DHGroup group = getDHGroup(dhConfig);
        writeDHParameter(group.getP(), output);
        writeDHParameter(group.getG(), output);
    }

    public static void writeDHParameter(BigInteger x, OutputStream output) throws IOException
    {
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(x), output);
    }
}
