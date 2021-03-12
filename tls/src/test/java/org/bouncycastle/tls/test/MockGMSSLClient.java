package org.bouncycastle.tls.test;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Hashtable;

/**
 * Mock GMSSL client
 *
 * @author Cliven
 * @since 2021-03-09 14:01:50
 */
public class MockGMSSLClient extends AbstractTlsClient
{
    private static final int[] DEFAULT_CIPHER_SUITES = new int[]
    {
        /*
         * GMSSL 1.1
         */
        CipherSuite.GMSSL_ECC_SM4_SM3,
    };

    public MockGMSSLClient()
    {
        this(new BcTlsCrypto(new SecureRandom()));
    }

    public MockGMSSLClient(TlsCrypto crypto)
    {
        super(crypto);
    }

    @Override
    protected ProtocolVersion[] getSupportedVersions()
    {
        return new ProtocolVersion[]{ProtocolVersion.GMSSLv11};
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        return new TlsAuthentication()
        {

            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException
            {
                System.out.println(">> TlsAuthentication on notifyServerCertificate");
            }

            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException
            {
                System.out.println(">> TlsAuthentication on getClientCredentials");
                return null;
            }
        };
    }

    /**
     * GMSSL  not support ClientExtensions
     *
     * @return empty list
     * @throws IOException not happen
     */
    @Override
    public Hashtable getClientExtensions() throws IOException
    {
        return new Hashtable(0);
    }

    /**
     * GMSSL Client generate random struct should be
     * struct
     * {
     *     unit32 gmt_unix_time;
     *     opaque random_bytes[28];
     * }
     *
     * @return true - use GMTUnixTime
     */
    @Override
    public boolean shouldUseGMTUnixTime()
    {
        return true;
    }
}
