package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsDHConfig;

public class AbstractTlsKeyExchangeFactory implements TlsKeyExchangeFactory
{
    public TlsKeyExchange createDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfig dhConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfig dhConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        int[] namedCurves, short[] clientECPointFormats, short[] serverECPointFormats) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentity pskIdentity, int[] namedCurves, short[] clientECPointFormats, short[] serverECPointFormats)
            throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentityManager pskIdentityManager, TlsDHConfig dhConfig,
        int[] namedCurves, short[] clientECPointFormats, short[] serverECPointFormats) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createRSAKeyExchange(Vector supportedSignatureAlgorithms) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
    
    public TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsSRPGroupVerifier groupVerifier, byte[] identity, byte[] password) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        byte[] identity, TlsSRPLoginParameters loginParameters) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
