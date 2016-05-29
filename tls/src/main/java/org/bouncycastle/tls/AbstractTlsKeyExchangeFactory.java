package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.crypto.params.DHParameters;

public class AbstractTlsKeyExchangeFactory implements TlsKeyExchangeFactory
{
    public TlsKeyExchange createDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        DHParameters dhParameters) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        DHParameters dhParameters) throws IOException
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

    public TlsKeyExchange createPSKKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentity pskIdentity, TlsPSKIdentityManager pskIdentityManager, DHParameters dhParameters,
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
