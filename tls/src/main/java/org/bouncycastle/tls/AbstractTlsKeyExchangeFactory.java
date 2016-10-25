package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

public class AbstractTlsKeyExchangeFactory
    implements TlsKeyExchangeFactory
{
    public TlsKeyExchange createDHKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfigVerifier dhConfigVerifier) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfig dhConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfigVerifier dhConfigVerifier) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfig dhConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfigVerifier ecConfigVerifier, short[] clientECPointFormats, short[] serverECPointFormats)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfig ecConfig, short[] serverECPointFormats) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfigVerifier ecConfigVerifier, short[] clientECPointFormats, short[] serverECPointFormats)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfig ecConfig, short[] serverECPointFormats) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentity pskIdentity, TlsDHConfigVerifier dhConfigVerifier, TlsECConfigVerifier ecConfigVerifier,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentityManager pskIdentityManager, TlsDHConfig dhConfig, TlsECConfig ecConfig,
        short[] serverECPointFormats) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createRSAKeyExchange(Vector supportedSignatureAlgorithms) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsSRPConfigVerifier srpConfigVerifier, byte[] identity, byte[] password) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        byte[] identity, TlsSRPLoginParameters loginParameters) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
