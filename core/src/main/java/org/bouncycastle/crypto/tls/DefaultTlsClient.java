package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

public abstract class DefaultTlsClient
    extends AbstractTlsClient
{

    protected int[] namedCurves;
    protected short[] clientECPointFormats, serverECPointFormats;

    public DefaultTlsClient()
    {
        super();
    }

    public DefaultTlsClient(TlsCipherFactory cipherFactory)
    {
        super(cipherFactory);
    }

    public int[] getCipherSuites()
    {
        return new int[]{CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,};
    }

    public Hashtable getClientExtensions()
        throws IOException
    {

        Hashtable clientExtensions = super.getClientExtensions();

        if (TlsECCUtils.containsECCCipherSuites(getCipherSuites()))
        {
            /*
             * RFC 4492 5.1. A client that proposes ECC cipher suites in its ClientHello message
             * appends these extensions (along with any others), enumerating the curves it supports
             * and the point formats it can parse. Clients SHOULD send both the Supported Elliptic
             * Curves Extension and the Supported Point Formats Extension.
             */
            /*
             * TODO Could just add all the curves since we support them all, but users may not want
             * to use unnecessarily large fields. Need configuration options.
             */
            this.namedCurves = new int[]{NamedCurve.secp256r1, NamedCurve.sect233r1, NamedCurve.secp224r1,
                NamedCurve.sect193r1, NamedCurve.secp192r1, NamedCurve.arbitrary_explicit_char2_curves,
                NamedCurve.arbitrary_explicit_prime_curves};
            this.clientECPointFormats = new short[]{ECPointFormat.ansiX962_compressed_char2,
                ECPointFormat.ansiX962_compressed_prime, ECPointFormat.uncompressed};

            if (clientExtensions == null)
            {
                clientExtensions = new Hashtable();
            }

            TlsECCUtils.addSupportedEllipticCurvesExtension(clientExtensions, namedCurves);
            TlsECCUtils.addSupportedPointFormatsExtension(clientExtensions, clientECPointFormats);
        }

        return clientExtensions;
    }

    public void processServerExtensions(Hashtable serverExtensions)
        throws IOException
    {

        super.processServerExtensions(serverExtensions);

        if (serverExtensions != null)
        {
            int[] namedCurves = TlsECCUtils.getSupportedEllipticCurvesExtension(serverExtensions);
            if (namedCurves != null)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            this.serverECPointFormats = TlsECCUtils.getSupportedPointFormatsExtension(serverExtensions);
            if (this.serverECPointFormats != null && !TlsECCUtils.isECCCipherSuite(this.selectedCipherSuite))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
    }

    public TlsKeyExchange getKeyExchange()
        throws IOException
    {

        switch (selectedCipherSuite)
        {
        case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
            return createDHKeyExchange(KeyExchangeAlgorithm.DH_DSS);

        case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
            return createDHKeyExchange(KeyExchangeAlgorithm.DH_RSA);

        case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
            return createDHEKeyExchange(KeyExchangeAlgorithm.DHE_DSS);

        case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
            return createDHEKeyExchange(KeyExchangeAlgorithm.DHE_RSA);

        case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
            return createECDHKeyExchange(KeyExchangeAlgorithm.ECDH_ECDSA);

        case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
            return createECDHKeyExchange(KeyExchangeAlgorithm.ECDH_RSA);

        case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
            return createECDHEKeyExchange(KeyExchangeAlgorithm.ECDHE_ECDSA);

        case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
            return createECDHEKeyExchange(KeyExchangeAlgorithm.ECDHE_RSA);

        case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_NULL_MD5:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
        case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
        case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
            return createRSAKeyExchange();

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsCipher getCipher()
        throws IOException
    {

        switch (selectedCipherSuite)
        {
        case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm._3DES_EDE_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_128_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_128_CBC, MACAlgorithm.hmac_sha256);

        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_128_GCM, MACAlgorithm._null);

        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha256);

        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha384);

        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_256_GCM, MACAlgorithm._null);

        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.CAMELLIA_128_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.CAMELLIA_256_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_RSA_WITH_NULL_MD5:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.NULL, MACAlgorithm.hmac_md5);

        case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.NULL, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.NULL, MACAlgorithm.hmac_sha256);

        case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.RC4_128, MACAlgorithm.hmac_md5);

        case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
        case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.RC4_128, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.SEED_CBC, MACAlgorithm.hmac_sha1);

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsKeyExchange createDHKeyExchange(int keyExchange)
    {
        return new TlsDHKeyExchange(keyExchange, supportedSignatureAlgorithms, null);
    }

    protected TlsKeyExchange createDHEKeyExchange(int keyExchange)
    {
        return new TlsDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, null);
    }

    protected TlsKeyExchange createECDHKeyExchange(int keyExchange)
    {
        return new TlsECDHKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats,
            serverECPointFormats);
    }

    protected TlsKeyExchange createECDHEKeyExchange(int keyExchange)
    {
        return new TlsECDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats,
            serverECPointFormats);
    }

    protected TlsKeyExchange createRSAKeyExchange()
    {
        return new TlsRSAKeyExchange(supportedSignatureAlgorithms);
    }
}
