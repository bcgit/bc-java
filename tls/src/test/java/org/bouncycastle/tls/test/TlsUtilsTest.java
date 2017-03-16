package org.bouncycastle.tls.test;

import java.util.Random;
import java.util.Vector;

import junit.framework.TestCase;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsServerContext;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;

public class TlsUtilsTest
    extends TestCase
{
    public void testChooseSignatureAndHash()
        throws Exception
    {
        int keyExchangeAlgorithm = KeyExchangeAlgorithm.ECDHE_RSA;

        TlsContext context = new TlsServerContext()
        {
            public TlsCrypto getCrypto()
            {
                return null;
            }

            public SecurityParameters getSecurityParameters()
            {
                return null;
            }

            public boolean isServer()
            {
                return false;
            }

            public ProtocolVersion getClientVersion()
            {
                return null;
            }

            public ProtocolVersion getServerVersion()
            {
                return ProtocolVersion.TLSv12;
            }

            public TlsSession getResumableSession()
            {
                return null;
            }

            public TlsSession getSession()
            {
                return null;
            }

            public Object getUserObject()
            {
                throw new UnsupportedOperationException();
            }

            public void setUserObject(Object userObject)
            {
                throw new UnsupportedOperationException();
            }

            public byte[] exportChannelBinding(int channelBinding)
            {
                throw new UnsupportedOperationException();
            }

            public byte[] exportKeyingMaterial(String asciiLabel, byte[] context_value, int length)
            {
                throw new UnsupportedOperationException();
            }
        };

        short signatureAlgorithm = TlsUtils.getSignatureAlgorithm(keyExchangeAlgorithm);
        Vector supportedSignatureAlgorithms = getSignatureAlgorithms(false);

        SignatureAndHashAlgorithm sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context,
                          supportedSignatureAlgorithms, signatureAlgorithm);

        assertEquals(HashAlgorithm.sha256, sigAlg.getHash());

        supportedSignatureAlgorithms = getSignatureAlgorithms(true);
        sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context,
                                  supportedSignatureAlgorithms, signatureAlgorithm);

        assertEquals(HashAlgorithm.sha256, sigAlg.getHash());

        supportedSignatureAlgorithms = getSignatureAlgorithms(true);
        sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context,
                                  supportedSignatureAlgorithms, signatureAlgorithm);

        assertEquals(HashAlgorithm.sha256, sigAlg.getHash());
    }

    private static Vector getSignatureAlgorithms(boolean randomise)
    {
        short[] hashAlgorithms = new short[]{ HashAlgorithm.sha1, HashAlgorithm.sha224, HashAlgorithm.sha256,
            HashAlgorithm.sha384, HashAlgorithm.sha512, HashAlgorithm.md5 };
        short[] signatureAlgorithms = new short[]{ SignatureAlgorithm.rsa, SignatureAlgorithm.dsa,
            SignatureAlgorithm.ecdsa };

        Vector result = new Vector();

        int hOffset = (randomise) ? new Random().nextInt() & 0xff : 0;
        int sOffset = (randomise) ? new Random().nextInt() & 0xff : 0;
        for (int i = 0; i < signatureAlgorithms.length; ++i)
        {
            for (int j = 0; j < hashAlgorithms.length; ++j)
            {
                result.addElement(new SignatureAndHashAlgorithm(
                    hashAlgorithms[(hOffset + j) % hashAlgorithms.length],
                    signatureAlgorithms[(sOffset + i) % signatureAlgorithms.length]));
            }
        }
        return result;
    }

}
