package org.bouncycastle.tls.test;

import java.util.Random;
import java.util.Vector;

import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsUtils;

import junit.framework.TestCase;

public class TlsUtilsTest
    extends TestCase
{
    public void testChooseSignatureAndHash()
        throws Exception
    {
        int keyExchangeAlgorithm = KeyExchangeAlgorithm.ECDHE_RSA;
        short signatureAlgorithm = TlsUtils.getLegacySignatureAlgorithmServer(keyExchangeAlgorithm);

        Vector supportedSignatureAlgorithms = getSignatureAlgorithms(false);
        SignatureAndHashAlgorithm sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(ProtocolVersion.TLSv12,
            supportedSignatureAlgorithms, signatureAlgorithm);
        assertEquals(HashAlgorithm.sha256, sigAlg.getHash());

        for (int count = 0; count < 10; ++count)
        {
            supportedSignatureAlgorithms = getSignatureAlgorithms(true);
            sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(ProtocolVersion.TLSv12, supportedSignatureAlgorithms,
                signatureAlgorithm);
            assertEquals(HashAlgorithm.sha256, sigAlg.getHash());
        }
    }

    private static Vector getSignatureAlgorithms(boolean randomise)
    {
        short[] hashAlgorithms = new short[]{ HashAlgorithm.sha1, HashAlgorithm.sha224, HashAlgorithm.sha256,
            HashAlgorithm.sha384, HashAlgorithm.sha512, HashAlgorithm.md5 };
        short[] signatureAlgorithms = new short[]{ SignatureAlgorithm.rsa, SignatureAlgorithm.dsa,
            SignatureAlgorithm.ecdsa };

        Vector result = new Vector();
        for (int i = 0; i < signatureAlgorithms.length; ++i)
        {
            for (int j = 0; j < hashAlgorithms.length; ++j)
            {
                result.addElement(new SignatureAndHashAlgorithm(hashAlgorithms[j], signatureAlgorithms[i]));
            }
        }

        if (randomise)
        {
            Random r = new Random();
            int count = result.size();
            for (int src = 0; src < count; ++src)
            {
                int dst = r.nextInt(count);
                if (src != dst)
                {
                    Object a = result.elementAt(src), b = result.elementAt(dst);
                    result.setElementAt(a, dst);
                    result.setElementAt(b, src);
                }
            }
        }

        return result;
    }
}
