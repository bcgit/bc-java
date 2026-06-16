package org.bouncycastle.jce.provider.test;

import java.io.IOException;
import java.security.Security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Confirms that BouncyCastleProvider.getPublicKey / getPrivateKey honour their declared IOException
 * contract when handed a structurally malformed SubjectPublicKeyInfo / PrivateKeyInfo decoded from
 * untrusted input: a key-info converter must not leak a RuntimeException (NullPointerException,
 * ArrayIndexOutOfBoundsException, ...) out of these helpers. A converter may also legitimately
 * return null or a key for degenerate input; only an escaping RuntimeException is a failure.
 */
public class MalformedKeyInfoTest
    extends SimpleTest
{
    // a spread of registered converters fed empty/short, no-parameter key material
    private static final ASN1ObjectIdentifier[] OIDS = new ASN1ObjectIdentifier[]
    {
        new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"),   // rsaEncryption
        new ASN1ObjectIdentifier("1.2.840.10045.2.1"),      // id-ecPublicKey
        new ASN1ObjectIdentifier("1.2.840.10040.4.1"),      // id-dsa
        new ASN1ObjectIdentifier("1.2.840.113549.1.1.10"),  // id-RSASSA-PSS
        new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6.34"),     // id-alg-xmss-hashsig (RFC 9802)
    };

    public String getName()
    {
        return "MalformedKeyInfo";
    }

    public void performTest()
        throws Exception
    {
        for (int i = 0; i != OIDS.length; i++)
        {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(OIDS[i]);

            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, new byte[0]);
            try
            {
                BouncyCastleProvider.getPublicKey(spki);
            }
            catch (IOException e)
            {
                // expected/acceptable — failure surfaces as the declared IOException
            }
            catch (RuntimeException e)
            {
                fail("RuntimeException " + e.getClass().getName() + " leaked from getPublicKey for " + OIDS[i]);
            }

            PrivateKeyInfo pki = new PrivateKeyInfo(algId, new DEROctetString(new byte[0]));
            try
            {
                BouncyCastleProvider.getPrivateKey(pki);
            }
            catch (IOException e)
            {
                // expected/acceptable
            }
            catch (RuntimeException e)
            {
                fail("RuntimeException " + e.getClass().getName() + " leaked from getPrivateKey for " + OIDS[i]);
            }
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new MalformedKeyInfoTest());
    }
}
