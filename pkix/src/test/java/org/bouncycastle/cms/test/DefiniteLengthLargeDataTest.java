package org.bouncycastle.cms.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAuthEnvelopedDataParser;
import org.bouncycastle.cms.CMSAuthEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Stress tests for the definite-length CMS stream generators with gigabyte
 * content (github #1482). Disabled by default — each test moves multiple
 * gigabytes — enable with {@code -Dbc.test.largedata=true}; the content size
 * can be overridden for debugging with
 * {@code -Dbc.test.largedata.size=<octets>}.
 *
 * <p>The round-trip tests pipe output straight into the corresponding
 * streaming parser on a second thread, so nothing is ever held in memory: the
 * producer writes a deterministic pattern, the consumer regenerates and
 * compares it octet for octet and verifies the recovered signatures /
 * decryption — at a content size just past the {@code byte[]} limit,
 * exercising the streaming parser's long definite-length support end to end.
 * {@link #testGenerationBeyondArrayLimit()} additionally checks the outer TLV
 * header and total octet count by hand, independent of the parser.</p>
 */
public class DefiniteLengthLargeDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final int BLOCK = 8192;
    private static final byte[] PATTERN = makePattern();

    private static boolean initialised = false;
    private static KeyPair signKP;
    private static X509Certificate signCert;
    private static KeyPair reciKP;
    private static X509Certificate reciCert;

    private static byte[] makePattern()
    {
        byte[] block = new byte[BLOCK];
        long x = 0x0123456789ABCDEFL;
        for (int i = 0; i != block.length; i++)
        {
            x = x * 6364136223846793005L + 1442695040888963407L;
            block[i] = (byte)(x >>> 56);
        }
        return block;
    }

    private static boolean enabled()
    {
        return "true".equals(System.getProperty("bc.test.largedata"));
    }

    private static long contentLength()
    {
        String override = System.getProperty("bc.test.largedata.size");
        if (override != null)
        {
            return Long.parseLong(override);
        }
        return (1L << 31) + 12345;      // just past the byte[] limit
    }

    private static long beyondArrayLength()
    {
        return contentLength();
    }

    public void setUp()
        throws Exception
    {
        if (!enabled() || initialised)
        {
            return;
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        signKP = CMSTestUtil.makeKeyPair();
        signCert = CMSTestUtil.makeCertificate(signKP, "O=Bouncy Castle, C=AU", signKP, "O=Bouncy Castle, C=AU");
        reciKP = CMSTestUtil.makeKeyPair();
        reciCert = CMSTestUtil.makeCertificate(reciKP, "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU", signKP, "O=Bouncy Castle, C=AU");
        initialised = true;
    }

    private static void writePattern(OutputStream out, long length)
        throws IOException
    {
        long remaining = length;
        while (remaining > 0)
        {
            int n = (int)Math.min(BLOCK, remaining);
            out.write(PATTERN, 0, n);
            remaining -= n;
        }
    }

    private static long drainAndCompare(InputStream in)
        throws IOException
    {
        byte[] buf = new byte[BLOCK];
        long total = 0;
        int patternOff = 0;
        int read;
        while ((read = in.read(buf)) >= 0)
        {
            for (int i = 0; i != read; i++)
            {
                if (buf[i] != PATTERN[patternOff])
                {
                    throw new IOException("content mismatch at octet " + (total + i));
                }
                patternOff = (patternOff + 1) % BLOCK;
            }
            total += read;
        }
        return total;
    }

    private interface Producer
    {
        void produce(OutputStream out)
            throws Exception;
    }

    /**
     * Run producer on a worker thread writing into a pipe read by the caller.
     */
    private InputStream piped(final Producer producer)
        throws IOException
    {
        final PipedOutputStream pOut = new PipedOutputStream();
        PipedInputStream pIn = new PipedInputStream(pOut, 1 << 20);

        Thread writer = new Thread(new Runnable()
        {
            public void run()
            {
                try
                {
                    producer.produce(pOut);
                    pOut.close();
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                    try
                    {
                        pOut.close();   // unblocks the reader, which then fails
                    }
                    catch (IOException ignored)
                    {
                    }
                }
            }
        }, "large-data-producer");
        writer.setDaemon(true);
        writer.start();

        return pIn;
    }

    public void testEnvelopedSinglePassLargeData()
        throws Exception
    {
        if (!enabled())
        {
            return;
        }

        final long length = contentLength();

        InputStream cmsIn = piped(new Producer()
        {
            public void produce(OutputStream out)
                throws Exception
            {
                CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
                edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(reciCert).setProvider(BC));
                edGen.setEncoding("DER");

                OutputStream env = edGen.open(out, length,
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM).setProvider(BC).build());
                writePattern(env, length);
                env.close();
            }
        });

        CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(cmsIn);
        RecipientInformation recipient = (RecipientInformation)ep.getRecipientInfos().getRecipients().iterator().next();
        long recovered = drainAndCompare(recipient.getContentStream(
            new JceKeyTransEnvelopedRecipient(reciKP.getPrivate()).setProvider(BC)).getContentStream());
        assertEquals(length, recovered);
        ep.close();
    }

    public void testAuthEnvelopedSinglePassLargeData()
        throws Exception
    {
        if (!enabled())
        {
            return;
        }

        final long length = contentLength();

        InputStream cmsIn = piped(new Producer()
        {
            public void produce(OutputStream out)
                throws Exception
            {
                CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();
                edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(reciCert).setProvider(BC));
                edGen.setEncoding("DER");

                OutputStream env = edGen.open(out, length,
                    (OutputAEADEncryptor)new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM).setProvider(BC).build());
                writePattern(env, length);
                env.close();
            }
        });

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(cmsIn);
        RecipientInformation recipient = (RecipientInformation)ep.getRecipientInfos().getRecipients().iterator().next();
        long recovered = drainAndCompare(recipient.getContentStream(
            new JceKeyTransAuthEnvelopedRecipient(reciKP.getPrivate()).setProvider(BC)).getContentStream());
        assertEquals(length, recovered);
    }

    public void testSignedSinglePassLargeData()
        throws Exception
    {
        if (!enabled())
        {
            return;
        }

        final long length = contentLength();

        InputStream cmsIn = piped(new Producer()
        {
            public void produce(OutputStream out)
                throws Exception
            {
                CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
                ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
                gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(signer, signCert));
                gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
                gen.setEncoding("DER");

                OutputStream sigOut = gen.open(out, length);
                writePattern(sigOut, length);
                sigOut.close();
            }
        });

        checkSignedContent(cmsIn, length);
    }

    public void testSignedTwoPassLargeData()
        throws Exception
    {
        if (!enabled())
        {
            return;
        }

        final long length = contentLength();

        InputStream cmsIn = piped(new Producer()
        {
            public void produce(OutputStream out)
                throws Exception
            {
                CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
                // ECDSA: variable-length signatures, the case needing two passes
                KeyPair ecKP = CMSTestUtil.makeEcDsaKeyPair();
                X509Certificate ecCert = CMSTestUtil.makeCertificate(ecKP, "O=Bouncy Castle, C=AU", signKP, "O=Bouncy Castle, C=AU");
                ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(ecKP.getPrivate());
                gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(signer, ecCert));
                gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(ecCert)));
                gen.setEncoding("DER");

                gen.generate(new CMSTypedData()
                {
                    public ASN1ObjectIdentifier getContentType()
                    {
                        return CMSObjectIdentifiers.data;
                    }

                    public Object getContent()
                    {
                        return null;    // streamed only
                    }

                    public void write(OutputStream cOut)
                        throws IOException, CMSException
                    {
                        writePattern(cOut, length);
                    }
                }, out);
            }
        });

        checkSignedContent(cmsIn, length);
    }

    /**
     * Generation past the byte[] limit: BC's ASN.1 parsers cannot yet read
     * definite lengths beyond 31 bits, so the round trip stops just short of
     * 2 GiB - here the generators run beyond it and the output's outer TLV
     * header and total octet count are verified by hand. Completion without
     * exception also means every internal exact-length enforcement matched.
     */
    public void testGenerationBeyondArrayLimit()
        throws Exception
    {
        if (!enabled())
        {
            return;
        }

        final long length = beyondArrayLength();

        // enveloped, AES-GCM: encrypted content = length + 16 octet tag
        HeaderCheckingOutputStream envOut = new HeaderCheckingOutputStream();
        CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(reciCert).setProvider(BC));
        edGen.setEncoding("DER");
        OutputStream env = edGen.open(envOut, length,
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM).setProvider(BC).build());
        writePattern(env, length);
        env.close();
        envOut.checkOuterHeader();

        // signed, single pass, RSA
        HeaderCheckingOutputStream sigOut = new HeaderCheckingOutputStream();
        CMSSignedDataStreamGenerator sGen = new CMSSignedDataStreamGenerator();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        sGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(signer, signCert));
        sGen.setEncoding("DER");
        OutputStream sig = sGen.open(sigOut, length);
        writePattern(sig, length);
        sig.close();
        sigOut.checkOuterHeader();
    }

    /**
     * Counts everything written and captures the first octets, so the outer
     * SEQUENCE header's long-form definite length can be checked against the
     * actual output size.
     */
    private static class HeaderCheckingOutputStream
        extends OutputStream
    {
        private final byte[] head = new byte[16];
        private int headLen = 0;
        private long total = 0;

        public void write(int b)
        {
            if (headLen < head.length)
            {
                head[headLen++] = (byte)b;
            }
            total++;
        }

        public void write(byte[] buf, int off, int len)
        {
            int keep = Math.min(len, head.length - headLen);
            System.arraycopy(buf, off, head, headLen, keep);
            headLen += keep;
            total += len;
        }

        void checkOuterHeader()
        {
            assertEquals("outer tag", 0x30, head[0] & 0xFF);
            int lenOctet = head[1] & 0xFF;
            assertTrue("expected long-form length", (lenOctet & 0x80) != 0);
            int n = lenOctet & 0x7F;
            long declared = 0;
            for (int i = 0; i != n; i++)
            {
                declared = (declared << 8) | (head[2 + i] & 0xFF);
            }
            assertEquals("outer definite length", total - 2 - n, declared);
        }
    }

    private void checkSignedContent(InputStream cmsIn, long length)
        throws Exception
    {
        CMSSignedDataParser sp = new CMSSignedDataParser(
            new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), cmsIn);

        long recovered = drainAndCompare(sp.getSignedContent().getContentStream());
        assertEquals(length, recovered);

        Collection certCollection;
        Collection signers = sp.getSignerInfos().getSigners();
        org.bouncycastle.util.Store certStore = sp.getCertificates();

        for (Iterator it = signers.iterator(); it.hasNext(); )
        {
            SignerInformation signer = (SignerInformation)it.next();
            certCollection = certStore.getMatches(signer.getSID());
            org.bouncycastle.cert.X509CertificateHolder cert =
                (org.bouncycastle.cert.X509CertificateHolder)certCollection.iterator().next();

            assertTrue(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }

        sp.close();
    }
}
