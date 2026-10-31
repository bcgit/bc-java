package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Provider;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSAuthEnvelopedDataParser;
import org.bouncycastle.cms.CMSAuthEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSAuthenticatedData;
import org.bouncycastle.cms.CMSAuthenticatedDataParser;
import org.bouncycastle.cms.CMSAuthenticatedDataStreamGenerator;
import org.bouncycastle.cms.CMSCompressedDataParser;
import org.bouncycastle.cms.CMSEncryptedData;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.tsp.cms.CMSTimeStampedDataParser;
import org.bouncycastle.util.encoders.Hex;

/**
 * Malformed CMS content - an absent, empty or truncated inner SEQUENCE, a mandatory field of the
 * wrong type, encapsulated content left out, a field whose encoding does not decode - has to
 * surface from the CMS containers and their streaming parsers as the checked exceptions they
 * declare, never as an unchecked NoSuchElementException / ArrayIndexOutOfBoundsException /
 * NullPointerException / ClassCastException / IllegalStateException.
 */
public class CMSMalformedContentTest
    extends TestCase
{
    private static final ASN1ObjectIdentifier DATA = CMSObjectIdentifiers.data;
    private static final AlgorithmIdentifier AES_CBC =
        new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.2"));
    private static final AlgorithmIdentifier SHA256 =
        new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));
    private static final AlgorithmIdentifier ZLIB = new AlgorithmIdentifier(CMSObjectIdentifiers.zlibCompress);

    private static final DigestCalculatorProvider DIGESTS = new BcDigestCalculatorProvider();

    // a malformed primitive BIT STRING (pad bits 9) and a constructed one holding an empty segment
    private static final String[] BAD_BIT_STRINGS = new String[]{ "03020900", "2380030000000000" };
    private static final String SIGNED_DATA_HEX = "06092a864886f70d010702";
    private static final String DATA_HEX = "06092a864886f70d010701";
    private static final String AES_CBC_HEX = "300b0609608648016503040102";
    private static final String EMPTY_SET_HEX = "31800000";
    private static final String BER_ENCAP_HEX = "3080" + DATA_HEX + "0000";

    private interface Parse
    {
        void run(byte[] encoding)
            throws Exception;
    }

    private static final Parse SIGNED = new Parse()
    {
        public void run(byte[] encoding)
            throws Exception
        {
            new CMSSignedData(encoding);
        }
    };

    private static final Parse SIGNED_PARSER = new Parse()
    {
        public void run(byte[] encoding)
            throws Exception
        {
            CMSSignedDataParser sp = new CMSSignedDataParser(DIGESTS, encoding);
            CMSTypedStream content = sp.getSignedContent();
            if (content != null)
            {
                content.drain();
            }
            sp.getSignerInfos();
        }
    };

    private static final Parse ENVELOPED = new Parse()
    {
        public void run(byte[] encoding)
            throws Exception
        {
            new CMSEnvelopedData(encoding);
        }
    };

    private static final Parse ENVELOPED_PARSER = new Parse()
    {
        public void run(byte[] encoding)
            throws Exception
        {
            new CMSEnvelopedDataParser(encoding);
        }
    };

    private static final Parse AUTHENTICATED = new Parse()
    {
        public void run(byte[] encoding)
            throws Exception
        {
            new CMSAuthenticatedData(encoding);
        }
    };

    private static final Parse AUTHENTICATED_PARSER = new Parse()
    {
        public void run(byte[] encoding)
            throws Exception
        {
            new CMSAuthenticatedDataParser(encoding, DIGESTS);
        }
    };

    private static final Parse AUTH_ENVELOPED = new Parse()
    {
        public void run(byte[] encoding)
            throws Exception
        {
            new CMSAuthEnvelopedData(encoding);
        }
    };

    private static final Parse AUTH_ENVELOPED_PARSER = new Parse()
    {
        public void run(byte[] encoding)
            throws Exception
        {
            new CMSAuthEnvelopedDataParser(encoding);
        }
    };

    private static final Parse TIME_STAMPED_PARSER = new Parse()
    {
        public void run(byte[] encoding)
            throws Exception
        {
            new CMSTimeStampedDataParser(encoding).getTimeStampTokens();
        }
    };

    private static final Parse COMPRESSED_PARSER = new Parse()
    {
        public void run(byte[] encoding)
            throws Exception
        {
            new CMSCompressedDataParser(new ByteArrayInputStream(encoding)).getContent(new ZlibExpanderProvider());
        }
    };

    public void testSignedData()
        throws Exception
    {
        ASN1ObjectIdentifier type = CMSObjectIdentifiers.signedData;
        Parse[] parsers = new Parse[]{ SIGNED, SIGNED_PARSER };

        expectRejected("no content", parsers, noContent(type));
        expectRejected("empty", parsers, contentInfo(type, new ASN1Encodable[0]));
        expectRejected("version only", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(1) }));
        expectRejected("no encapContentInfo", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(1), new DERSet(SHA256) }));
        expectRejected("no signerInfos", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(1), new DERSet(SHA256), new ContentInfo(DATA, null) }));
        expectRejected("digestAlgorithms not a SET", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(1), new ASN1Integer(2), new ContentInfo(DATA, null), new DERSet() }));
        expectRejected("encapContentInfo not a SEQUENCE", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(1), new DERSet(SHA256), new ASN1Integer(2), new DERSet() }));
        expectRejected("signerInfos not a SET", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(1), new DERSet(SHA256), new ContentInfo(DATA, null), new ASN1Integer(2) }));

        // indefinite-length SignedData whose fields hold a malformed primitive / constructed BIT STRING
        for (int i = 0; i != BAD_BIT_STRINGS.length; i++)
        {
            String bad = BAD_BIT_STRINGS[i];
            expectRejected("bad BIT STRING in certificates " + i, parsers, berContentInfo(SIGNED_DATA_HEX,
                "020101" + EMPTY_SET_HEX + BER_ENCAP_HEX + "a080" + bad + "0000" + EMPTY_SET_HEX));
            expectRejected("bad BIT STRING in digestAlgorithms " + i, parsers, berContentInfo(SIGNED_DATA_HEX,
                "020101" + "3180" + bad + "0000" + BER_ENCAP_HEX + EMPTY_SET_HEX));
        }
    }

    public void testEnvelopedData()
        throws Exception
    {
        ASN1ObjectIdentifier type = CMSObjectIdentifiers.envelopedData;
        Parse[] parsers = new Parse[]{ ENVELOPED, ENVELOPED_PARSER };

        expectRejected("no content", parsers, noContent(type));
        expectRejected("empty", parsers, contentInfo(type, new ASN1Encodable[0]));
        expectRejected("version only", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0) }));
        expectRejected("no encryptedContentInfo", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos() }));
        expectRejected("originatorInfo then truncated", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), originatorInfo(), recipientInfos() }));
        expectRejected("recipientInfos not a SET", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), new ASN1Integer(1), encryptedContentInfo(true) }));
        expectRejected("encryptedContentInfo truncated", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos(), new DERSequence(DATA) }));

        // encryptedContent is OPTIONAL in the ASN.1 but there is nothing to decrypt without it
        expectMissingContent("no encryptedContent", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos(), encryptedContentInfo(false) }));

        for (int i = 0; i != BAD_BIT_STRINGS.length; i++)
        {
            expectRejected("bad BIT STRING in recipientInfos " + i, parsers, berContentInfo("06092a864886f70d010703",
                "020100" + "3180" + BAD_BIT_STRINGS[i] + "0000" + "3080" + DATA_HEX + AES_CBC_HEX + "8001ff" + "0000"));
        }
    }

    public void testAuthenticatedData()
        throws Exception
    {
        ASN1ObjectIdentifier type = CMSObjectIdentifiers.authenticatedData;
        Parse[] parsers = new Parse[]{ AUTHENTICATED, AUTHENTICATED_PARSER };

        expectRejected("no content", parsers, noContent(type));
        expectRejected("empty", parsers, contentInfo(type, new ASN1Encodable[0]));
        expectRejected("version only", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0) }));
        expectRejected("no macAlgorithm", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos() }));
        expectRejected("no encapContentInfo", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos(), AES_CBC }));
        expectRejected("no mac", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos(), AES_CBC, encapContentInfo() }));
        expectRejected("originatorInfo then truncated", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), originatorInfo(), recipientInfos(), AES_CBC }));
        expectRejected("digestAlgorithm then truncated", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), originatorInfo(), recipientInfos(), AES_CBC,
            new DERTaggedObject(false, 1, SHA256) }));
        expectRejected("macAlgorithm not a SEQUENCE", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos(), new ASN1Integer(1), encapContentInfo(), mac() }));
        expectRejected("encapContentInfo not a SEQUENCE", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos(), AES_CBC, new ASN1Integer(1), mac() }));

        expectMissingContent("no eContent", new Parse[]{ AUTHENTICATED_PARSER }, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos(), AES_CBC, new ContentInfo(DATA, null), mac() }));

        for (int i = 0; i != BAD_BIT_STRINGS.length; i++)
        {
            expectRejected("bad BIT STRING in recipientInfos " + i, parsers, berContentInfo("060b2a864886f70d0109100102",
                "020100" + "3180" + BAD_BIT_STRINGS[i] + "0000" + AES_CBC_HEX + BER_ENCAP_HEX + "0400"));
        }
    }

    public void testTimeStampedData()
        throws Exception
    {
        String tsd = "060b2a864886f70d010910011f";
        Parse[] parsers = new Parse[]{ TIME_STAMPED_PARSER };

        expectRejected("wrong content type", parsers, berContentInfo(DATA_HEX, "020101"));
        expectRejected("no temporalEvidence", parsers, berContentInfo(tsd, "020101" + "0400"));
        for (int i = 0; i != BAD_BIT_STRINGS.length; i++)
        {
            expectRejected("bad BIT STRING in metaData " + i, parsers, berContentInfo(tsd,
                "020101" + "3080" + BAD_BIT_STRINGS[i] + "0000" + "0400" + "a0803080308000000000" + "0000"));
            expectRejected("bad BIT STRING in temporalEvidence " + i, parsers, berContentInfo(tsd,
                "020101" + "0400" + "a080" + BAD_BIT_STRINGS[i] + "0000"));
        }
    }

    /**
     * The attribute sets are only reached once the content has been read, so these are real messages
     * whose marker attribute value is patched after generation.
     */
    public void testMalformedAttributes()
        throws Exception
    {
        final Provider bc = new BouncyCastleProvider();
        final SecretKey kek = new SecretKeySpec(new byte[16], "AES");
        final byte[] kekId = new byte[]{ 1, 2, 3 };

        // Attribute { 1.2.3.4, SET { BIT STRING 5a5a5a } }
        String attr = "300d06032a0304" + "3106" + "0304005a5a5a";
        AttributeTable attrs = new AttributeTable(Attribute.getInstance(Hex.decode(attr)));

        byte[][] messages = new byte[5][];
        Parse[] parsers = new Parse[5];

        CMSEnvelopedDataStreamGenerator envGen = new CMSEnvelopedDataStreamGenerator();
        envGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(bc));
        envGen.setUnprotectedAttributeGenerator(new SimpleAttributeTableGenerator(attrs));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream out = envGen.open(bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(bc).build());
        out.write(new byte[20]);
        out.close();
        messages[0] = bOut.toByteArray();
        parsers[0] = new Parse()
        {
            public void run(byte[] encoding)
                throws Exception
            {
                CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(encoding);
                firstRecipient(ep.getRecipientInfos()).getContentStream(new JceKEKEnvelopedRecipient(kek).setProvider(bc)).drain();
                ep.getUnprotectedAttributes();
            }
        };

        for (int i = 0; i != 2; i++)
        {
            CMSAuthEnvelopedDataStreamGenerator authEnvGen = new CMSAuthEnvelopedDataStreamGenerator();
            authEnvGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(bc));
            if (i == 0)
            {
                authEnvGen.setAuthenticatedAttributeGenerator(new SimpleAttributeTableGenerator(attrs));
            }
            else
            {
                authEnvGen.setUnauthenticatedAttributeGenerator(new SimpleAttributeTableGenerator(attrs));
            }
            bOut = new ByteArrayOutputStream();
            out = authEnvGen.open(bOut, (OutputAEADEncryptor)new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM).setProvider(bc).build());
            out.write(new byte[20]);
            try
            {
                out.close();
            }
            catch (IOException e)
            {
                // a runtime without Cipher.updateAAD (pre-1.7) cannot generate authenticated attributes, so that case is skipped
                if (i == 0 && e.getMessage().startsWith("authenticated attributes require AEAD AAD support"))
                {
                    continue;
                }
                throw e;
            }
            messages[1 + i] = bOut.toByteArray();
            parsers[1 + i] = new Parse()
            {
                public void run(byte[] encoding)
                    throws Exception
                {
                    CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(encoding);
                    firstRecipient(ep.getRecipientInfos()).getContentStream(new JceKEKAuthEnvelopedRecipient(kek).setProvider(bc)).drain();
                    ep.getAuthAttrs();
                    ep.getMac();
                    ep.getUnauthAttrs();
                }
            };
        }

        for (int i = 0; i != 2; i++)
        {
            CMSAuthenticatedDataStreamGenerator authGen = new CMSAuthenticatedDataStreamGenerator();
            authGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(bc));
            if (i == 0)
            {
                authGen.setAuthenticatedAttributeGenerator(new SimpleAttributeTableGenerator(attrs));
            }
            else
            {
                authGen.setUnauthenticatedAttributeGenerator(new SimpleAttributeTableGenerator(attrs));
            }
            bOut = new ByteArrayOutputStream();
            out = authGen.open(bOut, new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(bc).build(),
                DIGESTS.get(SHA256));
            out.write(new byte[20]);
            out.close();
            messages[3 + i] = bOut.toByteArray();
            parsers[3 + i] = new Parse()
            {
                public void run(byte[] encoding)
                    throws Exception
                {
                    CMSAuthenticatedDataParser ap = new CMSAuthenticatedDataParser(encoding, DIGESTS);
                    firstRecipient(ap.getRecipientInfos()).getContentStream(new JceKEKAuthenticatedRecipient(kek).setProvider(bc)).drain();
                    ap.getAuthAttrs();
                    ap.getMac();
                    ap.getUnauthAttrs();
                }
            };
        }

        String[] labels = { "unprotectedAttrs", "AuthEnveloped authAttrs", "AuthEnveloped unauthAttrs",
            "Authenticated authAttrs", "Authenticated unauthAttrs" };
        for (int i = 0; i != messages.length; i++)
        {
            if (messages[i] == null)
            {
                continue;
            }

            String hex = Hex.toHexString(messages[i]);
            assertTrue(labels[i], hex.indexOf(attr) >= 0);

            // the unpatched message is the compatibility half
            parsers[i].run(messages[i]);

            Parse[] p = new Parse[]{ parsers[i] };
            expectRejected(labels[i] + ": bad BIT STRING in a value", p,
                Hex.decode(replace(hex, attr, "300d06032a0304" + "3106" + "0304095a5a5a")));
            expectRejected(labels[i] + ": element not an Attribute", p,
                Hex.decode(replace(hex, attr, "040d06032a0304" + "3106" + "0304005a5a5a")));
        }

        // getUnauthAttrs() has to read past the authenticated attributes and the mac itself
        CMSAuthEnvelopedDataParser aep = new CMSAuthEnvelopedDataParser(messages[2]);
        firstRecipient(aep.getRecipientInfos()).getContentStream(new JceKEKAuthEnvelopedRecipient(kek).setProvider(bc)).drain();
        assertNotNull(aep.getUnauthAttrs());
        assertNotNull(aep.getMac());

        CMSAuthenticatedDataParser ap = new CMSAuthenticatedDataParser(messages[4], DIGESTS);
        firstRecipient(ap.getRecipientInfos()).getContentStream(new JceKEKAuthenticatedRecipient(kek).setProvider(bc)).drain();
        assertNotNull(ap.getUnauthAttrs());
        assertNotNull(ap.getAuthAttrs());
        assertNotNull(ap.getMac());
    }

    private static RecipientInformation firstRecipient(RecipientInformationStore store)
    {
        return (RecipientInformation)store.getRecipients().iterator().next();
    }

    public void testAuthEnvelopedData()
        throws Exception
    {
        ASN1ObjectIdentifier type = CMSObjectIdentifiers.authEnvelopedData;
        Parse[] parsers = new Parse[]{ AUTH_ENVELOPED, AUTH_ENVELOPED_PARSER };

        expectRejected("no content", parsers, noContent(type));
        expectRejected("empty", parsers, contentInfo(type, new ASN1Encodable[0]));
        expectRejected("version only", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0) }));
        expectRejected("wrong version", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(1), recipientInfos(), encryptedContentInfo(true), mac() }));
        expectRejected("no authEncryptedContentInfo", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos() }));
        expectRejected("originatorInfo then truncated", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), originatorInfo(), recipientInfos(), encryptedContentInfo(true) }));
        expectRejected("recipientInfos not a SET", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), new ASN1Integer(1), encryptedContentInfo(true), mac() }));

        expectMissingContent("no encryptedContent", new Parse[]{ AUTH_ENVELOPED_PARSER }, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), recipientInfos(), encryptedContentInfo(false), mac() }));
    }

    public void testCompressedData()
        throws Exception
    {
        ASN1ObjectIdentifier type = CMSObjectIdentifiers.compressedData;
        Parse[] parsers = new Parse[]{ COMPRESSED_PARSER };

        expectRejected("no content", parsers, noContent(type));
        expectRejected("empty", parsers, contentInfo(type, new ASN1Encodable[0]));
        expectRejected("no compressionAlgorithm", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0) }));
        expectRejected("no encapContentInfo", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), ZLIB }));
        expectRejected("version not an INTEGER", parsers, contentInfo(type, new ASN1Encodable[]{
            ZLIB, ZLIB, encapContentInfo() }));
        expectRejected("encapContentInfo not a SEQUENCE", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), ZLIB, new ASN1Integer(1) }));

        expectMissingContent("no eContent", parsers, contentInfo(type, new ASN1Encodable[]{
            new ASN1Integer(0), ZLIB, new ContentInfo(DATA, null) }));
    }

    public void testEncryptedData()
        throws Exception
    {
        // CMSEncryptedData(ContentInfo) is documented to report malformed content as IllegalArgumentException
        ASN1Encodable[][] malformed = new ASN1Encodable[][]{
            new ASN1Encodable[0],
            new ASN1Encodable[]{ new ASN1Integer(0) }
        };

        for (int i = 0; i != malformed.length; i++)
        {
            try
            {
                new CMSEncryptedData(new ContentInfo(CMSObjectIdentifiers.encryptedData, new DERSequence(malformed[i])));
                fail("EncryptedData of size " + malformed[i].length + " not rejected");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
        }
    }

    // String.replace(CharSequence, CharSequence) is Java 5, and this test is compiled for the jdk1.4 distribution
    private static String replace(String s, String target, String replacement)
    {
        StringBuffer buf = new StringBuffer();
        int start = 0;
        int i;
        while ((i = s.indexOf(target, start)) >= 0)
        {
            buf.append(s.substring(start, i)).append(replacement);
            start = i + target.length();
        }
        return buf.append(s.substring(start)).toString();
    }

    private static void expectRejected(String label, Parse[] parsers, byte[] encoding)
    {
        for (int i = 0; i != parsers.length; i++)
        {
            try
            {
                parsers[i].run(encoding);
                fail(label + ": malformed content not rejected by parser " + i);
            }
            catch (CMSException e)
            {
                // expected
            }
            catch (IOException e)
            {
                // expected - the streaming parsers also declare IOException
            }
            catch (Exception e)
            {
                fail(label + ": parser " + i + " threw " + e);
            }
        }
    }

    private static void expectMissingContent(String label, Parse[] parsers, byte[] encoding)
    {
        for (int i = 0; i != parsers.length; i++)
        {
            try
            {
                parsers[i].run(encoding);
                fail(label + ": malformed content not rejected by parser " + i);
            }
            catch (CMSException e)
            {
                assertEquals(label + ": parser " + i, "Missing content.", e.getMessage());
            }
            catch (Exception e)
            {
                fail(label + ": parser " + i + " threw " + e);
            }
        }
    }

    private static byte[] noContent(ASN1ObjectIdentifier type)
        throws IOException
    {
        return new DERSequence(type).getEncoded();
    }

    /**
     * An indefinite-length ContentInfo, [0] and content SEQUENCE around the given hex fields.
     */
    private static byte[] berContentInfo(String typeHex, String fieldsHex)
    {
        return Hex.decode("3080" + typeHex + "a080" + "3080" + fieldsHex + "0000" + "0000" + "0000");
    }

    private static byte[] contentInfo(ASN1ObjectIdentifier type, ASN1Encodable[] fields)
        throws IOException
    {
        return new ContentInfo(type, new BERSequence(fields)).getEncoded();
    }

    private static DERSet recipientInfos()
    {
        return new DERSet(new DERSequence());
    }

    private static DERTaggedObject originatorInfo()
    {
        return new DERTaggedObject(false, 0, new DERSequence());
    }

    private static DERSequence encryptedContentInfo(boolean withContent)
    {
        if (withContent)
        {
            return new DERSequence(new ASN1Encodable[]{ DATA, AES_CBC,
                new DERTaggedObject(false, 0, new DEROctetString(new byte[16])) });
        }

        return new DERSequence(new ASN1Encodable[]{ DATA, AES_CBC });
    }

    private static ContentInfo encapContentInfo()
    {
        return new ContentInfo(DATA, new DEROctetString(new byte[3]));
    }

    private static DEROctetString mac()
    {
        return new DEROctetString(new byte[16]);
    }
}
