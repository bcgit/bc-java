package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSAuthEnvelopedDataParser;
import org.bouncycastle.cms.CMSAuthenticatedData;
import org.bouncycastle.cms.CMSAuthenticatedDataParser;
import org.bouncycastle.cms.CMSCompressedDataParser;
import org.bouncycastle.cms.CMSEncryptedData;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

/**
 * Malformed but DER-parseable CMS content - an absent, empty or truncated inner SEQUENCE, a
 * mandatory field of the wrong type, encapsulated content left out - has to surface from the CMS
 * containers and their streaming parsers as the checked exceptions they declare, never as an
 * unchecked NoSuchElementException / ArrayIndexOutOfBoundsException / NullPointerException /
 * ClassCastException.
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
