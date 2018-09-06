package org.bouncycastle.mime.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mime.BasicMimeParser;
import org.bouncycastle.mime.ConstantMimeContext;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeContext;
import org.bouncycastle.mime.MimeMultipartContext;
import org.bouncycastle.mime.MimeParser;
import org.bouncycastle.mime.MimeParserContext;
import org.bouncycastle.mime.MimeParserListener;
import org.bouncycastle.mime.MimeParserProvider;
import org.bouncycastle.mime.smime.SMimeParserListener;
import org.bouncycastle.mime.smime.SMimeParserProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/*
 This needs to be here to avoid issues with the 1.5 filter editing the html tags.
 */
public class MultipartParserTest
    extends TestCase
{

    protected void setUp()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    /**
     * Parse content header good.
     *
     * @throws Exception
     */
    public void testParseContentTypeHeader_wellformed()
        throws Exception
    {
        String value = "multipart/alternative;\n" +
            " boundary=\"Apple-Mail=_8B1F6ECB-9629-424B-B871-1357CCDBCC84\"";

        ArrayList values = new ArrayList();
        values.add("Content-type: " + value);

        Headers headers = new Headers(values, value);
        TestCase.assertEquals("multipart/alternative", headers.getContentType());
        Map fieldValues = headers.getContentTypeAttributes();
        TestCase.assertEquals(1, fieldValues.size());
        TestCase.assertEquals("{boundary=\"Apple-Mail=_8B1F6ECB-9629-424B-B871-1357CCDBCC84\"}", fieldValues.toString());
    }


    /**
     * Parse content header good.
     *
     * @throws Exception
     */
    public void testParseContentTypeHeader_wellformed_multi()
        throws Exception
    {
        String value = "multipart/signed;\n" +
            " boundary=\"Apple-Mail=_8B1F6ECB-9629-424B-B871-1357CCDBCC84\"; micalg=\"SHA1\"";

        ArrayList values = new ArrayList();
        values.add("Content-type: " + value);

        Headers headers = new Headers(values, value);
        TestCase.assertEquals("multipart/signed", headers.getContentType());
        Map fieldValues = headers.getContentTypeAttributes();
        TestCase.assertEquals(2, fieldValues.size());
        TestCase.assertEquals("{boundary=\"Apple-Mail=_8B1F6ECB-9629-424B-B871-1357CCDBCC84\", micalg=\"SHA1\"}", fieldValues.toString());
    }


    /**
     * Parse content header good.
     *
     * @throws Exception
     */
    public void testParseContentTypeHeader_broken()
        throws Exception
    {

        // Verify limit checking

        String value = "multipart/alternative;\n" +
            " boundary=\"cats\"; micalg=";

        ArrayList values = new ArrayList();
        values.add("Content-type: " + value);

        Headers headers = new Headers(values, value);
        TestCase.assertEquals("multipart/alternative", headers.getContentType());
        Map fieldValues = headers.getContentTypeAttributes();
        TestCase.assertEquals(2, fieldValues.size());
        TestCase.assertEquals("{boundary=\"cats\", micalg=}", fieldValues.toString());
    }

    /**
     * Parse content header good.
     *
     * @throws Exception
     */
    public void testParseContentTypeHeader_empty_micalg()
        throws Exception
    {

        // Verify limit checking

        String value = "multipart/alternative;\n" +
            " boundary=\"cats\"; micalg=\"\"";

        ArrayList values = new ArrayList();
        values.add("Content-type: " + value);

        Headers headers = new Headers(values, value);
        TestCase.assertEquals("multipart/alternative", headers.getContentType());
        Map fieldValues = headers.getContentTypeAttributes();
        TestCase.assertEquals(2, fieldValues.size());
        TestCase.assertEquals("{boundary=\"cats\", micalg=\"\"}", headers.getContentTypeAttributes().toString());
    }

    public void testSignedMultipart()
        throws Exception
    {
        final List results = new ArrayList();

        final TestDoneFlag dataParsed = new TestDoneFlag();

        MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

        MimeParser p = provider.createParser(this.getClass().getResourceAsStream("quotable.message"));

        p.parse(new SMimeParserListener()
        {
            public void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
                throws IOException
            {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                Streams.pipeAll((InputStream)inputStream, bos);
                results.add(bos.toString());
                System.out.println("#######################################################################");
                System.out.println(bos.toString());
                System.out.println("#######################################################################");
            }

            public void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
                throws CMSException
            {
                Collection c = signers.getSigners();
                Iterator it = c.iterator();

                while (it.hasNext())
                {
                    SignerInformation signer = (SignerInformation)it.next();
                    Collection certCollection = certificates.getMatches(signer.getSID());

                    Iterator certIt = certCollection.iterator();
                    X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

                    try
                    {
                        assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)));
                    }
                    catch (OperatorCreationException e)
                    {
                        e.printStackTrace();
                    }
                    catch (CertificateException e)
                    {
                        e.printStackTrace();
                    }
                }

                dataParsed.markDone();
            }

        });

        assertTrue(dataParsed.isDone());
    }

    public void testInvalidSha256SignedMultipart()
        throws Exception
    {
        final List results = new ArrayList();

        MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

        MimeParser p = provider.createParser(this.getClass().getResourceAsStream("3nnn_smime.eml"));

        p.parse(new SMimeParserListener()
        {
            public void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
                throws IOException
            {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                Streams.pipeAll((InputStream)inputStream, bos);
                results.add(bos.toString());
                System.out.println("#######################################################################");
                System.out.println(bos.toString());
                System.out.println("#######################################################################");
            }

            public void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
                throws CMSException
            {
                Collection c = signers.getSigners();
                Iterator it = c.iterator();

                while (it.hasNext())
                {
                    SignerInformation signer = (SignerInformation)it.next();
                    Collection certCollection = certificates.getMatches(signer.getSID());

                    Iterator certIt = certCollection.iterator();
                    X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

                    try
                    {
                        // in this case the signature is invalid
                        assertEquals(false, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)));
                    }
                    catch (OperatorCreationException e)
                    {
                        e.printStackTrace();
                    }
                    catch (CertificateException e)
                    {
                        e.printStackTrace();
                    }
                }
            }

        });
    }

    public void testEmbeddedMultipart()
        throws Exception
    {
        final List results = new ArrayList();

        MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

        MimeParser p = provider.createParser(this.getClass().getResourceAsStream("embeddedmulti.message"));

        p.parse(new SMimeParserListener()
        {
            public void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
                throws IOException
            {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                Streams.pipeAll((InputStream)inputStream, bos);
                results.add(bos.toString());
                System.out.println("#######################################################################");
                System.out.println(bos.toString());
                System.out.println("#######################################################################");
            }

            public void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
                throws CMSException
            {
                Collection c = signers.getSigners();
                Iterator it = c.iterator();

                while (it.hasNext())
                {
                    SignerInformation signer = (SignerInformation)it.next();
                    Collection certCollection = certificates.getMatches(signer.getSID());

                    Iterator certIt = certCollection.iterator();
                    X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

                    try
                    {
                        assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)));
                    }
                    catch (OperatorCreationException e)
                    {
                        e.printStackTrace();
                    }
                    catch (CertificateException e)
                    {
                        e.printStackTrace();
                    }
                }
            }

        });
    }

    public void testMultipartAlternative()
        throws Exception
    {
        final List results = new ArrayList();

        MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

        MimeParser p = provider.createParser(this.getClass().getResourceAsStream("multi-alternative.eml"));

        p.parse(new SMimeParserListener()
        {
            public void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
                throws IOException
            {

                MimeParser basicMimeParser = new BasicMimeParser(parserContext, headers, inputStream);

                basicMimeParser.parse(new MimeParserListener()
                {
                    public MimeContext createContext(MimeParserContext parserContext, Headers headers)
                    {
                        return new ConstantMimeContext();
                    }

                    public void object(MimeParserContext parserContext, Headers headers, InputStream inputStream)
                        throws IOException
                    {
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        Streams.pipeAll((InputStream)inputStream, bos);
                        results.add(bos.toString());
                        System.out.println("#######################################################################");
                        System.out.println(bos.toString());
                        System.out.println("#######################################################################");
                    }
                });
            }

            public void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
                throws CMSException
            {
                Collection c = signers.getSigners();
                Iterator it = c.iterator();

                while (it.hasNext())
                {
                    SignerInformation signer = (SignerInformation)it.next();
                    Collection certCollection = certificates.getMatches(signer.getSID());

                    Iterator certIt = certCollection.iterator();
                    X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

                    try
                    {
                        assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)));
                    }
                    catch (OperatorCreationException e)
                    {
                        e.printStackTrace();
                    }
                    catch (CertificateException e)
                    {
                        e.printStackTrace();
                    }
                }
            }

        });
    }

    /**
     * Happy path mime multipart test.
     *
     * @throws IOException
     */
    public void testMimeMultipart()
        throws Exception
    {
        final List results = new ArrayList();

        BasicMimeParser p = new BasicMimeParser(this.getClass().getResourceAsStream("simplemultipart.eml"));

        p.parse(new MimeParserListener()
        {
            public MimeContext createContext(MimeParserContext parserContext, Headers headers)
            {
                return new MimeMultipartContext()
                {
                    public InputStream applyContext(Headers headers, InputStream contentStream)
                        throws IOException
                    {
                        return contentStream;
                    }

                    public MimeContext createContext(int partNo)
                        throws IOException
                    {
                        return new MimeContext()
                        {
                            public InputStream applyContext(Headers headers, InputStream contentStream)
                                throws IOException
                            {
                                return contentStream;
                            }
                        };
                    }
                };
            }

            public void object(MimeParserContext parserContext, Headers headers, InputStream inputStream)
                throws IOException
            {
                results.add(Strings.fromByteArray(Streams.readAll(inputStream)));
            }
        });


        String[] expected = new String[]{
            "The cat sat on the mat\n" +
                "\n" +
                "Boo!\n" +
                "\n",
            "<html><head><meta http-equiv=\"Content-Type\" object=\"text/html; charset=us-ascii\"></head><object style=\"word-wrap: break-word; -webkit-nbsp-mode: space; line-break: after-white-space;\" class=\"\"><meta http-equiv=\"Content-Type\" object=\"text/html; charset=us-ascii\" class=\"\"><div style=\"word-wrap: break-word; -webkit-nbsp-mode: space; line-break: after-white-space;\" class=\"\">The cat sat on the mat<div class=\"\"><br class=\"\"></div><div class=\"\"><font size=\"7\" class=\"\">Boo!</font></div><div class=\"\"><font size=\"7\" class=\"\"><br class=\"\"></font></div><div class=\"\"><img src=\"http://img2.thejournal.ie/inline/1162441/original/?width=630&amp;version=1162441\" alt=\"Image result for cows\" class=\"\"></div></div></object></html>"
        };

        TestCase.assertEquals("Size same:", expected.length, results.size());

        for (int t = 0; t < results.size(); t++)
        {
            TestCase.assertEquals("Part: " + t, expected[t], results.get(t));
        }

    }



}
