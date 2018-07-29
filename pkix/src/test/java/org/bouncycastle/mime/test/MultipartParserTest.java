package org.bouncycastle.mime.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import junit.framework.TestCase;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
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

public class MultipartParserTest
    extends TestCase
{
//    /**
//     * Parse content header good.
//     *
//     * @throws Exception
//     */
//    public void testParseContentTypeHeader()
//        throws Exception
//    {
//
//        Map<String, List<String>> headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
//
//        ArrayList<String> values = new ArrayList<String>();
//        values.add("multipart/alternative;\n" +
//            " boundary=\"Apple-Mail=_8B1F6ECB-9629-424B-B871-1357CCDBCC84\"");
//
//        headers.put("Content-Type", values);
//
//        MimeUtils.ContentTypeInfo tinfo = MimeUtils.getContentTypeInfo(headers);
//
//        TestCase.assertEquals("multipart/alternative", tinfo.getName());
//        TestCase.assertEquals("Apple-Mail=_8B1F6ECB-9629-424B-B871-1357CCDBCC84", tinfo.getFields().get("boundary"));
//    }
//
//
//    public void testParseContentTypeHeaderSort()
//        throws Exception
//    {
//
//        Map<String, List<String>> headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
//
//        ArrayList<String> values = new ArrayList<String>();
//        values.add("text/plain");
//
//        headers.put("Content-Type", values);
//
//        MimeUtils.ContentTypeInfo tinfo = MimeUtils.getContentTypeInfo(headers);
//
//        TestCase.assertEquals("text/plain", tinfo.getName());
//        TestCase.assertEquals(0, tinfo.getFields().size());
//    }
//
//
//    public void testParseContentTypeNoHeader()
//        throws Exception
//    {
//
//        Map<String, List<String>> headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
//
//        ArrayList<String> values = new ArrayList<String>();
//
//        MimeUtils.ContentTypeInfo tinfo = MimeUtils.getContentTypeInfo(headers);
//
//        TestCase.assertNull(tinfo);
//    }
//
//
//    public void testParseContentTypeBroken()
//        throws Exception
//    {
//
//
//        //
//        // Semicolon only
//        //
//
//        {
//            // No name just a semicolon.
//            Map<String, List<String>> headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
//
//            ArrayList<String> values = new ArrayList<String>();
//            values.add(";");
//
//            headers.put("Content-Type", values);
//
//            MimeUtils.ContentTypeInfo tinfo = MimeUtils.getContentTypeInfo(headers);
//
//            TestCase.assertEquals("", tinfo.getName());
//            TestCase.assertEquals(0, tinfo.getFields().size());
//        }
//
//
//        {
//            // No field value
//            Map<String, List<String>> headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
//
//            ArrayList<String> values = new ArrayList<String>();
//            values.add("foo; cats=");
//
//            headers.put("Content-Type", values);
//
//            MimeUtils.ContentTypeInfo tinfo = MimeUtils.getContentTypeInfo(headers);
//
//            TestCase.assertEquals("foo", tinfo.getName());
//            TestCase.assertEquals("", tinfo.getFields().get("cats"));
//        }
//
//
//        {
//            // No equals
//            Map<String, List<String>> headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
//
//            ArrayList<String> values = new ArrayList<String>();
//            values.add("foo; cats");
//
//            headers.put("Content-Type", values);
//
//            MimeUtils.ContentTypeInfo tinfo = MimeUtils.getContentTypeInfo(headers);
//
//            TestCase.assertEquals("foo", tinfo.getName());
//            TestCase.assertNull(tinfo.getFields().get("cats")); // No = so no decode.
//        }
//
//
//        {
//            // Extra white space.
//            Map<String, List<String>> headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
//
//            ArrayList<String> values = new ArrayList<String>();
//            values.add("foo; cats\n=\nfish");
//
//            headers.put("Content-Type", values);
//
//            MimeUtils.ContentTypeInfo tinfo = MimeUtils.getContentTypeInfo(headers);
//
//            TestCase.assertEquals("foo", tinfo.getName());
//            TestCase.assertEquals("fish", tinfo.getFields().get("cats")); // No = so no decode.
//        }
//
//
//        {  // Just an equals not fieldName or value
//            Map<String, List<String>> headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
//
//            ArrayList<String> values = new ArrayList<String>();
//            values.add("foo;=");
//
//            headers.put("Content-Type", values);
//
//            MimeUtils.ContentTypeInfo tinfo = MimeUtils.getContentTypeInfo(headers);
//
//            TestCase.assertEquals("foo", tinfo.getName());
//            TestCase.assertEquals(0, tinfo.getFields().size());
//        }
//
//        { // Null value in map
//            Map<String, List<String>> headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
//            headers.put("Content-Type", null);
//            MimeUtils.ContentTypeInfo tinfo = MimeUtils.getContentTypeInfo(headers);
//            TestCase.assertNull(tinfo);
//        }
//
//    }

    
    public void testSignedMultipart()
        throws Exception
    {
        final ArrayList<Object> results = new ArrayList<Object>();

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

            @Override
            public void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
                throws CMSException
            {
                Collection c = signers.getSigners();
                Iterator it = c.iterator();

                while (it.hasNext())
                {
                    SignerInformation   signer = (SignerInformation)it.next();
                    Collection          certCollection = certificates.getMatches(signer.getSID());

                    Iterator        certIt = certCollection.iterator();
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

    public void testEmbeddedMultipart()
        throws Exception
    {
        final ArrayList<Object> results = new ArrayList<Object>();

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

            @Override
            public void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
                throws CMSException
            {
                Collection c = signers.getSigners();
                Iterator it = c.iterator();

                while (it.hasNext())
                {
                    SignerInformation   signer = (SignerInformation)it.next();
                    Collection          certCollection = certificates.getMatches(signer.getSID());

                    Iterator        certIt = certCollection.iterator();
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
        final ArrayList<Object> results = new ArrayList<Object>();

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
                    @Override
                    public MimeContext createContext(MimeParserContext parserContext, Headers headers)
                    {
                        return new ConstantMimeContext();
                    }

                    @Override
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

            @Override
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
        final ArrayList<Object> results = new ArrayList<Object>();

        BasicMimeParser p = new BasicMimeParser(this.getClass().getResourceAsStream("simplemultipart.eml"));

        p.parse(new MimeParserListener()
        {
            @Override
            public MimeContext createContext(MimeParserContext parserContext, Headers headers)
            {
                return new MimeMultipartContext()
                {

                    @Override
                    public InputStream applyContext(Headers headers, InputStream contentStream)
                        throws IOException
                    {
                        return contentStream;
                    }

                    @Override
                    public MimeContext createContext(int partNo)
                        throws IOException
                    {
                        return new MimeContext()
                        {
                            @Override
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
