package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.util.CRLFOutputStream;
import org.bouncycastle.util.Store;

/**
 * general class for generating a pkcs7-signature message.
 * <p>
 * A simple example of usage.
 *
 * <pre>
 *      X509Certificate signCert = ...
 *      KeyPair         signKP = ...
 *
 *      List certList = new ArrayList();
 *
 *      certList.add(signCert);
 *
 *      Store certs = new JcaCertStore(certList);
 *
 *      SMIMESignedGenerator gen = new SMIMESignedGenerator();
 *
 *      gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA1withRSA", signKP.getPrivate(), signCert));
 *
 *      gen.addCertificates(certs);
 *
 *      MimeMultipart       smime = fact.generate(content);
 * </pre>
 * <p>
 * Note 1: if you are using this class with AS2 or some other protocol
 * that does not use "7bit" as the default content transfer encoding you
 * will need to use the constructor that allows you to specify the default
 * content transfer encoding, such as "binary".
 * </p>
 * <p>
 * Note 2: between RFC 3851 and RFC 5751 the values used in the micalg parameter
 * for signed messages changed. We will accept both, but the default is now to use
 * RFC 5751. In the event you are dealing with an older style system you will also need
 * to use a constructor that sets the micalgs table and call it with RFC3851_MICALGS.
 * </p>
 */
public class SMIMESignedGenerator
    extends SMIMEGenerator
{
    public static final String  DIGEST_SHA1 = OIWObjectIdentifiers.idSHA1.getId();
    public static final String  DIGEST_MD5 = PKCSObjectIdentifiers.md5.getId();
    public static final String  DIGEST_SHA224 = NISTObjectIdentifiers.id_sha224.getId();
    public static final String  DIGEST_SHA256 = NISTObjectIdentifiers.id_sha256.getId();
    public static final String  DIGEST_SHA384 = NISTObjectIdentifiers.id_sha384.getId();
    public static final String  DIGEST_SHA512 = NISTObjectIdentifiers.id_sha512.getId();
    public static final String  DIGEST_GOST3411 = CryptoProObjectIdentifiers.gostR3411.getId();
    public static final String  DIGEST_RIPEMD128 = TeleTrusTObjectIdentifiers.ripemd128.getId();
    public static final String  DIGEST_RIPEMD160 = TeleTrusTObjectIdentifiers.ripemd160.getId();
    public static final String  DIGEST_RIPEMD256 = TeleTrusTObjectIdentifiers.ripemd256.getId();

    public static final String  ENCRYPTION_RSA = PKCSObjectIdentifiers.rsaEncryption.getId();
    public static final String  ENCRYPTION_DSA = X9ObjectIdentifiers.id_dsa_with_sha1.getId();
    public static final String  ENCRYPTION_ECDSA = X9ObjectIdentifiers.ecdsa_with_SHA1.getId();
    public static final String  ENCRYPTION_RSA_PSS = PKCSObjectIdentifiers.id_RSASSA_PSS.getId();
    public static final String  ENCRYPTION_GOST3410 = CryptoProObjectIdentifiers.gostR3410_94.getId();
    public static final String  ENCRYPTION_ECGOST3410 = CryptoProObjectIdentifiers.gostR3410_2001.getId();
    public static final String  ENCRYPTION_ECGOST3410_2012_256 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.getId();
    public static final String  ENCRYPTION_ECGOST3410_2012_512 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512.getId();

    private static final String CERTIFICATE_MANAGEMENT_CONTENT = "application/pkcs7-mime; name=smime.p7c; smime-type=certs-only";
    private static final String DETACHED_SIGNATURE_TYPE = "application/pkcs7-signature; name=smime.p7s; smime-type=signed-data";
    private static final String ENCAPSULATED_SIGNED_CONTENT_TYPE = "application/pkcs7-mime; name=smime.p7m; smime-type=signed-data";

    public static final Map RFC3851_MICALGS;
    public static final Map RFC5751_MICALGS;
    public static final Map STANDARD_MICALGS;

    static
    {
        AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                CommandMap commandMap = CommandMap.getDefaultCommandMap();

                if (commandMap instanceof MailcapCommandMap)
                {
                    CommandMap.setDefaultCommandMap(MailcapUtil.addCommands((MailcapCommandMap)commandMap));
                }

                return null;
            }
        });

        Map stdMicAlgs = new HashMap();

        stdMicAlgs.put(CMSAlgorithm.MD5, "md5");
        stdMicAlgs.put(CMSAlgorithm.SHA1, "sha-1");
        stdMicAlgs.put(CMSAlgorithm.SHA224, "sha-224");
        stdMicAlgs.put(CMSAlgorithm.SHA256, "sha-256");
        stdMicAlgs.put(CMSAlgorithm.SHA384, "sha-384");
        stdMicAlgs.put(CMSAlgorithm.SHA512, "sha-512");
        stdMicAlgs.put(CMSAlgorithm.GOST3411, "gostr3411-94");
        stdMicAlgs.put(CMSAlgorithm.GOST3411_2012_256, "gostr3411-2012-256");
        stdMicAlgs.put(CMSAlgorithm.GOST3411_2012_512, "gostr3411-2012-512");

        RFC5751_MICALGS = Collections.unmodifiableMap(stdMicAlgs);

        Map oldMicAlgs = new HashMap();

        oldMicAlgs.put(CMSAlgorithm.MD5, "md5");
        oldMicAlgs.put(CMSAlgorithm.SHA1, "sha1");
        oldMicAlgs.put(CMSAlgorithm.SHA224, "sha224");
        oldMicAlgs.put(CMSAlgorithm.SHA256, "sha256");
        oldMicAlgs.put(CMSAlgorithm.SHA384, "sha384");
        oldMicAlgs.put(CMSAlgorithm.SHA512, "sha512");
        oldMicAlgs.put(CMSAlgorithm.GOST3411, "gostr3411-94");
        oldMicAlgs.put(CMSAlgorithm.GOST3411_2012_256, "gostr3411-2012-256");
        oldMicAlgs.put(CMSAlgorithm.GOST3411_2012_512, "gostr3411-2012-512");

        RFC3851_MICALGS = Collections.unmodifiableMap(oldMicAlgs);

        STANDARD_MICALGS = RFC5751_MICALGS;
    }

    private final String defaultContentTransferEncoding;
    private final Map    micAlgs;

    private List                certStores = new ArrayList();
    private List                crlStores = new ArrayList();
    private List                attrCertStores = new ArrayList();
    private List                signerInfoGens = new ArrayList();
    private List                _signers = new ArrayList();
    private List                _oldSigners = new ArrayList();
    private Map                 _digests = new HashMap();

    /**
     * base constructor - default content transfer encoding 7bit
     */
    public SMIMESignedGenerator()
    {
        this("7bit", STANDARD_MICALGS);
    }

    /**
     * base constructor - default content transfer encoding explicitly set
     * 
     * @param defaultContentTransferEncoding new default to use.
     */
    public SMIMESignedGenerator(
        String defaultContentTransferEncoding)
    {
        this(defaultContentTransferEncoding, STANDARD_MICALGS);
    }

    /**
     * base constructor - default content transfer encoding explicitly set
     *
     * @param micAlgs a map of ANS1ObjectIdentifiers to strings hash algorithm names.
     */
    public SMIMESignedGenerator(
        Map micAlgs)
    {
        this("7bit", micAlgs);
    }

    /**
     * base constructor - default content transfer encoding explicitly set
     *
     * @param defaultContentTransferEncoding new default to use.
     * @param micAlgs a map of ANS1ObjectIdentifiers to strings hash algorithm names.
     */
    public SMIMESignedGenerator(
        String defaultContentTransferEncoding,
        Map micAlgs)
    {
        this.defaultContentTransferEncoding = defaultContentTransferEncoding;
        this.micAlgs = micAlgs;
    }

    /**
     * Add a store of precalculated signers to the generator.
     *
     * @param signerStore store of signers
     */
    public void addSigners(
        SignerInformationStore signerStore)
    {
        Iterator    it = signerStore.getSigners().iterator();

        while (it.hasNext())
        {
            _oldSigners.add(it.next());
        }
    }

    /**
     *
     * @param sigInfoGen
     */
    public void addSignerInfoGenerator(SignerInfoGenerator sigInfoGen)
    {
        signerInfoGens.add(sigInfoGen);
    }

    public void addCertificates(
        Store certStore)
    {
        certStores.add(certStore);
    }

    public void addCRLs(
        Store crlStore)
    {
        crlStores.add(crlStore);
    }

    public void addAttributeCertificates(
        Store certStore)
    {
        attrCertStores.add(certStore);
    }

    private void addHashHeader(
        StringBuffer header,
        List         signers)
    {
        int                 count = 0;
        
        //
        // build the hash header
        //
        Iterator   it = signers.iterator();
        Set        micAlgSet = new TreeSet();
        
        while (it.hasNext())
        {
            Object              signer = it.next();
            ASN1ObjectIdentifier digestOID;

            if (signer instanceof SignerInformation)
            {
                digestOID = ((SignerInformation)signer).getDigestAlgorithmID().getAlgorithm();
            }
            else
            {
                digestOID = ((SignerInfoGenerator)signer).getDigestAlgorithm().getAlgorithm();
            }

            String micAlg = (String)micAlgs.get(digestOID);

            if (micAlg == null)
            {
                micAlgSet.add("unknown");
            }
            else
            {
                micAlgSet.add(micAlg);
            }
        }
        
        it = micAlgSet.iterator();
        
        while (it.hasNext())
        {
            String    alg = (String)it.next();

            if (count == 0)
            {
                if (micAlgSet.size() != 1)
                {
                    header.append("; micalg=\"");
                }
                else
                {
                    header.append("; micalg=");
                }
            }
            else
            {
                header.append(',');
            }

            header.append(alg);

            count++;
        }

        if (count != 0)
        {
            if (micAlgSet.size() != 1)
            {
                header.append('\"');
            }
        }
    }

    private MimeMultipart make(
        MimeBodyPart    content)
    throws SMIMEException
    {
        try
        {
            MimeBodyPart sig = new MimeBodyPart();

            sig.setContent(new ContentSigner(content, false), DETACHED_SIGNATURE_TYPE);
            sig.addHeader("Content-Type", DETACHED_SIGNATURE_TYPE);
            sig.addHeader("Content-Disposition", "attachment; filename=\"smime.p7s\"");
            sig.addHeader("Content-Description", "S/MIME Cryptographic Signature");
            sig.addHeader("Content-Transfer-Encoding", encoding);

            //
            // build the multipart header
            //
            StringBuffer        header = new StringBuffer(
                    "signed; protocol=\"application/pkcs7-signature\"");

            List allSigners = new ArrayList(_signers);

            allSigners.addAll(_oldSigners);

            allSigners.addAll(signerInfoGens);

            addHashHeader(header, allSigners);

            MimeMultipart   mm = new MimeMultipart(header.toString());

            mm.addBodyPart(content);
            mm.addBodyPart(sig);

            return mm;
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting multi-part together.", e);
        }
    }

    /*
     * at this point we expect our body part to be well defined - generate with data in the signature
     */
    private MimeBodyPart makeEncapsulated(
        MimeBodyPart    content)
        throws SMIMEException
    {
        try
        {
            MimeBodyPart sig = new MimeBodyPart();

            sig.setContent(new ContentSigner(content, true), ENCAPSULATED_SIGNED_CONTENT_TYPE);
            sig.addHeader("Content-Type", ENCAPSULATED_SIGNED_CONTENT_TYPE);
            sig.addHeader("Content-Disposition", "attachment; filename=\"smime.p7m\"");
            sig.addHeader("Content-Description", "S/MIME Cryptographic Signed Data");
            sig.addHeader("Content-Transfer-Encoding", encoding);

            return sig;
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting body part together.", e);
        }
    }

    /**
     * Return a map of oids and byte arrays representing the digests calculated on the content during
     * the last generate.
     *
     * @return a map of oids (as String objects) and byte[] representing digests.
     */
    public Map getGeneratedDigests()
    {
        return new HashMap(_digests);
    }

    public MimeMultipart generate(
        MimeBodyPart    content)
        throws SMIMEException
    {
        return make(makeContentBodyPart(content));
    }

    public MimeMultipart generate(
        MimeMessage    message)
        throws SMIMEException
    {
        try
        {
            message.saveChanges();      // make sure we're up to date.
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("unable to save message", e);
        }

        return make(makeContentBodyPart(message));
    }

    /**
     * generate a signed message with encapsulated content
     * <p>
     * Note: doing this is strongly <b>not</b> recommended as it means a
     * recipient of the message will have to be able to read the signature to read the
     * message.
     */
    public MimeBodyPart generateEncapsulated(
        MimeBodyPart    content)
        throws SMIMEException
    {
        return makeEncapsulated(makeContentBodyPart(content));
    }

    public MimeBodyPart generateEncapsulated(
        MimeMessage    message)
        throws SMIMEException
    {
        try
        {
            message.saveChanges();      // make sure we're up to date.
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("unable to save message", e);
        }

        return makeEncapsulated(makeContentBodyPart(message));
    }

   /**
     * Creates a certificate management message which is like a signed message with no content
     * or signers but that still carries certificates and CRLs.
     *
     * @return a MimeBodyPart containing the certs and CRLs.
     */
    public MimeBodyPart generateCertificateManagement()
       throws SMIMEException
    {
        try
        {
            MimeBodyPart sig = new MimeBodyPart();

            sig.setContent(new ContentSigner(null, true), CERTIFICATE_MANAGEMENT_CONTENT);
            sig.addHeader("Content-Type", CERTIFICATE_MANAGEMENT_CONTENT);
            sig.addHeader("Content-Disposition", "attachment; filename=\"smime.p7c\"");
            sig.addHeader("Content-Description", "S/MIME Certificate Management Message");
            sig.addHeader("Content-Transfer-Encoding", encoding);

            return sig;
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting body part together.", e);
        }
    }

    private class ContentSigner
        implements SMIMEStreamingProcessor
    {
        private final MimeBodyPart content;
        private final boolean encapsulate;
        private final boolean  noProvider;

        ContentSigner(
            MimeBodyPart content,
            boolean      encapsulate)
        {
            this.content = content;
            this.encapsulate = encapsulate;
            this.noProvider = true;
        }

        protected CMSSignedDataStreamGenerator getGenerator()
            throws CMSException
        {
            CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

            for (Iterator it = certStores.iterator(); it.hasNext();)
            {
                gen.addCertificates((Store)it.next());
            }

            for (Iterator it = crlStores.iterator(); it.hasNext();)
            {
                gen.addCRLs((Store)it.next());
            }

            for (Iterator it = attrCertStores.iterator(); it.hasNext();)
            {
                gen.addAttributeCertificates((Store)it.next());
            }

            for (Iterator it = signerInfoGens.iterator(); it.hasNext();)
            {
                gen.addSignerInfoGenerator((SignerInfoGenerator)it.next());
            }

            gen.addSigners(new SignerInformationStore(_oldSigners));
            
            return gen;
        }

        private void writeBodyPart(
            OutputStream out,
            MimeBodyPart bodyPart)
            throws IOException, MessagingException
        {
            if (SMIMEUtil.isMultipartContent(bodyPart))
            {
                Object content = bodyPart.getContent();
                Multipart mp;
                if (content instanceof Multipart)
                {
                    mp = (Multipart)content;
                }
                else
                {
                    mp = new MimeMultipart(bodyPart.getDataHandler().getDataSource());
                }

                ContentType contentType = new ContentType(mp.getContentType());
                String boundary = "--" + contentType.getParameter("boundary");

                SMIMEUtil.LineOutputStream lOut = new SMIMEUtil.LineOutputStream(out);

                Enumeration headers = bodyPart.getAllHeaderLines();
                while (headers.hasMoreElements())
                {
                    lOut.writeln((String)headers.nextElement());
                }

                lOut.writeln();      // CRLF separator

                SMIMEUtil.outputPreamble(lOut, bodyPart, boundary);

                for (int i = 0; i < mp.getCount(); i++)
                {
                    lOut.writeln(boundary);
                    writeBodyPart(out, (MimeBodyPart)mp.getBodyPart(i));
                    lOut.writeln();       // CRLF terminator
                }

                lOut.writeln(boundary + "--");
            }
            else
            {
                if (SMIMEUtil.isCanonicalisationRequired(bodyPart, defaultContentTransferEncoding))
                {
                    out = new CRLFOutputStream(out);
                }

                bodyPart.writeTo(out);
            }
        }

        public void write(OutputStream out)
            throws IOException
        {
            try
            {
                CMSSignedDataStreamGenerator gen = getGenerator();
                
                OutputStream signingStream = gen.open(out, encapsulate);
                
                if (content != null)
                {
                    if (!encapsulate)
                    {
                        writeBodyPart(signingStream, content);
                    }
                    else
                    {
                        CommandMap commandMap = CommandMap.getDefaultCommandMap();

                        if (commandMap instanceof MailcapCommandMap)
                        {
                            content.getDataHandler().setCommandMap(MailcapUtil.addCommands((MailcapCommandMap)commandMap));
                        }

                        content.writeTo(signingStream);
                    }
                }
                
                signingStream.close();

                _digests = gen.getGeneratedDigests();
            }
            catch (MessagingException e)
            {
                throw new IOException(e.toString());
            }
            catch (CMSException e)
            {
                throw new IOException(e.toString());
            }
        }
    }
}
