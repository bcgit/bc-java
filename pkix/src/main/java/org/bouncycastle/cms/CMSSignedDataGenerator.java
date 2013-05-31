package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * general class for generating a pkcs7-signature message.
 * <p>
 * A simple example of usage, generating a detached signature.
 *
 * <pre>
 *      List             certList = new ArrayList();
 *      CMSTypedData     msg = new CMSProcessableByteArray("Hello world!".getBytes());
 *
 *      certList.add(signCert);
 *
 *      Store           certs = new JcaCertStore(certList);
 *
 *      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
 *      ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(signKP.getPrivate());
 *
 *      gen.addSignerInfoGenerator(
 *                new JcaSignerInfoGeneratorBuilder(
 *                     new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
 *                     .build(sha1Signer, signCert));
 *
 *      gen.addCertificates(certs);
 *
 *      CMSSignedData sigData = gen.generate(msg, false);
 * </pre>
 */
public class CMSSignedDataGenerator
    extends CMSSignedGenerator
{
    private List signerInfs = new ArrayList();

    private class SignerInf
    {
        final PrivateKey                  key;
        final Object                      signerIdentifier;
        final String                      digestOID;
        final String                      encOID;
        final CMSAttributeTableGenerator  sAttr;
        final CMSAttributeTableGenerator  unsAttr;
        final AttributeTable              baseSignedTable;

        SignerInf(
            PrivateKey                 key,
            Object                     signerIdentifier,
            String                     digestOID,
            String                     encOID,
            CMSAttributeTableGenerator sAttr,
            CMSAttributeTableGenerator unsAttr,
            AttributeTable             baseSignedTable)
        {
            this.key = key;
            this.signerIdentifier = signerIdentifier;
            this.digestOID = digestOID;
            this.encOID = encOID;
            this.sAttr = sAttr;
            this.unsAttr = unsAttr;
            this.baseSignedTable = baseSignedTable;
        }

        SignerInfoGenerator toSignerInfoGenerator(
            SecureRandom        random,
            Provider sigProvider,
            boolean             addDefaultAttributes)
            throws IOException, CertificateEncodingException, CMSException, OperatorCreationException, NoSuchAlgorithmException
        {
            String              digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(digestOID);
            String              signatureName = digestName + "with" + CMSSignedHelper.INSTANCE.getEncryptionAlgName(encOID);

            JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new BcDigestCalculatorProvider());

            if (addDefaultAttributes)
            {
                builder.setSignedAttributeGenerator(sAttr);
            }
            builder.setDirectSignature(!addDefaultAttributes);

            builder.setUnsignedAttributeGenerator(unsAttr);

            JcaContentSignerBuilder signerBuilder;

            try
            {
                signerBuilder = new JcaContentSignerBuilder(signatureName).setSecureRandom(random);
            }
            catch (IllegalArgumentException e)
            {
                throw new NoSuchAlgorithmException(e.getMessage());
            }

            if (sigProvider != null)
            {
                signerBuilder.setProvider(sigProvider);
            }

            ContentSigner contentSigner = signerBuilder.build(key);
            if (signerIdentifier instanceof X509Certificate)
            {
                return builder.build(contentSigner, (X509Certificate)signerIdentifier);
            }
            else
            {
                return builder.build(contentSigner, (byte[])signerIdentifier);
            }
        }
    }
    /**
     * base constructor
     */
    public CMSSignedDataGenerator()
    {
    }

    /**
     * constructor allowing specific source of randomness
     * @param rand instance of SecureRandom to use
     * @deprecated  rand ignored in new API, use base constructor.
     */
    public CMSSignedDataGenerator(
        SecureRandom rand)
    {
        super(rand);
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     *
     * @param key signing key to use
     * @param cert certificate containing corresponding public key
     * @param digestOID digest algorithm OID
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID)
        throws IllegalArgumentException
    {
        addSigner(key, cert, getEncOID(key, digestOID), digestOID);
    }

    /**
     * add a signer, specifying the digest encryption algorithm to use - no attributes other than the default ones will be
     * provided here.
     *
     * @param key signing key to use
     * @param cert certificate containing corresponding public key
     * @param encryptionOID digest encryption algorithm OID
     * @param digestOID digest algorithm OID
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID)
        throws IllegalArgumentException
    {
        doAddSigner(key, cert, encryptionOID, digestOID,
            new DefaultSignedAttributeTableGenerator(), null, null);
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID)
        throws IllegalArgumentException
    {
        addSigner(key, subjectKeyID, getEncOID(key, digestOID), digestOID);
    }

    /**
     * add a signer, specifying the digest encryption algorithm to use - no attributes other than the default ones will be
     * provided here.
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          encryptionOID,
        String          digestOID)
        throws IllegalArgumentException
    {
        doAddSigner(key, subjectKeyID, encryptionOID, digestOID,
            new DefaultSignedAttributeTableGenerator(), null, null);
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     *
     * @param key signing key to use
     * @param cert certificate containing corresponding public key
     * @param digestOID digest algorithm OID
     * @param signedAttr table of attributes to be included in signature
     * @param unsignedAttr table of attributes to be included as unsigned
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException
    {
        addSigner(key, cert, getEncOID(key, digestOID), digestOID, signedAttr, unsignedAttr);
    }

    /**
     * add a signer, specifying the digest encryption algorithm, with extra signed/unsigned attributes.
     *
     * @param key signing key to use
     * @param cert certificate containing corresponding public key
     * @param encryptionOID digest encryption algorithm OID
     * @param digestOID digest algorithm OID
     * @param signedAttr table of attributes to be included in signature
     * @param unsignedAttr table of attributes to be included as unsigned
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException
    {
        doAddSigner(key, cert, encryptionOID, digestOID,
          new DefaultSignedAttributeTableGenerator(signedAttr),
          new SimpleAttributeTableGenerator(unsignedAttr), signedAttr);
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     *
     * @param key signing key to use
     * @param subjectKeyID subjectKeyID of corresponding public key
     * @param digestOID digest algorithm OID
     * @param signedAttr table of attributes to be included in signature
     * @param unsignedAttr table of attributes to be included as unsigned
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException
    {
        addSigner(key, subjectKeyID, getEncOID(key, digestOID), digestOID, signedAttr,
            unsignedAttr); 
    }

    /**
     * add a signer, specifying the digest encryption algorithm, with extra signed/unsigned attributes.
     *
     * @param key signing key to use
     * @param subjectKeyID subjectKeyID of corresponding public key
     * @param encryptionOID digest encryption algorithm OID
     * @param digestOID digest algorithm OID
     * @param signedAttr table of attributes to be included in signature
     * @param unsignedAttr table of attributes to be included as unsigned
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          encryptionOID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException
    {
        doAddSigner(key, subjectKeyID, encryptionOID, digestOID,
            new DefaultSignedAttributeTableGenerator(signedAttr),
            new SimpleAttributeTableGenerator(unsignedAttr), signedAttr);
    }

    /**
     * add a signer with extra signed/unsigned attributes based on generators.
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGen,
        CMSAttributeTableGenerator  unsignedAttrGen)
        throws IllegalArgumentException
    {
        addSigner(key, cert, getEncOID(key, digestOID), digestOID, signedAttrGen, unsignedAttrGen);
    }

    /**
     * add a signer, specifying the digest encryption algorithm, with extra signed/unsigned attributes based on generators.
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGen,
        CMSAttributeTableGenerator  unsignedAttrGen)
        throws IllegalArgumentException
    {
        doAddSigner(key, cert, encryptionOID, digestOID, signedAttrGen,
            unsignedAttrGen, null);
    }

    /**
     * add a signer with extra signed/unsigned attributes based on generators.
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGen,
        CMSAttributeTableGenerator  unsignedAttrGen)
        throws IllegalArgumentException
    {
        addSigner(key, subjectKeyID, getEncOID(key, digestOID), digestOID, signedAttrGen,
            unsignedAttrGen);
    }

    /**
     * add a signer, including digest encryption algorithm, with extra signed/unsigned attributes based on generators.
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGen,
        CMSAttributeTableGenerator  unsignedAttrGen)
        throws IllegalArgumentException
    {
        doAddSigner(key, subjectKeyID, encryptionOID, digestOID,
            signedAttrGen, unsignedAttrGen, null);
    }

    private void doAddSigner(
        PrivateKey                  key,
        Object                      signerIdentifier,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGen,
        CMSAttributeTableGenerator  unsignedAttrGen,
        AttributeTable              baseSignedTable)
        throws IllegalArgumentException
    {
        signerInfs.add(new SignerInf(key, signerIdentifier, digestOID, encryptionOID,
            signedAttrGen, unsignedAttrGen, baseSignedTable));
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider.
     * @deprecated use generate() method not taking provider.
     */
    public CMSSignedData generate(
        CMSProcessable content,
        String         sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(content, CMSUtils.getProvider(sigProvider));
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider.
     * @deprecated use generate() method not taking provider.
     */
    public CMSSignedData generate(
        CMSProcessable content,
        Provider       sigProvider)
        throws NoSuchAlgorithmException, CMSException
    {
        return generate(content, false, sigProvider);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     * @deprecated use generate(CMSTypedData, boolean)
     */
    public CMSSignedData generate(
        String          eContentType,
        CMSProcessable  content,
        boolean         encapsulate,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(eContentType, content, encapsulate, CMSUtils.getProvider(sigProvider),
            true);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     * @deprecated use generate(CMSTypedData, boolean)
     */
    public CMSSignedData generate(
        String          eContentType,
        CMSProcessable  content,
        boolean         encapsulate,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, CMSException
    {
        return generate(eContentType, content, encapsulate, sigProvider, true);
    }

    /**
     * Similar method to the other generate methods. The additional argument
     * addDefaultAttributes indicates whether or not a default set of signed attributes
     * need to be added automatically. If the argument is set to false, no
     * attributes will get added at all.
     * @deprecated use generate(CMSTypedData, boolean)
     */
    public CMSSignedData generate(
        String                  eContentType,
        CMSProcessable          content,
        boolean                 encapsulate,
        String                  sigProvider,
        boolean                 addDefaultAttributes)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(eContentType, content, encapsulate, CMSUtils.getProvider(sigProvider),
            addDefaultAttributes);
    }

    /**
     * Similar method to the other generate methods. The additional argument
     * addDefaultAttributes indicates whether or not a default set of signed attributes
     * need to be added automatically. If the argument is set to false, no
     * attributes will get added at all.
     * @deprecated use setDirectSignature() on SignerInformationGenerator.
     */
    public CMSSignedData generate(
        String                  eContentType,
        final CMSProcessable    content,
        boolean                 encapsulate,
        Provider                sigProvider,
        boolean                 addDefaultAttributes)
        throws NoSuchAlgorithmException, CMSException
    {
        boolean isCounterSignature = (eContentType == null);

        final ASN1ObjectIdentifier contentTypeOID = isCounterSignature
            ?   null
            :   new ASN1ObjectIdentifier(eContentType);

        for (Iterator it = signerInfs.iterator(); it.hasNext();)
        {
            SignerInf signer = (SignerInf)it.next();

            try
            {
                signerGens.add(signer.toSignerInfoGenerator(rand, sigProvider,
                    addDefaultAttributes));
            }
            catch (OperatorCreationException e)
            {
                throw new CMSException("exception creating signerInf", e);
            }
            catch (IOException e)
            {
                throw new CMSException("exception encoding attributes", e);
            }
            catch (CertificateEncodingException e)
            {
                throw new CMSException("error creating sid.", e);
            }
        }

        signerInfs.clear();

        if (content != null)
        {
            return generate(new CMSTypedData()
            {
                public ASN1ObjectIdentifier getContentType()
                {
                    return contentTypeOID;
                }

                public void write(OutputStream out)
                    throws IOException, CMSException
                {
                    content.write(out);
                }

                public Object getContent()
                {
                    return content.getContent();
                }
            }, encapsulate);
        }
        else
        {
            return generate(new CMSAbsentContent(contentTypeOID), encapsulate);
        }
    }
    
    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data".
     * @deprecated use generate(CMSTypedData, boolean)
     */
    public CMSSignedData generate(
        CMSProcessable  content,
        boolean         encapsulate,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        if (content instanceof CMSTypedData)
        {
            return this.generate(((CMSTypedData)content).getContentType().getId(), content, encapsulate, sigProvider);
        }
        else
        {
            return this.generate(DATA, content, encapsulate, sigProvider);
        }
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data".
     * @deprecated use generate(CMSTypedData, boolean)
     */
    public CMSSignedData generate(
        CMSProcessable  content,
        boolean         encapsulate,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, CMSException
    {
        if (content instanceof CMSTypedData)
        {
            return this.generate(((CMSTypedData)content).getContentType().getId(), content, encapsulate, sigProvider);
        }
        else
        {
            return this.generate(DATA, content, encapsulate, sigProvider);
        }
    }

    public CMSSignedData generate(
        CMSTypedData content)
        throws CMSException
    {
        return generate(content, false);
    }

    public CMSSignedData generate(
        // FIXME Avoid accessing more than once to support CMSProcessableInputStream
        CMSTypedData content,
        boolean encapsulate)
        throws CMSException
    {
        if (!signerInfs.isEmpty())
        {
            throw new IllegalStateException("this method can only be used with SignerInfoGenerator");
        }

                // TODO
//        if (signerInfs.isEmpty())
//        {
//            /* RFC 3852 5.2
//             * "In the degenerate case where there are no signers, the
//             * EncapsulatedContentInfo value being "signed" is irrelevant.  In this
//             * case, the content type within the EncapsulatedContentInfo value being
//             * "signed" MUST be id-data (as defined in section 4), and the content
//             * field of the EncapsulatedContentInfo value MUST be omitted."
//             */
//            if (encapsulate)
//            {
//                throw new IllegalArgumentException("no signers, encapsulate must be false");
//            }
//            if (!DATA.equals(eContentType))
//            {
//                throw new IllegalArgumentException("no signers, eContentType must be id-data");
//            }
//        }
//
//        if (!DATA.equals(eContentType))
//        {
//            /* RFC 3852 5.3
//             * [The 'signedAttrs']...
//             * field is optional, but it MUST be present if the content type of
//             * the EncapsulatedContentInfo value being signed is not id-data.
//             */
//            // TODO signedAttrs must be present for all signers
//        }

        ASN1EncodableVector  digestAlgs = new ASN1EncodableVector();
        ASN1EncodableVector  signerInfos = new ASN1EncodableVector();

        digests.clear();  // clear the current preserved digest state

        //
        // add the precalculated SignerInfo objects.
        //
        for (Iterator it = _signers.iterator(); it.hasNext();)
        {
            SignerInformation signer = (SignerInformation)it.next();
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID()));

            // TODO Verify the content type and calculated digest match the precalculated SignerInfo
            signerInfos.add(signer.toASN1Structure());
        }

        //
        // add the SignerInfo objects
        //
        ASN1ObjectIdentifier contentTypeOID = content.getContentType();

        ASN1OctetString octs = null;

        if (content != null)
        {
            ByteArrayOutputStream bOut = null;

            if (encapsulate)
            {
                bOut = new ByteArrayOutputStream();
            }

            OutputStream cOut = CMSUtils.attachSignersToOutputStream(signerGens, bOut);

            // Just in case it's unencapsulated and there are no signers!
            cOut = CMSUtils.getSafeOutputStream(cOut);

            try
            {
                content.write(cOut);

                cOut.close();
            }
            catch (IOException e)
            {
                throw new CMSException("data processing exception: " + e.getMessage(), e);
            }

            if (encapsulate)
            {
                octs = new BEROctetString(bOut.toByteArray());
            }
        }

        for (Iterator it = signerGens.iterator(); it.hasNext();)
        {
            SignerInfoGenerator sGen = (SignerInfoGenerator)it.next();
            SignerInfo inf = sGen.generate(contentTypeOID);

            digestAlgs.add(inf.getDigestAlgorithm());
            signerInfos.add(inf);

            byte[] calcDigest = sGen.getCalculatedDigest();

            if (calcDigest != null)
            {
                digests.put(inf.getDigestAlgorithm().getAlgorithm().getId(), calcDigest);
            }
        }

        ASN1Set certificates = null;

        if (certs.size() != 0)
        {
            certificates = CMSUtils.createBerSetFromList(certs);
        }

        ASN1Set certrevlist = null;

        if (crls.size() != 0)
        {
            certrevlist = CMSUtils.createBerSetFromList(crls);
        }

        ContentInfo encInfo = new ContentInfo(contentTypeOID, octs);

        SignedData  sd = new SignedData(
                                 new DERSet(digestAlgs),
                                 encInfo,
                                 certificates,
                                 certrevlist,
                                 new DERSet(signerInfos));

        ContentInfo contentInfo = new ContentInfo(
            CMSObjectIdentifiers.signedData, sd);

        return new CMSSignedData(content, contentInfo);
    }

    /**
     * generate a set of one or more SignerInformation objects representing counter signatures on
     * the passed in SignerInformation object.
     *
     * @param signer the signer to be countersigned
     * @param sigProvider the provider to be used for counter signing.
     * @return a store containing the signers.
     * @deprecated use generateCounterSigners(SignerInformation)
     */
    public SignerInformationStore generateCounterSigners(SignerInformation signer, Provider sigProvider)
        throws NoSuchAlgorithmException, CMSException
    {
        return this.generate(null, new CMSProcessableByteArray(signer.getSignature()), false, sigProvider).getSignerInfos();
    }

    /**
     * generate a set of one or more SignerInformation objects representing counter signatures on
     * the passed in SignerInformation object.
     *
     * @param signer the signer to be countersigned
     * @param sigProvider the provider to be used for counter signing.
     * @return a store containing the signers.
     * @deprecated use generateCounterSigners(SignerInformation)
     */
    public SignerInformationStore generateCounterSigners(SignerInformation signer, String sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return this.generate(null, new CMSProcessableByteArray(signer.getSignature()), false, CMSUtils.getProvider(sigProvider)).getSignerInfos();
    }

    /**
     * generate a set of one or more SignerInformation objects representing counter signatures on
     * the passed in SignerInformation object.
     *
     * @param signer the signer to be countersigned
     * @return a store containing the signers.
     */
    public SignerInformationStore generateCounterSigners(SignerInformation signer)
        throws CMSException
    {
        return this.generate(new CMSProcessableByteArray(null, signer.getSignature()), false).getSignerInfos();
    }
}

