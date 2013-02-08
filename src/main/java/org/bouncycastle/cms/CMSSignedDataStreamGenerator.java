package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * General class for generating a pkcs7-signature message stream.
 * <p>
 * A simple example of usage.
 * </p>
 * <pre>
 *      X509Certificate signCert = ...
 *      certList.add(signCert);
 *
 *      Store           certs = new JcaCertStore(certList);
 *      ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(signKP.getPrivate());
 *
 *      CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
 *  
 *      gen.addSignerInfoGenerator(
 *                new JcaSignerInfoGeneratorBuilder(
 *                     new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
 *                     .build(sha1Signer, signCert));
 *
 *      gen.addCertificates(certs);
 *  
 *      OutputStream sigOut = gen.open(bOut);
 *  
 *      sigOut.write("Hello World!".getBytes());
 *      
 *      sigOut.close();
 * </pre>
 */
public class CMSSignedDataStreamGenerator
    extends CMSSignedGenerator
{
    private int  _bufferSize;

    /**
     * base constructor
     */
    public CMSSignedDataStreamGenerator()
    {
    }

    /**
     * constructor allowing specific source of randomness
     * @param rand instance of SecureRandom to use
     * @deprecated no longer required if the addSignerInfoGenerator method is used.
     */
    public CMSSignedDataStreamGenerator(
        SecureRandom rand)
    {
        super(rand);
    }

    /**
     * Set the underlying string size for encapsulated data
     * 
     * @param bufferSize length of octet strings to buffer the data.
     */
    public void setBufferSize(
        int bufferSize)
    {
        _bufferSize = bufferSize;
    }
    
    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, digestOID, CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
       addSigner(key, cert, digestOID, new DefaultSignedAttributeTableGenerator(),
           (CMSAttributeTableGenerator)null, sigProvider);
    }

    /**
     * add a signer, specifying the digest encryption algorithm - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, encryptionOID, digestOID, CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer, specifying digest encryptionOID - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
       addSigner(key, cert, encryptionOID, digestOID, new DefaultSignedAttributeTableGenerator(),
           (CMSAttributeTableGenerator)null, sigProvider);
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, digestOID, signedAttr, unsignedAttr,
            CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, cert, digestOID, new DefaultSignedAttributeTableGenerator(signedAttr),
            new SimpleAttributeTableGenerator(unsignedAttr), sigProvider);
    }

    /**
     * add a signer with extra signed/unsigned attributes - specifying digest
     * encryption algorithm.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, encryptionOID, digestOID, signedAttr, unsignedAttr,
            CMSUtils.getProvider(sigProvider));
    }

   /**
     * add a signer with extra signed/unsigned attributes and the digest encryption algorithm.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, cert, encryptionOID, digestOID,
            new DefaultSignedAttributeTableGenerator(signedAttr),
            new SimpleAttributeTableGenerator(unsignedAttr), sigProvider);
    }

    /**
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        String                      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, digestOID, signedAttrGenerator, unsignedAttrGenerator,
            CMSUtils.getProvider(sigProvider));
    }

    /**
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, cert, getEncOID(key, digestOID), digestOID, signedAttrGenerator,
            unsignedAttrGenerator, sigProvider);
    }

    /**
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        String                      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, encryptionOID, digestOID, signedAttrGenerator, unsignedAttrGenerator,
            CMSUtils.getProvider(sigProvider));
    }

    /**
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, cert, encryptionOID, digestOID, signedAttrGenerator, unsignedAttrGenerator, sigProvider, sigProvider);
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, digestOID, CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
       addSigner(key, subjectKeyID, digestOID, new DefaultSignedAttributeTableGenerator(),
           (CMSAttributeTableGenerator)null, sigProvider);
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignedInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          encryptionOID,
        String          digestOID,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, encryptionOID, digestOID, CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here, specifying the digest encryption algorithm.
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          encryptionOID,
        String          digestOID,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
       addSigner(key, subjectKeyID, encryptionOID, digestOID,
           new DefaultSignedAttributeTableGenerator(), (CMSAttributeTableGenerator)null,
           sigProvider);
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, digestOID, signedAttr, unsignedAttr,
            CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, digestOID,
            new DefaultSignedAttributeTableGenerator(signedAttr),
            new SimpleAttributeTableGenerator(unsignedAttr), sigProvider);
    }

    /**
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        String                      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, digestOID, signedAttrGenerator, unsignedAttrGenerator,
            CMSUtils.getProvider(sigProvider));
    }

    /**
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, getEncOID(key, digestOID), digestOID, signedAttrGenerator,
            unsignedAttrGenerator, sigProvider);
    }

    /**
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        String                      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, encryptionOID, digestOID, signedAttrGenerator,
            unsignedAttrGenerator, CMSUtils.getProvider(sigProvider));
    }

    /**
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, encryptionOID, digestOID, signedAttrGenerator, unsignedAttrGenerator, sigProvider, sigProvider);
    }

    /**
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider,
        Provider                    digProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        doAddSigner(key, cert, encryptionOID, digestOID, signedAttrGenerator, unsignedAttrGenerator, sigProvider, digProvider);
    }

    private void doAddSigner(PrivateKey key, Object signerId, String encryptionOID, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, Provider sigProvider, Provider digProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        String          digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(digestOID);
        String          signatureName = digestName + "with" + CMSSignedHelper.INSTANCE.getEncryptionAlgName(encryptionOID);

        JcaContentSignerBuilder signerBuilder;

        try
        {
            signerBuilder = new JcaContentSignerBuilder(signatureName).setSecureRandom(rand);
        }
        catch (IllegalArgumentException e)
        {
            throw new NoSuchAlgorithmException(e.getMessage());
        }

        if (sigProvider != null)
        {
            signerBuilder.setProvider(sigProvider);
        }

        try
        {
            JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();

            if (digProvider != null && !digProvider.getName().equalsIgnoreCase("SunRsaSign"))
            {
                calculatorProviderBuilder.setProvider(digProvider);
            }

            JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());

            builder.setSignedAttributeGenerator(signedAttrGenerator);

            builder.setUnsignedAttributeGenerator(unsignedAttrGenerator);

            try
            {
                ContentSigner contentSigner = signerBuilder.build(key);

                if (signerId instanceof X509Certificate)
                {
                    addSignerInfoGenerator(builder.build(contentSigner, (X509Certificate)signerId));
                }
                else
                {
                    addSignerInfoGenerator(builder.build(contentSigner, (byte[])signerId));
                }
            }
            catch (OperatorCreationException e)
            {
                if (e.getCause() instanceof NoSuchAlgorithmException)
                {
                    throw (NoSuchAlgorithmException)e.getCause();
                }
                if (e.getCause() instanceof InvalidKeyException)
                {
                    throw (InvalidKeyException)e.getCause();
                }
            }
        }
        catch (OperatorCreationException e)
        {
            throw new NoSuchAlgorithmException("unable to create operators: " + e.getMessage());
        }
        catch (CertificateEncodingException e)
        {
            throw new IllegalStateException("unable to encode certificate");
        }
    }

    /**
     * @deprecated use addSignerInfoGenerator
     */
    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider,
        Provider                    digProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        doAddSigner(key, subjectKeyID, encryptionOID, digestOID, signedAttrGenerator, unsignedAttrGenerator, sigProvider, digProvider);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider.
     */
    public OutputStream open(
        OutputStream out)
        throws IOException
    {
        return open(out, false);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data".
     */
    public OutputStream open(
        OutputStream out,
        boolean      encapsulate)
        throws IOException
    {
        return open(CMSObjectIdentifiers.data, out, encapsulate);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data". If dataOutputStream is non null the data
     * being signed will be written to the stream as it is processed.
     * @param out stream the CMS object is to be written to.
     * @param encapsulate true if data should be encapsulated.
     * @param dataOutputStream output stream to copy the data being signed to.
     */
    public OutputStream open(
        OutputStream out,
        boolean      encapsulate,
        OutputStream dataOutputStream)
        throws IOException
    {
        return open(CMSObjectIdentifiers.data, out, encapsulate, dataOutputStream);
    }

    /**
     * @deprecated use open(ASN1ObjectIdentifier, OutputStream, boolean)
     */
    public OutputStream open(
        OutputStream out,
        String       eContentType,
        boolean      encapsulate)
        throws IOException
    {
        return open(out, eContentType, encapsulate, null);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     */
    public OutputStream open(
        ASN1ObjectIdentifier eContentType,
        OutputStream out,
        boolean encapsulate)
        throws IOException
    {
        return open(eContentType, out, encapsulate, null);
    }

    /**
     * @deprecated use open(ASN1ObjectIdenfier, OutputStream, boolean, OutputStream)
     */
    public OutputStream open(
        OutputStream out,
        String eContentType,
        boolean      encapsulate,
        OutputStream dataOutputStream)
        throws IOException
    {
        return open(new ASN1ObjectIdentifier(eContentType), out, encapsulate, dataOutputStream);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     * @param eContentType OID for data to be signed.
     * @param out stream the CMS object is to be written to.
     * @param encapsulate true if data should be encapsulated.
     * @param dataOutputStream output stream to copy the data being signed to.
     */
    public OutputStream open(
        ASN1ObjectIdentifier eContentType,
        OutputStream out,
        boolean encapsulate,
        OutputStream dataOutputStream)
        throws IOException
    {
        // TODO
//        if (_signerInfs.isEmpty())
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

        //
        // ContentInfo
        //
        BERSequenceGenerator sGen = new BERSequenceGenerator(out);
        
        sGen.addObject(CMSObjectIdentifiers.signedData);
        
        //
        // Signed Data
        //
        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);
        
        sigGen.addObject(calculateVersion(eContentType));
        
        ASN1EncodableVector  digestAlgs = new ASN1EncodableVector();
        
        //
        // add the precalculated SignerInfo digest algorithms.
        //
        for (Iterator it = _signers.iterator(); it.hasNext();)
        {
            SignerInformation signer = (SignerInformation)it.next();
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID()));
        }
        
        //
        // add the new digests
        //

        for (Iterator it = signerGens.iterator(); it.hasNext();)
        {
            SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();

            digestAlgs.add(signerGen.getDigestAlgorithm());
        }

        sigGen.getRawOutputStream().write(new DERSet(digestAlgs).getEncoded());
        
        BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());
        eiGen.addObject(eContentType);

        // If encapsulating, add the data as an octet string in the sequence
        OutputStream encapStream = encapsulate
            ? CMSUtils.createBEROctetOutputStream(eiGen.getRawOutputStream(), 0, true, _bufferSize)
            : null;

        // Also send the data to 'dataOutputStream' if necessary
        OutputStream contentStream = CMSUtils.getSafeTeeOutputStream(dataOutputStream, encapStream);

        // Let all the signers see the data as it is written
        OutputStream sigStream = CMSUtils.attachSignersToOutputStream(signerGens, contentStream);

        return new CmsSignedDataOutputStream(sigStream, eContentType, sGen, sigGen, eiGen);
    }

    // TODO Make public?
    void generate(
        OutputStream    out,
        String          eContentType,
        boolean         encapsulate,
        OutputStream    dataOutputStream,
        CMSProcessable  content)
        throws CMSException, IOException
    {
        OutputStream signedOut = open(out, eContentType, encapsulate, dataOutputStream);
        if (content != null)
        {
            content.write(signedOut);
        }
        signedOut.close();
    }

    // RFC3852, section 5.1:
    // IF ((certificates is present) AND
    //    (any certificates with a type of other are present)) OR
    //    ((crls is present) AND
    //    (any crls with a type of other are present))
    // THEN version MUST be 5
    // ELSE
    //    IF (certificates is present) AND
    //       (any version 2 attribute certificates are present)
    //    THEN version MUST be 4
    //    ELSE
    //       IF ((certificates is present) AND
    //          (any version 1 attribute certificates are present)) OR
    //          (any SignerInfo structures are version 3) OR
    //          (encapContentInfo eContentType is other than id-data)
    //       THEN version MUST be 3
    //       ELSE version MUST be 1
    //
    private ASN1Integer calculateVersion(
        ASN1ObjectIdentifier contentOid)
    {
        boolean otherCert = false;
        boolean otherCrl = false;
        boolean attrCertV1Found = false;
        boolean attrCertV2Found = false;

        if (certs != null)
        {
            for (Iterator it = certs.iterator(); it.hasNext();)
            {
                Object obj = it.next();
                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tagged = (ASN1TaggedObject)obj;

                    if (tagged.getTagNo() == 1)
                    {
                        attrCertV1Found = true;
                    }
                    else if (tagged.getTagNo() == 2)
                    {
                        attrCertV2Found = true;
                    }
                    else if (tagged.getTagNo() == 3)
                    {
                        otherCert = true;
                    }
                }
            }
        }

        if (otherCert)
        {
            return new ASN1Integer(5);
        }

        if (crls != null)         // no need to check if otherCert is true
        {
            for (Iterator it = crls.iterator(); it.hasNext();)
            {
                Object obj = it.next();
                if (obj instanceof ASN1TaggedObject)
                {
                    otherCrl = true;
                }
            }
        }

        if (otherCrl)
        {
            return new ASN1Integer(5);
        }

        if (attrCertV2Found)
        {
            return new ASN1Integer(4);
        }

        if (attrCertV1Found)
        {
            return new ASN1Integer(3);
        }

        if (checkForVersion3(_signers, signerGens))
        {
            return new ASN1Integer(3);
        }

        if (!CMSObjectIdentifiers.data.equals(contentOid))
        {
            return new ASN1Integer(3);
        }

        return new ASN1Integer(1);
    }

    private boolean checkForVersion3(List signerInfos, List signerInfoGens)
    {
        for (Iterator it = signerInfos.iterator(); it.hasNext();)
        {
            SignerInfo s = SignerInfo.getInstance(((SignerInformation)it.next()).toASN1Structure());

            if (s.getVersion().getValue().intValue() == 3)
            {
                return true;
            }
        }

        for (Iterator it = signerInfoGens.iterator(); it.hasNext();)
        {
        	SignerInfoGenerator s = (SignerInfoGenerator)it.next();

            if (s.getGeneratedVersion().getValue().intValue() == 3)
            {
                return true;
            }
        }

        return false;
    }

    private class CmsSignedDataOutputStream
        extends OutputStream
    {
        private OutputStream         _out;
        private ASN1ObjectIdentifier _contentOID;
        private BERSequenceGenerator _sGen;
        private BERSequenceGenerator _sigGen;
        private BERSequenceGenerator _eiGen;

        public CmsSignedDataOutputStream(
            OutputStream         out,
            ASN1ObjectIdentifier contentOID,
            BERSequenceGenerator sGen,
            BERSequenceGenerator sigGen,
            BERSequenceGenerator eiGen)
        {
            _out = out;
            _contentOID = contentOID;
            _sGen = sGen;
            _sigGen = sigGen;
            _eiGen = eiGen;
        }

        public void write(
            int b)
            throws IOException
        {
            _out.write(b);
        }
        
        public void write(
            byte[] bytes,
            int    off,
            int    len)
            throws IOException
        {
            _out.write(bytes, off, len);
        }
        
        public void write(
            byte[] bytes)
            throws IOException
        {
            _out.write(bytes);
        }
        
        public void close()
            throws IOException
        {
            _out.close();
            _eiGen.close();

            digests.clear();    // clear the current preserved digest state

            if (certs.size() != 0)
            {
                ASN1Set certSet = CMSUtils.createBerSetFromList(certs);

                _sigGen.getRawOutputStream().write(new BERTaggedObject(false, 0, certSet).getEncoded());
            }

            if (crls.size() != 0)
            {
                ASN1Set crlSet = CMSUtils.createBerSetFromList(crls);

                _sigGen.getRawOutputStream().write(new BERTaggedObject(false, 1, crlSet).getEncoded());
            }

            //
            // collect all the SignerInfo objects
            //
            ASN1EncodableVector signerInfos = new ASN1EncodableVector();

            //
            // add the generated SignerInfo objects
            //

            for (Iterator it = signerGens.iterator(); it.hasNext();)
            {
                SignerInfoGenerator sigGen = (SignerInfoGenerator)it.next();


                try
                {
                    signerInfos.add(sigGen.generate(_contentOID));

                    byte[] calculatedDigest = sigGen.getCalculatedDigest();

                    digests.put(sigGen.getDigestAlgorithm().getAlgorithm().getId(), calculatedDigest);
                }
                catch (CMSException e)
                {
                    throw new CMSStreamException("exception generating signers: " + e.getMessage(), e);
                }
            }

            //
            // add the precalculated SignerInfo objects
            //
            {
                Iterator it = _signers.iterator();
                while (it.hasNext())
                {
                    SignerInformation signer = (SignerInformation)it.next();

                    // TODO Verify the content type and calculated digest match the precalculated SignerInfo
//                    if (!signer.getContentType().equals(_contentOID))
//                    {
//                        // TODO The precalculated content type did not match - error?
//                    }
//                    
//                    byte[] calculatedDigest = (byte[])_digests.get(signer.getDigestAlgOID());
//                    if (calculatedDigest == null)
//                    {
//                        // TODO We can't confirm this digest because we didn't calculate it - error?
//                    }
//                    else
//                    {
//                        if (!Arrays.areEqual(signer.getContentDigest(), calculatedDigest))
//                        {
//                            // TODO The precalculated digest did not match - error?
//                        }
//                    }

                    signerInfos.add(signer.toASN1Structure());
                }
            }
            
            _sigGen.getRawOutputStream().write(new DERSet(signerInfos).getEncoded());

            _sigGen.close();
            _sGen.close();
        }
    }
}
