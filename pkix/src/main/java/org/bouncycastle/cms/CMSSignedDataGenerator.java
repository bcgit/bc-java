package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;

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
    private boolean isDefiniteLength = false;

    /**
     * base constructor
     */
    public CMSSignedDataGenerator()
    {
    }

    /**
     * base constructor with a custom DigestAlgorithmIdentifierFinder
     */
    public CMSSignedDataGenerator(DigestAlgorithmIdentifierFinder digestAlgIdFinder)
    {
        super(digestAlgIdFinder);
    }

    /**
     * Specify use of definite length rather than indefinite length encoding.
     *
     * @param isDefiniteLength true use definite length, false use indefinite (default false).
     */
    public void setDefiniteLengthEncoding(boolean isDefiniteLength)
    {
        this.isDefiniteLength = isDefiniteLength;
    }

    /**
     * Generate a CMS Signed Data object carrying a detached CMS signature.
     *
     * @param content the content to be signed.
     */
    public CMSSignedData generate(
        CMSTypedData content)
        throws CMSException
    {
        return generate(content, false);
    }

    /**
     * Generate a CMS Signed Data object which can be carrying a detached CMS signature, or have encapsulated data, depending on the value
     * of the encapsulated parameter.
     *
     * @param content the content to be signed.
     * @param encapsulate true if the content should be encapsulated in the signature, false otherwise.
     */
    public CMSSignedData generate(
        // FIXME Avoid accessing more than once to support CMSProcessableInputStream
        CMSTypedData content,
        boolean encapsulate)
        throws CMSException
    {
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

        Set<AlgorithmIdentifier> digestAlgs = new LinkedHashSet<AlgorithmIdentifier>();
        ASN1EncodableVector signerInfos = new ASN1EncodableVector();

        digests.clear();  // clear the current preserved digest state

        //
        // add the precalculated SignerInfo objects.
        //
        for (Iterator it = _signers.iterator(); it.hasNext();)
        {
            SignerInformation signer = (SignerInformation)it.next();
            CMSUtils.addDigestAlgs(digestAlgs, signer, digestAlgIdFinder);
            // TODO Verify the content type and calculated digest match the precalculated SignerInfo
            signerInfos.add(signer.toASN1Structure());
        }

        //
        // add the SignerInfo objects
        //
        ASN1ObjectIdentifier encapContentType = content.getContentType();
        ASN1OctetString encapContent = null;

        // TODO[cms] Could be unnecessary copy e.g. if content is CMSProcessableByteArray (add hasContent method?)
        if (content.getContent() != null)
        {
            if (encapsulate)
            {
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                writeContentViaSignerGens(content, bOut);

                if (isDefiniteLength)
                {
                    encapContent = new DEROctetString(bOut.toByteArray());
                }
                else
                {
                    encapContent = new BEROctetString(bOut.toByteArray());
                }
            }
            else
            {
                writeContentViaSignerGens(content, null);
            }
        }

        for (Iterator it = signerGens.iterator(); it.hasNext();)
        {
            SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();
            SignerInfo signerInfo = generateSignerInfo(signerGen, encapContentType);
            digestAlgs.add(signerInfo.getDigestAlgorithm());
            signerInfos.add(signerInfo);
        }

        ASN1Set certificates = createSetFromList(this.certs, isDefiniteLength);

        ASN1Set crls = createSetFromList(this.crls, isDefiniteLength);

        ContentInfo encapContentInfo = new ContentInfo(encapContentType, encapContent);

        SignedData signedData = new SignedData(
            CMSUtils.convertToDlSet(digestAlgs),
            encapContentInfo,
            certificates,
            crls,
            new DERSet(signerInfos));

        ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.signedData, signedData);

        return new CMSSignedData(content, contentInfo);
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
        digests.clear();

        CMSTypedData content = new CMSProcessableByteArray(null, signer.getSignature());

        ArrayList signerInformations = new ArrayList();

        for (Iterator it = _signers.iterator(); it.hasNext();)
        {
            SignerInformation _signer = (SignerInformation)it.next();
            SignerInfo signerInfo = _signer.toASN1Structure();
            signerInformations.add(new SignerInformation(signerInfo, null, content, null));
        }

        writeContentViaSignerGens(content, null);

        for (Iterator it = signerGens.iterator(); it.hasNext();)
        {
            SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();
            SignerInfo signerInfo = generateSignerInfo(signerGen, null);
            signerInformations.add(new SignerInformation(signerInfo, null, content, null));
        }

        return new SignerInformationStore(signerInformations);
    }

    private SignerInfo generateSignerInfo(SignerInfoGenerator signerGen, ASN1ObjectIdentifier contentType)
        throws CMSException
    {
        SignerInfo signerInfo = signerGen.generate(contentType);

        byte[] calcDigest = signerGen.getCalculatedDigest();
        if (calcDigest != null)
        {
            digests.put(signerInfo.getDigestAlgorithm().getAlgorithm().getId(), calcDigest);
        }

        return signerInfo;
    }

    private void writeContentViaSignerGens(CMSTypedData content, OutputStream s)
        throws CMSException
    {
        OutputStream cOut = CMSUtils.attachSignersToOutputStream(signerGens, s);

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
    }

    private static ASN1Set createSetFromList(List list, boolean isDefiniteLength)
    {
        return list.size() < 1
            ?  null
            :  isDefiniteLength
            ?  CMSUtils.createDlSetFromList(list)
            :  CMSUtils.createBerSetFromList(list);
    }
}
