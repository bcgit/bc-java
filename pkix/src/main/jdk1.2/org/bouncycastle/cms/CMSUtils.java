package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BEROctetStringGenerator;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.io.TeeInputStream;
import org.bouncycastle.util.io.TeeOutputStream;

class CMSUtils
{
    private static final Set<String> des = new HashSet<String>();
    private static final Set mqvAlgs = new HashSet();
    private static final Set ecAlgs = new HashSet();
    private static final Set gostAlgs = new HashSet();

    static
    {
        des.add("DES");
        des.add("DESEDE");
        des.add(OIWObjectIdentifiers.desCBC.getId());
        des.add(PKCSObjectIdentifiers.des_EDE3_CBC.getId());
        des.add(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId());

        mqvAlgs.add(X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme);

        ecAlgs.add(X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme);
        ecAlgs.add(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme);

        gostAlgs.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_ESDH);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512);
    }

    static boolean isMQV(ASN1ObjectIdentifier algorithm)
    {
        return mqvAlgs.contains(algorithm);
    }

    static boolean isEC(ASN1ObjectIdentifier algorithm)
    {
        return ecAlgs.contains(algorithm);
    }

    static boolean isGOST(ASN1ObjectIdentifier algorithm)
    {
        return gostAlgs.contains(algorithm);
    }

    static boolean isRFC2631(ASN1ObjectIdentifier algorithm)
    {
        return algorithm.equals(PKCSObjectIdentifiers.id_alg_ESDH) || algorithm.equals(PKCSObjectIdentifiers.id_alg_SSDH);
    }

    static boolean isDES(String algorithmID)
    {
        String name = Strings.toUpperCase(algorithmID);

        return des.contains(name);
    }

    static boolean isEquivalent(AlgorithmIdentifier algId1, AlgorithmIdentifier algId2)
    {
        if (algId1 == null || algId2 == null)
        {
            return false;
        }

        if (!algId1.getAlgorithm().equals(algId2.getAlgorithm()))
        {
            return false;
        }

        ASN1Encodable params1 = algId1.getParameters();
        ASN1Encodable params2 = algId2.getParameters();
        if (params1 != null)
        {
            return params1.equals(params2) || (params1.equals(DERNull.INSTANCE) && params2 == null);
        }

        return params2 == null || params2.equals(DERNull.INSTANCE);
    }

    static ContentInfo readContentInfo(
        byte[] input)
        throws CMSException
    {
        // enforce limit checking as from a byte array
        return readContentInfo(new ASN1InputStream(input));
    }

    static ContentInfo readContentInfo(
        InputStream input)
        throws CMSException
    {
        // enforce some limit checking
        return readContentInfo(new ASN1InputStream(input));
    }

    static ASN1Set convertToDlSet(Set<AlgorithmIdentifier> digestAlgs)
    {
        return new DLSet((AlgorithmIdentifier[])digestAlgs.toArray(new AlgorithmIdentifier[digestAlgs.size()]));
    }

    static void addDigestAlgs(Set<AlgorithmIdentifier> digestAlgs, SignerInformation signer, DigestAlgorithmIdentifierFinder dgstAlgFinder)
    {
        digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(signer.getDigestAlgorithmID(), dgstAlgFinder));
        SignerInformationStore counterSignaturesStore = signer.getCounterSignatures();
        Iterator<SignerInformation> counterSignatureIt = counterSignaturesStore.iterator();
        while (counterSignatureIt.hasNext())
        {
            SignerInformation counterSigner = (SignerInformation)counterSignatureIt.next();
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(counterSigner.getDigestAlgorithmID(), dgstAlgFinder));
        }
    }

    static List getCertificatesFromStore(Store certStore)
        throws CMSException
    {
        List certs = new ArrayList();

        try
        {
            for (Iterator it = certStore.getMatches(null).iterator(); it.hasNext(); )
            {
                X509CertificateHolder c = (X509CertificateHolder)it.next();

                certs.add(c.toASN1Structure());
            }

            return certs;
        }
        catch (ClassCastException e)
        {
            throw new CMSException("error processing certs", e);
        }
    }

    static List getAttributeCertificatesFromStore(Store attrStore)
        throws CMSException
    {
        List certs = new ArrayList();

        try
        {
            for (Iterator it = attrStore.getMatches(null).iterator(); it.hasNext(); )
            {
                X509AttributeCertificateHolder attrCert = (X509AttributeCertificateHolder)it.next();

                certs.add(new DERTaggedObject(false, 2, attrCert.toASN1Structure()));
            }

            return certs;
        }
        catch (ClassCastException e)
        {
            throw new CMSException("error processing certs", e);
        }
    }


    static List getCRLsFromStore(Store crlStore)
        throws CMSException
    {
        List crls = new ArrayList();

        try
        {
            for (Iterator it = crlStore.getMatches(null).iterator(); it.hasNext(); )
            {
                Object rev = it.next();

                if (rev instanceof X509CRLHolder)
                {
                    X509CRLHolder c = (X509CRLHolder)rev;

                    crls.add(c.toASN1Structure());
                }
                else if (rev instanceof OtherRevocationInfoFormat)
                {
                    OtherRevocationInfoFormat infoFormat = OtherRevocationInfoFormat.getInstance(rev);

                    validateInfoFormat(infoFormat);

                    crls.add(new DERTaggedObject(false, 1, infoFormat));
                }
                else if (rev instanceof ASN1TaggedObject)
                {
                    crls.add(rev);
                }
            }

            return crls;
        }
        catch (ClassCastException e)
        {
            throw new CMSException("error processing certs", e);
        }
    }

    static void validateInfoFormat(OtherRevocationInfoFormat infoFormat)
    {
        if (CMSObjectIdentifiers.id_ri_ocsp_response.equals(infoFormat.getInfoFormat()))
        {
            OCSPResponse resp = OCSPResponse.getInstance(infoFormat.getInfo());

            if (OCSPResponseStatus.SUCCESSFUL != resp.getResponseStatus().getIntValue())
            {
                throw new IllegalArgumentException("cannot add unsuccessful OCSP response to CMS SignedData");
            }
        }
    }

    static Collection getOthersFromStore(ASN1ObjectIdentifier otherRevocationInfoFormat, Store otherRevocationInfos)
    {
        List others = new ArrayList();

        for (Iterator it = otherRevocationInfos.getMatches(null).iterator(); it.hasNext(); )
        {
            ASN1Encodable info = (ASN1Encodable)it.next();
            OtherRevocationInfoFormat infoFormat = new OtherRevocationInfoFormat(otherRevocationInfoFormat, info);

            validateInfoFormat(infoFormat);

            others.add(new DERTaggedObject(false, 1, infoFormat));
        }

        return others;
    }

    static ASN1Set createBerSetFromList(List derObjects)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Iterator it = derObjects.iterator(); it.hasNext(); )
        {
            v.add((ASN1Encodable)it.next());
        }

        return new BERSet(v);
    }

    static ASN1Set createDlSetFromList(List derObjects)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Iterator it = derObjects.iterator(); it.hasNext(); )
        {
            v.add((ASN1Encodable)it.next());
        }

        return new DLSet(v);
    }

    static ASN1Set createDerSetFromList(List derObjects)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Iterator it = derObjects.iterator(); it.hasNext(); )
        {
            v.add((ASN1Encodable)it.next());
        }

        return new DERSet(v);
    }

    static OutputStream createBEROctetOutputStream(OutputStream s,
                                                   int tagNo, boolean isExplicit, int bufferSize)
        throws IOException
    {
        BEROctetStringGenerator octGen = new BEROctetStringGenerator(s, tagNo, isExplicit);

        if (bufferSize != 0)
        {
            return octGen.getOctetOutputStream(new byte[bufferSize]);
        }

        return octGen.getOctetOutputStream();
    }

    private static ContentInfo readContentInfo(
        ASN1InputStream in)
        throws CMSException
    {
        try
        {
            ContentInfo info = ContentInfo.getInstance(in.readObject());
            if (info == null)
            {
                throw new CMSException("No content found.");
            }

            return info;
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading content.", e);
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Malformed content.", e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("Malformed content.", e);
        }
    }

    public static byte[] streamToByteArray(
        InputStream in)
        throws IOException
    {
        return Streams.readAll(in);
    }

    public static byte[] streamToByteArray(
        InputStream in,
        int limit)
        throws IOException
    {
        return Streams.readAllLimited(in, limit);
    }

    static InputStream attachDigestsToInputStream(Collection digests, InputStream s)
    {
        InputStream result = s;
        Iterator it = digests.iterator();
        while (it.hasNext())
        {
            DigestCalculator digest = (DigestCalculator)it.next();
            result = new TeeInputStream(result, digest.getOutputStream());
        }
        return result;
    }

    static OutputStream attachSignersToOutputStream(Collection signers, OutputStream s)
    {
        OutputStream result = s;
        Iterator it = signers.iterator();
        while (it.hasNext())
        {
            SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();
            result = getSafeTeeOutputStream(result, signerGen.getCalculatingOutputStream());
        }
        return result;
    }

    static OutputStream getSafeOutputStream(OutputStream s)
    {
        return s == null ? new NullOutputStream() : s;
    }

    static OutputStream getSafeTeeOutputStream(OutputStream s1,
                                               OutputStream s2)
    {
        return s1 == null ? getSafeOutputStream(s2)
            : s2 == null ? getSafeOutputStream(s1) : new TeeOutputStream(
            s1, s2);
    }

    static EncryptedContentInfo getEncryptedContentInfo(CMSTypedData content, OutputEncryptor contentEncryptor, byte[] encryptedContent)
    {
        return getEncryptedContentInfo(
            content.getContentType(),
            contentEncryptor.getAlgorithmIdentifier(),
            encryptedContent);
    }

    static EncryptedContentInfo getEncryptedContentInfo(ASN1ObjectIdentifier encryptedContentType, AlgorithmIdentifier encAlgId, byte[] encryptedContent)
    {
        ASN1OctetString encContent = new BEROctetString(encryptedContent);

        return new EncryptedContentInfo(
            encryptedContentType,
            encAlgId,
            encContent);
    }

    static ASN1EncodableVector getRecipentInfos(GenericKey encKey, List recipientInfoGenerators)
        throws CMSException
    {
        ASN1EncodableVector recipientInfos = new ASN1EncodableVector();
        Iterator it = recipientInfoGenerators.iterator();

        while (it.hasNext())
        {
            RecipientInfoGenerator recipient = (RecipientInfoGenerator)it.next();

            recipientInfos.add(recipient.generate(encKey));
        }
        return recipientInfos;
    }

    static void addRecipientInfosToGenerator(ASN1EncodableVector recipientInfos, BERSequenceGenerator authGen, boolean berEncodeRecipientSet)
        throws IOException
    {
        if (berEncodeRecipientSet)
        {
            authGen.getRawOutputStream().write(new BERSet(recipientInfos).getEncoded());
        }
        else
        {
            authGen.getRawOutputStream().write(new DERSet(recipientInfos).getEncoded());
        }
    }

    static void addOriginatorInfoToGenerator(BERSequenceGenerator envGen, OriginatorInfo originatorInfo)
        throws IOException
    {
        if (originatorInfo != null)
        {
            envGen.addObject(new DERTaggedObject(false, 0, originatorInfo));
        }
    }

    static void addAttriSetToGenerator(BERSequenceGenerator gen, CMSAttributeTableGenerator attriGen, int tagNo, Map parameters)
        throws IOException
    {
        if (attriGen != null)
        {
            gen.addObject(new DERTaggedObject(false, tagNo, new BERSet(attriGen.getAttributes(parameters).toASN1EncodableVector())));
        }
    }

    static ASN1Set processAuthAttrSet(CMSAttributeTableGenerator authAttrsGenerator, OutputAEADEncryptor encryptor)
        throws IOException
    {
        ASN1Set authenticatedAttrSet = null;
        if (authAttrsGenerator != null)
        {
            AttributeTable attrTable = authAttrsGenerator.getAttributes(new HashMap());

            authenticatedAttrSet = new DERSet(attrTable.toASN1EncodableVector());
            encryptor.getAADStream().write(authenticatedAttrSet.getEncoded(ASN1Encoding.DER));
        }
        return authenticatedAttrSet;
    }

    static AttributeTable getAttributesTable(ASN1SetParser set)
        throws IOException
    {
        if (set != null)
        {
            ASN1EncodableVector v = new ASN1EncodableVector();
            ASN1Encodable o;

            while ((o = set.readObject()) != null)
            {
                ASN1SequenceParser seq = (ASN1SequenceParser)o;

                v.add(seq.toASN1Primitive());
            }
            return new AttributeTable(new DERSet(v));
        }
        return null;
    }

    static ASN1Set getAttrDLSet(CMSAttributeTableGenerator gen)
    {
        return (gen != null) ? new DLSet(gen.getAttributes(new HashMap()).toASN1EncodableVector()) : null;
    }

    static ASN1Set getAttrBERSet(CMSAttributeTableGenerator gen)
    {
        return (gen != null) ? new BERSet(gen.getAttributes(new HashMap()).toASN1EncodableVector()) : null;
    }

    static byte[] encodeObj(
        ASN1Encodable obj)
        throws IOException
    {
        if (obj != null)
        {
            return obj.toASN1Primitive().getEncoded();
        }

        return null;
    }
}
