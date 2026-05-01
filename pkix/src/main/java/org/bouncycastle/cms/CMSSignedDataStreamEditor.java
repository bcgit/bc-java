package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.SignedDataParser;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class CMSSignedDataStreamEditor
{
    private static final CMSSignedHelper HELPER = CMSSignedHelper.INSTANCE;
    private static final DefaultDigestAlgorithmIdentifierFinder dgstAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
    /**
     * Add the specified digest algorithm to the signed data contained in the input stream and write
     * the updated signed data to the provided output stream. This ensures that the output signed data
     * includes the specified digest algorithm. Uses the provided DigestAlgorithmIdentifierFinder to
     * create the digest sets and the DigestCalculatorProvider for computing the required digests.
     * <p>
     * The output stream is returned unclosed.
     * </p>
     *
     * @param out                    the output stream where the updated signed data object will be written.
     * @param original               the input stream containing the original signed data to be modified.
     * @param digestAlgorithm        the digest algorithm to be added to the signed data.
     * @param digestAlgIdFinder      the DigestAlgorithmIdentifierFinder used to create the digest sets.
     * @param digestCalculatorProvider the DigestCalculatorProvider used to compute the digests.
     * @return the output stream containing the updated signed data.
     */
    public static OutputStream addDigestAlgorithm(OutputStream out, InputStream original,
                                                  AlgorithmIdentifier digestAlgorithm,
                                                  DigestAlgorithmIdentifierFinder digestAlgIdFinder,
                                                  DigestCalculatorProvider digestCalculatorProvider)
        throws IOException, CMSException
    {
        ContentInfoParser contentInfo = new ContentInfoParser((ASN1SequenceParser)new ASN1StreamParser(original).readObject());
        SignedDataParser signedData = SignedDataParser.getInstance(contentInfo.getContent(BERTags.SEQUENCE));
        BERSequenceGenerator sGen = new BERSequenceGenerator(out);

        sGen.addObject(CMSObjectIdentifiers.signedData);

        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

        // version number
        sigGen.addObject(signedData.getVersion());
        // digests
        ASN1EncodableVector digestAlgs = new ASN1EncodableVector();
        Map<AlgorithmIdentifier, DigestCalculator> digests = new LinkedHashMap<AlgorithmIdentifier, DigestCalculator>();
        try
        {
            for (Iterator it = ((DLSet)signedData.getDigestAlgorithms().toASN1Primitive()).iterator(); it.hasNext(); )
            {
                AlgorithmIdentifier oid = AlgorithmIdentifier.getInstance(it.next());
                digestAlgs.add(HELPER.fixDigestAlgID(oid, digestAlgIdFinder));
                digests.put(oid, digestCalculatorProvider.get(oid));
            }
            if (!digests.containsKey(digestAlgorithm))
            {
                digestAlgs.add(HELPER.fixDigestAlgID(digestAlgorithm, digestAlgIdFinder));
                digests.put(digestAlgorithm, digestCalculatorProvider.get(digestAlgorithm));
            }
        }
        catch (OperatorCreationException e)
        {
            throw new CMSException("unable to find digest algorithm");
        }
        sigGen.addObject(new DERSet(digestAlgs));

        CMSSignedDataParser.writeEncapContentInfoToGenerator(signedData, sigGen);

        CMSSignedDataParser.writeSetToGeneratorTagged(sigGen, signedData.getCertificates(), 0);
        CMSSignedDataParser.writeSetToGeneratorTagged(sigGen, signedData.getCrls(), 1);
        sigGen.addObject(signedData.getSignerInfos());

        sigGen.close();
        sGen.close();

        return out;
    }

    /**
     * Add the specified digest algorithm to the signed data contained in the input stream and write
     * the updated signed data to the provided output stream. This ensures that the output signed data
     * includes the specified digest algorithm.
     * <p>
     * The output stream is returned unclosed.
     * </p>
     *
     * @param out                    the output stream where the updated signed data object will be written.
     * @param original               the input stream containing the original signed data to be modified.
     * @param digestAlgorithm        the digest algorithm to be added to the signed data.
     * @return the output stream containing the updated signed data.
     */
    public static OutputStream addDigestAlgorithm(OutputStream out, InputStream original, AlgorithmIdentifier digestAlgorithm, DigestCalculatorProvider digestCalculatorProvider)
        throws IOException, CMSException
    {
        return addDigestAlgorithm(out, original, digestAlgorithm, dgstAlgFinder, digestCalculatorProvider);
    }
}
