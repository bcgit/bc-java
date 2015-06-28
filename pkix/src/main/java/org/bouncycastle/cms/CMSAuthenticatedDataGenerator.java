package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.TeeOutputStream;

/**
 * General class for generating a CMS authenticated-data message.
 *
 * A simple example of usage.
 *
 * <pre>
 *      CMSAuthenticatedDataGenerator  fact = new CMSAuthenticatedDataGenerator();
 *
 *      adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
 *
 *      CMSAuthenticatedData         data = fact.generate(new CMSProcessableByteArray(data),
 *                              new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build()));
 * </pre>
 */
public class CMSAuthenticatedDataGenerator
    extends CMSAuthenticatedGenerator
{
    /**
     * base constructor
     */
    public CMSAuthenticatedDataGenerator()
    {
    }

    /**
     * Generate an authenticated data object from the passed in typedData and MacCalculator.
     *
     * @param typedData the data to have a MAC attached.
     * @param macCalculator the calculator of the MAC to be attached.
     * @return the resulting CMSAuthenticatedData object.
     * @throws CMSException on failure in encoding data or processing recipients.
     */
    public CMSAuthenticatedData generate(CMSTypedData typedData, MacCalculator macCalculator)
        throws CMSException
    {
        return generate(typedData, macCalculator, null);
    }

    /**
     * Generate an authenticated data object from the passed in typedData and MacCalculator.
     *
     * @param typedData the data to have a MAC attached.
     * @param macCalculator the calculator of the MAC to be attached.
     * @param digestCalculator calculator for computing digest of the encapsulated data.
     * @return the resulting CMSAuthenticatedData object.
     * @throws CMSException on failure in encoding data or processing recipients.    
     */
    public CMSAuthenticatedData generate(CMSTypedData typedData, MacCalculator macCalculator, final DigestCalculator digestCalculator)
        throws CMSException
    {
        ASN1EncodableVector     recipientInfos = new ASN1EncodableVector();
        ASN1OctetString         encContent;
        ASN1OctetString         macResult;

        for (Iterator it = recipientInfoGenerators.iterator(); it.hasNext();)
        {
            RecipientInfoGenerator recipient = (RecipientInfoGenerator)it.next();

            recipientInfos.add(recipient.generate(macCalculator.getKey()));
        }

        AuthenticatedData authData;

        if (digestCalculator != null)
        {
            try
            {
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                OutputStream out = new TeeOutputStream(digestCalculator.getOutputStream(), bOut);

                typedData.write(out);

                out.close();

                encContent = new BEROctetString(bOut.toByteArray());
            }
            catch (IOException e)
            {
                throw new CMSException("unable to perform digest calculation: " + e.getMessage(), e);
            }

            Map parameters = getBaseParameters(typedData.getContentType(), digestCalculator.getAlgorithmIdentifier(), macCalculator.getAlgorithmIdentifier(), digestCalculator.getDigest());

            if (authGen == null)
            {
                authGen = new DefaultAuthenticatedAttributeTableGenerator();
            }
            ASN1Set authed = new DERSet(authGen.getAttributes(Collections.unmodifiableMap(parameters)).toASN1EncodableVector());

            try
            {
                OutputStream mOut = macCalculator.getOutputStream();

                mOut.write(authed.getEncoded(ASN1Encoding.DER));

                mOut.close();

                macResult = new DEROctetString(macCalculator.getMac());
            }
            catch (IOException e)
            {
                throw new CMSException("exception decoding algorithm parameters.", e);
            }
            ASN1Set unauthed = (unauthGen != null) ? new BERSet(unauthGen.getAttributes(Collections.unmodifiableMap(parameters)).toASN1EncodableVector()) : null;

            ContentInfo  eci = new ContentInfo(
                            CMSObjectIdentifiers.data,
                            encContent);

            authData = new AuthenticatedData(originatorInfo, new DERSet(recipientInfos), macCalculator.getAlgorithmIdentifier(), digestCalculator.getAlgorithmIdentifier(), eci, authed, macResult, unauthed);
        }
        else
        {
            try
            {
                ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
                OutputStream mOut = new TeeOutputStream(bOut, macCalculator.getOutputStream());

                typedData.write(mOut);

                mOut.close();

                encContent = new BEROctetString(bOut.toByteArray());

                macResult = new DEROctetString(macCalculator.getMac());
            }
            catch (IOException e)
            {
                throw new CMSException("exception decoding algorithm parameters.", e);
            }

            ASN1Set unauthed = (unauthGen != null) ? new BERSet(unauthGen.getAttributes(new HashMap()).toASN1EncodableVector()) : null;

            ContentInfo  eci = new ContentInfo(
                            CMSObjectIdentifiers.data,
                            encContent);

            authData = new AuthenticatedData(originatorInfo, new DERSet(recipientInfos), macCalculator.getAlgorithmIdentifier(), null, eci, null, macResult, unauthed);
        }

        ContentInfo contentInfo = new ContentInfo(
                CMSObjectIdentifiers.authenticatedData, authData);

        return new CMSAuthenticatedData(contentInfo, new DigestCalculatorProvider()
        {
            public DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier)
                throws OperatorCreationException
            {
                return digestCalculator;
            }
        });
    }
}