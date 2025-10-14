package org.bouncycastle.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.Challenge;
import org.bouncycastle.asn1.cmp.POPODecKeyChallContent;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;

/**
 * POPODecKeyChallContent ::= SEQUENCE OF Challenge
 * -- One Challenge per encryption key certification request (in the
 * -- same order as these requests appear in CertReqMessages).
 */
public class POPODecryptionKeyChallengeContentBuilder
{
    private final DigestCalculator owfCalculator;
    private final ASN1ObjectIdentifier challengeEncAlg;
    private ASN1EncodableVector challenges = new ASN1EncodableVector();

    public POPODecryptionKeyChallengeContentBuilder(DigestCalculator owfCalculator, ASN1ObjectIdentifier challengeEncAlg)
    {
        this.owfCalculator = owfCalculator;
        this.challengeEncAlg = challengeEncAlg;
    }

    public POPODecryptionKeyChallengeContentBuilder addChallenge(RecipientInfoGenerator recipientInfGenerator, GeneralName recipient, byte[] A)
        throws CMPException
    {
        byte[] integer = Arrays.clone(A);

        try
        {
            OutputStream dOut = owfCalculator.getOutputStream();

            dOut.write(new ASN1Integer(integer).getEncoded());

            dOut.close();
        }
        catch (IOException e)
        {
            throw new CMPException("unable to calculate witness", e);
        }

        CMSEnvelopedData encryptedChallenge;
        try
        {
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

            edGen.addRecipientInfoGenerator(recipientInfGenerator);

            encryptedChallenge = edGen.generate(
                new CMSProcessableByteArray(new Challenge.Rand(A, recipient).getEncoded()),
                new JceCMSContentEncryptorBuilder(challengeEncAlg).setProvider("BC").build());
        }
        catch (Exception e)
        {
            throw new CMPException("unable to encrypt challenge", e);
        }

        EnvelopedData encryptedRand = EnvelopedData.getInstance(encryptedChallenge.toASN1Structure().getContent());

        if (this.challenges.size() == 0)
        {
            this.challenges.add(new Challenge(owfCalculator.getAlgorithmIdentifier(), owfCalculator.getDigest(), encryptedRand));
        }
        else
        {
            this.challenges.add(new Challenge(owfCalculator.getDigest(), encryptedRand));
        }
        return this;
    }

    public POPODecryptionKeyChallengeContent build()
    {
        return new POPODecryptionKeyChallengeContent(POPODecKeyChallContent.getInstance(new DERSequence(challenges)), new DigestCalculatorProvider()
        {
            @Override
            public DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier)
                throws OperatorCreationException
            {
                return owfCalculator;
            }
        });
    }
}
