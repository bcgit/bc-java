package org.bouncycastle.asn1.cms.test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.CompressedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.EncryptedContentInfoParser;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.EnvelopedDataParser;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class CMSTest
    implements Test
{
    //
    // compressed data object
    //
    byte[]  compData = Base64.decode(
                    "MIAGCyqGSIb3DQEJEAEJoIAwgAIBADANBgsqhkiG9w0BCRADCDCABgkqhkiG9w0BBwGggASCAh54"
                  + "nO2UXW/aMBSG7yv5P+T6lWDxVxitdmGMm6FRQEkqdb0LWRoi0QAmROPf1x6FFu0v9LVz/BH7sX1O"
                  + "Yr1p2rJpe9lxW94G+Xa7rou8rTfNNzOe9J4ouwua/LX8EdvNYcv6fykjN/o8x+bN/qW0PdMUmz91"
                  + "U90Gy7rJ7fFjyLjebzf72gNvg7pZ1015F7zU6/I/KLmZpAphiP1FvmUvwvMz9G89nc9M8C7ftVBJ"
                  + "NjPJpWsY0TAcgIWU49ERmIOE76IIkQEkTrGYI6VXCQm9SlekM0HgydV5KEOSZvguT2zh2WRkYr/j"
                  + "kQHLIThngnHRScn4BcXbQnRHJjq24p3P/gQTM0U4RGKcJfoxAaXIkhlkJCNE0pURJg/3jh29g0hi"
                  + "7hEpv4ilBbdcuFxwTtmuaKtCCiSli0vZFGUwO7wuS0sWJoFS+OkiFsSH1gUHegHa54y5h/eFE7xs"
                  + "VYmy6kQrSKaeINqqXbaitS4jnqJaVSucFUOT+/kI2QJa4dHHj2E8f4DWbgfVYZ3bYLo5fU/7YFva"
                  + "ICvt655oN2FsoJ07heRg0vkP4yFS5wnGGRXOipP/nPNMCsGY8HWSKg2FkR+vDLgUEly4F2F49twg"
                  + "GmDgTSTJYk5dF+3leQ56CiBUimHY93EaQ/3CvyVkxyUXu+jFF53wVvJux3ec4UOK4tja1Rf1i/pF"
                  + "df9wBkpSd9mxT3dgbEA/LksyMepTm5I3c/eXNAAAAAAAAAAAAAA=");
    
    //
    // enveloped data
    //
    byte[]   envDataKeyTrns = Base64.decode(
            "MIAGCSqGSIb3DQEHA6CAMIACAQAxgcQwgcECAQAwKjAlMRYwFAYDVQQKEw1Cb3Vu"
          + "Y3kgQ2FzdGxlMQswCQYDVQQGEwJBVQIBCjANBgkqhkiG9w0BAQEFAASBgC5vdGrB"
          + "itQSGwifLf3KwPILjaB4WEXgT/IIO1KDzrsbItCJsMA0Smq2y0zptxT0pSRL6JRg"
          + "NMxLk1ySnrIrvGiEPLMR1zjxlT8yQ6VLX+kEoK43ztd1aaLw0oBfrcXcLN7BEpZ1"
          + "TIdjlBfXIOx1S88WY1MiYqJJFc3LMwRUaTEDMIAGCSqGSIb3DQEHATAdBglghkgB"
          + "ZQMEARYEEAfxLMWeaBOTTZQwUq0Y5FuggAQgwOJhL04rjSZCBCSOv5i5XpFfGsOd"
          + "YSHSqwntGpFqCx4AAAAAAAAAAAAA");
    
    byte[]   envDataKEK = Base64.decode(
            "MIAGCSqGSIb3DQEHA6CAMIACAQIxUqJQAgEEMAcEBQECAwQFMBAGCyqGSIb3DQEJE"
          + "AMHAgE6BDC7G/HyUPilIrin2Yeajqmj795VoLWETRnZAAFcAiQdoQWyz+oCh6WY/H"
          + "jHHi+0y+cwgAYJKoZIhvcNAQcBMBQGCCqGSIb3DQMHBAiY3eDBBbF6naCABBiNdzJb"
          + "/v6+UZB3XXKipxFDUpz9GyjzB+gAAAAAAAAAAAAA");

    byte[] envDataNestedNDEF = Base64.decode(
          "MIAGCSqGSIb3DQEHA6CAMIACAQAxge8wgewCAQAwgZUwgY8xKDAmBgNVBAoMH1RoZSBMZWdpb24g"
        + "b2YgdGhlIEJvdW5jeSBDYXN0bGUxLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3Vu"
        + "Y3ljYXN0bGUub3JnMREwDwYDVQQIDAhWaWN0b3JpYTESMBAGA1UEBwwJTWVsYm91cm5lMQswCQYD"
        + "VQQGEwJBVQIBATANBgkqhkiG9w0BAQEFAARABIXMd8xiTyWDKO/LQfvdGYTPW3I9oSQWwtm4OIaN"
        + "VINpfY2lfwTvbmE6VXiLKeALC0dMBV8z7DEM9hE0HVmvLDCABgkqhkiG9w0BBwEwHQYJYIZIAWUD"
        + "BAECBBB32ko6WrVxDTqwUYEpV6IUoIAEggKgS6RowrhNlmWWI13zxD/lryxkZ5oWXPUfNiUxYX/P"
        + "r5iscW3s8VKJKUpJ4W5SNA7JGL4l/5LmSnJ4Qu/xzxcoH4r4vmt75EDE9p2Ob2Xi1NuSFAZubJFc"
        + "Zlnp4e05UHKikmoaz0PbiAi277sLQlK2FcVsntTYVT00y8+IwuuQu0ATVqkXC+VhfjV/sK6vQZnw"
        + "2rQKedZhLB7B4dUkmxCujb/UAq4lgSpLMXg2P6wMimTczXyQxRiZxPeI4ByCENjkafXbfcJft2eD"
        + "gv1DEDdYM5WrW9Z75b4lmJiOJ/xxDniHCvum7KGXzpK1d1mqTlpzPC2xoz08/MO4lRf5Mb0bYdq6"
        + "CjMaYqVwGsYryp/2ayX+d8H+JphEG+V9Eg8uPcDoibwhDI4KkoyGHstPw5bxcy7vVFt7LXUdNjJc"
        + "K1wxaUKEXDGKt9Vj93FnBTLMX0Pc9HpueV5o1ipX34dn/P3HZB9XK8ScbrE38B1VnIgylStnhVFO"
        + "Cj9s7qSVqI2L+xYHJRHsxaMumIRnmRuOqdXDfIo28EZAnFtQ/b9BziMGVvAW5+A8h8s2oazhSmK2"
        + "23ftV7uv98ScgE8fCd3PwT1kKJM83ThTYyBzokvMfPYCCvsonMV+kTWXhWcwjYTS4ukrpR452ZdW"
        + "l3aJqDnzobt5FK4T8OGciOj+1PxYFZyRmCuafm2Dx6o7Et2Tu/T5HYvhdY9jHyqtDl2PXH4CTnVi"
        + "gA1YOAArjPVmsZVwAM3Ml46uyXXhcsXwQ1X0Tv4D+PSa/id4UQ2cObOw8Cj1eW2GB8iJIZVqkZaU"
        + "XBexqgWYOIoxjqODSeoZKiBsTK3c+oOUBqBDueY1i55swE2o6dDt95FluX6iyr/q4w2wLt3upY1J"
        + "YL+TuvZxAKviuAczMS1bAAAAAAAAAAAAAA==");

    //
    // signed data
    //
    byte[]   signedData = Base64.decode(
            "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCA"
                + "BAxIZWxsbyBXb3JsZCEAAAAAoIIEYjCCAg0wggF2oAMCAQICAQEwDQYJKoZIhvcN"
                + "AQEEBQAwJTEWMBQGA1UEChMNQm91bmN5IENhc3RsZTELMAkGA1UEBhMCQVUwHhcN"
                + "MDQxMDI0MDQzMDU4WhcNMDUwMjAxMDQzMDU4WjAlMRYwFAYDVQQKEw1Cb3VuY3kg"
                + "Q2FzdGxlMQswCQYDVQQGEwJBVTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA"
                + "mPc4CyEA6AOY9xhnWN01K6E4dEf1WEL88bXsV2IidUZza6UmESJ8RCBr+6pkKlJ3"
                + "WcewlRkqb2TVtWd5bMLT3jWL1md/GBvaOddexrmTAHYoRURKs5axGNJG2diIuCoE"
                + "bSvOloyfkDme27s3TjToR6wGF7X1yNkBqB4QcZkNu58CAwEAAaNNMEswHQYDVR0O"
                + "BBYEFH+Ic0o6jp/gHJYUXLBE1nrldKvWMB8GA1UdIwQYMBaAFH+Ic0o6jp/gHJYU"
                + "XLBE1nrldKvWMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEEBQADgYEAUwkntA6kejfR"
                + "ueVDg3Lc8Kcr5J74bDdOlpganzj5rx8YP0OZ7vwbo0SyC+kUZPKgvG8ngIHzgrPK"
                + "z7WnYd1fOhmLJcB6vlLgjCm0TdPHEXArKPbxxGszp0rjsMPJdSRXSrAEAw2W7CeT"
                + "+ejgruKXM3YxmTmXvBfI1r3InoIdbp0wggJNMIIBtqADAgECAgECMA0GCSqGSIb3"
                + "DQEBBAUAMCUxFjAUBgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJBgNVBAYTAkFVMB4X"
                + "DTA0MTAyNDA0MzA1OVoXDTA1MDIwMTA0MzA1OVowZTEYMBYGA1UEAxMPRXJpYyBI"
                + "LiBFY2hpZG5hMSQwIgYJKoZIhvcNAQkBFhVlcmljQGJvdW5jeWNhc3RsZS5vcmcx"
                + "FjAUBgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJBgNVBAYTAkFVMIGfMA0GCSqGSIb3"
                + "DQEBAQUAA4GNADCBiQKBgQCb7kKcZTpbjmJSkKxoaSfmAOu5m/eP+js3pqCZFmGK"
                + "RosbYkXoQJpfXeKKhUl+bMGw8rEAAJbC5NcKhJJcby+Ir+qlIfAml9AdgSG1wLQL"
                + "EiqWeW2/cpAAbCH893ClI+9I2eRAEa+0Wr772CdcMFvKd8/xvYvYSKzRf1TbLqAW"
                + "IwIDAQABo00wSzAdBgNVHQ4EFgQUQCY6SycXroWhCbohAFU3rq8mjVMwHwYDVR0j"
                + "BBgwFoAUf4hzSjqOn+AclhRcsETWeuV0q9YwCQYDVR0TBAIwADANBgkqhkiG9w0B"
                + "AQQFAAOBgQAR4iO82Qow9T9lgK7VOqMZk8SqL6CWe2DaEL8IXSgbIcWky4a0x6kX"
                + "em5b67MozWzrVqvdqGJ2ndcWGv8YRT9fErbgCiUjfIWDE/w9GBRaZCLNNBelZSaG"
                + "WwF7W4gpUR80DMKC1h8lDwckgqxQJx1Z4IpUqziNGKiex6TWujOQ8TGCAS8wggEr"
                + "AgEBMCowJTEWMBQGA1UEChMNQm91bmN5IENhc3RsZTELMAkGA1UEBhMCQVUCAQIw"
                + "CQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcN"
                + "AQkFMQ8XDTA0MTAyNDA0MzA1OVowIwYJKoZIhvcNAQkEMRYEFC73veYIzlQE6X1f"
                + "BC+V+J8cIyhxMA0GCSqGSIb3DQEBAQUABIGAYdt7f+Nxm7pv96tGFzc8SOIxQ7yY"
                + "QhGI1gGvn+8U2GSvLxOsZ86kjjmbuC7UxLT+91qzvKS+J2X+w1l87QamEQhRoiMx"
                + "FPdTrK5NYXhoulq0lttGwh6kk78HaR0gBtXlIJtmBUMkg85Haqeu4c3bAsVr58S/"
                + "gnzBDxfC+TQLyIwAAAAAAAA=");

    private boolean isSameAs(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }
        
        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        
        return true;
    }
    
    private TestResult compressionTest()
    {
        try
        {
            ContentInfo info = ContentInfo.getInstance(ASN1Primitive.fromByteArray(compData));
            CompressedData data = CompressedData.getInstance(info.getContent());

            data = new CompressedData(data.getCompressionAlgorithmIdentifier(), data.getEncapContentInfo());
            info = new ContentInfo(CMSObjectIdentifiers.compressedData, data);

            byte[] encoding = info.getEncoded();
            if (!isSameAs(encoding, compData))
            {
                return new SimpleTestResult(false, getName() + ": CMS compression failed to re-encode");
            }

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": CMS compression failed - " + e.toString(), e);
        }
    }
    
    private TestResult envelopedTest()
    {
        try
        {
            //
            // Key trans
            //
            ContentInfo info = ContentInfo.getInstance(ASN1Primitive.fromByteArray(envDataKeyTrns));
            EnvelopedData envData = EnvelopedData.getInstance(info.getContent());
            ASN1Set s = envData.getRecipientInfos();

            if (s.size() != 1)
            {
                return new SimpleTestResult(false, getName() + ": CMS KeyTrans enveloped, wrong number of recipients");
            }

            RecipientInfo recip = RecipientInfo.getInstance(s.getObjectAt(0));

            if (recip.getInfo() instanceof KeyTransRecipientInfo)
            {
                KeyTransRecipientInfo inf = KeyTransRecipientInfo.getInstance(recip.getInfo());

                inf = new KeyTransRecipientInfo(inf.getRecipientIdentifier(), inf.getKeyEncryptionAlgorithm(),
                    inf.getEncryptedKey());

                s = new DERSet(new RecipientInfo(inf));
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": CMS KeyTrans enveloped, wrong recipient type");
            }

            envData = new EnvelopedData(envData.getOriginatorInfo(), s, envData.getEncryptedContentInfo(), envData.getUnprotectedAttrs());
            info = new ContentInfo(CMSObjectIdentifiers.envelopedData, envData);

            byte[] encoding = info.getEncoded();
            if (!isSameAs(encoding, envDataKeyTrns))
            {
                return new SimpleTestResult(false, getName() + ": CMS KeyTrans enveloped failed to re-encode");
            }
            
            //
            // KEK
            //
            info = ContentInfo.getInstance(ASN1Primitive.fromByteArray(envDataKEK));
            envData = EnvelopedData.getInstance(info.getContent());
            s = envData.getRecipientInfos();

            if (s.size() != 1)
            {
                return new SimpleTestResult(false, getName() + ": CMS KEK enveloped, wrong number of recipients");
            }

            recip = RecipientInfo.getInstance(s.getObjectAt(0));

            if (recip.getInfo() instanceof KEKRecipientInfo)
            {
                KEKRecipientInfo inf = KEKRecipientInfo.getInstance(recip.getInfo());

                inf = new KEKRecipientInfo(inf.getKekid(), inf.getKeyEncryptionAlgorithm(), inf.getEncryptedKey());

                s = new DERSet(new RecipientInfo(inf));
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": CMS KEK enveloped, wrong recipient type");
            }

            envData = new EnvelopedData(envData.getOriginatorInfo(), s, envData.getEncryptedContentInfo(),
                envData.getUnprotectedAttrs());
            info = new ContentInfo(CMSObjectIdentifiers.envelopedData, envData);

            encoding = info.getEncoded();
            if (!isSameAs(encoding, envDataKEK))
            {
                return new SimpleTestResult(false, getName() + ": CMS KEK enveloped failed to re-encode");
            }

            // Nested NDEF problem
            ASN1StreamParser asn1In = new ASN1StreamParser(new ByteArrayInputStream(envDataNestedNDEF));
            ContentInfoParser ci = new ContentInfoParser((ASN1SequenceParser)asn1In.readObject());
            EnvelopedDataParser ed = new EnvelopedDataParser((ASN1SequenceParser)ci
                .getContent(BERTags.SEQUENCE));
            ed.getVersion();
            ed.getOriginatorInfo();
            ed.getRecipientInfos().toASN1Primitive();
            EncryptedContentInfoParser eci = ed.getEncryptedContentInfo();
            eci.getContentType();
            eci.getContentEncryptionAlgorithm();

            InputStream dataIn = ((ASN1OctetStringParser)eci.getEncryptedContent(BERTags.OCTET_STRING))
                .getOctetStream();
            Streams.drain(dataIn);
            dataIn.close();

            // Test data doesn't have unprotected attrs, bug was being thrown by this call
            ASN1SetParser upa = ed.getUnprotectedAttrs();
            if (upa != null)
            {
                upa.toASN1Primitive();
            }

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": CMS enveloped failed - " + e.toString(), e);
        }
    }

    private TestResult signedTest()
    {
        try
        {
            ContentInfo info = ContentInfo.getInstance(ASN1Primitive.fromByteArray(signedData));
            SignedData sData = SignedData.getInstance(info.getContent());

            sData = new SignedData(sData.getDigestAlgorithms(), sData.getEncapContentInfo(), sData.getCertificates(),
                sData.getCRLs(), sData.getSignerInfos());
            info = new ContentInfo(CMSObjectIdentifiers.signedData, sData);

            byte[] encoding = info.getEncoded();
            if (!isSameAs(encoding, signedData))
            {
                return new SimpleTestResult(false, getName() + ": CMS signed failed to re-encode");
            }

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": CMS signed failed - " + e.toString(), e);
        }
    }

    public TestResult perform()
    {
        TestResult  res = compressionTest();
        
        if (!res.isSuccessful())
        {
            return res;
        }
        
        res = envelopedTest();
        if (!res.isSuccessful())
        {
            return res;
        }
        
        return signedTest();
    }

    public String getName()
    {
        return "CMS";
    }

    public static void main(
        String[] args)
    {
        CMSTest    test = new CMSTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
