package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPKeyGenerator;
import org.bouncycastle.openpgp.api.SignatureParameters;
import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction;
import org.bouncycastle.openpgp.api.util.UTCUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.Strings;

public class OpenPGPCertificateTest
        extends APITest
{

    @Override
    public String getName()
    {
        return "OpenPGPCertificateTest";
    }

    @Override
    protected void performTestWith(OpenPGPApi api)
            throws IOException, PGPException
    {
        testOpenPGPv6Key(api);

        testBaseCasePrimaryKeySigns(api);
        testBaseCaseSubkeySigns(api);
        testPKSignsPKRevokedNoSubpacket(api);
        testSKSignsPKRevokedNoSubpacket(api);
        testPKSignsPKRevocationSuperseded(api);
        testGetPrimaryUserId(api);
    }

    private void testOpenPGPv6Key(OpenPGPApi api)
            throws IOException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);

        isTrue("Test key has no identities", key.getIdentities().isEmpty());

        OpenPGPCertificate.OpenPGPPrimaryKey primaryKey = key.getPrimaryKey();
        isEquals("Primary key identifier mismatch",
                new KeyIdentifier("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"),
                primaryKey.getKeyIdentifier());
        OpenPGPKey.OpenPGPSecretKey secretPrimaryKey = key.getSecretKey(primaryKey);
        isTrue("Secret Primary key MUST have reference to its public component",
                primaryKey == secretPrimaryKey.getPublicKey());
        isTrue("Primary key is expected to be signing key", primaryKey.isSigningKey());
        isTrue("Primary secret key is expected to be signing key", secretPrimaryKey.isSigningKey());
        isTrue("Primary secret key is expected to be certification key", secretPrimaryKey.isCertificationKey());
        isTrue("Primary key is expected to be certification key", primaryKey.isCertificationKey());

        List<OpenPGPCertificate.OpenPGPComponentKey> signingKeys = key.getSigningKeys();
        isEquals("Expected exactly 1 signing key", 1, signingKeys.size());
        OpenPGPCertificate.OpenPGPPrimaryKey signingKey = (OpenPGPCertificate.OpenPGPPrimaryKey) signingKeys.get(0);
        isEquals("Signing key is expected to be the same as primary key", primaryKey, signingKey);

        Features signingKeyFeatures = signingKey.getFeatures();
        // Features are extracted from direct-key signature
        isEquals("Signing key features mismatch. Expect features to be extracted from DK signature.",
                Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2,
                signingKeyFeatures.getFeatures());

        List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = key.getEncryptionKeys();
        isEquals("Expected exactly 1 encryption key", 1, encryptionKeys.size());
        OpenPGPCertificate.OpenPGPSubkey encryptionKey = (OpenPGPCertificate.OpenPGPSubkey) encryptionKeys.get(0);
        isTrue("Subkey MUST be encryption key", encryptionKey.isEncryptionKey());
        isEquals("Encryption subkey identifier mismatch",
                new KeyIdentifier("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"),
                encryptionKey.getKeyIdentifier());

        KeyFlags encryptionKeyFlags = encryptionKey.getKeyFlags();
        // Key Flags are extracted from subkey-binding signature
        isEquals("Encryption key flag mismatch. Expected key flags to be extracted from SB sig.",
                KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE,
                encryptionKeyFlags.getFlags());

        Features encryptionKeyFeatures = encryptionKey.getFeatures();
        // Features are extracted from direct-key signature
        isEquals("Encryption key features mismatch. Expected features to be extracted from DK sig.",
                Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2,
                encryptionKeyFeatures.getFeatures());
    }

    private void testBaseCasePrimaryKeySigns(OpenPGPApi api)
            throws IOException
    {
        // https://sequoia-pgp.gitlab.io/openpgp-interoperability-test-suite/results.html#Key_revocation_test__primary_key_signs_and_is_not_revoked__base_case_
        String cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsBNBFpJegABCACzr1V+GxVkrtfDjihYK+HtyEIcO52uw7O2kd7JbduYp4RK17jy\n" +
                "75N3EnsgmiIkSxXCWr+rTtonNs1zCJeUa/gwnNfs7mVgjL2rMOZU/KZ4MP0yOYU5\n" +
                "u5FjNPWz8hpFQ9GKqfdj0Op61h1pCQO45IjUQ3dCDj9Rfn44zHMB1ZrbmIH9nTR1\n" +
                "YIGHWmdm0LItb2WxIkwzWBAJ5acTlsmLyZZEQ1+8NDqktyzwFoQqTJvLU4StY2k6\n" +
                "h18ZKZdPyrdLoEyOuWkvjxmbhDk1Gt5KiS/yy7mrzIPLr0dmJe4vc8WLV+bXoyNE\n" +
                "x3H8o9CFcYehLfyqsy40lg92d6Kp96ww8dZ5ABEBAAHCwMQEHwEKAHgFgl4L4QAJ\n" +
                "EAitUcrkcPAGRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9y\n" +
                "Z4csZe1ah1tj2AjxfdDMsH2wvSEwZjb/73ICKnm7BySQAhUKApsDAh4BFiEE4yy2\n" +
                "2oICkbfnbbGoCK1RyuRw8AYAAGYFCACiKnCb2NBZa/Jj1aJe4R2rxPZj2ERXWe3b\n" +
                "JKNPKT7K0rVDkTw1JRiTfCsuAY2lY9sKJdhQZl+azXm64vvTc6hEGRQ/+XssDlE2\n" +
                "DIn8C34HDc495ZnryHNB8Dd5l1HdjqxfGIY6HBPJUdx0dedwP42Oisg9t5KsC8zl\n" +
                "d/+MIRgzkp+Dg0LXJVnDuwWEPoo2N6WhAr5ReLvXxALX5ht9Lb3lP0DASZvAKy9B\n" +
                "O/wRCr294J8dg/CowAfloyf0Ko+JjyjanmZn3acy5CGkVN2mc+PFUekGZDDy5ooY\n" +
                "kgXO/CmApuTNvabct+A7IVVdWWM5SWb90JvaV9SWji6nQphVm7StwsDEBB8BCgB4\n" +
                "BYJaSXoACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lh\n" +
                "LXBncC5vcmfVZdjLYZxDX2hvy3aGrsE4i0avLDMzf3e9kVHmaD6PAgIVCgKbAwIe\n" +
                "ARYhBOMsttqCApG3522xqAitUcrkcPAGAABQYwgArfIRxq95npUKAOPXs25nZlvy\n" +
                "+xQbrmsTxHhAYW8eGFcz82QwumoqrR8VfrojxM+eCZdTI85nM5kzznYDU2+cMhsZ\n" +
                "Vm5+VhGZy3e3QH4J/E31D7t1opCvj5g1eRJ4LgywB+cYGcZBYp/bQT9SUYuhZH2O\n" +
                "XCR04qSbpVUCIApnhBHxKNtOlqjAkHeaOdW/8XePsbfvrtVOLGYgrZXfY7Nqy3+W\n" +
                "zbdm8UvVPFXH+uHEzTgyvYbnJBYkjORmCqUKs860PL8ekeg+sL4PHSRj1UUfwcQD\n" +
                "55q0m3Vtew2KiIUi4wKi5LceDtprjoO5utU/1YfEAiNMeSQHXKq83dpazvjrUs0S\n" +
                "anVsaWV0QGV4YW1wbGUub3JnwsDEBBMBCgB4BYJaSXoACRAIrVHK5HDwBkcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmc6Rix7CeIfWwnaQjk3\n" +
                "bBrkAiY7jS9N+shuRdHZ0gKKsgIVCgKbAwIeARYhBOMsttqCApG3522xqAitUcrk\n" +
                "cPAGAACf9QgAsxtfAbyGbtofjrXTs9lsKEWvGgk02fSYyKjPbyaRqh72MlIlUXwq\n" +
                "q1ih2TJc3vwF8aNVDrcb9DnBabdt2M1vI3PUaeG31BmakC/XZCNCrbbJkyd/vdML\n" +
                "qw7prLrp0auVNNhLYxOK9usXbClNxluo4i/lSFVo5B9ai+ne1kKKiplzqy2qqhde\n" +
                "plomcwGHbB1CkZ04DmCMbSSFAGxYqUC/bBm0bolCebw/KIz9sEojNKt6mvsFN67/\n" +
                "hMYeJS0HVlwwc6i8iKSzC2D53iywhtvkdiKECXQeXDf9zNXAn1wpK01SLJ0iig7c\n" +
                "DFrtoqkfPYzbNfC0bt34fNx9iz3w9aEH8c7ATQRaSsuAAQgAu5yau9psltmWiUn7\n" +
                "fsRSqbQInO0iWnu4DK9IXB3ghNYMcii3JJEjHzgIxGf3GiJEjzubyRQaX5J/p7yB\n" +
                "1fOH8z7FYUuax1saGf9c1/b02N9gyXNlHam31hNaaL3ffFczI95p7MNrTtroTt5o\n" +
                "Zqsc+i+oKLZn7X0YAI4tEYwhSnUQYB/F7YqkkI4eV+7CxZPA8pBhXiAOK/zn416P\n" +
                "sZ6JS5wsM65yCtOHcAAIBnKDnC+bQi+f1WZesSocy/rXx3QEQmodDu3ojhS+VxcY\n" +
                "GeZCUcFF0FyZBIkGjHIVQLyOfjP3FRJ4qFXMz9/YIVoM4Y6guTERMTEj/KDG4BP7\n" +
                "RfJHTQARAQABwsI8BBgBCgHwBYJeC+EACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0\n" +
                "QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfcAa1ZPWTtg60w3Oo4dt4Fa8cKFYbZ\n" +
                "YsqDSHV5pwEfMwKbAsC8oAQZAQoAbwWCXgvhAAkQEPy8/w6Op5FHFAAAAAAAHgAg\n" +
                "c2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnL6I2+VyN5T1FoVgj3cdnMLYC\n" +
                "pcB5i/FRSCVKybuLzrgWIQTOphDQhPpR8hHhxGwQ/Lz/Do6nkQAArk8H/AhjM9lq\n" +
                "bffFL6RRR4HTjelspy4A3nyTicCljrDuXDUh23GfLvajTR5h16ZBqAF7cpb9rrlz\n" +
                "1C1WcS5JLVxzXAe7f+KOfXu+eyLhpTzZ8VT3pK3hHGaYwlVlXrBZP0JXgL8hm6hD\n" +
                "SXZQZtcpsnQ1uIHC9ONxUB4liNFhTqQCQYdQJFiFs1umUbo/C4KdzlDI08bM3CqE\n" +
                "Kat9vUFuGG68mDg0CrRZEWt946L5i8kZmBUkSShIm2k5e2qE/muYeM6qKQNsxlx3\n" +
                "VIf5eUhtxCi9fg7SjvHkdUSFstYcxAdaohWCFCEsDJI12hzcKQazSjvtKF4BNBKg\n" +
                "X/wLsbVQnYLd9ggWIQTjLLbaggKRt+dtsagIrVHK5HDwBgAANjMH/1MY7DJyxkiT\n" +
                "jc/jzmnVxqtHOZDCSmUqk0eh/6BHs+ostWqkGC6+7dfxDnptwcqandYey4KF2ajt\n" +
                "4nOwu0xQw/NEF3i81h7IiewY7G+YT69DUd+DvVUQemfKNYVOrMqoH7QU5o4YojdJ\n" +
                "iDeIp2d/JyJrqyof78JFAHnNZgHC2T2zo9E54dnOTY9VNUNCOUct5Rby0GXjTIUR\n" +
                "O0f485eGuZxVWdLRllDYOiCrQHPSHhrxHVXVMbYJoroPy+IyaJanVoAWgyipBmmI\n" +
                "DV8aINM2RLMsGkuPTRtITI2ZlGOQN7xgy4LqWzjPnrzMXfwBEDx/nrwdG6zEGMK8\n" +
                "AkVkMT5uJJvCwjwEGAEKAfAFglro/4AJEAitUcrkcPAGRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ/Q0Z6WDH2+8/F1xEEuiApsjnn2lGNZ2\n" +
                "DeIaklJzdqQOApsCwLygBBkBCgBvBYJa6P+ACRAQ/Lz/Do6nkUcUAAAAAAAeACBz\n" +
                "YWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfrVATyX3tgcM2z41fqYquxVhJR\n" +
                "avN6+w2SU4xEG++SqBYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAABGVggAsB8M2KI5\n" +
                "cxXKKgVHL1dEfzg9halVavktfcT6ZVC/+aDp94tvBCL16Guhq4ccN7DATrWx430/\n" +
                "GecY6E77qvhDzmCclSbdLbiZmsrVX9kCmTfrJzFQ64KfvIS5GgbL21+ZJ+pKW2HO\n" +
                "MBGn6sgAPmTqM5UsDCpsEKDt5CJcJr3sTc8D9NhEnc0dKsQ91+n9ms3W5tyyE6r9\n" +
                "pyM6ThBCMhbQkR7hE9XWAQeO1ILSFGnie0aFcTU0Oo0wL1MaiSyA/8XpKq23xfx1\n" +
                "kNS9hQkdq0aWehNoTJdCt1Nq1cWABy2rQR0x+qhGWowfsAjnBautxvet28t2kPCA\n" +
                "IMniYpWc89BwfhYhBOMsttqCApG3522xqAitUcrkcPAGAACq1gf/Q7H9Re5SWk+U\n" +
                "On/NQPRedf544YJ/YdQnve/hSaPGL33cUzf4yxzFILnK19Ird5f8/mTT1pg99L3i\n" +
                "xE3N5031JJKwFpCB69Rsysg88ZLDL2VLc3xdsAQdUbVaCqeRHKwtMtpBvbAFvF9p\n" +
                "lwam0SSXHHr/JkYm5ufXN6I8ib/nwr1bFbf/Se0Wuk9RG4ne9JUBCrGxakyVd+Og\n" +
                "LLhvzOmJa7fDC0uUZhTKFbjMxLhaas4HFYiRbfz2T0xz9gyDytDWsEFM+XoKHlEH\n" +
                "8Fx/U2B5/8N0Q+pIFoEuOmBO+5EPvPIlxNByHgiaNIuKt1Mu+UAb2Spl6D5zbDfX\n" +
                "/3vqxdhYHw==\n" +
                "=Ric2\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        TestSignature t0 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJYaEaACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmeoPMfalw2oS7uyOKnOXJSN8Gx7pr/BMlo3Xn8nTgx6\n" +
                "ORYhBOMsttqCApG3522xqAitUcrkcPAGAABXbAf/WfWaQYNuATAKwxYrJx4fd5kt\n" +
                "0M6sn1q7wK1MIxursG2+FuKafV25O9+pde8Nog77OEgegwk+HokOVFpVXfOzHQjs\n" +
                "8dwWTtTQlX5NIBNvtqS7cvCKhjsqaHKgmzsenMjCEbpDZ3C5CoqcYicykqEU/Ia0\n" +
                "ZGC4lzRByrgNy/w+/iLN748S707bzBLVc/sE73k9N5pANAlE+cA/sHI1Gp2WxJR9\n" +
                "t2Fk4x6/85PEnF1RHI16p/wSEeuRaBpyw9QGZBbVDVt5wvgttxZjteGGSwBM3WI/\n" +
                "gPfC0LW+JQ2W+dwY0PN/7yuARVRhXpKiBI4xqp7x3OanQX6quU77g3B8nXAt3A==\n" +
                "=StqT\n" +
                "-----END PGP SIGNATURE-----\n", false, "Sig predates primary key");
        TestSignature t1 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJa564ACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfM0EN4Ei0bQv6UO9BRq2wtUfV948cRynRMBb8TSGCG\n" +
                "tBYhBOMsttqCApG3522xqAitUcrkcPAGAAAlNwf+L0KQK9i/xmYKOMV2EX13QUoZ\n" +
                "vvb/pHGZaCQ9JtvEF2l2DT0DqByZ+tOv5Y4isU+un7CraoyvyajAwR0Yqk937B6C\n" +
                "HQHKMkmIl+5R4/xqSoWYmOidbrgilojPMBEhB3INQ8/THjjFijtLzitVhnWBd7+u\n" +
                "s0kcqnWnOdx2By4aDe+UEiyCfSE02e/0tIsM71RqiU91zH6dl6+q8nml7PsYuTFV\n" +
                "V09oQTbBuuvUe+YgN/uvyKVIsA64lQ+YhqEeIA8Quek7fHhW+du9OIhSPsbYodyx\n" +
                "VWMTXwSWKGNvZNAkpmgUYqFjS2Cx5ZUWblZLjrNKBwnnmt50qvUN7+o2pjlnfA==\n" +
                "=UuXb\n" +
                "-----END PGP SIGNATURE-----\n", true);
        TestSignature t2 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJdP4iACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfFzYGoiuSjN+gz1IDD4ZvRXGuPTHks0/pIiGY90mrZ\n" +
                "WxYhBOMsttqCApG3522xqAitUcrkcPAGAABGPAf/ck7tJAFoPIDd9fTPZANpNGoW\n" +
                "Fq6VuNfy/nLjz2gkHFX/lLAxQ0N3McIdRA++Ik/omb0lis3R2DVNgwqNm2OF34HE\n" +
                "qxmPmrQHBgk2q0fDH4NCE0XnYQjQT65V99IfiaQu+oS3Mq8MuYsDYvRVvRKMwt49\n" +
                "fcDnvFtAtCqEETdv6wV5cUZmdQ3L9NU9bApJ0jk+EHVdpfTUIbOYYGnsIe/4Aa0d\n" +
                "jgzu4Em79ynosOn//953XJ7OO8LCDi1EKt+nFuZARUlt/Jwwull6zzp7HUPw6HPt\n" +
                "Upp7os8TIPC4STwoSeEKaxEkrbMGFnDcoDajnKKRt5+MkB24Oq7PHvnzgnPpVg==\n" +
                "=Ljv7\n" +
                "-----END PGP SIGNATURE-----\n", true);
        TestSignature t3 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJmhTYiCRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfbjQf/zfoJQT0hhna4RDjOESBLgGaCbc5HLeo751F4\n" +
                "NxYhBOMsttqCApG3522xqAitUcrkcPAGAABqBQgAkkNmYf6yLPvox+ZayrLtMb9D\n" +
                "ghgt0nau72DSazsJ6SAq2QqIdr0RRhRa2gCETkp4PpeoDWmIvoVj35ZnfyeO/jqy\n" +
                "HECvRwO0WPA5FXQM6uG7s40vDTRFjlJMpPyHWnn2igcR64iDxBGmc40xi9CcmJP9\n" +
                "tmA26+1Nzj1LcfNvknKZ2UIOmnXiZY0QssIdyqsmJrdFpXs4UCLUzdXkfFLoxksU\n" +
                "mk4B6hig2IKMj5mnbWy/JQSXtjjI+HHmtzgWfXs7d9iQ61CklbtCOiPeWxvoqlGG\n" +
                "oK1wV1olcSar/RPKTlMmQpAg9dztQgrNs1oF7EF3i9kwNP7I5JzekPiOLH6oMw==\n" +
                "=5KMU\n" +
                "-----END PGP SIGNATURE-----\n", true);

        signatureValidityTest(api, cert, t0, t1, t2, t3);
    }

    private void testBaseCaseSubkeySigns(OpenPGPApi api)
            throws IOException
    {
        // https://sequoia-pgp.gitlab.io/openpgp-interoperability-test-suite/results.html#Key_revocation_test__subkey_signs__primary_key_is_not_revoked__base_case_
        String cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsBNBFpJegABCACzr1V+GxVkrtfDjihYK+HtyEIcO52uw7O2kd7JbduYp4RK17jy\n" +
                "75N3EnsgmiIkSxXCWr+rTtonNs1zCJeUa/gwnNfs7mVgjL2rMOZU/KZ4MP0yOYU5\n" +
                "u5FjNPWz8hpFQ9GKqfdj0Op61h1pCQO45IjUQ3dCDj9Rfn44zHMB1ZrbmIH9nTR1\n" +
                "YIGHWmdm0LItb2WxIkwzWBAJ5acTlsmLyZZEQ1+8NDqktyzwFoQqTJvLU4StY2k6\n" +
                "h18ZKZdPyrdLoEyOuWkvjxmbhDk1Gt5KiS/yy7mrzIPLr0dmJe4vc8WLV+bXoyNE\n" +
                "x3H8o9CFcYehLfyqsy40lg92d6Kp96ww8dZ5ABEBAAHCwMQEHwEKAHgFgl4L4QAJ\n" +
                "EAitUcrkcPAGRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9y\n" +
                "Z4csZe1ah1tj2AjxfdDMsH2wvSEwZjb/73ICKnm7BySQAhUKApsDAh4BFiEE4yy2\n" +
                "2oICkbfnbbGoCK1RyuRw8AYAAGYFCACiKnCb2NBZa/Jj1aJe4R2rxPZj2ERXWe3b\n" +
                "JKNPKT7K0rVDkTw1JRiTfCsuAY2lY9sKJdhQZl+azXm64vvTc6hEGRQ/+XssDlE2\n" +
                "DIn8C34HDc495ZnryHNB8Dd5l1HdjqxfGIY6HBPJUdx0dedwP42Oisg9t5KsC8zl\n" +
                "d/+MIRgzkp+Dg0LXJVnDuwWEPoo2N6WhAr5ReLvXxALX5ht9Lb3lP0DASZvAKy9B\n" +
                "O/wRCr294J8dg/CowAfloyf0Ko+JjyjanmZn3acy5CGkVN2mc+PFUekGZDDy5ooY\n" +
                "kgXO/CmApuTNvabct+A7IVVdWWM5SWb90JvaV9SWji6nQphVm7StwsDEBB8BCgB4\n" +
                "BYJaSXoACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lh\n" +
                "LXBncC5vcmfVZdjLYZxDX2hvy3aGrsE4i0avLDMzf3e9kVHmaD6PAgIVCgKbAwIe\n" +
                "ARYhBOMsttqCApG3522xqAitUcrkcPAGAABQYwgArfIRxq95npUKAOPXs25nZlvy\n" +
                "+xQbrmsTxHhAYW8eGFcz82QwumoqrR8VfrojxM+eCZdTI85nM5kzznYDU2+cMhsZ\n" +
                "Vm5+VhGZy3e3QH4J/E31D7t1opCvj5g1eRJ4LgywB+cYGcZBYp/bQT9SUYuhZH2O\n" +
                "XCR04qSbpVUCIApnhBHxKNtOlqjAkHeaOdW/8XePsbfvrtVOLGYgrZXfY7Nqy3+W\n" +
                "zbdm8UvVPFXH+uHEzTgyvYbnJBYkjORmCqUKs860PL8ekeg+sL4PHSRj1UUfwcQD\n" +
                "55q0m3Vtew2KiIUi4wKi5LceDtprjoO5utU/1YfEAiNMeSQHXKq83dpazvjrUs0S\n" +
                "anVsaWV0QGV4YW1wbGUub3JnwsDEBBMBCgB4BYJaSXoACRAIrVHK5HDwBkcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmc6Rix7CeIfWwnaQjk3\n" +
                "bBrkAiY7jS9N+shuRdHZ0gKKsgIVCgKbAwIeARYhBOMsttqCApG3522xqAitUcrk\n" +
                "cPAGAACf9QgAsxtfAbyGbtofjrXTs9lsKEWvGgk02fSYyKjPbyaRqh72MlIlUXwq\n" +
                "q1ih2TJc3vwF8aNVDrcb9DnBabdt2M1vI3PUaeG31BmakC/XZCNCrbbJkyd/vdML\n" +
                "qw7prLrp0auVNNhLYxOK9usXbClNxluo4i/lSFVo5B9ai+ne1kKKiplzqy2qqhde\n" +
                "plomcwGHbB1CkZ04DmCMbSSFAGxYqUC/bBm0bolCebw/KIz9sEojNKt6mvsFN67/\n" +
                "hMYeJS0HVlwwc6i8iKSzC2D53iywhtvkdiKECXQeXDf9zNXAn1wpK01SLJ0iig7c\n" +
                "DFrtoqkfPYzbNfC0bt34fNx9iz3w9aEH8c7ATQRaSsuAAQgAu5yau9psltmWiUn7\n" +
                "fsRSqbQInO0iWnu4DK9IXB3ghNYMcii3JJEjHzgIxGf3GiJEjzubyRQaX5J/p7yB\n" +
                "1fOH8z7FYUuax1saGf9c1/b02N9gyXNlHam31hNaaL3ffFczI95p7MNrTtroTt5o\n" +
                "Zqsc+i+oKLZn7X0YAI4tEYwhSnUQYB/F7YqkkI4eV+7CxZPA8pBhXiAOK/zn416P\n" +
                "sZ6JS5wsM65yCtOHcAAIBnKDnC+bQi+f1WZesSocy/rXx3QEQmodDu3ojhS+VxcY\n" +
                "GeZCUcFF0FyZBIkGjHIVQLyOfjP3FRJ4qFXMz9/YIVoM4Y6guTERMTEj/KDG4BP7\n" +
                "RfJHTQARAQABwsI8BBgBCgHwBYJeC+EACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0\n" +
                "QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfcAa1ZPWTtg60w3Oo4dt4Fa8cKFYbZ\n" +
                "YsqDSHV5pwEfMwKbAsC8oAQZAQoAbwWCXgvhAAkQEPy8/w6Op5FHFAAAAAAAHgAg\n" +
                "c2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnL6I2+VyN5T1FoVgj3cdnMLYC\n" +
                "pcB5i/FRSCVKybuLzrgWIQTOphDQhPpR8hHhxGwQ/Lz/Do6nkQAArk8H/AhjM9lq\n" +
                "bffFL6RRR4HTjelspy4A3nyTicCljrDuXDUh23GfLvajTR5h16ZBqAF7cpb9rrlz\n" +
                "1C1WcS5JLVxzXAe7f+KOfXu+eyLhpTzZ8VT3pK3hHGaYwlVlXrBZP0JXgL8hm6hD\n" +
                "SXZQZtcpsnQ1uIHC9ONxUB4liNFhTqQCQYdQJFiFs1umUbo/C4KdzlDI08bM3CqE\n" +
                "Kat9vUFuGG68mDg0CrRZEWt946L5i8kZmBUkSShIm2k5e2qE/muYeM6qKQNsxlx3\n" +
                "VIf5eUhtxCi9fg7SjvHkdUSFstYcxAdaohWCFCEsDJI12hzcKQazSjvtKF4BNBKg\n" +
                "X/wLsbVQnYLd9ggWIQTjLLbaggKRt+dtsagIrVHK5HDwBgAANjMH/1MY7DJyxkiT\n" +
                "jc/jzmnVxqtHOZDCSmUqk0eh/6BHs+ostWqkGC6+7dfxDnptwcqandYey4KF2ajt\n" +
                "4nOwu0xQw/NEF3i81h7IiewY7G+YT69DUd+DvVUQemfKNYVOrMqoH7QU5o4YojdJ\n" +
                "iDeIp2d/JyJrqyof78JFAHnNZgHC2T2zo9E54dnOTY9VNUNCOUct5Rby0GXjTIUR\n" +
                "O0f485eGuZxVWdLRllDYOiCrQHPSHhrxHVXVMbYJoroPy+IyaJanVoAWgyipBmmI\n" +
                "DV8aINM2RLMsGkuPTRtITI2ZlGOQN7xgy4LqWzjPnrzMXfwBEDx/nrwdG6zEGMK8\n" +
                "AkVkMT5uJJvCwjwEGAEKAfAFglro/4AJEAitUcrkcPAGRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ/Q0Z6WDH2+8/F1xEEuiApsjnn2lGNZ2\n" +
                "DeIaklJzdqQOApsCwLygBBkBCgBvBYJa6P+ACRAQ/Lz/Do6nkUcUAAAAAAAeACBz\n" +
                "YWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfrVATyX3tgcM2z41fqYquxVhJR\n" +
                "avN6+w2SU4xEG++SqBYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAABGVggAsB8M2KI5\n" +
                "cxXKKgVHL1dEfzg9halVavktfcT6ZVC/+aDp94tvBCL16Guhq4ccN7DATrWx430/\n" +
                "GecY6E77qvhDzmCclSbdLbiZmsrVX9kCmTfrJzFQ64KfvIS5GgbL21+ZJ+pKW2HO\n" +
                "MBGn6sgAPmTqM5UsDCpsEKDt5CJcJr3sTc8D9NhEnc0dKsQ91+n9ms3W5tyyE6r9\n" +
                "pyM6ThBCMhbQkR7hE9XWAQeO1ILSFGnie0aFcTU0Oo0wL1MaiSyA/8XpKq23xfx1\n" +
                "kNS9hQkdq0aWehNoTJdCt1Nq1cWABy2rQR0x+qhGWowfsAjnBautxvet28t2kPCA\n" +
                "IMniYpWc89BwfhYhBOMsttqCApG3522xqAitUcrkcPAGAACq1gf/Q7H9Re5SWk+U\n" +
                "On/NQPRedf544YJ/YdQnve/hSaPGL33cUzf4yxzFILnK19Ird5f8/mTT1pg99L3i\n" +
                "xE3N5031JJKwFpCB69Rsysg88ZLDL2VLc3xdsAQdUbVaCqeRHKwtMtpBvbAFvF9p\n" +
                "lwam0SSXHHr/JkYm5ufXN6I8ib/nwr1bFbf/Se0Wuk9RG4ne9JUBCrGxakyVd+Og\n" +
                "LLhvzOmJa7fDC0uUZhTKFbjMxLhaas4HFYiRbfz2T0xz9gyDytDWsEFM+XoKHlEH\n" +
                "8Fx/U2B5/8N0Q+pIFoEuOmBO+5EPvPIlxNByHgiaNIuKt1Mu+UAb2Spl6D5zbDfX\n" +
                "/3vqxdhYHw==\n" +
                "=Ric2\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        TestSignature t0 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJYaEaACRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmdVa4OG6WfRoRlj5+Zb6avhJUIZFvcIFiLuvrJp8Hio\n" +
                "iBYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAAAbaQgAjhBh0dLO0Sqiqkb2M3KWc25V\n" +
                "hJlcP3isFROJ0jikmXxkG9W04AvlA78tSxEP2n8a0CbxH/hT4g8mFb/qM5FKZcKf\n" +
                "HQxjbjUxBmVHa3EfMkwT7u1mVRmoWtJ59oVsKoqRb/kZ14i6VZ9NzfK8MRlL0e24\n" +
                "oNjkksZQ8ImjwwtvxSinxhezA6BtWi+dDnXAnG5Vva+6N/GRNPAAd8kFTPrlEqEz\n" +
                "uRbpq76r4taPjRjzMNcwZJoRVHSahWhDcXxNTalVUwt0DZFAskZ3gI+0VgU11bK1\n" +
                "QmIw2iR4itQY5f10HFNcl7uHLKnul0YyuvA5509HwCuEpdYUV/OxtlpVRaJ+yg==\n" +
                "=Rc6K\n" +
                "-----END PGP SIGNATURE-----\n", false, "Signature predates primary key");
        TestSignature t1 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJa564ACRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfcG7Iqn3OOKVjeJ61MlgERt08kcxh0x+BZFD7a8K7V\n" +
                "VBYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAACBIwf9EoS24IFeT3cPFf/nWxLFkbZK\n" +
                "fiy9WzyK4wlpO3VTyWPbXi6zpC4I5Rbp2jDk/c7Q3DnOZqFDv6TriTwuLYTJGPxr\n" +
                "U3dtDsFcKp4FcbgFyCDKIuLB+3kLaNpMXqdttEkY3Wd5m33XrBB7M0l5xZCk56Jm\n" +
                "H5L1sGNNNkCzG6P44qu69o5fkWxbYuX22fyhdeyxucJHMztqiMQYDwT7eSA92A1v\n" +
                "5OwA5D/k7GeyYFBFisxRijkdVtxstC9zkagC19VnZo7MRekA9gXj7kIna4XYRhfb\n" +
                "uQnN47HXdiWQytwypLvZ8JEJpRruyMAaHjX5OBXh0SK11xYWb6wB93+QfOahtg==\n" +
                "=UlUZ\n" +
                "-----END PGP SIGNATURE-----\n", false, "Subkey is not bound at this time");
        TestSignature t2 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJdP4iACRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcgkZw3ZSg8CZCKqJw2r4VqCpTuUhz6N0zX43d+1xop\n" +
                "2hYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAADnqAgAq+m6dDZpNOBaXH9nwv8/+HgR\n" +
                "MvRjnuLoa6zB5tcUhGPPVS0gg1PW0wfxlo1GPmgW3QDlV1zvcfYAZmV9uEC61wn/\n" +
                "+FkqN0Tceo487UvkWARE/mmRj5L8OgUTfqm1eebFQlMu/MeG9YOg+tXBy7XS7hy3\n" +
                "UdntIbtsv5oRTcybTnn5oiU2OFDlFC6sBNzOQt7wpyB1TKp2BdcsAv1RwmyCCCK4\n" +
                "bnmrpYH6woWMyVEVeMYfOHAx9vHD+od8Vf/v5L1M2N0nHzRWjjkobTVUr+xt/CyW\n" +
                "nq8SoazKYu3ETpZLeWX6Bciuv9+pzUCeClOSmBB1MFyyrTgbkOacHgrYnLvvtQ==\n" +
                "=WCKA\n" +
                "-----END PGP SIGNATURE-----\n", true);
        TestSignature t3 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJmhTYiCRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmdi3dCpJ4nZincNH5owv8+fJ5YpXljqtegtoBEnbbHP\n" +
                "thYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAAD0cQf/e8RHocRESJPbosqUuvC3ELnD\n" +
                "oSsJomDMUDfSfgpS5EhkOyJhvcrHkCbsHH2xlUEQ+zjJWY/dwM3FUkoj+p3kb/JC\n" +
                "Rn5cqQYlME+uJzjdHMyQCSOI1SvYwKCLCGPARDbCpeINrV++Oy29e6cv6/IcPlgo\n" +
                "k/0A7XuNq0YNxC7oopCj5ye3yVUvUmSCG2iV4oiWW5GhhPRzMeW7MFQmS0NUkAI8\n" +
                "hzJ8juTG4xP8SXnHCMakasZhJmtpMDd2BDZ7CrhWiWUQGrtd0eYkuyodreqVMGIF\n" +
                "BN80YgTNFW2MrblhDRRmxAqWzD9FedBwwSdgYbtkDwjsSq0S1jQV6aPndJqiLw==\n" +
                "=CIl0\n" +
                "-----END PGP SIGNATURE-----\n", true);

        signatureValidityTest(api, cert, t0, t1, t2, t3);
    }

    private void testPKSignsPKRevokedNoSubpacket(OpenPGPApi api)
            throws IOException
    {
        String cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsBNBFpJegABCACzr1V+GxVkrtfDjihYK+HtyEIcO52uw7O2kd7JbduYp4RK17jy\n" +
                "75N3EnsgmiIkSxXCWr+rTtonNs1zCJeUa/gwnNfs7mVgjL2rMOZU/KZ4MP0yOYU5\n" +
                "u5FjNPWz8hpFQ9GKqfdj0Op61h1pCQO45IjUQ3dCDj9Rfn44zHMB1ZrbmIH9nTR1\n" +
                "YIGHWmdm0LItb2WxIkwzWBAJ5acTlsmLyZZEQ1+8NDqktyzwFoQqTJvLU4StY2k6\n" +
                "h18ZKZdPyrdLoEyOuWkvjxmbhDk1Gt5KiS/yy7mrzIPLr0dmJe4vc8WLV+bXoyNE\n" +
                "x3H8o9CFcYehLfyqsy40lg92d6Kp96ww8dZ5ABEBAAHCwLsEIAEKAG8FglwqrYAJ\n" +
                "EAitUcrkcPAGRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9y\n" +
                "Z4KjdWVHTHye8HeUynibpgE5TYfFnnBt9bbOj99oplaTFiEE4yy22oICkbfnbbGo\n" +
                "CK1RyuRw8AYAAMxeB/4+QAncX1+678HeO1fweQ0Zkf4O6+Ew6EgCp4I2UZu+a5H8\n" +
                "ryI3B4WNShCDoV3CfOcUtUSUA8EOyrpYSW/3jPVfb01uxDNsZpf9piZG7DelIAef\n" +
                "wvQaZHJeytchv5+Wo+Jo6qg26BgvUlXW2x5NNcScGvCZt1RQ712PRDAfUnppRXBj\n" +
                "+IXWzOs52uYGFDFzJSLEUy6dtTdNCJk78EMoHsOwC7g5uUyHbjSfrdQncxgMwikl\n" +
                "C2LFSS7xYZwDgkkb70AT10Ot2jL6rLIT/1ChQZ0oRGJLBHiz3FUpanDQIDD49+dp\n" +
                "6FUmUUsubwwFkxBHyCbQ8cdbfBILNiD1pEo31dPTwsDEBB8BCgB4BYJeC+EACRAI\n" +
                "rVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmeH\n" +
                "LGXtWodbY9gI8X3QzLB9sL0hMGY2/+9yAip5uwckkAIVCgKbAwIeARYhBOMsttqC\n" +
                "ApG3522xqAitUcrkcPAGAABmBQgAoipwm9jQWWvyY9WiXuEdq8T2Y9hEV1nt2ySj\n" +
                "Tyk+ytK1Q5E8NSUYk3wrLgGNpWPbCiXYUGZfms15uuL703OoRBkUP/l7LA5RNgyJ\n" +
                "/At+Bw3OPeWZ68hzQfA3eZdR3Y6sXxiGOhwTyVHcdHXncD+NjorIPbeSrAvM5Xf/\n" +
                "jCEYM5Kfg4NC1yVZw7sFhD6KNjeloQK+UXi718QC1+YbfS295T9AwEmbwCsvQTv8\n" +
                "EQq9veCfHYPwqMAH5aMn9CqPiY8o2p5mZ92nMuQhpFTdpnPjxVHpBmQw8uaKGJIF\n" +
                "zvwpgKbkzb2m3LfgOyFVXVljOUlm/dCb2lfUlo4up0KYVZu0rcLAxAQfAQoAeAWC\n" +
                "Wkl6AAkQCK1RyuRw8AZHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1w\n" +
                "Z3Aub3Jn1WXYy2GcQ19ob8t2hq7BOItGrywzM393vZFR5mg+jwICFQoCmwMCHgEW\n" +
                "IQTjLLbaggKRt+dtsagIrVHK5HDwBgAAUGMIAK3yEcaveZ6VCgDj17NuZ2Zb8vsU\n" +
                "G65rE8R4QGFvHhhXM/NkMLpqKq0fFX66I8TPngmXUyPOZzOZM852A1NvnDIbGVZu\n" +
                "flYRmct3t0B+CfxN9Q+7daKQr4+YNXkSeC4MsAfnGBnGQWKf20E/UlGLoWR9jlwk\n" +
                "dOKkm6VVAiAKZ4QR8SjbTpaowJB3mjnVv/F3j7G3767VTixmIK2V32Ozast/ls23\n" +
                "ZvFL1TxVx/rhxM04Mr2G5yQWJIzkZgqlCrPOtDy/HpHoPrC+Dx0kY9VFH8HEA+ea\n" +
                "tJt1bXsNioiFIuMCouS3Hg7aa46DubrVP9WHxAIjTHkkB1yqvN3aWs7461LNEmp1\n" +
                "bGlldEBleGFtcGxlLm9yZ8LAxAQTAQoAeAWCWkl6AAkQCK1RyuRw8AZHFAAAAAAA\n" +
                "HgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnOkYsewniH1sJ2kI5N2wa\n" +
                "5AImO40vTfrIbkXR2dICirICFQoCmwMCHgEWIQTjLLbaggKRt+dtsagIrVHK5HDw\n" +
                "BgAAn/UIALMbXwG8hm7aH46107PZbChFrxoJNNn0mMioz28mkaoe9jJSJVF8KqtY\n" +
                "odkyXN78BfGjVQ63G/Q5wWm3bdjNbyNz1Gnht9QZmpAv12QjQq22yZMnf73TC6sO\n" +
                "6ay66dGrlTTYS2MTivbrF2wpTcZbqOIv5UhVaOQfWovp3tZCioqZc6stqqoXXqZa\n" +
                "JnMBh2wdQpGdOA5gjG0khQBsWKlAv2wZtG6JQnm8PyiM/bBKIzSrepr7BTeu/4TG\n" +
                "HiUtB1ZcMHOovIikswtg+d4ssIbb5HYihAl0Hlw3/czVwJ9cKStNUiydIooO3Axa\n" +
                "7aKpHz2M2zXwtG7d+HzcfYs98PWhB/HOwE0EWkrLgAEIALucmrvabJbZlolJ+37E\n" +
                "Uqm0CJztIlp7uAyvSFwd4ITWDHIotySRIx84CMRn9xoiRI87m8kUGl+Sf6e8gdXz\n" +
                "h/M+xWFLmsdbGhn/XNf29NjfYMlzZR2pt9YTWmi933xXMyPeaezDa07a6E7eaGar\n" +
                "HPovqCi2Z+19GACOLRGMIUp1EGAfxe2KpJCOHlfuwsWTwPKQYV4gDiv85+Nej7Ge\n" +
                "iUucLDOucgrTh3AACAZyg5wvm0Ivn9VmXrEqHMv618d0BEJqHQ7t6I4UvlcXGBnm\n" +
                "QlHBRdBcmQSJBoxyFUC8jn4z9xUSeKhVzM/f2CFaDOGOoLkxETExI/ygxuAT+0Xy\n" +
                "R00AEQEAAcLCPAQYAQoB8AWCXgvhAAkQCK1RyuRw8AZHFAAAAAAAHgAgc2FsdEBu\n" +
                "b3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn3AGtWT1k7YOtMNzqOHbeBWvHChWG2WLK\n" +
                "g0h1eacBHzMCmwLAvKAEGQEKAG8Fgl4L4QAJEBD8vP8OjqeRRxQAAAAAAB4AIHNh\n" +
                "bHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZy+iNvlcjeU9RaFYI93HZzC2AqXA\n" +
                "eYvxUUglSsm7i864FiEEzqYQ0IT6UfIR4cRsEPy8/w6Op5EAAK5PB/wIYzPZam33\n" +
                "xS+kUUeB043pbKcuAN58k4nApY6w7lw1Idtxny72o00eYdemQagBe3KW/a65c9Qt\n" +
                "VnEuSS1cc1wHu3/ijn17vnsi4aU82fFU96St4RxmmMJVZV6wWT9CV4C/IZuoQ0l2\n" +
                "UGbXKbJ0NbiBwvTjcVAeJYjRYU6kAkGHUCRYhbNbplG6PwuCnc5QyNPGzNwqhCmr\n" +
                "fb1BbhhuvJg4NAq0WRFrfeOi+YvJGZgVJEkoSJtpOXtqhP5rmHjOqikDbMZcd1SH\n" +
                "+XlIbcQovX4O0o7x5HVEhbLWHMQHWqIVghQhLAySNdoc3CkGs0o77SheATQSoF/8\n" +
                "C7G1UJ2C3fYIFiEE4yy22oICkbfnbbGoCK1RyuRw8AYAADYzB/9TGOwycsZIk43P\n" +
                "485p1carRzmQwkplKpNHof+gR7PqLLVqpBguvu3X8Q56bcHKmp3WHsuChdmo7eJz\n" +
                "sLtMUMPzRBd4vNYeyInsGOxvmE+vQ1Hfg71VEHpnyjWFTqzKqB+0FOaOGKI3SYg3\n" +
                "iKdnfycia6sqH+/CRQB5zWYBwtk9s6PROeHZzk2PVTVDQjlHLeUW8tBl40yFETtH\n" +
                "+POXhrmcVVnS0ZZQ2Dogq0Bz0h4a8R1V1TG2CaK6D8viMmiWp1aAFoMoqQZpiA1f\n" +
                "GiDTNkSzLBpLj00bSEyNmZRjkDe8YMuC6ls4z568zF38ARA8f568HRusxBjCvAJF\n" +
                "ZDE+biSbwsI8BBgBCgHwBYJa6P+ACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmf0NGelgx9vvPxdcRBLogKbI559pRjWdg3i\n" +
                "GpJSc3akDgKbAsC8oAQZAQoAbwWCWuj/gAkQEPy8/w6Op5FHFAAAAAAAHgAgc2Fs\n" +
                "dEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn61QE8l97YHDNs+NX6mKrsVYSUWrz\n" +
                "evsNklOMRBvvkqgWIQTOphDQhPpR8hHhxGwQ/Lz/Do6nkQAARlYIALAfDNiiOXMV\n" +
                "yioFRy9XRH84PYWpVWr5LX3E+mVQv/mg6feLbwQi9ehroauHHDewwE61seN9Pxnn\n" +
                "GOhO+6r4Q85gnJUm3S24mZrK1V/ZApk36ycxUOuCn7yEuRoGy9tfmSfqSlthzjAR\n" +
                "p+rIAD5k6jOVLAwqbBCg7eQiXCa97E3PA/TYRJ3NHSrEPdfp/ZrN1ubcshOq/acj\n" +
                "Ok4QQjIW0JEe4RPV1gEHjtSC0hRp4ntGhXE1NDqNMC9TGoksgP/F6Sqtt8X8dZDU\n" +
                "vYUJHatGlnoTaEyXQrdTatXFgActq0EdMfqoRlqMH7AI5wWrrcb3rdvLdpDwgCDJ\n" +
                "4mKVnPPQcH4WIQTjLLbaggKRt+dtsagIrVHK5HDwBgAAqtYH/0Ox/UXuUlpPlDp/\n" +
                "zUD0XnX+eOGCf2HUJ73v4Umjxi993FM3+MscxSC5ytfSK3eX/P5k09aYPfS94sRN\n" +
                "zedN9SSSsBaQgevUbMrIPPGSwy9lS3N8XbAEHVG1WgqnkRysLTLaQb2wBbxfaZcG\n" +
                "ptEklxx6/yZGJubn1zeiPIm/58K9WxW3/0ntFrpPURuJ3vSVAQqxsWpMlXfjoCy4\n" +
                "b8zpiWu3wwtLlGYUyhW4zMS4WmrOBxWIkW389k9Mc/YMg8rQ1rBBTPl6Ch5RB/Bc\n" +
                "f1Ngef/DdEPqSBaBLjpgTvuRD7zyJcTQch4ImjSLirdTLvlAG9kqZeg+c2w31/97\n" +
                "6sXYWB8=\n" +
                "=13Sf\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        TestSignature t0 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJYaEaACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmeoPMfalw2oS7uyOKnOXJSN8Gx7pr/BMlo3Xn8nTgx6\n" +
                "ORYhBOMsttqCApG3522xqAitUcrkcPAGAABXbAf/WfWaQYNuATAKwxYrJx4fd5kt\n" +
                "0M6sn1q7wK1MIxursG2+FuKafV25O9+pde8Nog77OEgegwk+HokOVFpVXfOzHQjs\n" +
                "8dwWTtTQlX5NIBNvtqS7cvCKhjsqaHKgmzsenMjCEbpDZ3C5CoqcYicykqEU/Ia0\n" +
                "ZGC4lzRByrgNy/w+/iLN748S707bzBLVc/sE73k9N5pANAlE+cA/sHI1Gp2WxJR9\n" +
                "t2Fk4x6/85PEnF1RHI16p/wSEeuRaBpyw9QGZBbVDVt5wvgttxZjteGGSwBM3WI/\n" +
                "gPfC0LW+JQ2W+dwY0PN/7yuARVRhXpKiBI4xqp7x3OanQX6quU77g3B8nXAt3A==\n" +
                "=StqT\n" +
                "-----END PGP SIGNATURE-----\n", false, "Signature predates primary key");
        TestSignature t1 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJa564ACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfM0EN4Ei0bQv6UO9BRq2wtUfV948cRynRMBb8TSGCG\n" +
                "tBYhBOMsttqCApG3522xqAitUcrkcPAGAAAlNwf+L0KQK9i/xmYKOMV2EX13QUoZ\n" +
                "vvb/pHGZaCQ9JtvEF2l2DT0DqByZ+tOv5Y4isU+un7CraoyvyajAwR0Yqk937B6C\n" +
                "HQHKMkmIl+5R4/xqSoWYmOidbrgilojPMBEhB3INQ8/THjjFijtLzitVhnWBd7+u\n" +
                "s0kcqnWnOdx2By4aDe+UEiyCfSE02e/0tIsM71RqiU91zH6dl6+q8nml7PsYuTFV\n" +
                "V09oQTbBuuvUe+YgN/uvyKVIsA64lQ+YhqEeIA8Quek7fHhW+du9OIhSPsbYodyx\n" +
                "VWMTXwSWKGNvZNAkpmgUYqFjS2Cx5ZUWblZLjrNKBwnnmt50qvUN7+o2pjlnfA==\n" +
                "=UuXb\n" +
                "-----END PGP SIGNATURE-----\n", false, "Hard revocations invalidate key at all times");
        TestSignature t2 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJdP4iACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfFzYGoiuSjN+gz1IDD4ZvRXGuPTHks0/pIiGY90mrZ\n" +
                "WxYhBOMsttqCApG3522xqAitUcrkcPAGAABGPAf/ck7tJAFoPIDd9fTPZANpNGoW\n" +
                "Fq6VuNfy/nLjz2gkHFX/lLAxQ0N3McIdRA++Ik/omb0lis3R2DVNgwqNm2OF34HE\n" +
                "qxmPmrQHBgk2q0fDH4NCE0XnYQjQT65V99IfiaQu+oS3Mq8MuYsDYvRVvRKMwt49\n" +
                "fcDnvFtAtCqEETdv6wV5cUZmdQ3L9NU9bApJ0jk+EHVdpfTUIbOYYGnsIe/4Aa0d\n" +
                "jgzu4Em79ynosOn//953XJ7OO8LCDi1EKt+nFuZARUlt/Jwwull6zzp7HUPw6HPt\n" +
                "Upp7os8TIPC4STwoSeEKaxEkrbMGFnDcoDajnKKRt5+MkB24Oq7PHvnzgnPpVg==\n" +
                "=Ljv7\n" +
                "-----END PGP SIGNATURE-----\n", false, "Hard revocations invalidate key at all times");
        TestSignature t3 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJmhTYiCRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfbjQf/zfoJQT0hhna4RDjOESBLgGaCbc5HLeo751F4\n" +
                "NxYhBOMsttqCApG3522xqAitUcrkcPAGAABqBQgAkkNmYf6yLPvox+ZayrLtMb9D\n" +
                "ghgt0nau72DSazsJ6SAq2QqIdr0RRhRa2gCETkp4PpeoDWmIvoVj35ZnfyeO/jqy\n" +
                "HECvRwO0WPA5FXQM6uG7s40vDTRFjlJMpPyHWnn2igcR64iDxBGmc40xi9CcmJP9\n" +
                "tmA26+1Nzj1LcfNvknKZ2UIOmnXiZY0QssIdyqsmJrdFpXs4UCLUzdXkfFLoxksU\n" +
                "mk4B6hig2IKMj5mnbWy/JQSXtjjI+HHmtzgWfXs7d9iQ61CklbtCOiPeWxvoqlGG\n" +
                "oK1wV1olcSar/RPKTlMmQpAg9dztQgrNs1oF7EF3i9kwNP7I5JzekPiOLH6oMw==\n" +
                "=5KMU\n" +
                "-----END PGP SIGNATURE-----\n", false, "Hard revocations invalidate key at all times");

        signatureValidityTest(api, cert, t0, t1, t2, t3);
    }

    private void testSKSignsPKRevokedNoSubpacket(OpenPGPApi api)
            throws IOException
    {
        // https://sequoia-pgp.gitlab.io/openpgp-interoperability-test-suite/results.html#Key_revocation_test__subkey_signs__primary_key_is_revoked__revoked__no_subpacket
        String cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsBNBFpJegABCACzr1V+GxVkrtfDjihYK+HtyEIcO52uw7O2kd7JbduYp4RK17jy\n" +
                "75N3EnsgmiIkSxXCWr+rTtonNs1zCJeUa/gwnNfs7mVgjL2rMOZU/KZ4MP0yOYU5\n" +
                "u5FjNPWz8hpFQ9GKqfdj0Op61h1pCQO45IjUQ3dCDj9Rfn44zHMB1ZrbmIH9nTR1\n" +
                "YIGHWmdm0LItb2WxIkwzWBAJ5acTlsmLyZZEQ1+8NDqktyzwFoQqTJvLU4StY2k6\n" +
                "h18ZKZdPyrdLoEyOuWkvjxmbhDk1Gt5KiS/yy7mrzIPLr0dmJe4vc8WLV+bXoyNE\n" +
                "x3H8o9CFcYehLfyqsy40lg92d6Kp96ww8dZ5ABEBAAHCwLsEIAEKAG8FglwqrYAJ\n" +
                "EAitUcrkcPAGRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9y\n" +
                "Z4KjdWVHTHye8HeUynibpgE5TYfFnnBt9bbOj99oplaTFiEE4yy22oICkbfnbbGo\n" +
                "CK1RyuRw8AYAAMxeB/4+QAncX1+678HeO1fweQ0Zkf4O6+Ew6EgCp4I2UZu+a5H8\n" +
                "ryI3B4WNShCDoV3CfOcUtUSUA8EOyrpYSW/3jPVfb01uxDNsZpf9piZG7DelIAef\n" +
                "wvQaZHJeytchv5+Wo+Jo6qg26BgvUlXW2x5NNcScGvCZt1RQ712PRDAfUnppRXBj\n" +
                "+IXWzOs52uYGFDFzJSLEUy6dtTdNCJk78EMoHsOwC7g5uUyHbjSfrdQncxgMwikl\n" +
                "C2LFSS7xYZwDgkkb70AT10Ot2jL6rLIT/1ChQZ0oRGJLBHiz3FUpanDQIDD49+dp\n" +
                "6FUmUUsubwwFkxBHyCbQ8cdbfBILNiD1pEo31dPTwsDEBB8BCgB4BYJeC+EACRAI\n" +
                "rVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmeH\n" +
                "LGXtWodbY9gI8X3QzLB9sL0hMGY2/+9yAip5uwckkAIVCgKbAwIeARYhBOMsttqC\n" +
                "ApG3522xqAitUcrkcPAGAABmBQgAoipwm9jQWWvyY9WiXuEdq8T2Y9hEV1nt2ySj\n" +
                "Tyk+ytK1Q5E8NSUYk3wrLgGNpWPbCiXYUGZfms15uuL703OoRBkUP/l7LA5RNgyJ\n" +
                "/At+Bw3OPeWZ68hzQfA3eZdR3Y6sXxiGOhwTyVHcdHXncD+NjorIPbeSrAvM5Xf/\n" +
                "jCEYM5Kfg4NC1yVZw7sFhD6KNjeloQK+UXi718QC1+YbfS295T9AwEmbwCsvQTv8\n" +
                "EQq9veCfHYPwqMAH5aMn9CqPiY8o2p5mZ92nMuQhpFTdpnPjxVHpBmQw8uaKGJIF\n" +
                "zvwpgKbkzb2m3LfgOyFVXVljOUlm/dCb2lfUlo4up0KYVZu0rcLAxAQfAQoAeAWC\n" +
                "Wkl6AAkQCK1RyuRw8AZHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1w\n" +
                "Z3Aub3Jn1WXYy2GcQ19ob8t2hq7BOItGrywzM393vZFR5mg+jwICFQoCmwMCHgEW\n" +
                "IQTjLLbaggKRt+dtsagIrVHK5HDwBgAAUGMIAK3yEcaveZ6VCgDj17NuZ2Zb8vsU\n" +
                "G65rE8R4QGFvHhhXM/NkMLpqKq0fFX66I8TPngmXUyPOZzOZM852A1NvnDIbGVZu\n" +
                "flYRmct3t0B+CfxN9Q+7daKQr4+YNXkSeC4MsAfnGBnGQWKf20E/UlGLoWR9jlwk\n" +
                "dOKkm6VVAiAKZ4QR8SjbTpaowJB3mjnVv/F3j7G3767VTixmIK2V32Ozast/ls23\n" +
                "ZvFL1TxVx/rhxM04Mr2G5yQWJIzkZgqlCrPOtDy/HpHoPrC+Dx0kY9VFH8HEA+ea\n" +
                "tJt1bXsNioiFIuMCouS3Hg7aa46DubrVP9WHxAIjTHkkB1yqvN3aWs7461LNEmp1\n" +
                "bGlldEBleGFtcGxlLm9yZ8LAxAQTAQoAeAWCWkl6AAkQCK1RyuRw8AZHFAAAAAAA\n" +
                "HgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnOkYsewniH1sJ2kI5N2wa\n" +
                "5AImO40vTfrIbkXR2dICirICFQoCmwMCHgEWIQTjLLbaggKRt+dtsagIrVHK5HDw\n" +
                "BgAAn/UIALMbXwG8hm7aH46107PZbChFrxoJNNn0mMioz28mkaoe9jJSJVF8KqtY\n" +
                "odkyXN78BfGjVQ63G/Q5wWm3bdjNbyNz1Gnht9QZmpAv12QjQq22yZMnf73TC6sO\n" +
                "6ay66dGrlTTYS2MTivbrF2wpTcZbqOIv5UhVaOQfWovp3tZCioqZc6stqqoXXqZa\n" +
                "JnMBh2wdQpGdOA5gjG0khQBsWKlAv2wZtG6JQnm8PyiM/bBKIzSrepr7BTeu/4TG\n" +
                "HiUtB1ZcMHOovIikswtg+d4ssIbb5HYihAl0Hlw3/czVwJ9cKStNUiydIooO3Axa\n" +
                "7aKpHz2M2zXwtG7d+HzcfYs98PWhB/HOwE0EWkrLgAEIALucmrvabJbZlolJ+37E\n" +
                "Uqm0CJztIlp7uAyvSFwd4ITWDHIotySRIx84CMRn9xoiRI87m8kUGl+Sf6e8gdXz\n" +
                "h/M+xWFLmsdbGhn/XNf29NjfYMlzZR2pt9YTWmi933xXMyPeaezDa07a6E7eaGar\n" +
                "HPovqCi2Z+19GACOLRGMIUp1EGAfxe2KpJCOHlfuwsWTwPKQYV4gDiv85+Nej7Ge\n" +
                "iUucLDOucgrTh3AACAZyg5wvm0Ivn9VmXrEqHMv618d0BEJqHQ7t6I4UvlcXGBnm\n" +
                "QlHBRdBcmQSJBoxyFUC8jn4z9xUSeKhVzM/f2CFaDOGOoLkxETExI/ygxuAT+0Xy\n" +
                "R00AEQEAAcLCPAQYAQoB8AWCXgvhAAkQCK1RyuRw8AZHFAAAAAAAHgAgc2FsdEBu\n" +
                "b3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn3AGtWT1k7YOtMNzqOHbeBWvHChWG2WLK\n" +
                "g0h1eacBHzMCmwLAvKAEGQEKAG8Fgl4L4QAJEBD8vP8OjqeRRxQAAAAAAB4AIHNh\n" +
                "bHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZy+iNvlcjeU9RaFYI93HZzC2AqXA\n" +
                "eYvxUUglSsm7i864FiEEzqYQ0IT6UfIR4cRsEPy8/w6Op5EAAK5PB/wIYzPZam33\n" +
                "xS+kUUeB043pbKcuAN58k4nApY6w7lw1Idtxny72o00eYdemQagBe3KW/a65c9Qt\n" +
                "VnEuSS1cc1wHu3/ijn17vnsi4aU82fFU96St4RxmmMJVZV6wWT9CV4C/IZuoQ0l2\n" +
                "UGbXKbJ0NbiBwvTjcVAeJYjRYU6kAkGHUCRYhbNbplG6PwuCnc5QyNPGzNwqhCmr\n" +
                "fb1BbhhuvJg4NAq0WRFrfeOi+YvJGZgVJEkoSJtpOXtqhP5rmHjOqikDbMZcd1SH\n" +
                "+XlIbcQovX4O0o7x5HVEhbLWHMQHWqIVghQhLAySNdoc3CkGs0o77SheATQSoF/8\n" +
                "C7G1UJ2C3fYIFiEE4yy22oICkbfnbbGoCK1RyuRw8AYAADYzB/9TGOwycsZIk43P\n" +
                "485p1carRzmQwkplKpNHof+gR7PqLLVqpBguvu3X8Q56bcHKmp3WHsuChdmo7eJz\n" +
                "sLtMUMPzRBd4vNYeyInsGOxvmE+vQ1Hfg71VEHpnyjWFTqzKqB+0FOaOGKI3SYg3\n" +
                "iKdnfycia6sqH+/CRQB5zWYBwtk9s6PROeHZzk2PVTVDQjlHLeUW8tBl40yFETtH\n" +
                "+POXhrmcVVnS0ZZQ2Dogq0Bz0h4a8R1V1TG2CaK6D8viMmiWp1aAFoMoqQZpiA1f\n" +
                "GiDTNkSzLBpLj00bSEyNmZRjkDe8YMuC6ls4z568zF38ARA8f568HRusxBjCvAJF\n" +
                "ZDE+biSbwsI8BBgBCgHwBYJa6P+ACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmf0NGelgx9vvPxdcRBLogKbI559pRjWdg3i\n" +
                "GpJSc3akDgKbAsC8oAQZAQoAbwWCWuj/gAkQEPy8/w6Op5FHFAAAAAAAHgAgc2Fs\n" +
                "dEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn61QE8l97YHDNs+NX6mKrsVYSUWrz\n" +
                "evsNklOMRBvvkqgWIQTOphDQhPpR8hHhxGwQ/Lz/Do6nkQAARlYIALAfDNiiOXMV\n" +
                "yioFRy9XRH84PYWpVWr5LX3E+mVQv/mg6feLbwQi9ehroauHHDewwE61seN9Pxnn\n" +
                "GOhO+6r4Q85gnJUm3S24mZrK1V/ZApk36ycxUOuCn7yEuRoGy9tfmSfqSlthzjAR\n" +
                "p+rIAD5k6jOVLAwqbBCg7eQiXCa97E3PA/TYRJ3NHSrEPdfp/ZrN1ubcshOq/acj\n" +
                "Ok4QQjIW0JEe4RPV1gEHjtSC0hRp4ntGhXE1NDqNMC9TGoksgP/F6Sqtt8X8dZDU\n" +
                "vYUJHatGlnoTaEyXQrdTatXFgActq0EdMfqoRlqMH7AI5wWrrcb3rdvLdpDwgCDJ\n" +
                "4mKVnPPQcH4WIQTjLLbaggKRt+dtsagIrVHK5HDwBgAAqtYH/0Ox/UXuUlpPlDp/\n" +
                "zUD0XnX+eOGCf2HUJ73v4Umjxi993FM3+MscxSC5ytfSK3eX/P5k09aYPfS94sRN\n" +
                "zedN9SSSsBaQgevUbMrIPPGSwy9lS3N8XbAEHVG1WgqnkRysLTLaQb2wBbxfaZcG\n" +
                "ptEklxx6/yZGJubn1zeiPIm/58K9WxW3/0ntFrpPURuJ3vSVAQqxsWpMlXfjoCy4\n" +
                "b8zpiWu3wwtLlGYUyhW4zMS4WmrOBxWIkW389k9Mc/YMg8rQ1rBBTPl6Ch5RB/Bc\n" +
                "f1Ngef/DdEPqSBaBLjpgTvuRD7zyJcTQch4ImjSLirdTLvlAG9kqZeg+c2w31/97\n" +
                "6sXYWB8=\n" +
                "=13Sf\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        TestSignature t0 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJYaEaACRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmdVa4OG6WfRoRlj5+Zb6avhJUIZFvcIFiLuvrJp8Hio\n" +
                "iBYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAAAbaQgAjhBh0dLO0Sqiqkb2M3KWc25V\n" +
                "hJlcP3isFROJ0jikmXxkG9W04AvlA78tSxEP2n8a0CbxH/hT4g8mFb/qM5FKZcKf\n" +
                "HQxjbjUxBmVHa3EfMkwT7u1mVRmoWtJ59oVsKoqRb/kZ14i6VZ9NzfK8MRlL0e24\n" +
                "oNjkksZQ8ImjwwtvxSinxhezA6BtWi+dDnXAnG5Vva+6N/GRNPAAd8kFTPrlEqEz\n" +
                "uRbpq76r4taPjRjzMNcwZJoRVHSahWhDcXxNTalVUwt0DZFAskZ3gI+0VgU11bK1\n" +
                "QmIw2iR4itQY5f10HFNcl7uHLKnul0YyuvA5509HwCuEpdYUV/OxtlpVRaJ+yg==\n" +
                "=Rc6K\n" +
                "-----END PGP SIGNATURE-----\n", false, "Signature predates primary key");
        TestSignature t1 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJa564ACRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfcG7Iqn3OOKVjeJ61MlgERt08kcxh0x+BZFD7a8K7V\n" +
                "VBYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAACBIwf9EoS24IFeT3cPFf/nWxLFkbZK\n" +
                "fiy9WzyK4wlpO3VTyWPbXi6zpC4I5Rbp2jDk/c7Q3DnOZqFDv6TriTwuLYTJGPxr\n" +
                "U3dtDsFcKp4FcbgFyCDKIuLB+3kLaNpMXqdttEkY3Wd5m33XrBB7M0l5xZCk56Jm\n" +
                "H5L1sGNNNkCzG6P44qu69o5fkWxbYuX22fyhdeyxucJHMztqiMQYDwT7eSA92A1v\n" +
                "5OwA5D/k7GeyYFBFisxRijkdVtxstC9zkagC19VnZo7MRekA9gXj7kIna4XYRhfb\n" +
                "uQnN47HXdiWQytwypLvZ8JEJpRruyMAaHjX5OBXh0SK11xYWb6wB93+QfOahtg==\n" +
                "=UlUZ\n" +
                "-----END PGP SIGNATURE-----\n", false, "Hard revocations invalidate key at all times");
        TestSignature t2 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJdP4iACRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcgkZw3ZSg8CZCKqJw2r4VqCpTuUhz6N0zX43d+1xop\n" +
                "2hYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAADnqAgAq+m6dDZpNOBaXH9nwv8/+HgR\n" +
                "MvRjnuLoa6zB5tcUhGPPVS0gg1PW0wfxlo1GPmgW3QDlV1zvcfYAZmV9uEC61wn/\n" +
                "+FkqN0Tceo487UvkWARE/mmRj5L8OgUTfqm1eebFQlMu/MeG9YOg+tXBy7XS7hy3\n" +
                "UdntIbtsv5oRTcybTnn5oiU2OFDlFC6sBNzOQt7wpyB1TKp2BdcsAv1RwmyCCCK4\n" +
                "bnmrpYH6woWMyVEVeMYfOHAx9vHD+od8Vf/v5L1M2N0nHzRWjjkobTVUr+xt/CyW\n" +
                "nq8SoazKYu3ETpZLeWX6Bciuv9+pzUCeClOSmBB1MFyyrTgbkOacHgrYnLvvtQ==\n" +
                "=WCKA\n" +
                "-----END PGP SIGNATURE-----\n", false, "Hard revocations invalidate key at all times");
        TestSignature t3 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJmhTYiCRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmdi3dCpJ4nZincNH5owv8+fJ5YpXljqtegtoBEnbbHP\n" +
                "thYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAAD0cQf/e8RHocRESJPbosqUuvC3ELnD\n" +
                "oSsJomDMUDfSfgpS5EhkOyJhvcrHkCbsHH2xlUEQ+zjJWY/dwM3FUkoj+p3kb/JC\n" +
                "Rn5cqQYlME+uJzjdHMyQCSOI1SvYwKCLCGPARDbCpeINrV++Oy29e6cv6/IcPlgo\n" +
                "k/0A7XuNq0YNxC7oopCj5ye3yVUvUmSCG2iV4oiWW5GhhPRzMeW7MFQmS0NUkAI8\n" +
                "hzJ8juTG4xP8SXnHCMakasZhJmtpMDd2BDZ7CrhWiWUQGrtd0eYkuyodreqVMGIF\n" +
                "BN80YgTNFW2MrblhDRRmxAqWzD9FedBwwSdgYbtkDwjsSq0S1jQV6aPndJqiLw==\n" +
                "=CIl0\n" +
                "-----END PGP SIGNATURE-----\n", false, "Hard revocations invalidate key at all times");

        signatureValidityTest(api, cert, t0, t1, t2, t3);
    }

    private void testPKSignsPKRevocationSuperseded(OpenPGPApi api)
            throws IOException
    {
        // https://sequoia-pgp.gitlab.io/openpgp-interoperability-test-suite/results.html#Key_revocation_test__primary_key_signs_and_is_revoked__revoked__superseded
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsBNBFpJegABCACzr1V+GxVkrtfDjihYK+HtyEIcO52uw7O2kd7JbduYp4RK17jy\n" +
                "75N3EnsgmiIkSxXCWr+rTtonNs1zCJeUa/gwnNfs7mVgjL2rMOZU/KZ4MP0yOYU5\n" +
                "u5FjNPWz8hpFQ9GKqfdj0Op61h1pCQO45IjUQ3dCDj9Rfn44zHMB1ZrbmIH9nTR1\n" +
                "YIGHWmdm0LItb2WxIkwzWBAJ5acTlsmLyZZEQ1+8NDqktyzwFoQqTJvLU4StY2k6\n" +
                "h18ZKZdPyrdLoEyOuWkvjxmbhDk1Gt5KiS/yy7mrzIPLr0dmJe4vc8WLV+bXoyNE\n" +
                "x3H8o9CFcYehLfyqsy40lg92d6Kp96ww8dZ5ABEBAAHCwM8EIAEKAIMFglwqrYAJ\n" +
                "EAitUcrkcPAGRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9y\n" +
                "Z1X0jZPeNNpSsn78ulDPJNHa0QaeI5oAUdBGbIKSOT0uEx0BS2V5IGlzIHN1cGVy\n" +
                "c2VkZWQWIQTjLLbaggKRt+dtsagIrVHK5HDwBgAAr2QIAKAY5bHFbRkoItYBJBN1\n" +
                "aV1jjrpYdwLM+0LHf8GcRCeO1Pt9I1J021crwTw14sTCxi6WH4qbQSBxRqAEej/A\n" +
                "wfk1kmkm4WF7zTUT+fXIHDJxFJJXqFZ+LWldYYEVqSi02gpbYkyLm9hxoLDoAxS2\n" +
                "bj/sFaH4Bxr/eUCqjOiEsGzdY1m65+cp5jv8cJK05jwqxO5/3KZcF/ShA7AN3dJi\n" +
                "NAokoextBtXBWlGvrDIfFafOy/uCnsO6NeORWbgZ88TOXPD816ff5Y8kMwkDkIk2\n" +
                "9dK4m0aL/MDI+Fgx78zRYwn5xHbTMaFz+hex+gjo4grx3KYXeoxBAchUuTsVNoo4\n" +
                "kbfCwMQEHwEKAHgFgl4L4QAJEAitUcrkcPAGRxQAAAAAAB4AIHNhbHRAbm90YXRp\n" +
                "b25zLnNlcXVvaWEtcGdwLm9yZ4csZe1ah1tj2AjxfdDMsH2wvSEwZjb/73ICKnm7\n" +
                "BySQAhUKApsDAh4BFiEE4yy22oICkbfnbbGoCK1RyuRw8AYAAGYFCACiKnCb2NBZ\n" +
                "a/Jj1aJe4R2rxPZj2ERXWe3bJKNPKT7K0rVDkTw1JRiTfCsuAY2lY9sKJdhQZl+a\n" +
                "zXm64vvTc6hEGRQ/+XssDlE2DIn8C34HDc495ZnryHNB8Dd5l1HdjqxfGIY6HBPJ\n" +
                "Udx0dedwP42Oisg9t5KsC8zld/+MIRgzkp+Dg0LXJVnDuwWEPoo2N6WhAr5ReLvX\n" +
                "xALX5ht9Lb3lP0DASZvAKy9BO/wRCr294J8dg/CowAfloyf0Ko+JjyjanmZn3acy\n" +
                "5CGkVN2mc+PFUekGZDDy5ooYkgXO/CmApuTNvabct+A7IVVdWWM5SWb90JvaV9SW\n" +
                "ji6nQphVm7StwsDEBB8BCgB4BYJaSXoACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0\n" +
                "QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfVZdjLYZxDX2hvy3aGrsE4i0avLDMz\n" +
                "f3e9kVHmaD6PAgIVCgKbAwIeARYhBOMsttqCApG3522xqAitUcrkcPAGAABQYwgA\n" +
                "rfIRxq95npUKAOPXs25nZlvy+xQbrmsTxHhAYW8eGFcz82QwumoqrR8VfrojxM+e\n" +
                "CZdTI85nM5kzznYDU2+cMhsZVm5+VhGZy3e3QH4J/E31D7t1opCvj5g1eRJ4Lgyw\n" +
                "B+cYGcZBYp/bQT9SUYuhZH2OXCR04qSbpVUCIApnhBHxKNtOlqjAkHeaOdW/8XeP\n" +
                "sbfvrtVOLGYgrZXfY7Nqy3+Wzbdm8UvVPFXH+uHEzTgyvYbnJBYkjORmCqUKs860\n" +
                "PL8ekeg+sL4PHSRj1UUfwcQD55q0m3Vtew2KiIUi4wKi5LceDtprjoO5utU/1YfE\n" +
                "AiNMeSQHXKq83dpazvjrUs0SanVsaWV0QGV4YW1wbGUub3JnwsDEBBMBCgB4BYJa\n" +
                "SXoACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBn\n" +
                "cC5vcmc6Rix7CeIfWwnaQjk3bBrkAiY7jS9N+shuRdHZ0gKKsgIVCgKbAwIeARYh\n" +
                "BOMsttqCApG3522xqAitUcrkcPAGAACf9QgAsxtfAbyGbtofjrXTs9lsKEWvGgk0\n" +
                "2fSYyKjPbyaRqh72MlIlUXwqq1ih2TJc3vwF8aNVDrcb9DnBabdt2M1vI3PUaeG3\n" +
                "1BmakC/XZCNCrbbJkyd/vdMLqw7prLrp0auVNNhLYxOK9usXbClNxluo4i/lSFVo\n" +
                "5B9ai+ne1kKKiplzqy2qqhdeplomcwGHbB1CkZ04DmCMbSSFAGxYqUC/bBm0bolC\n" +
                "ebw/KIz9sEojNKt6mvsFN67/hMYeJS0HVlwwc6i8iKSzC2D53iywhtvkdiKECXQe\n" +
                "XDf9zNXAn1wpK01SLJ0iig7cDFrtoqkfPYzbNfC0bt34fNx9iz3w9aEH8c7ATQRa\n" +
                "SsuAAQgAu5yau9psltmWiUn7fsRSqbQInO0iWnu4DK9IXB3ghNYMcii3JJEjHzgI\n" +
                "xGf3GiJEjzubyRQaX5J/p7yB1fOH8z7FYUuax1saGf9c1/b02N9gyXNlHam31hNa\n" +
                "aL3ffFczI95p7MNrTtroTt5oZqsc+i+oKLZn7X0YAI4tEYwhSnUQYB/F7YqkkI4e\n" +
                "V+7CxZPA8pBhXiAOK/zn416PsZ6JS5wsM65yCtOHcAAIBnKDnC+bQi+f1WZesSoc\n" +
                "y/rXx3QEQmodDu3ojhS+VxcYGeZCUcFF0FyZBIkGjHIVQLyOfjP3FRJ4qFXMz9/Y\n" +
                "IVoM4Y6guTERMTEj/KDG4BP7RfJHTQARAQABwsI8BBgBCgHwBYJeC+EACRAIrVHK\n" +
                "5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfcAa1Z\n" +
                "PWTtg60w3Oo4dt4Fa8cKFYbZYsqDSHV5pwEfMwKbAsC8oAQZAQoAbwWCXgvhAAkQ\n" +
                "EPy8/w6Op5FHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn\n" +
                "L6I2+VyN5T1FoVgj3cdnMLYCpcB5i/FRSCVKybuLzrgWIQTOphDQhPpR8hHhxGwQ\n" +
                "/Lz/Do6nkQAArk8H/AhjM9lqbffFL6RRR4HTjelspy4A3nyTicCljrDuXDUh23Gf\n" +
                "LvajTR5h16ZBqAF7cpb9rrlz1C1WcS5JLVxzXAe7f+KOfXu+eyLhpTzZ8VT3pK3h\n" +
                "HGaYwlVlXrBZP0JXgL8hm6hDSXZQZtcpsnQ1uIHC9ONxUB4liNFhTqQCQYdQJFiF\n" +
                "s1umUbo/C4KdzlDI08bM3CqEKat9vUFuGG68mDg0CrRZEWt946L5i8kZmBUkSShI\n" +
                "m2k5e2qE/muYeM6qKQNsxlx3VIf5eUhtxCi9fg7SjvHkdUSFstYcxAdaohWCFCEs\n" +
                "DJI12hzcKQazSjvtKF4BNBKgX/wLsbVQnYLd9ggWIQTjLLbaggKRt+dtsagIrVHK\n" +
                "5HDwBgAANjMH/1MY7DJyxkiTjc/jzmnVxqtHOZDCSmUqk0eh/6BHs+ostWqkGC6+\n" +
                "7dfxDnptwcqandYey4KF2ajt4nOwu0xQw/NEF3i81h7IiewY7G+YT69DUd+DvVUQ\n" +
                "emfKNYVOrMqoH7QU5o4YojdJiDeIp2d/JyJrqyof78JFAHnNZgHC2T2zo9E54dnO\n" +
                "TY9VNUNCOUct5Rby0GXjTIURO0f485eGuZxVWdLRllDYOiCrQHPSHhrxHVXVMbYJ\n" +
                "oroPy+IyaJanVoAWgyipBmmIDV8aINM2RLMsGkuPTRtITI2ZlGOQN7xgy4LqWzjP\n" +
                "nrzMXfwBEDx/nrwdG6zEGMK8AkVkMT5uJJvCwjwEGAEKAfAFglro/4AJEAitUcrk\n" +
                "cPAGRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ/Q0Z6WD\n" +
                "H2+8/F1xEEuiApsjnn2lGNZ2DeIaklJzdqQOApsCwLygBBkBCgBvBYJa6P+ACRAQ\n" +
                "/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfr\n" +
                "VATyX3tgcM2z41fqYquxVhJRavN6+w2SU4xEG++SqBYhBM6mENCE+lHyEeHEbBD8\n" +
                "vP8OjqeRAABGVggAsB8M2KI5cxXKKgVHL1dEfzg9halVavktfcT6ZVC/+aDp94tv\n" +
                "BCL16Guhq4ccN7DATrWx430/GecY6E77qvhDzmCclSbdLbiZmsrVX9kCmTfrJzFQ\n" +
                "64KfvIS5GgbL21+ZJ+pKW2HOMBGn6sgAPmTqM5UsDCpsEKDt5CJcJr3sTc8D9NhE\n" +
                "nc0dKsQ91+n9ms3W5tyyE6r9pyM6ThBCMhbQkR7hE9XWAQeO1ILSFGnie0aFcTU0\n" +
                "Oo0wL1MaiSyA/8XpKq23xfx1kNS9hQkdq0aWehNoTJdCt1Nq1cWABy2rQR0x+qhG\n" +
                "WowfsAjnBautxvet28t2kPCAIMniYpWc89BwfhYhBOMsttqCApG3522xqAitUcrk\n" +
                "cPAGAACq1gf/Q7H9Re5SWk+UOn/NQPRedf544YJ/YdQnve/hSaPGL33cUzf4yxzF\n" +
                "ILnK19Ird5f8/mTT1pg99L3ixE3N5031JJKwFpCB69Rsysg88ZLDL2VLc3xdsAQd\n" +
                "UbVaCqeRHKwtMtpBvbAFvF9plwam0SSXHHr/JkYm5ufXN6I8ib/nwr1bFbf/Se0W\n" +
                "uk9RG4ne9JUBCrGxakyVd+OgLLhvzOmJa7fDC0uUZhTKFbjMxLhaas4HFYiRbfz2\n" +
                "T0xz9gyDytDWsEFM+XoKHlEH8Fx/U2B5/8N0Q+pIFoEuOmBO+5EPvPIlxNByHgia\n" +
                "NIuKt1Mu+UAb2Spl6D5zbDfX/3vqxdhYHw==\n" +
                "=9epL\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        TestSignature t0 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJYaEaACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmeoPMfalw2oS7uyOKnOXJSN8Gx7pr/BMlo3Xn8nTgx6\n" +
                "ORYhBOMsttqCApG3522xqAitUcrkcPAGAABXbAf/WfWaQYNuATAKwxYrJx4fd5kt\n" +
                "0M6sn1q7wK1MIxursG2+FuKafV25O9+pde8Nog77OEgegwk+HokOVFpVXfOzHQjs\n" +
                "8dwWTtTQlX5NIBNvtqS7cvCKhjsqaHKgmzsenMjCEbpDZ3C5CoqcYicykqEU/Ia0\n" +
                "ZGC4lzRByrgNy/w+/iLN748S707bzBLVc/sE73k9N5pANAlE+cA/sHI1Gp2WxJR9\n" +
                "t2Fk4x6/85PEnF1RHI16p/wSEeuRaBpyw9QGZBbVDVt5wvgttxZjteGGSwBM3WI/\n" +
                "gPfC0LW+JQ2W+dwY0PN/7yuARVRhXpKiBI4xqp7x3OanQX6quU77g3B8nXAt3A==\n" +
                "=StqT\n" +
                "-----END PGP SIGNATURE-----\n", false, "Signature predates primary key");
        TestSignature t1 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJa564ACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfM0EN4Ei0bQv6UO9BRq2wtUfV948cRynRMBb8TSGCG\n" +
                "tBYhBOMsttqCApG3522xqAitUcrkcPAGAAAlNwf+L0KQK9i/xmYKOMV2EX13QUoZ\n" +
                "vvb/pHGZaCQ9JtvEF2l2DT0DqByZ+tOv5Y4isU+un7CraoyvyajAwR0Yqk937B6C\n" +
                "HQHKMkmIl+5R4/xqSoWYmOidbrgilojPMBEhB3INQ8/THjjFijtLzitVhnWBd7+u\n" +
                "s0kcqnWnOdx2By4aDe+UEiyCfSE02e/0tIsM71RqiU91zH6dl6+q8nml7PsYuTFV\n" +
                "V09oQTbBuuvUe+YgN/uvyKVIsA64lQ+YhqEeIA8Quek7fHhW+du9OIhSPsbYodyx\n" +
                "VWMTXwSWKGNvZNAkpmgUYqFjS2Cx5ZUWblZLjrNKBwnnmt50qvUN7+o2pjlnfA==\n" +
                "=UuXb\n" +
                "-----END PGP SIGNATURE-----\n", true);
        TestSignature t2 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJdP4iACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfFzYGoiuSjN+gz1IDD4ZvRXGuPTHks0/pIiGY90mrZ\n" +
                "WxYhBOMsttqCApG3522xqAitUcrkcPAGAABGPAf/ck7tJAFoPIDd9fTPZANpNGoW\n" +
                "Fq6VuNfy/nLjz2gkHFX/lLAxQ0N3McIdRA++Ik/omb0lis3R2DVNgwqNm2OF34HE\n" +
                "qxmPmrQHBgk2q0fDH4NCE0XnYQjQT65V99IfiaQu+oS3Mq8MuYsDYvRVvRKMwt49\n" +
                "fcDnvFtAtCqEETdv6wV5cUZmdQ3L9NU9bApJ0jk+EHVdpfTUIbOYYGnsIe/4Aa0d\n" +
                "jgzu4Em79ynosOn//953XJ7OO8LCDi1EKt+nFuZARUlt/Jwwull6zzp7HUPw6HPt\n" +
                "Upp7os8TIPC4STwoSeEKaxEkrbMGFnDcoDajnKKRt5+MkB24Oq7PHvnzgnPpVg==\n" +
                "=Ljv7\n" +
                "-----END PGP SIGNATURE-----\n", false, "Key is revoked at this time");
        TestSignature t3 = new TestSignature("-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJmhTYiCRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfbjQf/zfoJQT0hhna4RDjOESBLgGaCbc5HLeo751F4\n" +
                "NxYhBOMsttqCApG3522xqAitUcrkcPAGAABqBQgAkkNmYf6yLPvox+ZayrLtMb9D\n" +
                "ghgt0nau72DSazsJ6SAq2QqIdr0RRhRa2gCETkp4PpeoDWmIvoVj35ZnfyeO/jqy\n" +
                "HECvRwO0WPA5FXQM6uG7s40vDTRFjlJMpPyHWnn2igcR64iDxBGmc40xi9CcmJP9\n" +
                "tmA26+1Nzj1LcfNvknKZ2UIOmnXiZY0QssIdyqsmJrdFpXs4UCLUzdXkfFLoxksU\n" +
                "mk4B6hig2IKMj5mnbWy/JQSXtjjI+HHmtzgWfXs7d9iQ61CklbtCOiPeWxvoqlGG\n" +
                "oK1wV1olcSar/RPKTlMmQpAg9dztQgrNs1oF7EF3i9kwNP7I5JzekPiOLH6oMw==\n" +
                "=5KMU\n" +
                "-----END PGP SIGNATURE-----\n", true);

        signatureValidityTest(api, CERT, t0, t1, t2, t3);
    }

    private void signatureValidityTest(OpenPGPApi api, String cert, TestSignature... testSignatures)
            throws IOException
    {
        OpenPGPCertificate certificate = api.readKeyOrCertificate().parseCertificate(cert);

        for (int i = 0; i != testSignatures.length; i++)
        {
            TestSignature test = testSignatures[i];
            PGPSignature signature = test.getSignature();
            OpenPGPCertificate.OpenPGPComponentKey signingKey = certificate.getSigningKeyFor(signature);

            boolean valid = signingKey.isBoundAt(signature.getCreationTime());
            if (valid != test.isExpectValid())
            {
                StringBuilder sb = new StringBuilder("Key validity mismatch. Expected " + signingKey.toString() +
                        (test.isExpectValid() ? (" to be valid at ") : (" to be invalid at ")) + UTCUtil.format(signature.getCreationTime()));
                if (test.getMsg() != null)
                {
                    sb.append(" because:\n").append(test.getMsg());
                }
                sb.append("\n").append(signingKey.getSignatureChains());
                fail(sb.toString());
            }
        }
    }

    private void testGetPrimaryUserId(OpenPGPApi api)
            throws PGPException
    {
        final Date now = new Date((new Date().getTime() / 1000) * 1000);
        Date oneHourAgo = new Date(now.getTime() - 1000 * 60 * 60);

        OpenPGPKeyGenerator gen = api.generateKey(oneHourAgo);
        OpenPGPKey key = gen.withPrimaryKey()
                .addUserId("Old non-primary <non-primary@user.id>")
                .addUserId("New primary <primary@user.id>",
                        SignatureParameters.Callback.Util.modifyHashedSubpackets(new SignatureSubpacketsFunction()
                        {
                            public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                            {
                                subpackets.removePacketsOfType(SignatureSubpacketTags.CREATION_TIME);
                                subpackets.setSignatureCreationTime(now);
                                subpackets.setPrimaryUserID(false, true);
                                return subpackets;
                            }
                        }))
                .build(null);
        isEquals("Expect to find valid, explicit primary user ID",
                key.getUserId("New primary <primary@user.id>"),
                key.getPrimaryUserId());

        isEquals("Explicit primary UserID is not yet valid, so return implicit UID",
                key.getUserId("Old non-primary <non-primary@user.id>"),
                key.getPrimaryUserId(oneHourAgo));
    }

    public static class TestSignature
    {
        private final PGPSignature signature;
        private final boolean expectValid;
        private final String msg;

        public TestSignature(String armoredSignature, boolean expectValid)
                throws IOException
        {
            this(armoredSignature, expectValid, null);
        }

        public TestSignature(String armoredSignature, boolean expectValid, String msg)
                throws IOException
        {
            this.signature = parseSignature(armoredSignature);
            this.expectValid = expectValid;
            this.msg = msg;
        }

        private static PGPSignature parseSignature(String armoredSignature)
                throws IOException
        {
            ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(armoredSignature));
            ArmoredInputStream aIn = new ArmoredInputStream(bIn);
            BCPGInputStream pIn = new BCPGInputStream(aIn);
            PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);

            PGPSignatureList sigs = (PGPSignatureList) objFac.nextObject();

            pIn.close();
            aIn.close();
            bIn.close();

            return sigs.get(0);
        }

        public PGPSignature getSignature()
        {
            return signature;
        }

        public boolean isExpectValid()
        {
            return expectValid;
        }

        public String getMsg()
        {
            return msg;
        }
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPCertificateTest());
    }
}
