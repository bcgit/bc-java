package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class IgnoreUnknownEncryptedSessionKeys
    extends SimpleTest
{

    private PGPSecretKeyRing tsk;

    public static void main(String[] args)
    {
        SimpleTest.runTest(new IgnoreUnknownEncryptedSessionKeys());
    }

    public String getName()
    {
        return "IgnoreUnknownEncryptedSessionKeys";
    }

    public void performTest()
        throws Exception
    {
        readKey();

        // pkesk + unknown pkesk
        pkesk3_pkesk23_seip();
        pkesk23_pkesk3_seip();

        // pkesk + unknown skesk
        skesk23_pkesk3_seip();
        pkesk3_skesk23_seip();
    }

    private void readKey()
        throws IOException
    {
        String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: Bob's OpenPGP Transferable Secret Key\n" +
            "\n" +
            "lQVYBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAQAL/RZqbJW2IqQDCnJi4Ozm++gPqBPiX1RhTWSjwxfM\n" +
            "cJKUZfzLj414rMKm6Jh1cwwGY9jekROhB9WmwaaKT8HtcIgrZNAlYzANGRCM4TLK\n" +
            "3VskxfSwKKna8l+s+mZglqbAjUg3wmFuf9Tj2xcUZYmyRm1DEmcN2ZzpvRtHgX7z\n" +
            "Wn1mAKUlSDJZSQks0zjuMNbupcpyJokdlkUg2+wBznBOTKzgMxVNC9b2g5/tMPUs\n" +
            "hGGWmF1UH+7AHMTaS6dlmr2ZBIyogdnfUqdNg5sZwsxSNrbglKP4sqe7X61uEAIQ\n" +
            "bD7rT3LonLbhkrj3I8wilUD8usIwt5IecoHhd9HziqZjRCc1BUBkboUEoyedbDV4\n" +
            "i4qfsFZ6CEWoLuD5pW7dEp0M+WeuHXO164Rc+LnH6i1VQrpb1Okl4qO6ejIpIjBI\n" +
            "1t3GshtUu/mwGBBxs60KBX5g77mFQ9lLCRj8lSYqOsHRKBhUp4qM869VA+fD0BRP\n" +
            "fqPT0I9IH4Oa/A3jYJcg622GwQYA1LhnP208Waf6PkQSJ6kyr8ymY1yVh9VBE/g6\n" +
            "fRDYA+pkqKnw9wfH2Qho3ysAA+OmVOX8Hldg+Pc0Zs0e5pCavb0En8iFLvTA0Q2E\n" +
            "LR5rLue9uD7aFuKFU/VdcddY9Ww/vo4k5p/tVGp7F8RYCFn9rSjIWbfvvZi1q5Tx\n" +
            "+akoZbga+4qQ4WYzB/obdX6SCmi6BndcQ1QdjCCQU6gpYx0MddVERbIp9+2SXDyL\n" +
            "hpxjSyz+RGsZi/9UAshT4txP4+MZBgDfK3ZqtW+h2/eMRxkANqOJpxSjMyLO/FXN\n" +
            "WxzTDYeWtHNYiAlOwlQZEPOydZFty9IVzzNFQCIUCGjQ/nNyhw7adSgUk3+BXEx/\n" +
            "MyJPYY0BYuhLxLYcrfQ9nrhaVKxRJj25SVHj2ASsiwGJRZW4CC3uw40OYxfKEvNC\n" +
            "mer/VxM3kg8qqGf9KUzJ1dVdAvjyx2Hz6jY2qWCyRQ6IMjWHyd43C4r3jxooYKUC\n" +
            "YnstRQyb/gCSKahveSEjo07CiXMr88UGALwzEr3npFAsPW3osGaFLj49y1oRe11E\n" +
            "he9gCHFm+fuzbXrWmdPjYU5/ZdqdojzDqfu4ThfnipknpVUM1o6MQqkjM896FHm8\n" +
            "zbKVFSMhEP6DPHSCexMFrrSgN03PdwHTO6iBaIBBFqmGY01tmJ03SxvSpiBPON9P\n" +
            "NVvy/6UZFedTq8A07OUAxO62YUSNtT5pmK2vzs3SAZJmbFbMh+NN204TRI72GlqT\n" +
            "t5hcfkuv8hrmwPS/ZR6q312mKQ6w/1pqO9qitCFCb2IgQmFiYmFnZSA8Ym9iQG9w\n" +
            "ZW5wZ3AuZXhhbXBsZT6JAc4EEwEKADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgEC\n" +
            "F4AWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAUCXaWe+gAKCRD7/MgqAV5zMG9sC/9U\n" +
            "2T3RrqEbw533FPNfEflhEVRIZ8gDXKM8hU6cqqEzCmzZT6xYTe6sv4y+PJBGXJFX\n" +
            "yhj0g6FDkSyboM5litOcTupURObVqMgA/Y4UKERznm4fzzH9qek85c4ljtLyNufe\n" +
            "doL2pp3vkGtn7eD0QFRaLLmnxPKQ/TlZKdLE1G3u8Uot8QHicaR6GnAdc5UXQJE3\n" +
            "BiV7jZuDyWmZ1cUNwJkKL6oRtp+ZNDOQCrLNLecKHcgCqrpjSQG5oouba1I1Q6Vl\n" +
            "sP44dhA1nkmLHtxlTOzpeHj4jnk1FaXmyasurrrI5CgU/L2Oi39DGKTH/A/cywDN\n" +
            "4ZplIQ9zR8enkbXquUZvFDe+Xz+6xRXtb5MwQyWODB3nHw85HocLwRoIN9WdQEI+\n" +
            "L8a/56AuOwhs8llkSuiITjR7r9SgKJC2WlAHl7E8lhJ3VDW3ELC56KH308d6mwOG\n" +
            "ZRAqIAKzM1T5FGjMBhq7ZV0eqdEntBh3EcOIfj2M8rg1MzJv+0mHZOIjByawikad\n" +
            "BVgEXaWc8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90YNBj+xS1ldGD\n" +
            "bUdZqZeef2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pzh0LzrBrVNHar\n" +
            "29b5ExdI7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4PIp1DU9ewcc2\n" +
            "WB38Ofqut3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+D9LiTWcxdUPB\n" +
            "leu8iwDRjAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYOiEFBJ9lbb4te\n" +
            "g9m5UT/AaVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t0c91kbNE5lgj\n" +
            "Z7xz6los0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLsT7Vr1QMX9jzn\n" +
            "JtTPxdXytSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH970TGYOe2aUcSx\n" +
            "IRDMXDOPyzEfjwARAQABAAv9F2CwsjS+Sjh1M1vegJbZjei4gF1HHpEM0K0PSXsp\n" +
            "SfVvpR4AoSJ4He6CXSMWg0ot8XKtDuZoV9jnJaES5UL9pMAD7JwIOqZm/DYVJM5h\n" +
            "OASCh1c356/wSbFbzRHPtUdZO9Q30WFNJM5pHbCJPjtNoRmRGkf71RxtvHBzy7np\n" +
            "Ga+W6U/NVKHw0i0CYwMI0YlKDakYW3Pm+QL+gHZFvngGweTod0f9l2VLLAmeQR/c\n" +
            "+EZs7lNumhuZ8mXcwhUc9JQIhOkpO+wreDysEFkAcsKbkQP3UDUsA1gFx9pbMzT0\n" +
            "tr1oZq2a4QBtxShHzP/ph7KLpN+6qtjks3xB/yjTgaGmtrwM8tSe0wD1RwXS+/1o\n" +
            "BHpXTnQ7TfeOGUAu4KCoOQLv6ELpKWbRBLWuiPwMdbGpvVFALO8+kvKAg9/r+/ny\n" +
            "zM2GQHY+J3Jh5JxPiJnHfXNZjIKLbFbIPdSKNyJBuazXW8xIa//mEHMI5OcvsZBK\n" +
            "clAIp7LXzjEjKXIwHwDcTn9pBgDpdOKTHOtJ3JUKx0rWVsDH6wq6iKV/FTVSY5jl\n" +
            "zN+puOEsskF1Lfxn9JsJihAVO3yNsp6RvkKtyNlFazaCVKtDAmkjoh60XNxcNRqr\n" +
            "gCnwdpbgdHP6v/hvZY54ZaJjz6L2e8unNEkYLxDt8cmAyGPgH2XgL7giHIp9jrsQ\n" +
            "aS381gnYwNX6wE1aEikgtY91nqJjwPlibF9avSyYQoMtEqM/1UjTjB2KdD/MitK5\n" +
            "fP0VpvuXpNYZedmyq4UOMwdkiNMGAOrfmOeT0olgLrTMT5H97Cn3Yxbk13uXHNu/\n" +
            "ZUZZNe8s+QtuLfUlKAJtLEUutN33TlWQY522FV0m17S+b80xJib3yZVJteVurrh5\n" +
            "HSWHAM+zghQAvCesg5CLXa2dNMkTCmZKgCBvfDLZuZbjFwnwCI6u/NhOY9egKuUf\n" +
            "SA/je/RXaT8m5VxLYMxwqQXKApzD87fv0tLPlVIEvjEsaf992tFEFSNPcG1l/jpd\n" +
            "5AVXw6kKuf85UkJtYR1x2MkQDrqY1QX/XMw00kt8y9kMZUre19aCArcmor+hDhRJ\n" +
            "E3Gt4QJrD9z/bICESw4b4z2DbgD/Xz9IXsA/r9cKiM1h5QMtXvuhyfVeM01enhxM\n" +
            "GbOH3gjqqGNKysx0UODGEwr6AV9hAd8RWXMchJLaExK9J5SRawSg671ObAU24SdY\n" +
            "vMQ9Z4kAQ2+1ReUZzf3ogSMRZtMT+d18gT6L90/y+APZIaoArLPhebIAGq39HLmJ\n" +
            "26x3z0WAgrpA1kNsjXEXkoiZGPLKIGoe3hqJAbYEGAEKACAWIQTRpm4aI7GCyZgP\n" +
            "eIz7/MgqAV5zMAUCXaWc8gIbDAAKCRD7/MgqAV5zMOn/C/9ugt+HZIwX308zI+QX\n" +
            "c5vDLReuzmJ3ieE0DMO/uNSC+K1XEioSIZP91HeZJ2kbT9nn9fuReuoff0T0Dief\n" +
            "rbwcIQQHFFkrqSp1K3VWmUGp2JrUsXFVdjy/fkBIjTd7c5boWljv/6wAsSfiv2V0\n" +
            "JSM8EFU6TYXxswGjFVfc6X97tJNeIrXL+mpSmPPqy2bztcCCHkWS5lNLWQw+R7Vg\n" +
            "71Fe6yBSNVrqC2/imYG2J9zlowjx1XU63Wdgqp2Wxt0l8OmsB/W80S1fRF5G4SDH\n" +
            "s9HXglXXqPsBRZJYfP+VStm9L5P/sKjCcX6WtZR7yS6G8zj/X767MLK/djANvpPd\n" +
            "NVniEke6hM3CNBXYPAMhQBMWhCulcoz+0lxi8L34rMN+Dsbma96psdUrn7uLaB91\n" +
            "6we0CTfF8qqm7BsVAgalon/UUiuMY80U3ueoj3okiSTiHIjD/YtpXSPioC8nMng7\n" +
            "xqAY9Bwizt4FWgXuLm1a4+So4V9j1TRCXd12Uc2l2RNmgDE=\n" +
            "=miES\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
        ByteArrayInputStream byteIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(key));
        ArmoredInputStream armorIn = new ArmoredInputStream(byteIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);
        tsk = (PGPSecretKeyRing)objectFactory.nextObject();
    }

    private void pkesk3_pkesk23_seip()
        throws IOException, PGPException
    {
        String msg = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv/RkfFn2Ec8fev6d05zZLbMgCMxg0GVrDKOrWluSKPYTlq\n" +
            "6TTzkn1qWIICAbM+R5Co17AEoLrHzB1deB5U8InYf3geTLKqCprEs+l4795xJxpf\n" +
            "x6ZJUlcO2mQPsHv+O/4weLWmvZZTok5ibK/3tj+vQL/haho4qcBATIiG6gxCAHxD\n" +
            "kXue7tNCrXlmCSoumr6sxK9+whIzcftbEDwjWnQGjZIUzM4l92Vx9s0l2Eg6gmrz\n" +
            "sXmP6cZIPkIOV7ms31ca/xkMElE1ezx4rAcxhL7efb8ygbkP+LQHuKwnM4643t7X\n" +
            "q2BZsMw4VIolBZGTvvFxNn1RJYkOguDhMmCXO6aRyOjidFr4DwlnV/EhzaYelZX0\n" +
            "PgHYomrPg59+wpFYkAV80bxFmEuB7EyxYsBY44ceXFCgiVbClq62BrXZhxuaRS/+\n" +
            "k9AGY6bicKqUnDStQopOQIh0bg1V/1rOr7Eg1ltNnib7G4HP6wlZ2ZyTMcEM8hog\n" +
            "T97kEybBbAu/v1xX6C0cwUoXQUFBQUFBQUEJYWFhYWFhYWFhYWFhYWFhYWFhYWFh\n" +
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYdJMARce\n" +
            "/wBlQyUPYPUSlV6ksTXttx7JqiMULd28op6mGZpg/FkTiPgjGhS1Mdp7bu6q5Eo/\n" +
            "qC2QFVHqeC6Gm0eliO1RS0sOflvhbKtJgg==\n" +
            "=6qUY\n" +
            "-----END PGP MESSAGE-----\n";

        attemptDecryption(msg);
    }

    private void pkesk23_pkesk3_seip()
        throws PGPException, IOException
    {
        String msg = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wUoXQUFBQUFBQUEJYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh\n" +
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYcHAzAN8L6pN+Tw3sgEL/0ZHxZ9h\n" +
            "HPH3r+ndOc2S2zIAjMYNBlawyjq1pbkij2E5auk085J9aliCAgGzPkeQqNewBKC6\n" +
            "x8wdXXgeVPCJ2H94HkyyqgqaxLPpeO/ecScaX8emSVJXDtpkD7B7/jv+MHi1pr2W\n" +
            "U6JOYmyv97Y/r0C/4WoaOKnAQEyIhuoMQgB8Q5F7nu7TQq15ZgkqLpq+rMSvfsIS\n" +
            "M3H7WxA8I1p0Bo2SFMzOJfdlcfbNJdhIOoJq87F5j+nGSD5CDle5rN9XGv8ZDBJR\n" +
            "NXs8eKwHMYS+3n2/MoG5D/i0B7isJzOOuN7e16tgWbDMOFSKJQWRk77xcTZ9USWJ\n" +
            "DoLg4TJglzumkcjo4nRa+A8JZ1fxIc2mHpWV9D4B2KJqz4OffsKRWJAFfNG8RZhL\n" +
            "gexMsWLAWOOHHlxQoIlWwpautga12YcbmkUv/pPQBmOm4nCqlJw0rUKKTkCIdG4N\n" +
            "Vf9azq+xINZbTZ4m+xuBz+sJWdmckzHBDPIaIE/e5BMmwWwLv79cV+gtHNJMARce\n" +
            "/wBlQyUPYPUSlV6ksTXttx7JqiMULd28op6mGZpg/FkTiPgjGhS1Mdp7bu6q5Eo/\n" +
            "qC2QFVHqeC6Gm0eliO1RS0sOflvhbKtJgg==\n" +
            "=qITG\n" +
            "-----END PGP MESSAGE-----\n";

        attemptDecryption(msg);
    }

    private void pkesk3_skesk23_seip()
        throws PGPException, IOException
    {
        String msg = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv/RkfFn2Ec8fev6d05zZLbMgCMxg0GVrDKOrWluSKPYTlq\n" +
            "6TTzkn1qWIICAbM+R5Co17AEoLrHzB1deB5U8InYf3geTLKqCprEs+l4795xJxpf\n" +
            "x6ZJUlcO2mQPsHv+O/4weLWmvZZTok5ibK/3tj+vQL/haho4qcBATIiG6gxCAHxD\n" +
            "kXue7tNCrXlmCSoumr6sxK9+whIzcftbEDwjWnQGjZIUzM4l92Vx9s0l2Eg6gmrz\n" +
            "sXmP6cZIPkIOV7ms31ca/xkMElE1ezx4rAcxhL7efb8ygbkP+LQHuKwnM4643t7X\n" +
            "q2BZsMw4VIolBZGTvvFxNn1RJYkOguDhMmCXO6aRyOjidFr4DwlnV/EhzaYelZX0\n" +
            "PgHYomrPg59+wpFYkAV80bxFmEuB7EyxYsBY44ceXFCgiVbClq62BrXZhxuaRS/+\n" +
            "k9AGY6bicKqUnDStQopOQIh0bg1V/1rOr7Eg1ltNnib7G4HP6wlZ2ZyTMcEM8hog\n" +
            "T97kEybBbAu/v1xX6C0cw00XCQMIH+0WngOJjNf/YWFhYWFhYWFhYWFhYWFhYWFh\n" +
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYdJM\n" +
            "ARce/wBlQyUPYPUSlV6ksTXttx7JqiMULd28op6mGZpg/FkTiPgjGhS1Mdp7bu6q\n" +
            "5Eo/qC2QFVHqeC6Gm0eliO1RS0sOflvhbKtJgg==\n" +
            "=erqS\n" +
            "-----END PGP MESSAGE-----";
        attemptDecryption(msg);
    }

    private void skesk23_pkesk3_seip()
        throws PGPException, IOException
    {
        String msg = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "w00XCQMIH+0WngOJjNf/YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh\n" +
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYcHAzAN8L6pN+Tw3sgEL/0ZH\n" +
            "xZ9hHPH3r+ndOc2S2zIAjMYNBlawyjq1pbkij2E5auk085J9aliCAgGzPkeQqNew\n" +
            "BKC6x8wdXXgeVPCJ2H94HkyyqgqaxLPpeO/ecScaX8emSVJXDtpkD7B7/jv+MHi1\n" +
            "pr2WU6JOYmyv97Y/r0C/4WoaOKnAQEyIhuoMQgB8Q5F7nu7TQq15ZgkqLpq+rMSv\n" +
            "fsISM3H7WxA8I1p0Bo2SFMzOJfdlcfbNJdhIOoJq87F5j+nGSD5CDle5rN9XGv8Z\n" +
            "DBJRNXs8eKwHMYS+3n2/MoG5D/i0B7isJzOOuN7e16tgWbDMOFSKJQWRk77xcTZ9\n" +
            "USWJDoLg4TJglzumkcjo4nRa+A8JZ1fxIc2mHpWV9D4B2KJqz4OffsKRWJAFfNG8\n" +
            "RZhLgexMsWLAWOOHHlxQoIlWwpautga12YcbmkUv/pPQBmOm4nCqlJw0rUKKTkCI\n" +
            "dG4NVf9azq+xINZbTZ4m+xuBz+sJWdmckzHBDPIaIE/e5BMmwWwLv79cV+gtHNJM\n" +
            "ARce/wBlQyUPYPUSlV6ksTXttx7JqiMULd28op6mGZpg/FkTiPgjGhS1Mdp7bu6q\n" +
            "5Eo/qC2QFVHqeC6Gm0eliO1RS0sOflvhbKtJgg==\n" +
            "=Chcy\n" +
            "-----END PGP MESSAGE-----\n";
        attemptDecryption(msg);
    }

    private void attemptDecryption(String msg)
        throws IOException, PGPException
    {
        ByteArrayInputStream byteIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(msg));
        ArmoredInputStream armorIn = new ArmoredInputStream(byteIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);

        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)objectFactory.nextObject();
        isTrue(encryptedDataList != null);

        InputStream decryptIn = null;
        for (int i = 0; i != encryptedDataList.size(); i++)
        {
            PGPEncryptedData encryptedData = encryptedDataList.get(i);
            if (encryptedData instanceof PGPPublicKeyEncryptedData)
            {
                PGPPublicKeyEncryptedData pkesk = (PGPPublicKeyEncryptedData)encryptedData;
                PGPSecretKey secretKey = tsk.getSecretKey(pkesk.getKeyID());
                isTrue(secretKey != null);

                PGPPrivateKey privateKey = secretKey.extractPrivateKey(null);
                decryptIn = pkesk.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
                break;
            }
            else if (encryptedData instanceof PGPPBEEncryptedData)
            {
                PGPPBEEncryptedData skesk = (PGPPBEEncryptedData)encryptedData;
                // decryptIn = skesk.getDataStream(new BcPBEDataDecryptorFactory())
            }
            else
            {
                throw new PGPException("Unknown packet");
            }
        }

        objectFactory = new BcPGPObjectFactory(decryptIn);
        PGPLiteralData literalData = (PGPLiteralData)objectFactory.nextObject();

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getDataStream(), byteOut);
        decryptIn.close();

        isEquals("Encrypted using SEIP + MDC.", byteOut.toString());
    }
}
