package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * This test checks how stable BCs {@link PGPPublicKeyRing} parser function is when it comes to unknown key algorithms.
 * The implementation should ignore unknown subkeys in order to be upwards compatible with future certificates.
 *
 * @see <a href="https://tests.sequoia-pgp.org/#Mock_PQ_subkey">OpenPGP Interoperability Test Suite - Mock PQ subkey</a>
 */
public class UnrecognizableSubkeyParserTest
    extends SimpleTest
{

    public static void main(String[] arg)
    {
        runTest(new UnrecognizableSubkeyParserTest());
    }
    
    public String getName()
    {
        return "UnrecognizableSubkeyParserTest";
    }
    
    public void performTest()
        throws Exception
    {
        baseCase();
        subkeyHasUnknownAlgo_MPIEncoding();
        subkeyHasUnknownAlgoOpaqueEncodingSmall();
        subkeyHasEcdsaUnknownCurveMPIEncoding();
        subkeyHasEddsaUknownCurveMPIEncoding();
        subkeyHasEcdhUnknownCurveMPIEncoding();

        // The data in these files is actually out of range, they appear to contain MPIs which
        // result in an EOF exception if parsed. GPG shows this also.
//        subkeyHasEcdsaUnknownCurveOpaqueEncodingSmall();
//        subkeyHasEddsaUnknownCurveOpaqueEncodingSmall();
//        subkeyHasEcdhUnknownCurveOpaqueEncodingSmall();
    }

    // base case
    private void baseCase()
        throws IOException
    {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsDNBF2lnPIBDADW\n" +
            "ML9cbGMrp12CtF9b2P6z9TTT74S8iyBOzaSvdGDQY/sUtZXRg21HWamXnn9sSXvI\n" +
            "DEINOQ6A9QxdxoqWdCHrOuW3ofneYXoG+zeKc4dC86wa1TR2q9vW+RMXSO4uImA+\n" +
            "Uzula/6k1DogDf28qhCxMwG/i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6rrd5y2AO\n" +
            "baifV7wIhEJnvqgFXDN2RXGjLeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA0YwIMgIT\n" +
            "86Rafp1qKlgPNbiIlC1g9RY/iFaGN2b4Ir6GDohBQSfZW2+LXoPZuVE/wGlQ01rh\n" +
            "827KVZW4lXvqsge+wtnWlszcselGATyzqOK9LdHPdZGzROZYI2e8c+paLNDdVPL6\n" +
            "vdRBUnkCaEkOtl1mr2JpQi5nTU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV8rUnR76U\n" +
            "qVC7KidNepdHbZjjXCt8/Zo+Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwzj8sxH48A\n" +
            "EQEAAcLBPgQYAQoAcgWCXaWc8gkQ+/zIKgFeczBHFAAAAAAAHgAgc2FsdEBub3Rh\n" +
            "dGlvbnMuc2VxdW9pYS1wZ3Aub3JniJK8Q5VEmU0QnIrlhswzdHX12wiDXkd7YN6Q\n" +
            "RM1qbOkCmwwWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAxM8L+wQoJeiDA8PqBunw\n" +
            "mAeuWMniUdKhG1w1Flrt9aZkUoBr9nIulpoRox56Uws33QjN6+CkGMuGj3FbNEHK\n" +
            "6JL46NnUAQbkioUtHXO55KwQrvaBVwDhacIWWOKIlfOvg61XPsV6vJ65AanF1TyY\n" +
            "/zPlhRRWam1dBPwO5Zmbi3UMAKkOd52Ju48CQAkCl1Uoo7Z0YGJwjyHuD1swX9ic\n" +
            "atg9MO1zjmoRvgvNxO8MqPdb9ioEE9srKwTjMBWXegs8bbQJtvFU/59jI64ZKAqQ\n" +
            "lmy3Qstz12hmgJsX1iRnE+Y287SC5KzTuysEd36zKkOCBlVbTmkaayC5bbaiLmOG\n" +
            "sjUiF9ft2i2nfM+2v8QvpRrUV6LGRUP2I6PNiQhdTV3ZyPD1u5xD6Yg69n2XSHQE\n" +
            "6vCrIXtj5UmlMq5Y4vrAGqzNqHHZITKhfETm+0iGOy4L6Uyuhj3gGjWJ1shhlHx4\n" +
            "KcbFeBqrT9utHUoKfa9oUr0o6IMrmT+94bOtyPRPUF7QJl+dig==\n" +
            "=0Jja\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing bobCert = certFromString(CERT);
        isEquals(2, count(bobCert.getPublicKeys()));
    }

    public void subkeyHasUnknownAlgo_MPIEncoding()
        throws IOException
    {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsFKBF2lnPJjCACo\n" +
            "21HB2d5WEFpHBfjyu55+z3N45AoMDZxDa9cyy5lqa0ImwFR4At+CmH+tA3/0+LwZ\n" +
            "CgG0sm+wMUScxLfPle6G81qXuxhaAEFwsoCWMObRmXZ/t8ujlkGCEG2BOh/bkpQd\n" +
            "mXwznNLC9ri7Gs+V/RYCwhih/Nl6raQgi3hAMJWi+P78ZuOBgrDiiPF+F4UFTl9T\n" +
            "fvtb05YLd1pZhLp/nUgGrIc10BHnGORfn12vDMa5tcE59K6Z97UCu6gG/HeUNw4a\n" +
            "aLDmojN3WUFUSI3KWORzEU6zVrntQxPgt3HYoii/ZtEGOZyKvRTm/s0do10o0i7i\n" +
            "sp9gDIXQsBme/qotf/moCAD6WjF0nEtHC33wnCowYWa8VS9sp9CYxgO6zl4WC81B\n" +
            "wNcEHVLwt8p1Wy1GGRWPp/NtLfv000FOfrAoqjwGtIVv4QZPIywS+MKxoB0h/YVs\n" +
            "jFxCXxHY3K9GMsTjRI55vk8DkekXOUpw5zBnBCzRE/HfdrGeuzFYcJBoCFbpg1SC\n" +
            "gDGy1owuzZ09xT/mn2ailhgTnypsPupIOG19Ro39lz9SaJRSXFTFI12UA8bYq7OU\n" +
            "7Kl78EkrcBV1VH/3/jlwDmE6OMN+ybpzWJ/gRL1YkV8dwPyXtGmoKkXFm+CdDVFE\n" +
            "m+bkJk4XxiclwbfLVsY4rCKghW5hRjJtPPWgrvAXzt9xwsE+BBgBCgByBYJdpZzy\n" +
            "CRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5v\n" +
            "cmddsypF+7C1PmvhG7iGs/MQFjOHDTRYU2dWxmdLSNUyWgKbDBYhBNGmbhojsYLJ\n" +
            "mA94jPv8yCoBXnMwAACauAv/WaMjAZ2ZOO/+wlJA4CSfXBs07HeCDZBOryt1dQ7l\n" +
            "bdSQVGP7ncWPzqeOEHvHqODLHX+D2x7fUYo9LuWyay9vnhc/GVFRwaPMNVhHCQGj\n" +
            "rWPaldOWVEx+xtY0dEJyO9Vchb+H0I3+pgjiHP8dD6Mb0XmwgB1TprVEaoAeq1t6\n" +
            "/oUFfU6xNpL5rlT4fm+mkP+sS605NW9ZSbUpwxvvjUmahA1tNQnfezwV8GyjosXD\n" +
            "QtE8RDGki7EzkBEMtFGHcqOMNbqYpBxXJXS1IPC00VJZZkYnwArLLWUdWKgZjM6Q\n" +
            "6yj9etO7BmbaaI1Ff/rJEoqRQsiXgQkCBNwQUeQopafU4SWfFwglhS0zuzM37CtN\n" +
            "/DEDWsrDBEY9kTszlda2fN9BCuATEU9ml5KqJ1A/eOSdlRk6/eFoyrbo4wh0G9+C\n" +
            "MrUZbPWA9DOD/VA57OE30hiCSmxmrEWdrFnhNJGxXxQlPnR2wZKihetPp3RQ2J9h\n" +
            "/Y2Ze1hbQCOT+DqqgX4KKeVN\n" +
            "=r4sv\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing cert = certFromString(CERT);
        isEquals("Unrecognizable subkey must be ignored", 1, count(cert.getPublicKeys()));
    }

    public void subkeyHasUnknownAlgoOpaqueEncodingSmall()
        throws IOException
    {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsFGBF2lnPJjvQJO\n" +
            "VJxScq4+CLtil6Z8TjYbzBWwHaq86Z7bvbYPDy5pHK0ZafvZUxlVR5u3oV5OQkdt\n" +
            "Uc+Bz32TYoGkmGAgoPOIvdXWNDsofu5LryRT0G1qmmT3yy/pm3F20/j/S2AGGR0t\n" +
            "8+INmOZDgkDPJ0eDwLYdwtF3jUPEIKJJHYBvzQNt73o/gpZ5b/uWfpmksecRIhnK\n" +
            "nPM75vom8IzXqENj9aqrYw1gEBoG6marAlY3cCsOwNB8XhuMF/wmvbXDs4faa+nT\n" +
            "L84GxCZ/Vrmzmr9XPO5Bwc2dGwVpsPRkCKMndeMNRVz6iZaaGeKIhquPsRGaGB2x\n" +
            "zexZnXy/M+q5R/p31Jz7e5P1olDxXxplBfh8PUdJU/tDSYJ5LTcxF6Yqu84/f4hO\n" +
            "CkaWSbUDIoTCh49BVnq0Iptc2GMS42FYkRKCUxIFokk39FY0sWPg3mWoaDya1Hf4\n" +
            "iEPSP+PPMOUYFzgTQ8JNcificKa1KQPJgt2KymG1StFMm6+eERhIt6seA8eApsRL\n" +
            "BdOL+mvzg4qp5guu2qL2wnef8o/DjS1VdLro6uexjtd3rJNsawbL4E/4boICQd6x\n" +
            "3nge792es533rm9gzbt82bJ3Fb6xFDbG1OjbQakQJW7TxE3Qiduu0ZwDAjsHZjei\n" +
            "JmfoNgee/6W2AMEN5bwB3/E5+WDeP8cuuO9ldpvCwT4EGAEKAHIFgl2lnPIJEPv8\n" +
            "yCoBXnMwRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZwmv\n" +
            "6gvC4U2ijOJieWwup2iXb+34JkPTbrtPunh+X2ukApsMFiEE0aZuGiOxgsmYD3iM\n" +
            "+/zIKgFeczAAAH+ZC/4otDK4pP1X7Jp3S9HuOnWXYM3uTPdaPcYKWZTwOdsx+0ha\n" +
            "ohTINcOBdGvlJd7Kkc/eX5rstRouWjtzReIW6tPgdTSlP4jW1b1xFm4c2R+05kFM\n" +
            "l3J/lptLuer/PIGONdqdUevHR2Zsttter3TqlyrZq0y+N2K4OgMRlBUWpCl0Wusl\n" +
            "iHV6ALnms4zUGrhlQIKSDDU8zHVzJD6QIDOd3qEUnIqFOqP+x0nIrvYK/eSQ72nD\n" +
            "6M0P4Lh1sa/TZcbf3fLfR52NrFToeuP5MKH1ZXrNckqjIMp0IF+TNauwgze/zshV\n" +
            "f6ve41CgDUVFZHxGRhtJ1dLzrx9YHqjXOZ7XRZnhfgB+DCwJ1QCIWDioJ18O9pfE\n" +
            "7IosyFzRY53V3q85p5q/5RtBePsqp6Zx9dY8zNfU+Ph18YH/c4ls1uqrRPcNdIRV\n" +
            "6vJ6HKWePAGVj/uJJdFSc1/QyZzvuxRJVvbWiapD57cfsmmc3VkKmGOQN5v/gDn8\n" +
            "J27Z7zpkTfD9QCroP84=\n" +
            "=NHTB\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing cert = certFromString(CERT);
        isEquals("Unrecognizable subkey must be ignored", 1, count(cert.getPublicKeys()));
    }

    public void subkeyHasEcdsaUnknownCurveMPIEncoding()
        throws IOException
    {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsBUBF2lnPITCwYJ\n" +
            "KwYBBAGColpjCACWbQQxg5E2dxC/pZ3ZFQyJD1gKDrXLPJ8lZVCRrKtSo2qVcqas\n" +
            "Zb2GNojV8LD2l+3Eq+HMsFaLnkD/Ot4S0DgwfyLPNeKPXLRBD5BrhjewD2Kd5J1P\n" +
            "4eAX/t/X8oe/66gk2Mk2ykf8IfMPk7FsX5SjurepoH8nCzfHY5NBU9+UVOFnhLPq\n" +
            "UgKDVdkhNdhHgxPXcYE61lRpwKjSEKBx/oRshCxlyrJcQdAth1ogGT5wAu0gZ6wl\n" +
            "d6us2Xkt3FG2CJU2xS0Xd3EaPLRmN5hmKEQHMk/aoeVXMVIXNA5OskDcIzS7UbPQ\n" +
            "s8DEHa38TUUezGndB6605LdRmukVsTJogj+swsE+BBgBCgByBYJdpZzyCRD7/Mgq\n" +
            "AV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcz2ySS\n" +
            "QEIaXr2QHnziGOW6GNcw58dJ7mxxVOF27uwEygKbIBYhBNGmbhojsYLJmA94jPv8\n" +
            "yCoBXnMwAACu9gwAprtxTYXyrblfVgOmXHLT1TncS5S7gfrpSa8n5ckPBrIuWGxo\n" +
            "MuJJ8GQXnqtJCBTsbq/oV/5GN3aAc37mqV7e6fYSfmoBCF5AXTXvf2Tsgo9g53Mv\n" +
            "CWnW2glTY+tEtu2ySzVq3h7rLGvVI8qiWOAPQ0cxxTQVUPwbV+LUhtO4KCDBe2hk\n" +
            "Oa9UFtHj51+7GomUPPdCta9E2Ws0+JEqBaHy7zshk/sRQsyQkO0nUk2ZAfnZP3ru\n" +
            "pYcstBQLmcSt8KvTUuC48VC6lZlqydsP3AnjSGleRto4DWRAuuoQcONTBeS83a88\n" +
            "YY7qVK4F6L/Iz1662Ojh110Ynvuj0+Br0QoBFtsEpHlTMtuFUQEQ9MaYvj880vjM\n" +
            "NdN5tMfKKmk8lUYD0TvBQFcomuil+gJ5yyU6hHoFJA/vynXT2OkiOfxoWmzjL7Hg\n" +
            "dRVC4ABUoe1TZyJ6vPRifaRaRz85MUJ/DspuKU02KFqLHfJmLdnBRHME8rKkHzj9\n" +
            "V9++XwJcdrSlKEyM\n" +
            "=H4J2\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing cert = certFromString(CERT);
        isTrue("BC must be able to deal with ecdsa subkeys with unknown curves", cert != null);
    }

    public void subkeyHasEcdsaUnknownCurveOpaqueEncodingSmall()
        throws IOException
    {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsFSBF2lnPITCwYJ\n" +
            "KwYBBAGColpjvQJOVJxScq4+CLtil6Z8TjYbzBWwHaq86Z7bvbYPDy5pHK0ZafvZ\n" +
            "UxlVR5u3oV5OQkdtUc+Bz32TYoGkmGAgoPOIvdXWNDsofu5LryRT0G1qmmT3yy/p\n" +
            "m3F20/j/S2AGGR0t8+INmOZDgkDPJ0eDwLYdwtF3jUPEIKJJHYBvzQNt73o/gpZ5\n" +
            "b/uWfpmksecRIhnKnPM75vom8IzXqENj9aqrYw1gEBoG6marAlY3cCsOwNB8XhuM\n" +
            "F/wmvbXDs4faa+nTL84GxCZ/Vrmzmr9XPO5Bwc2dGwVpsPRkCKMndeMNRVz6iZaa\n" +
            "GeKIhquPsRGaGB2xzexZnXy/M+q5R/p31Jz7e5P1olDxXxplBfh8PUdJU/tDSYJ5\n" +
            "LTcxF6Yqu84/f4hOCkaWSbUDIoTCh49BVnq0Iptc2GMS42FYkRKCUxIFokk39FY0\n" +
            "sWPg3mWoaDya1Hf4iEPSP+PPMOUYFzgTQ8JNcificKa1KQPJgt2KymG1StFMm6+e\n" +
            "ERhIt6seA8eApsRLBdOL+mvzg4qp5guu2qL2wnef8o/DjS1VdLro6uexjtd3rJNs\n" +
            "awbL4E/4boICQd6x3nge792es533rm9gzbt82bJ3Fb6xFDbG1OjbQakQJW7TxE3Q\n" +
            "iduu0ZwDAjsHZjeiJmfoNgee/6W2AMEN5bwB3/E5+WDeP8cuuO9ldpvCwT4EGAEK\n" +
            "AHIFgl2lnPIJEPv8yCoBXnMwRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVv\n" +
            "aWEtcGdwLm9yZ2D5VebWq2faBWfN/Xv9L7YE6ss0CyFu8W1UO+8s77+4ApsgFiEE\n" +
            "0aZuGiOxgsmYD3iM+/zIKgFeczAAACEADACLjx/4NTe+OZTnkjQrBNxMAiP0a5xM\n" +
            "9JcbJC0BHfH5cmWowQg31ZWCHFbMkEIkRg6BiiE22v4lBF8yeF20MyilKTlqp3+7\n" +
            "4f2zYD7pIOBMxdeE9qqOAdNDB2EV6n5B4XX/u11YxPoSNNMNTRE3sWyBotL/yxbN\n" +
            "J0/Odt9Zkjxp8MD0IgZoZ6p8dUaBg1vQOBBQosw81L9LMlceuWfpmxxngzIhEg7S\n" +
            "3tKKSTh22AQW0iHKLFQ9AAU26B2x52od/OsZt8YGNT7X2q7qPY24EKAl6zu60o4M\n" +
            "SzjQFjlk3FJT2LU8iy/WN9BS8fN6B9CzWN8qspjLBJhJncs+Hb19VwIhy1M71hGo\n" +
            "vf1eVR6YPdxaS5Gnmil57QWrkUHT8Rg9YoZI4TXdkr/L35petxkUyasesJGj0a+z\n" +
            "Lo3HODSpaio5mXzamfZHWwbWzNEfKX2N6xbU3ELujSsHIlR62Vr+y54vF0oxZKWF\n" +
            "y+sd/w4RCr6LfQbFPbeTSn2zZ5jsKEq3s10=\n" +
            "=YESV\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

        PGPPublicKeyRing cert = certFromString(CERT);
        isTrue("BC must be able to deal with ecdsa subkeys with unknown curves", cert != null);
    }

    public void subkeyHasEddsaUknownCurveMPIEncoding()
        throws IOException
    {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsBUBF2lnPIWCwYJ\n" +
            "KwYBBAGColpjCACWbQQxg5E2dxC/pZ3ZFQyJD1gKDrXLPJ8lZVCRrKtSo2qVcqas\n" +
            "Zb2GNojV8LD2l+3Eq+HMsFaLnkD/Ot4S0DgwfyLPNeKPXLRBD5BrhjewD2Kd5J1P\n" +
            "4eAX/t/X8oe/66gk2Mk2ykf8IfMPk7FsX5SjurepoH8nCzfHY5NBU9+UVOFnhLPq\n" +
            "UgKDVdkhNdhHgxPXcYE61lRpwKjSEKBx/oRshCxlyrJcQdAth1ogGT5wAu0gZ6wl\n" +
            "d6us2Xkt3FG2CJU2xS0Xd3EaPLRmN5hmKEQHMk/aoeVXMVIXNA5OskDcIzS7UbPQ\n" +
            "s8DEHa38TUUezGndB6605LdRmukVsTJogj+swsE+BBgBCgByBYJdpZzyCRD7/Mgq\n" +
            "AV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmc7yihp\n" +
            "VMM6W5JxVjS5XFlN7/6u1zryiHBHJz/PyEh3QAKbIBYhBNGmbhojsYLJmA94jPv8\n" +
            "yCoBXnMwAAAo0Qv/T6b7nAeu70XTUEtGi8PJ2jVdJlRfkpJLAccc2kkc4yhKX+yi\n" +
            "umM4w87bBJhYia/d1bQCi1JdZMV7eHM6b7OuYeLyn/7a+3SdCuWp5qXKjae86+u2\n" +
            "aUrZlwWB5puvAFg6af3pMzWn4KkH/AcEpGs79Nb9CxNWMdfKcDiUhamacYEa2JsN\n" +
            "R16+0YVzji3t7PjLVs39GcOmL5x1LNC45z6MSbAwHatL+4SSNnfBWHQzrNy8XGeU\n" +
            "YICMninvVaVCKCK+h+cSgDd39+TBS85qi6pqrlPUcVex3uCYI1xQyTVPvTwSfgAm\n" +
            "kEbDMovBbEddr0fatwHtkY4JTcZJbkm59/CuwWkrTfY1NLl/Z6V+gGzvpSJcw6aH\n" +
            "PyFybWeuFQFN4mL9urjcFlCUCfii8k51WKknK0UAq8cPwldajzrHfGWmuou4grcH\n" +
            "jYluBe4DSZN1tysrcESzL8LJjzmZdoYp+eKtF7PtetuwF6HkAgvZmv9LteBxlTYM\n" +
            "sntZAriceDP//L+f\n" +
            "=vaVc\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing cert = certFromString(CERT);
        isTrue("BC must be able to deal with EdDSA subkeys with unknown curves", cert != null);
    }

    public void subkeyHasEddsaUnknownCurveOpaqueEncodingSmall()
        throws IOException
    {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsFSBF2lnPIWCwYJ\n" +
            "KwYBBAGColpjvQJOVJxScq4+CLtil6Z8TjYbzBWwHaq86Z7bvbYPDy5pHK0ZafvZ\n" +
            "UxlVR5u3oV5OQkdtUc+Bz32TYoGkmGAgoPOIvdXWNDsofu5LryRT0G1qmmT3yy/p\n" +
            "m3F20/j/S2AGGR0t8+INmOZDgkDPJ0eDwLYdwtF3jUPEIKJJHYBvzQNt73o/gpZ5\n" +
            "b/uWfpmksecRIhnKnPM75vom8IzXqENj9aqrYw1gEBoG6marAlY3cCsOwNB8XhuM\n" +
            "F/wmvbXDs4faa+nTL84GxCZ/Vrmzmr9XPO5Bwc2dGwVpsPRkCKMndeMNRVz6iZaa\n" +
            "GeKIhquPsRGaGB2xzexZnXy/M+q5R/p31Jz7e5P1olDxXxplBfh8PUdJU/tDSYJ5\n" +
            "LTcxF6Yqu84/f4hOCkaWSbUDIoTCh49BVnq0Iptc2GMS42FYkRKCUxIFokk39FY0\n" +
            "sWPg3mWoaDya1Hf4iEPSP+PPMOUYFzgTQ8JNcificKa1KQPJgt2KymG1StFMm6+e\n" +
            "ERhIt6seA8eApsRLBdOL+mvzg4qp5guu2qL2wnef8o/DjS1VdLro6uexjtd3rJNs\n" +
            "awbL4E/4boICQd6x3nge792es533rm9gzbt82bJ3Fb6xFDbG1OjbQakQJW7TxE3Q\n" +
            "iduu0ZwDAjsHZjeiJmfoNgee/6W2AMEN5bwB3/E5+WDeP8cuuO9ldpvCwT4EGAEK\n" +
            "AHIFgl2lnPIJEPv8yCoBXnMwRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVv\n" +
            "aWEtcGdwLm9yZwYOAgWPDMbQ+ZQ+EvYDPmqfCvOsQZU5+0Dwc/yhRkU9ApsgFiEE\n" +
            "0aZuGiOxgsmYD3iM+/zIKgFeczAAAGmqDACVIA5DEzDPYMHjzjhr0DqghqAdm21I\n" +
            "1gxO4Tkdvsy4QCjoD+h0MAnOPzFMPc77JLNtkGZsnLWikoFwLWypuwK3a/OWIJV5\n" +
            "tmfTvCe4NxKSer+b5zm2kFeY5PX0R17jQ7iyuvcHgV5giMXIsVxu8nAG0jad4DNL\n" +
            "+hf09zVLPmLuWjKpNrj+qi1HKxAgPGMwv3utYmZRrhR3FYAtHiD4u/uUoPXNjlwK\n" +
            "nOK6O2/YC6wo1Ko2XbX6qlGNylC1Xs77D12HeqjJTxuEnHtx/nAms3Oy9QWrkyyt\n" +
            "JvoEjstR7pxnCbivyQYs9nzYd9b08hAMMXgO/b3FyIb8zdW7mZULgfQBIpnpeGGt\n" +
            "7reZREz96GEAh0FME6M4yzGGRavsGqzaTwMhDHQYdEYMpUjcRcqhD4YiCoOjgwHl\n" +
            "duOW6z6rk0en0qyaGLBeAzmjhdjvzmls4MaLxOz/BUZyVLQxnkkFn4wu6WKhlBaG\n" +
            "Vjudp5bF+Rq7/zE+eJ8QeJ9e9auU15l2mU0=\n" +
            "=Q07p\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing cert = certFromString(CERT);
        isTrue("BC must be able to deal with EdDSA subkeys with unknown curves", cert != null);
    }

    public void subkeyHasEcdhUnknownCurveMPIEncoding()
        throws IOException
    {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsBYBF2lnPISCwYJ\n" +
            "KwYBBAGColpjCACWbQQxg5E2dxC/pZ3ZFQyJD1gKDrXLPJ8lZVCRrKtSo2qVcqas\n" +
            "Zb2GNojV8LD2l+3Eq+HMsFaLnkD/Ot4S0DgwfyLPNeKPXLRBD5BrhjewD2Kd5J1P\n" +
            "4eAX/t/X8oe/66gk2Mk2ykf8IfMPk7FsX5SjurepoH8nCzfHY5NBU9+UVOFnhLPq\n" +
            "UgKDVdkhNdhHgxPXcYE61lRpwKjSEKBx/oRshCxlyrJcQdAth1ogGT5wAu0gZ6wl\n" +
            "d6us2Xkt3FG2CJU2xS0Xd3EaPLRmN5hmKEQHMk/aoeVXMVIXNA5OskDcIzS7UbPQ\n" +
            "s8DEHa38TUUezGndB6605LdRmukVsTJogj+sAwEKCcLBPgQYAQoAcgWCXaWc8gkQ\n" +
            "+/zIKgFeczBHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn\n" +
            "kk2fbBUnrwgriBN+y99YLB9bP0hGxPKnxhSpXEh7BlECmwwWIQTRpm4aI7GCyZgP\n" +
            "eIz7/MgqAV5zMAAAYrgL/jNsGt3f4LKUr8J/cUwE8uOmNAvt2cGPLux7Z99L9ov+\n" +
            "zeB03uEs+sxqXyFmx8Ftssr/OtlMKBeXX7XQPgVzUdlsuZPvDYuDATgkMbvPM61E\n" +
            "p3ktt4cQO3ObSrQnsK1hLbHyh2sER068+BaYDpM58L+YcyLIADnzaFozOgXVnFvm\n" +
            "dR9cvR2S+j4xCDTWw6r7Cjnwp7HJoyPsOrTJcyb65QWGXkdjU604MljuRl+JRuuM\n" +
            "9TBxEadqfLvB3rH9c49QdGU//Zm9belnd9U5Xm56dpmQ7P0JYysKbFnZbGed34JV\n" +
            "kplPdCXx66E/O8gKsYpqYoj0xwlddXEVBDowJ1DE74wLX1aCbT4WAbmsKfPB4Bzs\n" +
            "NCg5qdrNKlBhozZqOcuPaIqPgJTz7s7+xz2r/ZZaEZH+8/UYZybbofuRtZyfwuBZ\n" +
            "H1L5bT4KEf0oDpIbAu8fnVc8s+npv5inri7IrEdsbsm/HR02jgsG9eSOSvGipdpz\n" +
            "YrmhD20OVj0MhB6X3huw4Q==\n" +
            "=wHFT\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing cert = certFromString(CERT);
        isTrue("BC must be able to deal with ECDH subkeys with unknown curves", cert != null);
    }

    public void subkeyHasEcdhUnknownCurveOpaqueEncodingSmall()
        throws IOException
    {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsFWBF2lnPISCwYJ\n" +
            "KwYBBAGColpjvQJOVJxScq4+CLtil6Z8TjYbzBWwHaq86Z7bvbYPDy5pHK0ZafvZ\n" +
            "UxlVR5u3oV5OQkdtUc+Bz32TYoGkmGAgoPOIvdXWNDsofu5LryRT0G1qmmT3yy/p\n" +
            "m3F20/j/S2AGGR0t8+INmOZDgkDPJ0eDwLYdwtF3jUPEIKJJHYBvzQNt73o/gpZ5\n" +
            "b/uWfpmksecRIhnKnPM75vom8IzXqENj9aqrYw1gEBoG6marAlY3cCsOwNB8XhuM\n" +
            "F/wmvbXDs4faa+nTL84GxCZ/Vrmzmr9XPO5Bwc2dGwVpsPRkCKMndeMNRVz6iZaa\n" +
            "GeKIhquPsRGaGB2xzexZnXy/M+q5R/p31Jz7e5P1olDxXxplBfh8PUdJU/tDSYJ5\n" +
            "LTcxF6Yqu84/f4hOCkaWSbUDIoTCh49BVnq0Iptc2GMS42FYkRKCUxIFokk39FY0\n" +
            "sWPg3mWoaDya1Hf4iEPSP+PPMOUYFzgTQ8JNcificKa1KQPJgt2KymG1StFMm6+e\n" +
            "ERhIt6seA8eApsRLBdOL+mvzg4qp5guu2qL2wnef8o/DjS1VdLro6uexjtd3rJNs\n" +
            "awbL4E/4boICQd6x3nge792es533rm9gzbt82bJ3Fb6xFDbG1OjbQakQJW7TxE3Q\n" +
            "iduu0ZwDAjsHZjeiJmfoNgee/6W2AMEN5bwB3/E5+WDeP8cuuO9ldpsDAQoJwsE+\n" +
            "BBgBCgByBYJdpZzyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5z\n" +
            "ZXF1b2lhLXBncC5vcmffToHhPNsk5u1Dzn9L46BOCMWN8MAOIOR2ZtAgLpGXMwKb\n" +
            "DBYhBNGmbhojsYLJmA94jPv8yCoBXnMwAACsCAwAqqJnhqjRYnbyEs30f/FsghrL\n" +
            "uQ3TIm6OTo8/Ab6B/WrBqf8naKCmQlW4X67vhJMGFLTp6iBeOy7dfBStXmk6iZEY\n" +
            "XwZ1BBmUCFuUOwYUPYn1nWItJOVOK68Iux+0wyT1N3ZFoN5NXoXyX8CnmBTdg3AG\n" +
            "dcUYF7zAxQkHr4ysVGqQuHMYN6c2JCzU/JJpST0RxYl8nQSv8VWZIiYGHOp3jNNQ\n" +
            "T+8B5Wo5lU7l7hVBinuhYfp3yJjoGtmrz8aGCkksLP49d7iJw1ueJdNucNKeKsye\n" +
            "1xq0HgTLDKmxJOjzC8RuRDoyUkQjml1tJ+pefPbWOsSDIwA2C5nnuqei4qrLt3SD\n" +
            "6+08HJw/cmzS6VyWD1UHg6+CjV6nJQrukY2gsVHsZeCo1XBFHex12M0ORPo2mYSm\n" +
            "Htdk1MGl6H9n/clYfWnCU5BpuaDXjjwjGb8RML3elJXW/gwCbw3P+FZZClJlTaqO\n" +
            "TPMq2Bh0B/4GULi9pPpUEw1SCOdPoo9dtnACNsEX\n" +
            "=655d\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing cert = certFromString(CERT);
        isTrue("BC must be able to deal with ECDH subkeys with unknown curves", cert != null);
    }

    private int count(Iterator iterator)
    {
        int i = 0;
        while (iterator.hasNext())
        {
            iterator.next();
            i++;
        }
        return i;
    }

    private PGPPublicKeyRing certFromString(String string)
        throws IOException
    {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(string));
        ArmoredInputStream armorIn = new ArmoredInputStream(bytesIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);

        Object next = objectFactory.nextObject();
        isTrue("Object in stream MUST NOT be null", next != null);
        isTrue("Object in stream must be PGPPublicKeyRing", next instanceof PGPPublicKeyRing);
        return (PGPPublicKeyRing)next;
    }
}
