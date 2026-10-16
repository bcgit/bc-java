package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.JcaOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestInstanceProvider;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class SmartCardMessageSigningTest
        extends AbstractOpenPGPSmartCardTest
{
    public static boolean DEBUG = false;

    public SmartCardMessageSigningTest(OpenPGPSmartCardManager manager, TestProperties testProperties)
    {
        super(manager, testProperties);
    }

    @Override
    public String getName()
    {
        return "SmartCardMessageSigningTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testSigningWithFixedEd25519Key();
        testSigningWithFixedRSA2048Key();

        testSigningWithV4RSA2048Key();
        testSigningWithV4RSA3072Key();
        testSigningWithV4RSA4096Key();

        testSigningWithV4LegacyEd25519Key();
        testSigningWithV4Ed25519Key();

        testSigningwithV4NISTP256Key();
        testSigningwithV4NISTP384Key();
        testSigningwithV4NISTP521Key();

        testSigningWithV4BrainpoolP256r1Key();
        testSigningWithV4BrainpoolP384r1Key();
        testSigningWithV4BrainpoolP512r1Key();
    }

    private void testSigningWithFixedEd25519Key()
            throws IOException, PGPException, CardException
    {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: 7C28 AAAA 6DEE C6EA A7CE  D054 9457 4C72 50EC A574\n" +
                "\n" +
                "lEkEao29dhuqXSRk+TNsKYKJIHKhKB98/GiN0SCkwFvcx3KvieSVpACqawicHEvS\n" +
                "1kXXkKUPpRdwtZKUnMNN0YE9O1SRvUIqmg9NwpcEHxsKAEMWoQR8KKqqbe7G6qfO\n" +
                "0FSUV0xyUOyldAWCao29dgIeCQYVDgwKCQgFFgABAgMECwkIBwcnCQIIAgcCApsB\n" +
                "BQkJZgGAAAoJEJRXTHJQ7KV0y5xT8JKN77XlF3oOY94ou4qyuyEUDP5C7xB8dDlw\n" +
                "MUzHs8pcSfEg7MESKLkumAhC4+den6BAMzx5+gbP4GdQWFkJnEkEao29dhsq7MUG\n" +
                "ULIS5rcUL1rfqCEpwGev4Y/qwpdJysV1h3ooewCWC5UAjjtD6IY3qiuGnxh7Ai1d\n" +
                "YT2sT/J8Ts1pn5M8cQ1qwsAnBBgbCgCTFqEEfCiqqm3uxuqnztBUlFdMclDspXQF\n" +
                "gmqNvXYCmwJyoAQZGwoAHRahBDJMrGM8rUvO1msleNNNwz1aJY/+BYJqjb12AAoJ\n" +
                "ENNNwz1aJY/+xSNKmMlCQ5qOVy+J5Fsl+mkhSjPSrGv0JRkteE0eUMaohLZIWIvG\n" +
                "GYJSB9+vLpIWyi9w6rvVP5lFK0gZHG8Ae/sCAAoJEJRXTHJQ7KV0b/JZuHMtofmJ\n" +
                "YewbHXoXY6s5EqNNO/H+Sl+kfkjBTH/YZG3iSyPUEFHgyg9hTTBsgC5sn4yVKaE/\n" +
                "09VtSX24axQJ\n" +
                "=ypQU\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(KEY);
        testSigningWithKey(key);
    }

    private void testSigningWithFixedRSA2048Key()
            throws PGPException, IOException, CardException
    {
        String FIXED_RSAKEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: 7B07 6F1B D26F 61D9 3AAD  8E1A 8065 E0B9 DC9E CAAC\n" +
                "\n" +
                "lQcYBGp9/wQBEACzNbEsg0EF8TqDPm8K2DDiYEd7NOSdVFrdNFXKyNvy+3UuvEq9\n" +
                "mIk/MWzSR/kisVLs3BVzhf2npufsKoohyd+GiEBkLsaCoql+mbfajeLZZGX/wOKR\n" +
                "EZQkzETSwgfZ89OtAdxXGTP9fjaGh4rIMQNIC64QFm4wlvebPaUBzMzTKOKOEPuV\n" +
                "nrS7p/OrWTGkXfO+81y59LgDR3+Ay+XTq2wjjO8EGp9X1OG39wSspkz6rVDX6pX2\n" +
                "In5FJwW224NLoQ6R99kvR+NgfRbIswUZkrZPCbn04orP1tXbFcD9AUhIQmVT7J5X\n" +
                "0Qy1EgGqOwuHdep/vxklREVj2hGJqPHi4vx5OTlylmXQIPB92NHUTeFKiwPwA4nB\n" +
                "Y+NHv+cmW4C1j5blgnxxRwwgM72vcwI2mNDuI7Tw0gtZUvT2OXLgPn5k1MfJ2JJz\n" +
                "nx1w09eyjcnTRf1NegmkyYLFgM5bHiLxAwVKtzc7XtSpqLJdnsoDGvcdh74MzYIi\n" +
                "8DuWCau0bLQGjvaVFCQLy6THuv+B+pmr90MqgtON51eqm/ewTw1rWDZsiShcS7eu\n" +
                "rX6GZQj+Cq3sV4XoiUAvVLBu/fBCfTJu44GJNR/v4lcSyWEqUw70Q63kVs5RXORD\n" +
                "x3wLf8tW2V43/fzPQc/MZnN544Y5GGwxwij4SPsOM2cmNAkty3JZahYh9QARAQAB\n" +
                "AA/8C0n+LgNB3PGQ2AreZkNI9EAdM9VL8xII4n2VGFmGBLNADIBvM0ZUNWQUENY/\n" +
                "Cw2hX0TCufl4CYM2gbM96sCTkVJf8m+n5Ahov1rh/aVWfVwZUmUaLXB7PpFhL7QD\n" +
                "vpnhFoYf4gGECIHwEvifqEC+J8Z+LorbLu0zp9alE40mxStPXXFG1Lc5d2DH6F4n\n" +
                "OTPZ7CHa3RpdxSC2sKxaslzOfebQ37Do1ljItBTReV0rsdbdJhAKMx+B7zIOgBhc\n" +
                "sWG+tmwNUf2OhNnpNFD8QnVYtEROliIqaf4eKddS+VBTxCMg/72cgLetVaXoVb4Z\n" +
                "pqAQJ5mOjsE50pjYGS3iHukuZXFN5w8OtoWTP+fOJvQiJYi/Vj2uRf2TzPyn/98p\n" +
                "VOmUGrcuOZh9cTY8LNsNTWFJ84om+ZUa4pAlvYgtfEpcbZvXW7PXI+wm5RRBTD5X\n" +
                "Ps/ozqwEV/4ygj64rwkn/Lwd6quLikGKg4M2VQvbkhlOHvQOQaaX5br8lBePdV5m\n" +
                "yAx2flBDhBiMo0o8bIxxUXQiyDvs7axUrP/oVKadVqDggINIIqbVm4EW3CJ9KxKd\n" +
                "AxCO+Fo/IH7+p/Qxt3lMpD7FBkDAVEG8QZh9SvuCcbKYxagOy+srp4CJmZGvCXOl\n" +
                "B8Z5SRdrSMUbY/Mcb9K+737R0NPYGr935/n5ncwtWaR/nXkIALvZizzprN/oNyJj\n" +
                "9oi0OCwfN2Y5YQz1XXe8DlYlVFIxfe5oswpQIOS8TiIoy7P3C2ofiugXaL6PlYlP\n" +
                "wA3Bl5BGDkJrK71+6Q08LWM53CJT3FHw9plDOyydnbcf5vnkCSo3/qr6qV3hQJxC\n" +
                "WBn9WATn32foJvUo5NfyI07PszrfRtjpp5ArZodUYhGqIIqAHp6lbCsONPCzxMhv\n" +
                "AvLw3bbBx5FzoydBcSdkJyow3+6BPVsx8Oe+0Dkg5Y4XOxsGYXW3cklyMBl9YWVd\n" +
                "34mZt0GuoNBozxN3YcOW2XLBaUeApMAxVzifji3Ajk1mULL+Mtqlqfzqo+VmGFMV\n" +
                "VuQsdv8IAPQ5tUkaj5RDZB02aFTSL7uH/iz4cUPX520KPuQR7mQzW2tXL6U+KUvx\n" +
                "Y3J/jSkzxdjN8UG0XQhCsnJJsQEk4WQ+ynGwb4lw0KcIoD/miJdx3sm0X407OMwC\n" +
                "cjtkmWuCz2mKE4kd0uS76jMueemScpsYGWbk/ucDLCmxBr68NvM/ie/PcKesI2Lc\n" +
                "7n8hh9y2LNYkwYruOSLpJzHdaCJa+gMy/kHaIvhpp2Z9R5lSNR12tau+dB5E5vHZ\n" +
                "bdySFx8kJ5Arok2Ie7R/b8iSOX73j8Zkq6O/+MvcWanQCdjnQTznyrhQFz9hA32X\n" +
                "pdVYCgaHSVV40v0ADZzYB35efAV/+wsH/0ok5NoNx2DqAtJ0uuC21CWBcIsQZj7W\n" +
                "kx/pakg4q58GTtrTHnVBvHV9AdfXI3CGOrOdpAc7hhaPAJmSdmvyqtBghQ+44fHq\n" +
                "3T6NfZQbXD9/VDE2Nhcr/7S/BjnMhOjarucqgP5SZWYhDHEIn+YeK8aKFUFllyoY\n" +
                "yoxSKBp/JJI07LJ4n+hpdgM9EryBrQuE3uxPgxuuTXIFAzPnc3/RqMhCwouBaX6/\n" +
                "tVLkgtV/dmwKBF4mYfiF7V8eAqBgZNtJ/bsl5yBW/zV7sKJDiAdyVh1dsYgI2ZBv\n" +
                "wCI3EWmRDQIrJJRb2kr+ExPOfI8sZzlSQt7X/c5qLH/5/bPTLkX0Azxv7sLBmQQf\n" +
                "AQoAQxahBHsHbxvSb2HZOq2OGoBl4LncnsqsBYJqff8EAh4JBhUODAoJCAUWAAEC\n" +
                "AwQLCQgHBycJAggCBwICmwEFCQlmAYAACgkQgGXgudyeyqzTAw/6A0yBRvqsnpHz\n" +
                "bYkT0BDJByqZnDoFLXIN3Kmlb97YfHxiD3Oe4hyQ8lScTDa8y41M5WtuHfpfoe7f\n" +
                "7KdJkykoXwsgI6UsDDq0QwVcPdM4UhMj8YlRQV/DO1AqrJ1F1YLMumaXErpAMnFP\n" +
                "RqcAFWZkwRkocHhe0Qj+VL8kPCdURHxiPPTzkWBSI8YBr+dKp3GWhYxcN1wU5SqM\n" +
                "wwdRjQarxJW9sCfLk4M6PIdrgBaqIXc7JMMGHLbV91kuUpNKjDVsi42gSAvE6t4/\n" +
                "GOrQOI2moYyvqSq+sEBHoN8bDA1VoWeSxo/DcqaWWy03bDvo9Ok2lOzFkfFPZDM0\n" +
                "U5hs8VChQ0KXaYmeerAGHtVBXKggVWFJ0qdPjzqUiTPTa1k9ORj8mr4mWp3zAhMD\n" +
                "dOKMz59B3pjU5FBJ8wo4QyTMZJzrDqDcdCldZg4XdWjvBZYlp5mD5ri58oe04FGA\n" +
                "0rIroelH63vmbi7Hy2AHRnXspmoDaCrFO2eh+MuS8su1+pTZnDwJC2Gnp35wWGVx\n" +
                "qXwv7JozulN5+d9/IEnVWE/CbNHa3ddFIUd5ssppfOId5QDBeWGGZ+Z0IO/wCJlX\n" +
                "29AxVicNuW2544Sa4b/xgiCoqirUjsZoGLi9IrfkGAcyEN+aY8jK+fY6Ovq+h1KD\n" +
                "nq51taWwrG7ebMj54yrYIXXVWXOkHMidBxgEan3/BAEQAL0Xph43UkHPw0kQ0y3r\n" +
                "/JH5ugD8tHCQoIxF2XR4i79SXaNwyaRHlq2vELwxnS648V1lH4o1u30anQbOGTV3\n" +
                "MsTAFM/T2aQIljpX0CUuZHyxNHNrkgPz4MZO+UmFgr1/86Zo0w3qG/JiUxCl3vzt\n" +
                "iiOsn0raJ4B4Fzl8QUpSIPVwv1QRzbaCeMWi1IxlPQuhRWiCZWpTWw1D5JOGXfYC\n" +
                "BYoogFWqEq84vJ6ZEXiek9hleOMi7/dXF+4KwlNNMws+tt0quHrQ5iopFu2vFNwv\n" +
                "S+A5gveGap7Nz1EryH+NLTV2jFeVX+jaqozh1M02mqLTXLO/egDNJ7aWVXprd9HA\n" +
                "0tcbhOlgNX4962VlQ2qq0rRcPQ37x486ezAiSAoK6QqnEnXk+vjjupnifRmUx0do\n" +
                "WFiBzvM8qL8q3f9dcrUZTHOJgR+R3YECxUJklbwZiY9oCGdWWtIC9U5gJrO0wqjb\n" +
                "R1uHqTo5CRMZ/4Yr3J4RWEwRbdhPlWklGWj2Sot+tAhfnohO0FvY18oxtpFoIMq4\n" +
                "ZPNFaA8uvrDFgnTUFO18B0PFjXS7qotRtcCGbVDI4M4CmJBFPq1Dv1YPL4LGxJRT\n" +
                "EiQAtI4jkyEjZZcIKX2Nb0JMeXDHhxf/u7ewiT/wD0Yf8ZHuwT9EnULUoalYE98N\n" +
                "m+Usc3LB031aAXXHk6gxfbyHABEBAAEAD/wKtNAUXeWBEcETiKmsVp7nqlARxj0h\n" +
                "MnnPTL/R4bwSim4ALF6pDTScLjwFq87OhReFcOL8RwE6mssmm3y/PjnYUgKGUeRn\n" +
                "bo+y9fiJt7q7ef0SRpZEiwZrCVsBWAHdtjpBbdClX7VStVEmsX2SrJBpvK24Oz8z\n" +
                "/ZizCd9Yf0Cbz6pwRCHK96WG6yqbAxBrHCfQkbF+96vsGwVSJQV6QbBhRjHIp+cu\n" +
                "7J4hYgv53GCv8UQ1osDGLF7lJ3l2kKRsj+ciq/c4sk3rN9sIfM/y4kAAOMFllRgX\n" +
                "AxLTRxCvHXs1z7nagPv73zBQ5xMkG2IIs2xIRnXN8yUQfX/m0ow84BdlOtWRUJCO\n" +
                "VJKO2vDpeCzcWng+dO1nme6kAC4N5xwl2fWsOcKTiV1Pln00zt/qWcQ1CBBsTE4h\n" +
                "LGHqySptez0z+6sXzZMYjIne0dxc7SaqJQierC+eCzC1obrN19/4Wq3mW3iTt0T3\n" +
                "7X3x4+T7+VnMdQltkCKhVmU41NVWPJznSqtxBqgKAX5yGem+q6lhYk0PIWdLyQt9\n" +
                "DYaqQ+W0gYPrqI8KnCAtBPjTjGJxGyaTywZzNh40spRxhGnZ+UyCTGWTT8v5cbOD\n" +
                "vi1lrjJ5QlxOViY8J59IIyMLnIbhVN4q0KsriYsNJfLUaPTVFzpwrLw6a1zg3NPk\n" +
                "Y2ASeUDfbwOR4QgAxuLx/Kp96dfgt1t+1yCthUEG1uHRxW0Qg5PIy2F7cUzZ/16r\n" +
                "KNXs5w9jktAVbCyVeNl/m0EcbRiDysyCUwoVmSBhvQAB7/GEY7BdLdGwkTfC52Gl\n" +
                "HVraH11Ezjbn35ILSXBBFEKTQKC71iawEzmCGuTfcTJ0tyK1oMFtl5vBuY168zbi\n" +
                "vuEmHM/Nl5M/p65xjTn3yXKZSQRz7v2FPKzQZtiU+EKlW5te5vy1+b7wJev5uKnx\n" +
                "6MDvJ6FYkZnmTi+O0bXXv0SfQ9EnbMu1xDPllSc7Fiw0QgwAJdOqAjOJvB2QzZQc\n" +
                "z3t+oI6m1FHtXeUUn6n1EVjszjZopMfz+itDjQgA82SxVOFE9wQam1cyfW9MtEOf\n" +
                "Nb2Y5GOJwyxWmc+z85L1Ek6TvH2VoZgqXaB1esCuCxDuSn5Ys869IYNttxSE4aG4\n" +
                "isyzQWO/CK3k7vdMUxUxZOF5DW2B+Y8NBoY4BAP7nMRMN/QWoVAddMm3SIHrERTM\n" +
                "Dh1PnCYJBClUl61kwgatuwIzXIfqnGizzcouu3TSOOLyq1l4GD7qLmg8bGXGrVpq\n" +
                "iYmrp4LAMadrDMkUe9dMvIAd0cMn1ZHFilwDOoWyKCUrYDFuiAV/dOe03wROSei5\n" +
                "wAUVECnHNYqXaxZagQj5iZZGK+lmTKQdvRkQAcvYlL8UtNeSWCgbTW5KKa9RYwf9\n" +
                "GWwaysWVne7B6msV+ATYkSO4PuTxUsExzZXc0nRbwTlSpOyTvLUlP/u+3SbgzsDH\n" +
                "bW9glWkFtdtoKGZfCIwKQ6TIY164SgbcT6lye/yg5ZbZj6y67NJyGkk221LYcF2B\n" +
                "Te61WaLX1A0xWd3Lh1ii8FarTjKpMbrcZKEAX5ipg4VJiA9QtCrMCqrUjJ+as76R\n" +
                "+9awabYCAWT3VE0yjZH7ofV2XKpPH7r5Qlj+cV4tEP4MBzWqsk3TdCDrVrhE+b2U\n" +
                "qSi0ZvLuqJcuOB9mOO8g9d0Rk+yzUTBcIPspqGpGRKS4ky5kXW5OWO5siLWs5Ycs\n" +
                "lk9gEy3g6di7Hl55pDuYZoI6wsOsBBgBCgJWFqEEewdvG9JvYdk6rY4agGXgudye\n" +
                "yqwFgmp9/wQCmwLBdKAEGQEKAB0WoQRtQaT/LJSOUtf5yITolL8loLF9YwWCan3/\n" +
                "BAAKCRDolL8loLF9Y2atEACyvnE3tr+5heIfS2G/yj80JVcGHcYxR6866gqTHAfT\n" +
                "vMHGB07iuuwG7LBPMl7OjaYeuDRfHBYiU+qtIdNDiMxYZ+evMAiIVtft3nRYZ2PA\n" +
                "4Lya5ZfikYvpdxAeoTKRdqliDF8XyI+ide8gTrQQ3eHrHrTF0W/PpP2IfvRcvyEx\n" +
                "f9odVaa7mKXtH4cSrw3sWGWb/0skFFHWfwtPsXaxzCwFsRJvwBpq3immgJErqGHg\n" +
                "TEMVoXwh5EiVHwZOq/0dlJYAT8hp5WuFJzbrhE0NvhZr4fGrWae8RLs9lUBdqkUY\n" +
                "6Q58XyoD/yHkQyK4nhAdMZxJFaf+dlZQZGznIV8hPXlRSpSDHeSAIJN9GNHVVgja\n" +
                "ikokgDEK+qBXJtCmCUvqpbfbKJlctt1/g0S4Uo0Lo4JvXd22SFAkg8mqfVIYxfmC\n" +
                "2gpGIAo8QL3oh4n4bhPnTYSi+0cFEVHJV0eBhcx5riFD3SZo/wXJoa6stgAGcO4b\n" +
                "RE4Tz1glmFREmXK7QZZ51beOxBqlBJhOeUX6Udj2D1Cbv5Zh8rcZFackxEtoq+G4\n" +
                "9mYiMgJ2w4y5D2H6wkpBcE8TTp/MkRvfz+pEWL9pptQO0qpm3h0Lp0iOHBLIMtRP\n" +
                "xt8tMEbc8UToZ3k15oYuTq8CzniGE8iZ/yXbNMY13Dokp92ItSaHSlSh9cK8yKzX\n" +
                "UAAKCRCAZeC53J7KrP5XD/9e7FymJ7YalrF7IILZkDLu/ZwWasywoJoVNCb3YLG3\n" +
                "JcQ4BQ15Jj1SrypUBRDmD/OxMKZmjUKEziJ20Bih7l8iCu2ESq6lUsJ39e2rBLRe\n" +
                "JWUYYzghMcgUYRTHNJJlcm/QWUBxz9KPo4C0E3JD5OXhlP8U5seTEY29sAg8PP67\n" +
                "V4GHcZo6wEZEpo9UsLwYw+FCy+ykxB/E29ZZG/Xg6mK0Wz6x9ZreOS3cqDShPrLW\n" +
                "ttYeBpBsXyOQkFr5xT/9VsUMOdk5HZo+5O+ygoPKLq86wGJlVgYJTVQrgZhK1EP+\n" +
                "6Hq23mbWb23Uc2iu/9kfntC54O2arY+20xvG6tDXfMy16fzd3v6C5mBKxfRza5Jc\n" +
                "0FTlsVH4sykESJPguAJG879HkbKKIf9vYew0yC7hviCLwhisK+lBSeAFnGY1rZeZ\n" +
                "RYl3B5MOKbJwNL5x14F3s1ks9sdMebYnGCchEzYRUb2LrZZA9dFsnl31HCf4Xdma\n" +
                "yrjiMOd5WLsijX6x+04/qhXRRDwGjYVzJAsq1KNEzJVxJXk5OUdDUNFRQGVAOaQd\n" +
                "xnyZ//ihZW96a4DxOKkQLu4IWGTPAQVdBajvnlZXR4L9IbS3RFRUwVYV3CLPlaCe\n" +
                "sn4IYRs5tL+Qj9HJurJGrfJx49I6/FmYqtqkKA77gRX9qgNVMpBfolL/2qc1Ut0t\n" +
                "1p0HGARqff8EARAAi0Nh2GQFaai/ai18nHJB9fgfEIYWTHIguoQehlszoMAWqL0Z\n" +
                "I0OHN4CWG0aXxbl9spC1FVd2QA7dqR1yWh1ycHMJL6zwq9lxhevgG6tid+JMFwbN\n" +
                "jQ5yauvwT3bwrhmhuTIrdeMawNAO8ja+faWgJXcZJTl7DLJ1EQ4YFW/19qUvw2P9\n" +
                "mGlwEGbwDfLAOgG3I6FdEPkrlAzmMboKKZat6nx5a8cfu3CtGVZLhR0m7ZEwvJO0\n" +
                "9dCy556BZigLd8lOgzVcl/SlABCnLlayMbCS/x6ky6QJ3+XAgfnEWTXWC58q0IKs\n" +
                "Z0/HPyLN+WCL7Cx2abZy0lnnXcpYWVVzdZ0Bexk5Qw0q2I1WUiWVcACtVvbcAiBK\n" +
                "aH7ZFjr0kkNm2JEBIR/dtrWptGrQiGIWQIKzgIwVCkow7EMjEx71/QwhJsjcQeDy\n" +
                "kHS3v3fVvwqKpmo8c96tJHAi7ad6MkCCgDJHvflzocbBPGjAIBQPPz1LxbSiI/7k\n" +
                "h9xa/6xmyFBkGK5yKxrMuH/mWxFb+1l5Ih1QcsxEOi58aWms2tOFe0kn4ihGOdQO\n" +
                "WktbE0M8U5wJ7Jvl8hU2MIdcr8fHTLqVpcreWN7a1J2N0zMOxm1aMQUVtU2WsVLL\n" +
                "QE+c4Dcsdaijw7SfPZnKTbVHIwGeL/+ZodFxjMno2zNwK9PG8zuDsNONKrEAEQEA\n" +
                "AQAP+gPm3zUjfRQilAjGJElzcuFD+QYK5VFxzSe/3EviMd/qId7LO/FFMUlFaaJz\n" +
                "NH0BhahDVHkeZzcqQEM+ipEQ/1jWA3oTe8ORpxQCfnGOa4bb9bFoRMmtj763kTCy\n" +
                "YdHu8LbYogEYKNkhuzMShGNobyrXKGkAY3zNyM8YHv9sXW7Yqy4e4612hTStPaj8\n" +
                "yS5jrlCDcxd7pu3rlc0eeK4FOI0EvP4sQqy+XnGcSlqWoE8w4M9K/PUtY/Khxt+O\n" +
                "3BHLt4IGzh5WNQOu2inhNSlRPv0cGOMfwhF4EkNSAfjus9DFixSM5LmysYY77Zt0\n" +
                "FteG82MvQNsfhVNkAClLzJ1Z/DJlKl5cz08hkPuDomK8Xrev7z808pNujb+hPn1C\n" +
                "0fD0X1P73CUIlEUG7TRL3Vukf8AJBEdImfjdl9VpxF0Wl9T8h++RE7UOTy8xhw9r\n" +
                "lTJnlj50cQa2DSPbSMIpPysVEwtG7ig4lP7RuSW2OI88yho7+t4gojULQEi69pr5\n" +
                "QFS5HdxJhMbGkV2XQgkM4yLDOlQTa/0AB0oSVZZl5DNtv2bZJFE50UVnhe58heG/\n" +
                "f7kYZf11lCt57mvUMBoxg2eSvB6ZeOPfvr6u8REyvuEZYxU8LAqq2oygPjhO3QsI\n" +
                "yLBAevG8+xHVlMjEY7Z2E1NmvPtRfREE6odcXgUqJnQTrk9xCAC67mhkVlKJj7Ql\n" +
                "lIOQl9xHSgce7GH6mbcYWcvbKKd6leTQ0pK1peh8uvDY4sYGlouG1q3Ep51ReGE4\n" +
                "v66Zpr0EYERvyTxu61gPnELFJSlcDevkxnULxSdcvF9dKbLMklwtQpYlZ0n6zo4G\n" +
                "yReWw8eEIgUqUy0ceoTMY0K6cA/OIHfZuxc2V/1Cei+CgClus5kzG2A9c1o+/bRY\n" +
                "DTuDlbssIHU7tRfk1eFfe482FDaTLnHLwrlRbus28jVbQVhW/wwc4YRi5oQZe3MR\n" +
                "jNVt2YFjGHVFS+ngEi8fPQf+JdZHiZDW+MHnyyJiMzTryzFwg33LhyWUC4icCO0b\n" +
                "QX5T1zK9CAC+uBzGUjQU/fuhjDTp5nWajhzigKHIXr44MqSKih9dmCmLcxPzHkHg\n" +
                "5BhgdJmKDlPNPMIQFSK5sL6rfgsdOJUo4FuMMsMjA9KFRZge8UVm33mhzidyxmgu\n" +
                "Ybe6iPeilr6gPf2AckLpwHZlSvh6e7+pqy+L4liCvO5OjbjbHjnqv/rHWQbnN/Xw\n" +
                "K+VdNNvMtuD+kETRPEuko52si45FfzhH20RsR2ko2byhludlHQchdzF987HraPak\n" +
                "wDymkobfoTZI3NLjGJ/PoofVeci+//FvA3UPwO/TKeoTew5iOmqEQaw2utjBKD9A\n" +
                "zCX2zyc7GBlpkZIZ69WzodCtWPJR3zEFCACXzyocsAKp8VjSzLgYJlnIw/dDh5ML\n" +
                "S6CDov6fxQeTz4sF0GLZmgwkPNeV1XMKAkPWKViBw5MbxQUaUBC/2UtNdxb0/Ai9\n" +
                "oyssfBus6FAsQ/LzAoEgwQwTJZacRZ8KXbM0gBJ2l5S8cfpl0mZLEV2m0qyQPnRV\n" +
                "76L4hgQjW4oMdZxazpCYUfi2rtTSZoL0ZhSZAKGkdAGtBe1K5mSUGrSHkty9riFA\n" +
                "hAJSTI8r86jMSA5z9bTM8ahGDWWzKs/O5IqAaGiBCsVTSyrYm6c5UegHu6eMSn11\n" +
                "XpfjXG4S5XJMm1KlPHtbQm1NylJdgp1nycWZGAkJA6Oxnj9YKp2hUPEQcC7CwXYE\n" +
                "GAEKACAWoQR7B28b0m9h2TqtjhqAZeC53J7KrAWCan3/BAKbDAAKCRCAZeC53J7K\n" +
                "rMOcEACxiIyZhjG9u67OTfvlj/x3KgX50fXB0epSWTv+ZmsNAkx9JFl5j/ALmzhI\n" +
                "JvZLaYXNmN3Ud/a64tz0ju2ArrvtDQ63ZoFRN1x7GvYoT6ONltk1+LaHb/N+gpRL\n" +
                "JnHHUFfEHqGOZQkpdlSRO0ogd0uGF5e7WBvR8sVFW6NlFEXONfdYgFAAL2la+6rV\n" +
                "+Rps0NPq2xJyERZodPM+5K1wpP4Egtb2oerO8S6cztxNdshrHvP86Cy4HvwOKtC+\n" +
                "hHyKX4GLeNV9NTyUDzHPWx0PmGBwH0IaMDPQaMNBD06+HSDq4XFtPwyImaR19QR+\n" +
                "twGxaeN/4vQYl/IxtijtxGVBMLzJ+ypnhyc/MQUPZ2Bzbfhaz4SPgUs1TDXq3xCK\n" +
                "wMs71bVVn4o8FM5szCulYcdgkNMSlqLFSOUE+fK1t+m6gD4sLtma8dVA23ncePYO\n" +
                "rMmfYta+8hUH9HJkVqRhkDRQpO9xrac5Ms8je8pN1JN9zDGZ1gTiGlRaANGoOOg4\n" +
                "aGu7u1PYQxY0ZHBsUkszAAFcpHVQ2NttI3df+ELdBYeR7Bk5+GquWs5WI7+LyuXP\n" +
                "3nBaKNg6aRoIrm0fEyXQoFZbpVycjReP1qh7sleUab23EjYJ7OSk1dogWqtGgzDR\n" +
                "+O4yuICoi0bM7ITpeY+gDhnFsiCOXOSyBKAS+H+sysjLO42lLw==\n" +
                "=N+HH\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(FIXED_RSAKEY);
        testSigningWithKey(key);
    }

    private void testSigningWithV4RSA2048Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with 2048-bit v4 RSA key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(2048))
                .addSigningSubkey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(2048))
                .build();
        testSigningWithKey(key);
    }

    private void testSigningWithV4RSA3072Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with 3072-bit v4 RSA key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(3072))
                .addSigningSubkey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(3072))
                .build();
        testSigningWithKey(key);
    }

    private void testSigningWithV4RSA4096Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with 4096-bit v4 RSA key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(4096))
                .addSigningSubkey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(4096))
                .build();
        testSigningWithKey(key);
    }

    private void testSigningWithV4Ed25519Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with Ed25519(27) v4 key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey(PGPKeyPairGenerator::generateEd25519KeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateEd25519KeyPair)
                .build();
        testSigningWithKey(key);
    }

    private void testSigningWithV4LegacyEd25519Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with LegacyEd25519(22) v4 key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey(PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .build();
        testSigningWithKey(key);
    }

    private void testSigningwithV4NISTP256Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with NIST-P256 ECDSA(19) v4 key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey(PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .build();
        testSigningWithKey(key);
    }

    private void testSigningwithV4NISTP384Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with NIST-P384 ECDSA(19) v4 key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey(PGPKeyPairGenerator::generateNistP384ECDSAKeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateNistP384ECDSAKeyPair)
                .build();
        testSigningWithKey(key);
    }

    private void testSigningwithV4NISTP521Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with NIST-P521 ECDSA(19) v4 key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey(PGPKeyPairGenerator::generateNistP521ECDSAKeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateNistP521ECDSAKeyPair)
                .build();
        testSigningWithKey(key);
    }

    private void testSigningWithV4BrainpoolP256r1Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with Brainpool P256r1 ECDSA(19) v4 key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey(PGPKeyPairGenerator::generateBrainpoolP256r1ECDSAKeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateBrainpoolP256r1ECDSAKeyPair)
                .build();
        testSigningWithKey(key);
    }

    private void testSigningWithV4BrainpoolP384r1Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with Brainpool P384r1 ECDSA(19) v4 key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey(PGPKeyPairGenerator::generateBrainpoolP384r1ECDSAKeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateBrainpoolP384r1ECDSAKeyPair)
                .build();
        testSigningWithKey(key);
    }

    private void testSigningWithV4BrainpoolP512r1Key()
            throws PGPException, CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Test signing with Brainpool P512r1 ECDSA(19) v4 key");
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey(PGPKeyPairGenerator::generateBrainpoolP512r1ECDSAKeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateBrainpoolP512r1ECDSAKeyPair)
                .build();
        testSigningWithKey(key);
    }

    private void testSigningWithKey(OpenPGPKey softwareKey)
            throws CardException, IOException, PGPException
    {
        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        // -DM System.out.println
        System.out.println("Sign with " + card.getCardType() + " " + card.getVersion() + " (" + card.getBackend().getName() + ")");
        card.reset();

        if (DEBUG)
        {
            // -DM System.out.println
            System.out.println(softwareKey.toAsciiArmoredString());
        }

        char[] adminPin = properties.getAdminPin();

        OpenPGPKey externalKey = cardUtils.toExternalKey(softwareKey);

        // Upload keys to card
        OpenPGPKey.OpenPGPSecretKey signingKey = softwareKey.getSecretKey(softwareKey.getSigningKeys().get(0));
        card.uploadSigningKey(signingKey.unlock(), k -> adminPin);
        KeyPassphraseProvider userPinProvider = new KeyPassphraseProvider.DefaultKeyPassphraseProvider()
                .addPassphrase(externalKey, properties.getUserPin());

        // Generate signed message using smart card
        byte[] plaintext = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = api.signAndOrEncryptMessage()
                .addCustomPGPContentSignerBuilderProviderFactory(manager)
                .addSigningKey(externalKey, userPinProvider)
                .open(bOut);
        mOut.write(plaintext);
        mOut.close();

        if (DEBUG)
        {
            // -DM System.out.println
            System.out.println(bOut);
        }

        // verify message
        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addVerificationCertificate(softwareKey.toCertificate())
                .process(bIn);
        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(mIn, bOut);
        mIn.close();
        OpenPGPMessageInputStream.Result result = mIn.getResult();

        boolean valid = result.getSignatures().get(0).isValid();
        if (!valid)
        {
            // -DM System.out.println
            System.out.println(softwareKey.toAsciiArmoredString());
        }
        isTrue("Signature MUST be valid.", valid);
    }

    public static void main(String[] args)
            throws CardException
    {
        OpenPGPSmartCardManager m;
        TestProperties p;

        // BCYK
        try
        {
            p = YubikeyTestInstanceProvider.defaultProperties();

            // BCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, new BcOpenPGPSmartCardImplementation()));
            runTest(new SmartCardMessageSigningTest(m, p));

            // JCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, new JcaOpenPGPSmartCardImplementation()));
            runTest(new SmartCardMessageSigningTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of SmartCardMessageSigningTest on Yubikey: " + e.getMessage());
        }

        p = new TestProperties(1312);
        SimulatorOpenPGPSmartCardBackend sim = new SimulatorOpenPGPSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, p.getSerialNumber()));
        m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        runTest(new SmartCardMessageSigningTest(m, p));
    }
}
