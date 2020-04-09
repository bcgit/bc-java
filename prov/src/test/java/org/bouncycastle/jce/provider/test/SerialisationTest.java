package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class SerialisationTest
    extends SimpleTest
{
    private static BigInteger mod = new BigInteger("69919157209851583596607278525201743749468350078269839551939850344506918649679");
    private static BigInteger pubExp = new BigInteger("65537");
    private static BigInteger privExp = new BigInteger("6387323103214694462561419908301918608189256611651974386490887304224030221257");
    private static BigInteger crtExp = new BigInteger("49050879172577973803420172068797326635");
    private static BigInteger p = new BigInteger("272712035519670228866910009292918035133");
    private static BigInteger q = new BigInteger("256384567247338962716621434774670631163");
    private static BigInteger expP = new BigInteger("121540093892892992427860713054115232161");
    private static BigInteger expQ = new BigInteger("169333445127196347119779037859859594883");

    private static byte[] rsaPub = Base64.decode(
                "rO0ABXNyAC1vcmcuYm91bmN5Y2FzdGxlLmpjZS5wcm92aWRlci5KQ0VSU0FQdWJsaWNLZXklImoOW/pshAIAAkwAB21vZHV"
              + "sdXN0ABZMamF2YS9tYXRoL0JpZ0ludGVnZXI7TAAOcHVibGljRXhwb25lbnRxAH4AAXhwc3IAFGphdmEubWF0aC5CaWdJbn"
              + "RlZ2VyjPyfH6k7+x0DAAZJAAhiaXRDb3VudEkACWJpdExlbmd0aEkAE2ZpcnN0Tm9uemVyb0J5dGVOdW1JAAxsb3dlc3RTZ"
              + "XRCaXRJAAZzaWdudW1bAAltYWduaXR1ZGV0AAJbQnhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cP//////////"
              + "/////v////4AAAABdXIAAltCrPMX+AYIVOACAAB4cAAAACCalNcvvJNMM944KWzzuH2MXkKbiW10OEzGQb9B9MM/T3hzcQB"
              + "+AAP///////////////7////+AAAAAXVxAH4ABwAAAAMBAAF4");

    private static byte[] rsaPriv = Base64.decode(
                "rO0ABXNyADFvcmcuYm91bmN5Y2FzdGxlLmpjZS5wcm92aWRlci5KQ0VSU0FQcml2YXRlQ3J0S2V5bLqHzgJzVS4CAAZMAA5"
              + "jcnRDb2VmZmljaWVudHQAFkxqYXZhL21hdGgvQmlnSW50ZWdlcjtMAA5wcmltZUV4cG9uZW50UHEAfgABTAAOcHJpbWVFeH"
              + "BvbmVudFFxAH4AAUwABnByaW1lUHEAfgABTAAGcHJpbWVRcQB+AAFMAA5wdWJsaWNFeHBvbmVudHEAfgABeHIALm9yZy5ib"
              + "3VuY3ljYXN0bGUuamNlLnByb3ZpZGVyLkpDRVJTQVByaXZhdGVLZXlG6wnAB89BHAMABEwAB21vZHVsdXNxAH4AAUwAEHBr"
              + "Y3MxMkF0dHJpYnV0ZXN0ABVMamF2YS91dGlsL0hhc2h0YWJsZTtMAA5wa2NzMTJPcmRlcmluZ3QAEkxqYXZhL3V0aWwvVmV"
              + "jdG9yO0wAD3ByaXZhdGVFeHBvbmVudHEAfgABeHBzcgAUamF2YS5tYXRoLkJpZ0ludGVnZXKM/J8fqTv7HQMABkkACGJpdE"
              + "NvdW50SQAJYml0TGVuZ3RoSQATZmlyc3ROb256ZXJvQnl0ZU51bUkADGxvd2VzdFNldEJpdEkABnNpZ251bVsACW1hZ25pd"
              + "HVkZXQAAltCeHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhw///////////////+/////gAAAAF1cgACW0Ks8xf4"
              + "BghU4AIAAHhwAAAAIJqU1y+8k0wz3jgpbPO4fYxeQpuJbXQ4TMZBv0H0wz9PeHNyABNqYXZhLnV0aWwuSGFzaHRhYmxlE7s"
              + "PJSFK5LgDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAACHcIAAAACwAAAAB4c3IAEGphdmEudXRpbC5WZW"
              + "N0b3LZl31bgDuvAQMAA0kAEWNhcGFjaXR5SW5jcmVtZW50SQAMZWxlbWVudENvdW50WwALZWxlbWVudERhdGF0ABNbTGphd"
              + "mEvbGFuZy9PYmplY3Q7eHAAAAAAAAAAAHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAApwcHBwcHBw"
              + "cHBweHNxAH4ABv///////////////v////4AAAABdXEAfgAKAAAAIA4fGMVoocAtYNiamDRvnzBmMv/l8FibkQsOUJjxrmP"
              + "JeHhzcQB+AAb///////////////7////+AAAAAXVxAH4ACgAAABAk5tsPIq2YfF0nfLPvAKUreHNxAH4ABv////////////"
              + "///v////4AAAABdXEAfgAKAAAAEFtvxUfS67k0bWmAU9/geaF4c3EAfgAG///////////////+/////gAAAAF1cQB+AAoAA"
              + "AAQf2RvbOpsxhCjGK1vhd7+g3hzcQB+AAb///////////////7////+AAAAAXVxAH4ACgAAABDNKm1zRn/cYal03dRjdxK9"
              + "eHNxAH4ABv///////////////v////4AAAABdXEAfgAKAAAAEMDh3xza3MJ4XNak/35BYPt4c3EAfgAG///////////////"
              + "+/////gAAAAF1cQB+AAoAAAADAQABeA==");

    private static byte[] rsaPub2 = Base64.decode(
                 "rO0ABXNyAD5vcmcuYm91bmN5Y2FzdGxlLmpjYWpjZS5wcm92aWRlci5hc3ltbWV0cmljLnJzYS5CQ1JTQVB1YmxpY0tleS"
              +  "Uiag5b+myEAgACTAAHbW9kdWx1c3QAFkxqYXZhL21hdGgvQmlnSW50ZWdlcjtMAA5wdWJsaWNFeHBvbmVudHEAfgABeHBz"
              +  "cgAUamF2YS5tYXRoLkJpZ0ludGVnZXKM/J8fqTv7HQMABkkACGJpdENvdW50SQAJYml0TGVuZ3RoSQATZmlyc3ROb256ZXJvQnl0ZU51bUkADGxvd2VzdFNldEJpdEkABnNpZ251bVsACW1hZ25pdHVkZXQAAltCeHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhw///////////////+/////gAAAAF1cgACW0Ks8xf4BghU4AIAAHhwAAAAIJqU1y+8k0wz3jgpbPO4fYxeQpuJbXQ4TMZBv0H0wz9PeHNxAH4AA////////////////v////4AAAABdXEAfgAHAAAAAwEAAXg=");

    private static BigInteger elGamalY = new BigInteger("89822212135401014750127909969755994242838935150891306006689219384134393835581");
    private static BigInteger elGamalX = new BigInteger("23522982289275336984843296896007818700866293719703239515258104457243931686357");
    private static BigInteger elGamalG = new BigInteger("29672625807664138507782226105202719390719480236799714903174779490259822385963");
    private static BigInteger elGamalP = new BigInteger("98263422916834911205348180460395783697757584103849580149025105739079617780363");
    
    private static byte[] elGamalPub = Base64.decode(
                "rO0ABXNyADFvcmcuYm91bmN5Y2FzdGxlLmpjZS5wcm92aWRlci5KQ0VFbEdhbWFsUHVibGljS2V5eOnUVVUsZjQDAAJMAAZ"
              + "lbFNwZWN0ADBMb3JnL2JvdW5jeWNhc3RsZS9qY2Uvc3BlYy9FbEdhbWFsUGFyYW1ldGVyU3BlYztMAAF5dAAWTGphdmEvbW"
              + "F0aC9CaWdJbnRlZ2VyO3hwc3IAFGphdmEubWF0aC5CaWdJbnRlZ2VyjPyfH6k7+x0DAAZJAAhiaXRDb3VudEkACWJpdExlb"
              + "md0aEkAE2ZpcnN0Tm9uemVyb0J5dGVOdW1JAAxsb3dlc3RTZXRCaXRJAAZzaWdudW1bAAltYWduaXR1ZGV0AAJbQnhyABBq"
              + "YXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cP///////////////v////4AAAABdXIAAltCrPMX+AYIVOACAAB4cAAAACD"
              + "GlZIJNbVQCnj4wiR0o8gGbKtJEWJBllz8NAELXcqwPXhzcQB+AAT///////////////7////+AAAAAXVxAH4ACAAAACDZPy"
              + "BetQ1Ed8NUnTfXb+MBhFVK1KRe2LzQP7oVz2Kai3hzcQB+AAT///////////////7////+AAAAAXVxAH4ACAAAACBBmhxth"
              + "0FhU4SsG01Wjyi1dlZFZvOy1zFC12XRGO8bK3h4");

    private static byte[] elGamalPriv = Base64.decode(
                "rO0ABXNyADJvcmcuYm91bmN5Y2FzdGxlLmpjZS5wcm92aWRlci5KQ0VFbEdhbWFsUHJpdmF0ZUtleULhxV+2vMBOAwAETAA"
              + "GZWxTcGVjdAAwTG9yZy9ib3VuY3ljYXN0bGUvamNlL3NwZWMvRWxHYW1hbFBhcmFtZXRlclNwZWM7TAAQcGtjczEyQXR0cm"
              + "lidXRlc3QAFUxqYXZhL3V0aWwvSGFzaHRhYmxlO0wADnBrY3MxMk9yZGVyaW5ndAASTGphdmEvdXRpbC9WZWN0b3I7TAABe"
              + "HQAFkxqYXZhL21hdGgvQmlnSW50ZWdlcjt4cHNyABRqYXZhLm1hdGguQmlnSW50ZWdlcoz8nx+pO/sdAwAGSQAIYml0Q291"
              + "bnRJAAliaXRMZW5ndGhJABNmaXJzdE5vbnplcm9CeXRlTnVtSQAMbG93ZXN0U2V0Qml0SQAGc2lnbnVtWwAJbWFnbml0dWR"
              + "ldAACW0J4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHD///////////////7////+AAAAAXVyAAJbQqzzF/gGCF"
              + "TgAgAAeHAAAAAgNAGJQeYfM6ToYoA3ePFdEe7yh8hKecr+WZA0AwxrtdV4c3EAfgAG///////////////+/////gAAAAF1c"
              + "QB+AAoAAAAg2T8gXrUNRHfDVJ0312/jAYRVStSkXti80D+6Fc9imot4c3EAfgAG///////////////+/////gAAAAF1cQB+"
              + "AAoAAAAgQZocbYdBYVOErBtNVo8otXZWRWbzstcxQtdl0RjvGyt4eA==");

    private static BigInteger dhY = new BigInteger("1925747248304483170395506065378568192931506039297732684689153183373019672434");
    private static BigInteger dhX = new BigInteger("3");
    private static BigInteger dhG = new BigInteger("3493483775405590747011712302510626058005717040655777294576367636428413099058");
    private static BigInteger dhP = new BigInteger("106557663805518855012633095511067237673895862256610675920943888960856082029127");

    private static byte[] dhPub = Base64.decode(
                "rO0ABXNyACxvcmcuYm91bmN5Y2FzdGxlLmpjZS5wcm92aWRlci5KQ0VESFB1YmxpY0tlefz+KCkPI+T8AwACTAAGZGhTcGV"
              + "jdAAjTGphdmF4L2NyeXB0by9zcGVjL0RIUGFyYW1ldGVyU3BlYztMAAF5dAAWTGphdmEvbWF0aC9CaWdJbnRlZ2VyO3hwc3"
              + "IAFGphdmEubWF0aC5CaWdJbnRlZ2VyjPyfH6k7+x0DAAZJAAhiaXRDb3VudEkACWJpdExlbmd0aEkAE2ZpcnN0Tm9uemVyb"
              + "0J5dGVOdW1JAAxsb3dlc3RTZXRCaXRJAAZzaWdudW1bAAltYWduaXR1ZGV0AAJbQnhyABBqYXZhLmxhbmcuTnVtYmVyhqyV"
              + "HQuU4IsCAAB4cP///////////////v////4AAAABdXIAAltCrPMX+AYIVOACAAB4cAAAACAEQe8vYXxZPS5oAUy0e0yRYxK"
              + "EAO3GjhMWZKNw8flvcnhzcQB+AAT///////////////7////+AAAAAXVxAH4ACAAAACDrlYAb5zOABHPgsK6oIKtMFgPD3v"
              + "nbTosOnokaSVsaR3hzcQB+AAT///////////////7////+AAAAAXVxAH4ACAAAACAHuT3jEhOVRGfaKdFOX6J2vDYxiMPQW"
              + "ljjL/3Xz85cMnh3BAAAAAB4");

    private static byte[] dhPriv = Base64.decode(
                "rO0ABXNyAC1vcmcuYm91bmN5Y2FzdGxlLmpjZS5wcm92aWRlci5KQ0VESFByaXZhdGVLZXkEURpYQRlitAMABEwABmRoU3B"
              + "lY3QAI0xqYXZheC9jcnlwdG8vc3BlYy9ESFBhcmFtZXRlclNwZWM7TAAQcGtjczEyQXR0cmlidXRlc3QAFUxqYXZhL3V0aW"
              + "wvSGFzaHRhYmxlO0wADnBrY3MxMk9yZGVyaW5ndAASTGphdmEvdXRpbC9WZWN0b3I7TAABeHQAFkxqYXZhL21hdGgvQmlnS"
              + "W50ZWdlcjt4cHNyABRqYXZhLm1hdGguQmlnSW50ZWdlcoz8nx+pO/sdAwAGSQAIYml0Q291bnRJAAliaXRMZW5ndGhJABNm"
              + "aXJzdE5vbnplcm9CeXRlTnVtSQAMbG93ZXN0U2V0Qml0SQAGc2lnbnVtWwAJbWFnbml0dWRldAACW0J4cgAQamF2YS5sYW5"
              + "nLk51bWJlcoaslR0LlOCLAgAAeHD///////////////7////+AAAAAXVyAAJbQqzzF/gGCFTgAgAAeHAAAAABA3hzcQB+AA"
              + "b///////////////7////+AAAAAXVxAH4ACgAAACDrlYAb5zOABHPgsK6oIKtMFgPD3vnbTosOnokaSVsaR3hzcQB+AAb//"
              + "/////////////7////+AAAAAXVxAH4ACgAAACAHuT3jEhOVRGfaKdFOX6J2vDYxiMPQWljjL/3Xz85cMnh3BAAAAAB4");

    private static BigInteger dsaY = new BigInteger("6189794363048388077684611193598066807847399153242870209962581468350882042922904596556915269714052441467859854436813271130403014368908908961326314287317209");
    private static BigInteger dsaX = new BigInteger("45673695048287886591258561084679393738177012644");
    private static BigInteger dsaG = new BigInteger("3245524385217980657302535456606469153364622623109429686740209357408427939040123729832874550911504858612362156241316117434271994372338032643547044203024422");
    private static BigInteger dsaP = new BigInteger("8836853285188714261909188099204635517862922237850722644742752953058083563923137941667883080809922365262319540202714582925718707421743492259382127680083261");

    private static byte[] dsaPub = Base64.decode(
                "rO0ABXNyAC1vcmcuYm91bmN5Y2FzdGxlLmpjZS5wcm92aWRlci5KREtEU0FQdWJsaWNLZXkYUfY34kLIBwMAAkwAB2RzYVN"
              + "wZWN0ACRMamF2YS9zZWN1cml0eS9pbnRlcmZhY2VzL0RTQVBhcmFtcztMAAF5dAAWTGphdmEvbWF0aC9CaWdJbnRlZ2VyO3"
              + "hwc3IAFGphdmEubWF0aC5CaWdJbnRlZ2VyjPyfH6k7+x0DAAZJAAhiaXRDb3VudEkACWJpdExlbmd0aEkAE2ZpcnN0Tm9ue"
              + "mVyb0J5dGVOdW1JAAxsb3dlc3RTZXRCaXRJAAZzaWdudW1bAAltYWduaXR1ZGV0AAJbQnhyABBqYXZhLmxhbmcuTnVtYmVy"
              + "hqyVHQuU4IsCAAB4cP///////////////v////4AAAABdXIAAltCrPMX+AYIVOACAAB4cAAAAEB2LxWpG2UqKz0HcWZwDii"
              + "fO0+3sXqWwmnAnHw8HbPRbtJUozr0As4FX7loWxvWyV+CJDse2KwdxISyMmq6hMDZeHNxAH4ABP///////////////v////"
              + "4AAAABdXEAfgAIAAAAQKi5o5xNZaCAFFAV6dWnHHjG0TVoA7d34RUNF0GhquH6BH/W3BvW4fy428+NPnCgUvJM9iLBTpuBn"
              + "oepupEE1T14c3EAfgAE///////////////+/////gAAAAF1cQB+AAgAAAAU/tVyr5rbnY4WkK7C6NK21c9jn8V4c3EAfgAE"
              + "///////////////+/////gAAAAF1cQB+AAgAAABAPffK8RBcfUspb5PsGDyjZf4Tqcmo5UhuaABmUnq8Vqb3P7jc1+LNaTh"
              + "mUJSnjWQ4+kyCeeJgPH9d3iBd5blQJnh4");

    private static byte[] dsaPriv = Base64.decode(
                "rO0ABXNyAC5vcmcuYm91bmN5Y2FzdGxlLmpjZS5wcm92aWRlci5KREtEU0FQcml2YXRlS2V5vxcJOSU9rboDAANMAAthdHR"
              + "yQ2FycmllcnQAPUxvcmcvYm91bmN5Y2FzdGxlL2pjZS9wcm92aWRlci9QS0NTMTJCYWdBdHRyaWJ1dGVDYXJyaWVySW1wbD"
              + "tMAAdkc2FTcGVjdAAkTGphdmEvc2VjdXJpdHkvaW50ZXJmYWNlcy9EU0FQYXJhbXM7TAABeHQAFkxqYXZhL21hdGgvQmlnS"
              + "W50ZWdlcjt4cHNyABRqYXZhLm1hdGguQmlnSW50ZWdlcoz8nx+pO/sdAwAGSQAIYml0Q291bnRJAAliaXRMZW5ndGhJABNm"
              + "aXJzdE5vbnplcm9CeXRlTnVtSQAMbG93ZXN0U2V0Qml0SQAGc2lnbnVtWwAJbWFnbml0dWRldAACW0J4cgAQamF2YS5sYW5"
              + "nLk51bWJlcoaslR0LlOCLAgAAeHD///////////////7////+AAAAAXVyAAJbQqzzF/gGCFTgAgAAeHAAAAAUCAAUTkau3a"
              + "uChEXbN4isGH4aY6R4c3EAfgAF///////////////+/////gAAAAF1cQB+AAkAAABAqLmjnE1loIAUUBXp1acceMbRNWgDt"
              + "3fhFQ0XQaGq4foEf9bcG9bh/Ljbz40+cKBS8kz2IsFOm4Geh6m6kQTVPXhzcQB+AAX///////////////7////+AAAAAXVx"
              + "AH4ACQAAABT+1XKvmtudjhaQrsLo0rbVz2OfxXhzcQB+AAX///////////////7////+AAAAAXVxAH4ACQAAAEA998rxEFx"
              + "9Sylvk+wYPKNl/hOpyajlSG5oAGZSerxWpvc/uNzX4s1pOGZQlKeNZDj6TIJ54mA8f13eIF3luVAmeHNyABNqYXZhLnV0aW"
              + "wuSGFzaHRhYmxlE7sPJSFK5LgDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAACHcIAAAACwAAAAB4c3IAE"
              + "GphdmEudXRpbC5WZWN0b3LZl31bgDuvAQMAA0kAEWNhcGFjaXR5SW5jcmVtZW50SQAMZWxlbWVudENvdW50WwALZWxlbWVu"
              + "dERhdGF0ABNbTGphdmEvbGFuZy9PYmplY3Q7eHAAAAAAAAAAAHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB"
              + "4cAAAAApwcHBwcHBwcHBweHg=");

    public String getName()
    {
        return "Serialisation";
    }

    public void performTest() throws Exception
    {
        rsaTest();
        elGamalTest();
        dhTest();
        dsaTest();
    }

    private void rsaTest()
        throws Exception
    {
        RSAPublicKey pub = (RSAPublicKey)readObject(rsaPub);

        if (!mod.equals(pub.getModulus()))
        {
            fail("public key modulus mismatch");
        }
        if (!pubExp.equals(pub.getPublicExponent()))
        {
            fail("public key exponent mismatch");
        }

        isTrue(null != pub.getEncoded());

        RSAPublicKey pub2 = (RSAPublicKey)readObject(rsaPub2);

        if (!mod.equals(pub2.getModulus()))
        {
            fail("public key 2 modulus mismatch");
        }
        if (!pubExp.equals(pub2.getPublicExponent()))
        {
            fail("public key 2 exponent mismatch");
        }

        isTrue(null != pub.getEncoded());

        RSAPrivateCrtKey priv = (RSAPrivateCrtKey)readObject(rsaPriv);

        if (!mod.equals(priv.getModulus()))
        {
            fail("private key modulus mismatch");
        }
        if (!privExp.equals(priv.getPrivateExponent()))
        {
            fail("private key exponent mismatch");
        }
        if (!p.equals(priv.getPrimeP()))
        {
            fail("private key p mismatch");
        }
        if (!q.equals(priv.getPrimeQ()))
        {
            fail("private key q mismatch");
        }
        if (!expP.equals(priv.getPrimeExponentP()))
        {
            fail("private key p exponent mismatch");
        }
        if (!expQ.equals(priv.getPrimeExponentQ()))
        {
            fail("private key q exponent mismatch");
        }
        if (!crtExp.equals(priv.getCrtCoefficient()))
        {
            fail("private key crt exponent mismatch");
        }

        isTrue(null != priv.getEncoded());

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        KeyPair kp = kpGen.generateKeyPair();

        testSerialisation(kp.getPublic());
        testSerialisation(kp.getPrivate());

        kpGen = KeyPairGenerator.getInstance("RSASSA-PSS", "BC");

        kp = kpGen.generateKeyPair();

        testSerialisation(kp.getPublic());
        testSerialisation(kp.getPrivate());
    }

    private void elGamalTest()
        throws Exception
    {
        ElGamalPublicKey pub = (ElGamalPublicKey)readObject(elGamalPub);

        if (!elGamalY.equals(pub.getY()))
        {
            fail("public key y mismatch");
        }
        if (!elGamalG.equals(pub.getParameters().getG()))
        {
            fail("public key g mismatch");
        }
        if (!elGamalP.equals(pub.getParameters().getP()))
        {
            fail("public key p mismatch");
        }
        
        ElGamalPrivateKey priv = (ElGamalPrivateKey)readObject(elGamalPriv);

        if (!elGamalX.equals(priv.getX()))
        {
            fail("private key x mismatch");
        }
        if (!elGamalG.equals(priv.getParameters().getG()))
        {
            fail("private key g mismatch");
        }
        if (!elGamalP.equals(priv.getParameters().getP()))
        {
            fail("private key p mismatch");
        }
    }

    private void dhTest()
        throws Exception
    {
        DHPublicKey pub = (DHPublicKey)readObject(dhPub);

        if (!dhY.equals(pub.getY()))
        {
            fail("dh public key y mismatch");
        }
        if (!dhG.equals(pub.getParams().getG()))
        {
            fail("dh public key g mismatch");
        }
        if (!dhP.equals(pub.getParams().getP()))
        {
            fail("dh public key p mismatch");
        }
        if (0 != pub.getParams().getL())
        {
            fail("dh public key l mismatch");
        }

        DHPrivateKey priv = (DHPrivateKey)readObject(dhPriv);

        if (!dhX.equals(priv.getX()))
        {
            fail("dh private key x mismatch");
        }
        if (!dhG.equals(priv.getParams().getG()))
        {
            fail("dh private key g mismatch");
        }
        if (!dhP.equals(priv.getParams().getP()))
        {
            fail("dh private key p mismatch");
        }
        if (0 != priv.getParams().getL())
        {
            fail("dh private key l mismatch");
        }

        isTrue(null != priv.getEncoded());

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DH", "BC");

        KeyPair kp = kpGen.generateKeyPair();

        testDhSerialisation(kp.getPublic());
        testDhSerialisation(kp.getPrivate());
    }

    private void dsaTest()
        throws Exception
    {
        DSAPublicKey pub = (DSAPublicKey)readObject(dsaPub);

        if (!dsaY.equals(pub.getY()))
        {
            fail("dsa public key y mismatch");
        }
        if (!dsaG.equals(pub.getParams().getG()))
        {
            fail("dsa public key g mismatch");
        }
        if (!dsaP.equals(pub.getParams().getP()))
        {
            fail("dsa public key p mismatch");
        }

        DSAPrivateKey priv = (DSAPrivateKey)readObject(dsaPriv);

        if (!dsaX.equals(priv.getX()))
        {
            fail("dsa private key x mismatch");
        }
        if (!dsaG.equals(priv.getParams().getG()))
        {
            fail("dsa private key g mismatch");
        }
        if (!dsaP.equals(priv.getParams().getP()))
        {
            fail("dsa private key p mismatch");
        }

        isTrue(null != priv.getEncoded());

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", "BC");

        KeyPair kp = kpGen.generateKeyPair();

        testSerialisation(kp.getPublic());
        testSerialisation(kp.getPrivate());
    }

    private Object readObject(byte[] key)
        throws IOException, ClassNotFoundException
    {
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(key));

        return oIn.readObject();
    }

    private void testDhSerialisation(Key key)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(key);

        Key sKey = (Key)readObject(bOut.toByteArray());

        // Diffie-Hellman keys drop the Q parameter on serialisation, perhaps this should change...
        isTrue("alg mismatch: " + sKey.getAlgorithm(), key.getAlgorithm().equals(sKey.getAlgorithm()));
//        isTrue("encoding mismatch: " + sKey.getAlgorithm() + " public: " + (sKey instanceof PublicKey), areEqual(key.getEncoded(), sKey.getEncoded()));
    }

    private void testSerialisation(Key key)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(key);

        Key sKey = (Key)readObject(bOut.toByteArray());

        isTrue("alg mismatch: " + sKey.getAlgorithm(), key.getAlgorithm().equals(sKey.getAlgorithm()));
        isTrue("encoding mismatch: " + sKey.getAlgorithm() + " public: " + (sKey instanceof PublicKey), areEqual(key.getEncoded(), sKey.getEncoded()));
    }
    
    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());
        
        runTest(new SerialisationTest());
    }
}
