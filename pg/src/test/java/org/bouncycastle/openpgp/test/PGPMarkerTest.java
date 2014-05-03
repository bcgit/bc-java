package org.bouncycastle.openpgp.test;

import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class PGPMarkerTest
    implements Test
{
    private byte[] message1 = Base64.decode(
        "qANQR1DBwU4DdrlXatQSHgoQCADWlhY3bWWaOTm4t2espRWPFQmETeinnieHce64"
     + "lmEIFzaryEWeSdQc8XGfDzcb7sxq7b5b9Hm6OrACcCbSp2KGEJNG5kJmo2A16UPq"
     + "JdK4xNelpJRh3KcJPv+N/9VJrMdj4C+DRnGNFg1hTQf3RKsX+ms2V0OBC5vGlOZY"
     + "zX+XZz/7hl1PXVLN23u4npZI/1xETI2VtRoM76S6oykGXxMtT3+sGU1fAVEKVS45"
     + "pyQHWbBqApkWrURq0xBqpVfDwOgGw09dJxt2igW9hjvNAd9tJiMGrMF5o2OLlub7"
     + "c7FiK+dWLLcw+nx7Hl6FQmo9E8qyW8x1Cb78HjR/JXMgH/ngB/4gba6xX+s5TJkW"
     + "H2Wpp5ePTw39EqHosUMrm05R+C0ha3EyyaJIvKj2WWmImKu5PWo1t37Pi6KHFNC3"
     + "wsYJMRKnnNtd34luMTOgLpDcdgClzfp2p6EqHMoB7Uj3etlLmbN+vpGgz9qkLBRV"
     + "7MpR1yE9qrZNeGgbkry6N31w5E7HoAHu5JNcwxgzbJoj2lI8uvs6Gf7fEoQOuAPE"
     + "W/SGlfR2BdBPiJ1yErMElc2O8LVS0wTwwifHpEsMV+1ntl1EC5d052lo+6q7zNqD"
     + "uYt1/2if6h9W9fe+S9mzr0ZAtxIN2ZGOFJJRnqzjDQ4siB9nnwr6YgvUVRSr/lQB"
     + "hDTd0bmjyWacCt0PPMJWchO6A5tzqKUpTWSYibpdks80kLQogQHsJTZd/kpS0I6f"
     + "gD0HYYlMssZwhg2J2TWwXDpDTgQ6mzFKbGSdOSk/deTJj2+EubzxaZcxZEocCJA8"
     + "bppCj4kLBnCj1LjYx7A=");
    
    private byte[] message2 = Base64.decode(
       "qANQR1DBwU4DZlTzKj+E4aMQCADruFAojUIlHGcnswLIekvhbVnaHnbCt6Kp"
     + "IL2zppmEIYJ9n1xCO1k+3Y5j9vNATbqCVWs1HD0aAL3PRI1eZ1l8GkIBCd2z"
     + "tcZpSI/uyI/JCzVW2stCH0gpP2V7zcjk8HaIuBz4ZsyU9m7v6LwCDPB4CTrb"
     + "Z5nn5Jm3eowonQsRL/3TpJtG+IjTaw29NbCBNNX8quM5LwfIsfWovqNv28r1"
     + "aX8FsqoTRsWEfQ7dMV/swVGqv0PgKxqErdnZVJ2yOJqjLk+lBJT6zhqPijGV"
     + "10pc68hdZxxLU1KZq25DAjS12xcAgagjRkOmYE/H1oEjGZlXfS4y/xQ7skHa"
     + "HI+b04vECACTpQPwCXhxYiNWnf4XhJPONIGyrsXVtsTNwzOShFPmeUvpipP4"
     + "HknakBkBuUY49xcffQogW/NlGCZnQOulDLE6fCH/krkSmI8WVP5Vhf6bM1Qm"
     + "92dHZFoTrrcQ9NVGaCNHHWf7KXkNfKdTkE23LdggoVrVAzO4WcdqVc6s/or7"
     + "jQYP9zXLeu8+GGFMxe/9FCtoIWbujGQHsdDEkCK4h+D44EVDPzbvWj39ZB4w"
     + "hHoab8RLHd7njcrPeoCPdYkFVCKOSuLdxxYZDbbmgpISaafrafwefkkESeGu"
     + "JzbNhmyS8zfOiejWzndaLYWUSE/sqISK9Pg+xKundnFPk04+AhIRyYEoUjG3"
     + "LgGVyM49mrM8E7QwAGU0m/VCJLoOu+N74Z1rp1wFdA5yCllFlONNM4Czhd1D"
     + "ZMyLFqGXiKlyVCPlUTN2uVisYQGr6iNGYSPxpKjwiAzdeeQBPOETG0vd3nTO"
     + "MN4BMKcG+kRJd5FU72SRfmbGwPPjd1gts9xFvtj4Tvpkam8=");

    public TestResult perform()
    {
        try
        {
            //
            // test encrypted message
            //
            JcaPGPObjectFactory        pgpFact = new JcaPGPObjectFactory(message1);

            Object    o;
            
            if (pgpFact.nextObject() instanceof PGPMarker)
            {
                if (pgpFact.nextObject() instanceof PGPEncryptedDataList)
                {
                    return new SimpleTestResult(true, getName() + ": Okay");
                }
                else
                {
                    return new SimpleTestResult(false, getName() + ": error processing after marker.");
                }
            }
            
            pgpFact = new JcaPGPObjectFactory(message2);

            if (pgpFact.nextObject() instanceof PGPMarker)
            {
                if (pgpFact.nextObject() instanceof PGPEncryptedDataList)
                {
                    return new SimpleTestResult(true, getName() + ": Okay");
                }
                else
                {
                    return new SimpleTestResult(false, getName() + ": error processing after marker.");
                }
            }
            
            return new SimpleTestResult(false, getName() + ": marker not found");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public String getName()
    {
        return "PGPMarkerTest";
    }

    public static void main(
        String[]    args)
    {
        Test            test = new PGPMarkerTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
