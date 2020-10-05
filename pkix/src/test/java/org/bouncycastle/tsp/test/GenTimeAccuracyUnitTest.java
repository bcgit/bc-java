package org.bouncycastle.tsp.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.tsp.Accuracy;
import org.bouncycastle.tsp.GenTimeAccuracy;

public class GenTimeAccuracyUnitTest
    extends TestCase
{
    private static final ASN1Integer ZERO_VALUE = new ASN1Integer(0);
    private static final ASN1Integer ONE_VALUE = new ASN1Integer(1);
    private static final ASN1Integer TWO_VALUE = new ASN1Integer(2);
    private static final ASN1Integer THREE_VALUE = new ASN1Integer(3);

    public void testOneTwoThree()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ONE_VALUE, TWO_VALUE, THREE_VALUE));
        
        checkValues(accuracy, ONE_VALUE, TWO_VALUE, THREE_VALUE);
        
        checkToString(accuracy, "1.002003");
    }

    public void testThreeTwoOne()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(THREE_VALUE, TWO_VALUE, ONE_VALUE));
        
        checkValues(accuracy, THREE_VALUE, TWO_VALUE, ONE_VALUE);
        
        checkToString(accuracy, "3.002001");
    }
    
    public void testTwoThreeTwo()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(TWO_VALUE, THREE_VALUE, TWO_VALUE));
        
        checkValues(accuracy, TWO_VALUE, THREE_VALUE, TWO_VALUE);
        
        checkToString(accuracy, "2.003002");
    }
    

    public void testZeroTwoThree()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ZERO_VALUE, TWO_VALUE, THREE_VALUE));
        
        checkValues(accuracy, ZERO_VALUE, TWO_VALUE, THREE_VALUE);
        
        checkToString(accuracy, "0.002003");
    }

    public void testThreeTwoNull()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(THREE_VALUE, TWO_VALUE, null));
        
        checkValues(accuracy, THREE_VALUE, TWO_VALUE, ZERO_VALUE);
        
        checkToString(accuracy, "3.002000");
    }
    
    public void testOneNullOne()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ONE_VALUE, null, ONE_VALUE));
        
        checkValues(accuracy, ONE_VALUE, ZERO_VALUE, ONE_VALUE);
        
        checkToString(accuracy, "1.000001");
    }
    
    public void testZeroNullNull()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ZERO_VALUE, null, null));
        
        checkValues(accuracy, ZERO_VALUE, ZERO_VALUE, ZERO_VALUE);
        
        checkToString(accuracy, "0.000000");
    }
    
    public void testNullNullNull()
    {   
        GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(null, null, null));
        
        checkValues(accuracy, ZERO_VALUE, ZERO_VALUE, ZERO_VALUE);
        
        checkToString(accuracy, "0.000000");
    }
    
    private void checkValues(
        GenTimeAccuracy accuracy,
        ASN1Integer      secs,
        ASN1Integer      millis,
        ASN1Integer      micros)
    {
        assertEquals(secs.intValueExact(), accuracy.getSeconds());
        assertEquals(millis.intValueExact(), accuracy.getMillis());
        assertEquals(micros.intValueExact(), accuracy.getMicros());
    }
    
    private void checkToString(
        GenTimeAccuracy accuracy,
        String          expected)
    {
        assertEquals(expected, accuracy.toString());
    }
}
