package org.bouncycastle.pkix.util.filter;

public class TrustedInput
{

    protected Object input;
    
    public TrustedInput(Object input)
    {
        this.input = input; 
    }
    
    public Object getInput()
    {
        return input;
    }
    
    public String toString()
    {
        return input.toString();
    }
    
}
