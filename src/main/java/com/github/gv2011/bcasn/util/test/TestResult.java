package com.github.gv2011.bcasn.util.test;

public interface TestResult
{
    public boolean isSuccessful();
    
    public Throwable getException();
    
    public String toString();
}
