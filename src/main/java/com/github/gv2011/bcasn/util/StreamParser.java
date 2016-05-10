package com.github.gv2011.bcasn.util;

import java.util.Collection;

public interface StreamParser
{
    Object read() throws StreamParsingException;

    Collection readAll() throws StreamParsingException;
}
