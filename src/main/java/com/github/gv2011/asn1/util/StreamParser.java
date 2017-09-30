package com.github.gv2011.asn1.util;

import java.util.Collection;

public interface StreamParser
{
    Object read() throws StreamParsingException;

    Collection<?> readAll() throws StreamParsingException;
}
