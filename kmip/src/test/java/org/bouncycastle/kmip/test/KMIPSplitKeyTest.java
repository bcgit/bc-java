package org.bouncycastle.kmip.test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.stream.XMLStreamException;

import org.bouncycastle.kmip.wire.KMIPInputStream;
import org.bouncycastle.kmip.wire.message.KMIPMessage;
import org.bouncycastle.test.TestResourceFinder;


public class KMIPSplitKeyTest
{
    private static int indentLevel = 0; // Variable to track indentation level

    private static void parse(String filename)
    {
        try (InputStream inputStream = TestResourceFinder.findTestResource("crypto/split/", filename))
        {
            KMIPInputStream stream = new KMIPInputStream(inputStream);
            KMIPMessage[] messages = stream.parse();
            System.out.println(messages.length);
        }
        catch (FileNotFoundException e)
        {
            System.err.println("File not found: " + e.getMessage());
        }
        catch (IOException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error parsing XML: " + e.getMessage());
        }
    }

    public static void main(String[] args)
    {
        parse("TC-SJ-1-21.xml");
        parse("TC-SJ-2-21.xml");
        parse("TC-SJ-3-21.xml");
        parse("TC-SJ-4-21.xml");


//        XMLInputFactory factory = XMLInputFactory.newInstance();
//        KMIPTest test = new KMIPTest();
//        try (InputStream inputStream = TestResourceFinder.findTestResource("crypto/split/", "TC-SJ-2-21.xml"))
//        {
//
//            XMLEventReader eventReader = factory.createXMLEventReader(inputStream);
//
//            while (eventReader.hasNext())
//            {
//                XMLEvent event = eventReader.nextEvent();
//
//                // Process the start elements
//                if (event.isStartElement())
//                {
//                    StartElement startElement = event.asStartElement();
//                    printIndent(); // Print indentation based on the current level
//                    System.out.print("Start Element: " + startElement.getName().getLocalPart());
//
//                    // Print attributes if there are any
//                    if (startElement.getAttributes() != null)
//                    {
//                        for (Iterator it = startElement.getAttributes(); it.hasNext(); )
//                        {
//                            Attribute attribute = (Attribute)it.next();
//                            System.out.print(" [Attribute: " + attribute.getName() + " = " + attribute.getValue() + "]");
//                        }
//                    }
//                    System.out.println(); // Move to the next line
//                    indentLevel++; // Increase the indent level for child elements
//                }
//
////                // Process character data
////                if (event.isCharacters()) {
////                    Characters characters = event.asCharacters();
////                    String text = characters.getData().trim();
////                    if (!text.isEmpty()) {
////                        printIndent(); // Print indentation
////                        System.out.println("Text: " + text); // Print text content
////                    }
////                }
//
//                // Process end elements
//                if (event.isEndElement())
//                {
//                    indentLevel--; // Decrease the indent level
//                    printIndent(); // Print indentation for end element
//                    EndElement endElement = event.asEndElement();
//                    System.out.println("End Element: " + endElement.getName().getLocalPart());
//                }
//            }
//        }
//        catch (FileNotFoundException e)
//        {
//            System.err.println("File not found: " + e.getMessage());
//        }
//        catch (XMLStreamException | IOException e)
//        {
//            System.err.println("Error processing XML: " + e.getMessage());
//        }
    }

    // Method to print indentation based on current level
    private static void printIndent()
    {
        for (int i = 0; i < indentLevel; i++)
        {
            System.out.print("    "); // Adjust the number of spaces for indentation
        }
    }


    // Helper to read the protocol version
//    private static void readProtocolVersion(Element header) {
//        Element protocolVersion = (Element) header.getElementsByTagName("ProtocolVersion").item(0);
//        readElementValue(protocolVersion, "ProtocolVersionMajor");
//        readElementValue(protocolVersion, "ProtocolVersionMinor");
//    }
//
//    // Helper method to read an element by its tag name
//    private static void readElementValue(Element parent, String tagName) {
//        Element element = (Element) parent.getElementsByTagName(tagName).item(0);
//        if (element != null) {
//            String type = element.getAttribute("type");
//            String value = element.getAttribute("value");
//            System.out.println("  " + tagName + " (" + type + "): " + value);
//        }
//    }
//
//    // Helper to read attributes
//    private static void readAttributes(Element attributes) {
//        readElementValue(attributes, "CryptographicAlgorithm");
//        readElementValue(attributes, "CryptographicLength");
//        readElementValue(attributes, "CryptographicUsageMask");
//
//        // Handle Name separately
//        Element name = (Element) attributes.getElementsByTagName("Name").item(0);
//        if (name != null) {
//            readElementValue(name, "NameValue");
//            readElementValue(name, "NameType");
//        }
//    }
}
//
//public interface Document extends Node {
//    // Creates a new Element with the given tag name.
//    Element createElement(String tagName) throws DOMException;
//
//    // Returns the root element of the document.
//    Element getDocumentElement();
//
//    // Imports a node from another document to this document.
//    Node importNode(Node importedNode, boolean deep) throws DOMException;
//
//    // Returns a NodeList of all elements in the document with the specified tag name.
//    NodeList getElementsByTagName(String tagname);
//
//    // Returns an element by its ID.
//    Element getElementById(String elementId);
//}
//
//public interface Element extends Node {
//    // Returns the value of an attribute by name.
//    String getAttribute(String name);
//
//    // Sets the value of an attribute by name.
//    void setAttribute(String name, String value) throws DOMException;
//
//    // Returns a NodeList of all descendant elements with a given tag name.
//    NodeList getElementsByTagName(String name);
//
//    // Removes an attribute by name.
//    void removeAttribute(String name) throws DOMException;
//
//    void normalize();
//}
//
//public interface Node {
//    // Returns the name of this node.
//    String getNodeName();
//
//    // Returns the value of this node.
//    String getNodeValue() throws DOMException;
//
//    // Returns the type of this node.
//    short getNodeType();
//
//    // Returns the parent node of this node.
//    Node getParentNode();
//
//    // Returns a NodeList of child nodes.
//    NodeList getChildNodes();
//
//    // Returns the first child node.
//    Node getFirstChild();
//
//    // Returns the last child node.
//    Node getLastChild();
//
//    // Appends a new child node to this node.
//    Node appendChild(Node newChild) throws DOMException;
//
//    // Removes a child node from this node.
//    Node removeChild(Node oldChild) throws DOMException;
//}
//
//public interface NodeList {
//    // Returns the number of nodes in this list.
//    int getLength();
//
//    // Returns the node at the specified index.
//    Node item(int index);
//}