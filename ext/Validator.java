/*
    javac -cp \* Validator.java
    java -cp xmlsec-1.5.3.jar:. Validator raw.xml cert.pem
*/

//package com.kaleosoftware;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.validation.*;
import javax.xml.xpath.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.stream.StreamSource;

import org.apache.xml.security.utils.Base64;
import org.xml.sax.InputSource;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.StringReader;
import java.io.File;
import java.util.Scanner;
import java.security.*;
import java.security.cert.*;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Validating an XML Signature using the JSR 105 API.
 */
public class Validator {

    //
    // Synopsis: java Validator [document]
    //
    //    args[0] path to SAML response XML
    //    args[1] optional path to X509 PEM
    public static void main(String[] args) throws Exception {
        String samlResponse = new String(readFile(args[0]));
        String pem = "";
        if (args[1].length() > 1) {
            pem = new String(readFile(args[1]));
        }
        org.apache.xml.security.Init.init();
        System.out.println("Valid?: " + validate(samlResponse, pem));
    }

    // Validator.validate(saml_response, pem (optional)) returns boolean indicating if the doc has been validated
    // If pem is blank then the cert from the saml response will be used
    public static boolean validate(String samlResponse, String pem) {
        boolean coreValidity = false;
        try {
            // New Java versions (java 7u25+) are more strict in parsing ID nodes.
            // The right way to handle this is to make sure we specify a schema. Unfortunately
            // this worked but was very slow (30+seconds). Also tried local schema, still slow. Not sure why.

            // SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            // Schema schema = schemaFactory.newSchema(new URL("http://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd"));
            // DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // dbf.setNamespaceAware(true);
            // dbf.setSchema(schema);
            // Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(samlResponse)));

            X509Certificate x509 = null;
            if (pem.length() > 0) {
                byte [] decoded = Base64.decode(pem.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", ""));
                x509 = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
            }

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(samlResponse)));

            // So, it turns out you can hack your way past the problem if you specifically identify the nodes as ID nodes
            // Loop through the doc and tag every element with an ID attribute as an XML ID node.
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("//*[@ID]");
            NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
            for (int i=0; i<nodeList.getLength() ; i++) {
                Element elem = (Element) nodeList.item(i);
                Attr attr = (Attr) elem.getAttributes().getNamedItem("ID");
                elem.setIdAttributeNode(attr, true);
            }

            // Find Signature element
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new Exception("Cannot find Signature element");
            }

            // Create a DOM XMLSignatureFactory that will be used to unmarshal the
            // document containing the XMLSignature
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            // Create a DOMValidateContext and specify a KeyValue KeySelector and document context
            DOMValidateContext valContext;
            if (x509 == null) {
                valContext = new DOMValidateContext(new RawX509KeySelector(), nl.item(0));
            } else {
                valContext = new DOMValidateContext(x509.getPublicKey(), nl.item(0));
            }

            XMLSignature signature = fac.unmarshalXMLSignature(valContext);

            // Validate the XMLSignature (generated above)
            coreValidity = signature.validate(valContext);
        } catch (Exception ex) {
            System.out.println("[SAML Validator] Exception:" + ex.getMessage());
            coreValidity = false;
        }
        // // Check core validation status
        // if (coreValidity == false) {
        //     System.err.println("Signature failed core validation");
        //     boolean sv = signature.getSignatureValue().validate(valContext);
        //     System.out.println("signature validation status: " + sv);
        //     // check the validation status of each Reference
        //     Iterator i = signature.getSignedInfo().getReferences().iterator();
        //     for (int j=0; i.hasNext(); j++) {
        //         boolean refValid =
        //             ((Reference) i.next()).validate(valContext);
        //         System.out.println("ref["+j+"] validity status: " + refValid);
        //     }
        // } else {
        //     System.out.println("Signature passed core validation");
        // }
        return coreValidity;
    }



    /**
     * KeySelector which would retrieve the X509Certificate out of the
     * KeyInfo element and return the public key.
     * NOTE: If there is an X509CRL in the KeyInfo element, then revoked
     * certificate will be ignored.
     */
    public static class RawX509KeySelector extends KeySelector {

        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
                throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            // search for X509Data in keyinfo
            Iterator<?> iter = keyInfo.getContent().iterator();
            while (iter.hasNext()) {
                XMLStructure kiType = (XMLStructure) iter.next();
                if (kiType instanceof X509Data) {
                    X509Data xd = (X509Data) kiType;
                    Object[] entries = xd.getContent().toArray();
                    X509CRL crl = null;
                    // Looking for CRL before finding certificates
                    for (int i = 0; (i < entries.length && crl == null); i++) {
                        if (entries[i] instanceof X509CRL) {
                            crl = (X509CRL) entries[i];
                        }
                    }
                    Iterator<?> xi = xd.getContent().iterator();
                    while (xi.hasNext()) {
                        Object o = xi.next();
                        // skip non-X509Certificate entries
                        if (o instanceof X509Certificate) {
                            if ((purpose != KeySelector.Purpose.VERIFY) &&
                                    (crl != null) &&
                                    crl.isRevoked((X509Certificate)o)) {
                                continue;
                            } else {
                                return new SimpleKeySelectorResult
                                        (((X509Certificate)o).getPublicKey());
                            }
                        }
                    }
                }
            }
            throw new KeySelectorException("No X509Certificate found!");
        }
    }


    private static class SimpleKeySelectorResult implements KeySelectorResult {
        private PublicKey pk;
        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() { return pk; }
    }

    private static String readFile(String pathname) throws Exception {
        File file = new File(pathname);
        StringBuilder fileContents = new StringBuilder((int)file.length());
        Scanner scanner = new Scanner(file);
        String lineSeparator = System.getProperty("line.separator");

        try {
            while(scanner.hasNextLine()) {
                fileContents.append(scanner.nextLine() + lineSeparator);
            }
            return fileContents.toString();
        } finally {
            scanner.close();
        }
    }


}
