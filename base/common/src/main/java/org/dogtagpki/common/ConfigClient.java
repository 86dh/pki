//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2013 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package org.dogtagpki.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * @author Endi S. Dewata
 */
public class ConfigClient extends Client {

    public final static Logger logger = LoggerFactory.getLogger(ConfigClient.class);

    public ConfigClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "config");
    }

    public ConfigData getConfig() throws Exception {
        return get(ConfigData.class);
    }

    public ConfigData getConfig(
            String names,
            String substores,
            String sessionID)
            throws Exception {

        logger.info("Getting configuration properties");

        List<NameValuePair> content = new ArrayList<>();
        content.add(new BasicNameValuePair("op", "get"));
        content.add(new BasicNameValuePair("names", names));
        content.add(new BasicNameValuePair("substores", substores));
        content.add(new BasicNameValuePair("xmlOutput", "true"));
        content.add(new BasicNameValuePair("sessionID", sessionID));

        String response = client.post(
                subsystem + "/admin/" + subsystem + "/getConfigEntries",
                content,
                String.class);
        logger.debug("Response: " + response);

        if (response == null) {
            throw new IOException("Unable to get configuration properties");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        logger.debug("Status: " + status);

        if (status.equals(ConfigResource.AUTH_FAILURE)) {
            throw new EAuthException("Authentication failed");
        }

        if (!status.equals(ConfigResource.SUCCESS)) {
            String error = parser.getValue("Error");
            throw new IOException(error);
        }

        logger.info("Properties:");
        Map<String, String> properties = new HashMap<>();

        Document doc = parser.getDocument();
        NodeList nameNodes = doc.getElementsByTagName("name");
        int nameCount = nameNodes.getLength();

        for (int i = 0; i < nameCount; i++) {
            Node nameNode = nameNodes.item(i);
            NodeList nameChildNodes = nameNode.getChildNodes();
            String name = nameChildNodes.item(0).getNodeValue();
            logger.info("- " + name);

            Node parentNode = nameNode.getParentNode();
            NodeList siblingNodes = parentNode.getChildNodes();
            int siblingCount = siblingNodes.getLength();

            String value = "";
            for (int j = 0; j < siblingCount; j++) {
                Node siblingNode = siblingNodes.item(j);
                String siblingNodeName = siblingNode.getNodeName();
                if (!siblingNodeName.equals("value")) continue;

                NodeList valueNodes = siblingNode.getChildNodes();
                if (valueNodes.getLength() > 0) {
                    value = valueNodes.item(0).getNodeValue();
                }

                break;
            }

            properties.put(name, value);
        }

        ConfigData config = new ConfigData();
        config.setProperties(properties);

        return config;
    }

    public ConfigData updateConfig(ConfigData configData) throws Exception {
        HttpEntity entity = client.entity(configData);
        return patch(null, null, entity, ConfigData.class);
    }
}
