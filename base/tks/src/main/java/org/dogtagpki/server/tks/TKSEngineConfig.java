//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.apache.commons.lang3.StringUtils;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;

public class TKSEngineConfig extends EngineConfig {

    public TKSEngineConfig(ConfigStorage storage) {
        super(storage);
    }

    public TKSConfig getTKSConfig() {
        return getSubStore("tks", TKSConfig.class);
    }

    public Collection<String> getTPSConnectorIDs() throws EBaseException {
        String list = getString("tps.list", "");
        ArrayList<String> array = new ArrayList<>(Arrays.asList(list.split(",")));
        array.removeAll(Collections.singleton(""));
        return array;
    }

    public void setTPSConnectorIDs(Collection<String> list) throws EBaseException {
        putString("tps.list", StringUtils.join(list, ","));
    }

    public TPSConnectorConfig getTPSConnectorConfig(String id) {
        return getSubStore("tps." + id, TPSConnectorConfig.class);
    }

    public void removeTPSConnectorConfig(String id) {
        removeSubStore("tps." + id);
    }
}
