//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps;

import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;

public class TPSEngineConfig extends EngineConfig {

    public TPSEngineConfig(ConfigStorage storage) {
        super(storage);
    }

    /**
     * Returns tps.* parameters.
     */
    public TPSConfig getTPSConfig() {
        return getSubStore("tps", TPSConfig.class);
    }

    /**
     * Returns tokendb.* parameters.
     */
    public TokenDBConfig getTokenDBConfig() {
        return getSubStore("tokendb", TokenDBConfig.class);
    }
}
