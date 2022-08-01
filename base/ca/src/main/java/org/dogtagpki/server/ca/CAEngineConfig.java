//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca;

import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;

public class CAEngineConfig extends EngineConfig {

    public CAEngineConfig(ConfigStorage storage) {
        super(storage);
    }

    /**
     * Returns ca.* parameters.
     */
    public CAConfig getCAConfig() {
        return getSubStore("ca", CAConfig.class);
    }

    /**
     * Returns profile.* parameters.
     */
    public ProfileSubsystemConfig getProfileSubsystemConfig() {
        return getSubStore("profile", ProfileSubsystemConfig.class);
    }
}
