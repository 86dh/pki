//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.apps;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class PreOpConfig extends ConfigStore {

    public PreOpConfig(ConfigStorage storage) {
        super(storage);
    }

    public PreOpConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
