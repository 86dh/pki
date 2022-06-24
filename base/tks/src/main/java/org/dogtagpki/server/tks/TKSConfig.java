//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class TKSConfig extends ConfigStore {

    public TKSConfig(ConfigStorage storage) {
        super(storage);
    }

    public TKSConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
