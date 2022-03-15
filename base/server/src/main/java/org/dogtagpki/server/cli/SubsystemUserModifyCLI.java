//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.user.UserCollection;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemUserModifyCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemUserModifyCLI.class);

    public SubsystemUserModifyCLI(CLI parent) {
        super("mod", "Modify " + parent.getParent().getName().toUpperCase() + " user", parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "add-see-also", true, "Link user to a certificate.");
        option.setArgName("subject DN");
        options.addOption(option);

        option = new Option(null, "del-see-also", true, "Unlink user to a certificate.");
        option.setArgName("subject DN");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing user ID");
        }

        String userID = cmdArgs[0];

        initializeTomcatJSS();
        String subsystem = parent.getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        UGSubsystemConfig ugConfig = cs.getUGSubsystemConfig();
        LDAPConfig ldapConfig = ugConfig.getLDAPConfig();

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        IPasswordStore passwordStore = IPasswordStore.create(psc);

        UGSubsystem ugSubsystem = new UGSubsystem();

        String addSeeAlso = cmd.getOptionValue("add-see-also");
        String delSeeAlso = cmd.getOptionValue("del-see-also");

        UserCollection response = new UserCollection();

        try {
            ugSubsystem.init(ldapConfig, socketConfig, passwordStore);

            if (addSeeAlso != null) {
                ugSubsystem.addSeeAlso(userID, addSeeAlso);
            }

            if (delSeeAlso != null) {
                ugSubsystem.removeSeeAlso(userID, delSeeAlso);
            }

        } finally {
            ugSubsystem.shutdown();
        }
    }
}
