/**
 * Copyright 2015 DuraSpace, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.simplericity.jettyconsole.security;

import static org.slf4j.LoggerFactory.getLogger;


import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.util.security.Password;
import org.eclipse.jetty.webapp.WebAppContext;
import org.simplericity.jettyconsole.api.DefaultStartOption;
import org.simplericity.jettyconsole.api.JettyConsolePluginBase;
import org.simplericity.jettyconsole.api.StartOption;
import org.slf4j.Logger;

import java.io.File;
import java.util.ArrayList;
import java.util.List;


/**
 * @author awoods
 * @since 2015-11-11
 */
public class JettySecurityPlugin extends JettyConsolePluginBase {

    private static final Logger LOGGER = getLogger(JettySecurityPlugin.class);

    private List<File> jettyUsersFile = new ArrayList<>(); // There should never be more than one file in this list

    private StartOption jettyUsersOption = new JettyUsersFileOption("usersFile", jettyUsersFile);

    /**
     * Constructor
     */
    public JettySecurityPlugin() {
        super(JettySecurityPlugin.class);
        addStartOptions(jettyUsersOption);
    }

    @Override
    public void beforeStart(final WebAppContext context) {
        final SecurityHandler sh = new ConstraintSecurityHandler();
        final HashLoginService loginService = new HashLoginService("fcrepo");

        if (!jettyUsersFile.isEmpty()) {
            LOGGER.info("Found users file: {}", jettyUsersFile.get(0).getAbsolutePath());
            loginService.setConfig(jettyUsersFile.get(0).getAbsolutePath());
        } else {
            LOGGER.info("Did not find users file, using defaults!");
            loginService.putUser("user1", new Password("password1"), new String[]{"fedoraUser"});
            loginService.putUser("user2", new Password("password2"), new String[]{"fedoraUser"});
            loginService.putUser("admin1", new Password("password3"), new String[]{"fedoraAdmin"});
        }

        sh.setLoginService(loginService);
        context.setSecurityHandler(sh);
    }

    class JettyUsersFileOption extends DefaultStartOption {
        private List<File> usersFile;

        JettyUsersFileOption(String name, List<File> usersFile) {
            super(name);
            this.usersFile = usersFile;
        }

        @Override
        public String validate(String value) {
            File file = new File(value);
            if(!file.exists()) {
                return "Jetty users file " + file.toString() + " does not exist!";
            } else {
                usersFile.add(file);
                return null;
            }
        }
    }
}
