//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

@WebListener
public class ESTWebListener implements ServletContextListener {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ESTWebListener.class);

    public ESTEngine createEngine() {
        return new ESTEngine();
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {

        ServletContext servletContext = event.getServletContext();
        String path = event.getServletContext().getContextPath();
        String id;

        if ("".equals(path)) {
            id = "ROOT";
        } else {
            id = path.substring(1);
        }
        ESTEngine engine = createEngine();
	engine.setID(id);
        servletContext.setAttribute("engine", engine);

        try {
            engine.start(event.getServletContext().getContextPath());
        } catch (Throwable e) {
            logger.error("Unable to start EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to start EST engine: " + e.getMessage(), e);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        try {
            ESTEngine.getInstance().stop();
        } catch (Throwable e) {
            logger.error("Unable to stop EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to stop EST engine: " + e.getMessage(), e);
        }
    }
}
