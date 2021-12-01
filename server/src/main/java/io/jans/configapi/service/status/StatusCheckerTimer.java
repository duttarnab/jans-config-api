/*
 * Janssen Project software is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.configapi.service.status;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import javax.inject.Named;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.exec.CommandLine;
import io.jans.configapi.model.status.StatsData;
import io.jans.configapi.model.status.FacterData;
import io.jans.util.process.ProcessHelper;

import io.jans.configapi.configuration.ConfigurationFactory;
import io.jans.configapi.model.configuration.ApiAppConfiguration;
import io.jans.configapi.service.auth.ConfigurationService;
import io.jans.configapi.service.cdi.event.StatusCheckerTimerEvent;
import io.jans.service.cdi.async.Asynchronous;
import io.jans.service.cdi.event.BaseConfigurationReload;
import io.jans.service.cdi.event.ConfigurationEvent;
import io.jans.service.cdi.event.ConfigurationUpdate;
import io.jans.service.cdi.event.LdapConfigurationReload;
import io.jans.service.cdi.event.Scheduled;
import io.jans.service.timer.event.TimerEvent;
import io.jans.service.timer.schedule.TimerSchedule;
import io.jans.util.StringHelper;
import io.jans.util.properties.FileConfiguration;
import org.apache.commons.lang.StringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;

@ApplicationScoped
@Named
public class StatusCheckerTimer {

    private final static int DEFAULT_INTERVAL = 5 * 60; // 1 minute
    public static final String PROGRAM_FACTER = "facter";

    @Inject
    private Logger log;

    @Inject
    private Event<TimerEvent> timerEvent;

    @Inject
    private ConfigurationService configurationService;

    @Inject
    private ConfigurationFactory configurationFactory;

    private AtomicBoolean isActive;

    @PostConstruct
    public void create() {
    }

    public void initTimer() {
        log.debug("Initializing Daily Status Cheker Timer");
        this.isActive = new AtomicBoolean(false);

        final int delay = 1 * 60;
        final int interval = DEFAULT_INTERVAL;

        timerEvent.fire(new TimerEvent(new TimerSchedule(delay, interval), new StatusCheckerTimerEvent(),
                Scheduled.Literal.INSTANCE));
    }

    @Asynchronous
    public void process(@Observes @Scheduled StatusCheckerTimerEvent statusCheckerTimerEvent) {
        if (this.isActive.get()) {
            return;
        }

        if (!this.isActive.compareAndSet(false, true)) {
            return;
        }

        try {
            processInt();
        } finally {
            this.isActive.set(false);
        }
    }

    /**
     * Gather periodically site and server status
     * 
     * @param when     Date
     * @param interval Interval
     */
    private void processInt() {
        log.debug("Starting update of configuration status");
        ApiAppConfiguration apiAppConfiguration = configurationFactory.getApiAppConfiguration();

        log.debug("Setting FactorAttributes");
        StatsData statsData = new StatsData();
        Date currentDateTime = new Date();
        statsData.setLastUpdate(currentDateTime);
        statsData.setFacterData(getFacterData());
        statsData.setDbType(configurationService.getPersistenceType());
        
        //configurationService.updateStatsData(statsData); //TODO????
        log.debug("Configuration status update finished");
    }

    private FacterData getFacterData() {
        log.debug("Getting Server status");
        FacterData facterData = new FacterData();
        ObjectMapper mapper = new ObjectMapper();
        if (!isLinux()) {
            return facterData;
        }
        CommandLine commandLine = new CommandLine(PROGRAM_FACTER);
        commandLine.addArgument("-j");
        String resultOutput;
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream(4096);) {
            boolean result = ProcessHelper.executeProgram(commandLine, false, 0, bos);
            if (!result) {
                return facterData;
            }
            resultOutput = new String(bos.toByteArray(), "UTF-8");
            facterData = mapper.readValue(resultOutput, FacterData.class);
        } catch (UnsupportedEncodingException ex) {
            log.error("Failed to parse program {} output", PROGRAM_FACTER, ex);
            return facterData;
        } catch (IOException e) {
            e.printStackTrace();
        }
        log.debug("Server status - facterData:{}", facterData);
        return facterData;
    }

    private boolean isLinux() {
        String osName = System.getProperty("os.name");
        return !StringHelper.isEmpty(osName) && osName.toLowerCase().contains("linux");
    }

    private String toIntString(Number number) {
        return (number == null) ? null : String.valueOf(number.intValue());
    }

}
