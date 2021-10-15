package io.jans.configapi.plugin.casa.rest;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jans.orm.PersistenceEntryManager;

import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.annotation.PostConstruct;
import javax.inject.Inject;

import org.gluu.casa.conf.MainSettings;
import org.gluu.casa.model.ApplicationConfiguration;

import org.slf4j.Logger;

@ApplicationScoped
public class BaseResource {

    public static final String CASA_CONFIG_SCOPE = "https://jans.io/casa.config";
    public static final String CASA_2FA_SCOPE = "https://jans.io/casa.2fa";
    private static final String CONFIG_DN = "ou=casa,ou=configuration,o=jans";

    @Inject
    Logger logger;

    ObjectMapper mapper;

    @Inject
    private PersistenceEntryManager entryManager;

    private ApplicationConfiguration casaConfig;

    public MainSettings getCasaSettings() {
        reloadCasaConfiguration();
        return casaConfig.getSettings();
    }

    public void saveSettings(MainSettings newSettings) throws Exception {

        try {
            casaConfig.setSettings(newSettings);
            logger.trace("Persisting update in configuration");
            entryManager.merge(casaConfig);
        } catch (Throwable e) {
            logger.error("Unable to persist changes");
            logger.error(e.getMessage(), e);
            throw new Exception(e);
        }

    }

    public <T> T getPluginConfiguration(MainSettings settings, String pluginId, Class<T> configClass) throws Exception {
        Map<String, Object> conf = settings.getPluginSettings().get(pluginId);
        if (conf == null) {
            logger.warn("Plugin {} seems not to have a configuration established", pluginId);
            return null;
        }
        return mapper.convertValue(conf, configClass);
    }

    public void setPluginConfiguration(MainSettings settings, String pluginId, Object config) {
        Map<String, Object> conf = mapper.convertValue(config, new TypeReference<Map<String, Object>>(){});
        settings.getPluginSettings().put(pluginId, conf);
    }

    private void reloadCasaConfiguration() {
        casaConfig = entryManager.find(ApplicationConfiguration.class, CONFIG_DN);
    }

    @PostConstruct
    private void init() {
        reloadCasaConfiguration();
        mapper = new ObjectMapper();
    }

}
