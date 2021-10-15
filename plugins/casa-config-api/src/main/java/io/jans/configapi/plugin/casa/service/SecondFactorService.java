package io.jans.configapi.plugin.casa.service;

import io.jans.as.model.config.StaticConfiguration;
import io.jans.orm.model.base.CustomObjectAttribute;
import io.jans.orm.model.base.SimpleUser;
import io.jans.orm.search.filter.Filter;
import io.jans.orm.PersistenceEntryManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.Collectors;

import javax.enterprise.context.ApplicationScoped;
import javax.annotation.PostConstruct;
import javax.inject.Inject;

import org.gluu.casa.model.User;

import org.slf4j.Logger;

@ApplicationScoped
public class SecondFactorService {

    private static final String PREFERRED_METHOD_ATTR = "jansPreferredMethod";

    @Inject
    private PersistenceEntryManager entryManager;

    @Inject
    private StaticConfiguration staticConfiguration;

    @Inject
    private Logger logger;

    private String peopleDn;

    public List<User> searchUsers2FAEnabled(String pattern) {

        Stream<Filter> stream = Stream.of("uid", "givenName", "sn")
                .map(attr -> Filter.createSubstringFilter(attr, null, new String[]{ pattern }, null));

        Filter filter = Filter.createANDFilter(
                Filter.createORFilter(stream.collect(Collectors.toList())),
                Filter.createPresenceFilter(PREFERRED_METHOD_ATTR)
        );
        List<User> result = new ArrayList<>(); 
        try {
            logger.debug("Running user query against database"); 
            List<SimpleUser> list =  entryManager.findEntries(peopleDn, SimpleUser.class, filter);
            for (SimpleUser u : list) {
                User user = new User();
                user.setId(u.getAttribute("inum"));
                user.setUserName(u.getAttribute("uid"));
                user.setGivenName(u.getAttribute("givenName"));
                user.setLastName(u.getAttribute("sn"));
                user.setPreferredMethod(u.getAttribute(PREFERRED_METHOD_ATTR));

                result.add(user);
            }
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return result;

    }

    public List<String> disable2FAFor(List<String> inums) {

        List<String> results = new ArrayList<>();
        for (String inum : inums) {
            try {
                Filter filter = Filter.createEqualityFilter("inum", inum);
                logger.debug("Finding user with inum {}", inum);
                SimpleUser user = entryManager.findEntries(peopleDn, SimpleUser.class, filter, 1).get(0);
                List<CustomObjectAttribute> attrs = user.getCustomAttributes();
                //Clear the attribute if present
                attrs.stream().filter(ca -> ca.getName().equals(PREFERRED_METHOD_ATTR)).
                    findFirst().ifPresent(ca -> ca.setValues(Collections.emptyList()));

                logger.debug("Disabling users' 2FA");
                entryManager.merge(user);
                results.add(inum);
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
        return results;

    }

    @PostConstruct
    private void init() {
        peopleDn = staticConfiguration.getBaseDn().getPeople();
    }

}
