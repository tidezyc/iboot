package me.tidezyc.iboot.security;

import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

/**
 * @author tidezyc
 */
@Component
public class AuthenticationManagerImpl implements AuthenticationManager {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String principal = (String) authentication.getPrincipal();
        String credentials = (String) authentication.getCredentials();
        if (StringUtils.equals(principal, "zyc") && StringUtils.equals(credentials, "123")) {
            authentication.setAuthenticated(true);
        }
        return authentication;
    }
}
