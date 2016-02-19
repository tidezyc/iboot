package me.tidezyc.iboot.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.Http401AuthenticationEntryPoint;
import org.springframework.boot.autoconfigure.security.SecurityAuthorizeMode;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.web.ErrorController;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author zyc
 */
@Configuration
@EnableConfigurationProperties
@ConditionalOnClass({EnableWebSecurity.class, AuthenticationEntryPoint.class})
@ConditionalOnMissingBean(WebSecurityConfiguration.class)
@ConditionalOnWebApplication
@EnableWebSecurity
public class SecurityConfig {

    private static List<String> DEFAULT_IGNORED = Arrays.asList("/css/**", "/js/**", "/images/**", "/**/favicon.ico");

    @Bean
    @ConditionalOnMissingBean({IgnoredPathsWebSecurityConfigurerAdapter.class})
    public IgnoredPathsWebSecurityConfigurerAdapter ignoredPathsWebSecurityConfigurerAdapter() {
        return new IgnoredPathsWebSecurityConfigurerAdapter();
    }

    public static void configureHeaders(HeadersConfigurer<?> configurer, SecurityProperties.Headers headers) throws Exception {
        if (headers.getHsts() != SecurityProperties.Headers.HSTS.NONE) {
            boolean includeSubdomains = headers.getHsts() == SecurityProperties.Headers.HSTS.ALL;
            HstsHeaderWriter writer = new HstsHeaderWriter(includeSubdomains);
            writer.setRequestMatcher(AnyRequestMatcher.INSTANCE);
            configurer.addHeaderWriter(writer);
        }
        if (!headers.isContentType()) {
            configurer.contentTypeOptions().disable();
        }
        if (!headers.isXss()) {
            configurer.xssProtection().disable();
        }
        if (!headers.isCache()) {
            configurer.cacheControl().disable();
        }
        if (!headers.isFrame()) {
            configurer.frameOptions().disable();
        }
    }

    public static List<String> getIgnored(SecurityProperties security) {
        List<String> ignored = new ArrayList<String>(security.getIgnored());
        if (ignored.isEmpty()) {
            ignored.addAll(DEFAULT_IGNORED);
        } else if (ignored.contains("none")) {
            ignored.remove("none");
        }
        return ignored;
    }

    // Get the ignored paths in early
    @Order(SecurityProperties.IGNORED_ORDER)
    private static class IgnoredPathsWebSecurityConfigurerAdapter
            implements WebSecurityConfigurer<WebSecurity> {

        @Autowired(required = false)
        private ErrorController errorController;

        @Autowired
        private SecurityProperties security;

        @Autowired
        private ServerProperties server;

        @Override
        public void configure(WebSecurity builder) throws Exception {
        }

        @Override
        public void init(WebSecurity builder) throws Exception {
            List<String> ignored = getIgnored(this.security);
            if (this.errorController != null) {
                ignored.add(normalizePath(this.errorController.getErrorPath()));
            }
            String[] paths = this.server.getPathsArray(ignored);
            if (!ObjectUtils.isEmpty(paths)) {
                builder.ignoring().antMatchers(paths);
            }
        }

        private String normalizePath(String errorPath) {
            String result = StringUtils.cleanPath(errorPath);
            if (!result.startsWith("/")) {
                result = "/" + result;
            }
            return result;
        }

    }

    @Configuration
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    protected static class ApplicationWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private SecurityProperties security;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            if (this.security.isRequireSsl()) {
                http.requiresChannel().anyRequest().requiresSecure();
            }
            if (!this.security.isEnableCsrf()) {
                http.csrf().disable();
            }
            // No cookies for application endpoints by default
            http.sessionManagement().sessionCreationPolicy(this.security.getSessions());
            http.formLogin();
            configureHeaders(http.headers(), this.security.getHeaders());
            String[] paths = getSecureApplicationPaths();
            if (paths.length > 0) {
                http.requestMatchers().antMatchers(paths);
                String[] roles = this.security.getUser().getRole().toArray(new String[0]);
                SecurityAuthorizeMode mode = this.security.getBasic().getAuthorizeMode();
                if (mode == null || mode == SecurityAuthorizeMode.ROLE) {
                    http.authorizeRequests().anyRequest().hasAnyRole(roles);
                } else if (mode == SecurityAuthorizeMode.AUTHENTICATED) {
                    http.authorizeRequests().anyRequest().authenticated();
                }
            }
        }

        private String[] getSecureApplicationPaths() {
            List<String> list = new ArrayList<String>();
            for (String path : this.security.getBasic().getPath()) {
                path = (path == null ? "" : path.trim());
                if (path.equals("/**")) {
                    return new String[]{path};
                }
                if (!path.equals("")) {
                    list.add(path);
                }
            }
            return list.toArray(new String[list.size()]);
        }
    }
}
