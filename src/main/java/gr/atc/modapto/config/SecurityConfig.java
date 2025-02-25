package gr.atc.modapto.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import gr.atc.modapto.filter.CsrfCookieFilter;
import gr.atc.modapto.keycloak.JwtAuthConverter;
import gr.atc.modapto.keycloak.UnauthorizedEntryPoint;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

  @Value("${spring.security.cors.domains}")
  private String corsDomainsRaw;

  /**
   * Initialize and Configure Security Filter Chain of HTTP connection
   * 
   * @param http HttpSecurity
   * @param entryPoint UnauthorizedEntryPoint -> To add proper API Response to the authorized
   *        request
   * @return SecurityFilterChain
   */
  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
      UnauthorizedEntryPoint entryPoint) throws Exception {
    CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
    requestHandler.setCsrfRequestAttributeName("_csrf");

    // Convert Keycloak Roles with class to Spring Security Roles
    JwtAuthConverter jwtAuthConverter = new JwtAuthConverter();

    // Set Session to Stateless so not to keep any information about the JWT
    http.sessionManagement(
        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // Configure CORS access
        .cors(corsCustomizer -> corsCustomizer.configurationSource(corsConfigurationSource()))
        // Configure CSRF Token
        .csrf(csrf -> csrf.csrfTokenRequestHandler(requestHandler)
            .ignoringRequestMatchers("/api/users/**", "/api/admin/**", "/api/user-manager/**") // For
                                                                                               // now
                                                                                               // ignore
                                                                                               // all
                                                                                               // requests
                                                                                               // under
                                                                                               // api/users,
                                                                                               // and
                                                                                               // api/admin
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
        .exceptionHandling(exc -> exc.authenticationEntryPoint(entryPoint))
        // HTTP Requests authorization properties on URLs
        .authorizeHttpRequests(
            authorizeRequests -> authorizeRequests
                .requestMatchers("/api/users/authenticate", "/api/users/refresh-token",
                    "/api/users/activate", "/api/users/reset-password",
                    "/api/users/forgot-password", "/api/user-manager/**")
                .permitAll().anyRequest().authenticated())
        // JWT Authentication Configuration to use with Keycloak
        .oauth2ResourceServer(oauth2ResourceServerCustomizer -> oauth2ResourceServerCustomizer
            .jwt(jwtCustomizer -> jwtCustomizer.jwtAuthenticationConverter(jwtAuthConverter)));
    return http.build();
  }

  /**
   * Initialize Granted Authorities Bean
   * 
   * @return GrantedAuthorityDefaults
   */
  @Bean
  public GrantedAuthorityDefaults grantedAuthorityDefaults() {
    return new GrantedAuthorityDefaults("");
  }

  /**
   * Settings for CORS
   *
   * @return CorsConfigurationSource
   */
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    // Split and trim domains
    List<String> corsDomains = Arrays.stream(corsDomainsRaw.split(","))
                                     .map(String::trim)
                                     .toList();
                                     
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(corsDomains);
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    configuration.setAllowedHeaders(Arrays.asList("*"));
    configuration.setAllowCredentials(true);
    configuration.setMaxAge(86400L);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

}
