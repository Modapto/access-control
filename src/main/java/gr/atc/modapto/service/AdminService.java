package gr.atc.modapto.service;

import gr.atc.modapto.dto.keycloak.ClientDTO;
import gr.atc.modapto.dto.keycloak.ClientRoleDTO;
import gr.atc.modapto.dto.keycloak.GroupDTO;
import gr.atc.modapto.dto.keycloak.RealmRoleDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import static gr.atc.modapto.exception.CustomExceptions.*;

import java.util.Collections;
import java.util.List;

@Service
@Slf4j
public class AdminService implements IAdminService {

    @Value("${keycloak.admin.uri}")
    private String adminUri;

    @Value("${keycloak.client-id}")
    private String clientName;

    private final RestTemplate restTemplate = new RestTemplate();

    // Strings commonly used
    private static final String DEFAULT_ROLE = "default-roles-modapto-dev";

    /**
     * Retrieve all User Roles from Keycloak
     * @param token : JWT Token value
     * @return List<String> : User Roles
     */
    @Override
    public List<String> retrieveAllUserRoles(String token) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Object> entity = new HttpEntity<>(headers);

            String requestUri = adminUri.concat("/roles");
            ResponseEntity<List<RealmRoleDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            // Valid Resposne
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null )
                return response.getBody().stream()
                        .map(RealmRoleDTO::getName)
                        .filter(name -> !name.equals(DEFAULT_ROLE))
                        .toList();

            // Invalid Response return empty List
            return Collections.emptyList();
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieval of user roles: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP error during retrieval of user roles", e);
        } catch (RestClientException e) {
            log.error("Error during retrieval of user roles: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieval of user roles", e);
        }
    }

    /**
     * Retrieve all Pilots from Keycloak
     * @param token : JWT Token value
     * @return List<String> : Pilot Names
     */
    @Override
    public List<String> retrieveAllPilots(String token) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Object> entity = new HttpEntity<>(headers);

            String requestUri = adminUri.concat("/groups");
            ResponseEntity<List<GroupDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            // Valid Resposne
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null )
                return response.getBody().stream()
                        .map(GroupDTO::getName)
                        .toList();

            // Invalid Response return empty List
            return Collections.emptyList();
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieval of pilot codes: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP error during retrieval of pilot codes", e);
        } catch (RestClientException e) {
            log.error("Error during retrieval of pilot codes: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieval of pilot codes", e);
        }
    }

    /**
     * Retrieve all Pilot Roles from Keycloak
     * @param token : JWT Token value
     * @return List<String> : Pilot Roles
     */
    @Override
    public List<String> retrieveAllPilotRoles(String token) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Object> entity = new HttpEntity<>(headers);

            // Retrieve Client ID
            String clientId = retrieveClientId(entity);
            if (clientId == null){
                log.error("Unable to locate the client's id");
                return Collections.emptyList();
            }

            String requestUri = adminUri.concat("/clients/").concat(clientId).concat("/roles");
            ResponseEntity<List<ClientRoleDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            // Valid Resposne
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null )
                return response.getBody().stream()
                        .map(ClientRoleDTO::getName)
                        .toList();

            // Invalid Response return empty List
            return Collections.emptyList();
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieval of pilot roles: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP error during retrieval of pilot roles", e);
        } catch (RestClientException e) {
            log.error("Error during retriaval of pilot roles: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieval of pilot roles", e);
        }
    }

    /**
     * Retrieve Client ID for a given Client
     * @param entity : HttpEntity containing the JWT Token in Headers
     * @return String : Client ID
     */
    private String retrieveClientId(HttpEntity<Object> entity){
        try {
            String requestUri = adminUri.concat("/clients");
            ResponseEntity<List<ClientDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            // Valid Resposne
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null )
               return response.getBody().stream()
                        .filter(client -> client.getClientId().equals(clientName))
                        .map(ClientDTO::getId)
                        .findFirst()
                        .orElse(null);


            // Invalid Response return null
            return null;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieval of client ID: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP error during retrieval of client ID", e);
        } catch (RestClientException e) {
            log.error("Error during retrieval of client ID: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieval of client ID", e);
        }
    }
}
