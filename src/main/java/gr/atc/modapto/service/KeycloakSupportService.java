package gr.atc.modapto.service;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import gr.atc.modapto.dto.keycloak.ClientDTO;
import gr.atc.modapto.dto.keycloak.GroupDTO;
import gr.atc.modapto.dto.keycloak.RoleRepresentationDTO;
import gr.atc.modapto.exception.CustomExceptions;
import gr.atc.modapto.exception.CustomExceptions.DataRetrievalException;
import gr.atc.modapto.exception.CustomExceptions.KeycloakException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

/**
 * We utilize this component to include some common functionalities for the Keycloak Requests
 */
@Service
@Slf4j
public class KeycloakSupportService {

    @Value("${keycloak.token-uri}")
    private String tokenUri;

    @Value("${keycloak.admin.uri}")
    private String adminUri;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    private final RestTemplate restTemplate = new RestTemplate();

    // Strings commonly used
    private static final String TOKEN = "access_token";
    private static final String GRANT_TYPE = "grant_type";
    private static final String CLIENT_ID = "client_id";
    private static final String CLIENT_SECRET = "client_secret";
    private static final String ROLE_NOT_FOUND_MESSAGE = "User Role not found in Keycloak";
    private static final String CLIENT_NOT_FOUND_MESSAGE = "Client not found in Keycloak";
    private static final String GROUP_NOT_FOUND_MESSAGE = "Pilot Code not found in Keycloak";
    private static final String ERROR_FIELD = "errorMessage";


    // Store the clientId as variable and update it daily
    private String cachedClientId;

    // Called after the creation of Bean to retrieve client ID
    @PostConstruct
    public void init() {
        this.cachedClientId = retrieveClientId(retrieveComponentJwtToken(), clientId);
    }

    @Scheduled(fixedRate = 24 * 60 * 60 * 1000)
    public void refreshClientId() {
        this.cachedClientId = retrieveClientId(retrieveComponentJwtToken(),clientId);
    }

    public String getClientId() {
        return cachedClientId != null ? cachedClientId : retrieveClientId(retrieveComponentJwtToken(), clientId);
    }

    /**
     * Generate a JWT Token to access Keycloak resources
     *
     * @return Token
     */
    public String retrieveComponentJwtToken(){
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            String client = clientId;
            String secret = clientSecret;

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add(CLIENT_ID, client);
            map.add(CLIENT_SECRET, secret);
            map.add(GRANT_TYPE, "client_credentials");

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    tokenUri,
                    HttpMethod.POST,
                    entity,
                    new ParameterizedTypeReference<>() {
                    }
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                Map<String, Object> responseBody = response.getBody();
                if (responseBody == null || responseBody.get(TOKEN) == null) {
                    return null;
                }
                return responseBody.get(TOKEN).toString();
            }
            return null;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during authenticating the client: Error: {}", e.getMessage());
            return null;
        } catch (RestClientException e) {
            log.error("Rest Client error during authenticating the client: Error: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Retrieve Client ID for a given Client
     *
     * @param token : JWT Token Value
     * @return String : Client ID
     */
    public String retrieveClientId(String token, String clientName){
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Object> entity = new HttpEntity<>(headers);

            // Retrieve Client ID from Keycloak
            String requestUri = adminUri.concat("/clients");
            ResponseEntity<List<ClientDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            // Parse response
            return Optional.ofNullable(response)
                .filter(resp -> resp.getStatusCode().is2xxSuccessful())
                .map(ResponseEntity::getBody)
                .map(body -> body.stream()
                    .filter(client -> client.getClientId().equals(clientName))
                    .map(ClientDTO::getId)
                    .findFirst()
                    .orElse(null))
                .orElse(null);
        } catch (HttpServerErrorException e) {
            log.error("HTTP server error during retrieval of client ID: {}", e.getMessage(), e);
            throw new CustomExceptions.KeycloakException("HTTP server error during retrieval of client ID", e);
        } catch (HttpClientErrorException e) {
          Map<String, Object> responseBody = e.getResponseBodyAs(new ParameterizedTypeReference<Map<String, Object>>() {});
          if (responseBody != null && responseBody.containsKey(ERROR_FIELD)) {
            throw new DataRetrievalException(responseBody.get(ERROR_FIELD).toString());
          }
          throw new DataRetrievalException(CLIENT_NOT_FOUND_MESSAGE);
        } catch (RestClientException e) {
            log.error("Error during retrieval of client ID: {}", e.getMessage(), e);
            throw new CustomExceptions.KeycloakException("Error during retrieval of client ID", e);
        }
    }

    /**
     * Retrieve Group ID for a given Pilot Code
     *
     * @param token : JWT Token Value
     * @return String : Client ID
     */
    public String retrievePilotCodeID(String pilot, String token){
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Object> entity = new HttpEntity<>(headers);

            // Retrieve Group ID from Keycloak
            String requestUri = adminUri.concat("/groups");
            ResponseEntity<List<GroupDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

           // Parse response
           return Optional.ofNullable(response)
              .filter(resp -> resp.getStatusCode().is2xxSuccessful())
              .map(ResponseEntity::getBody)
              .map(body -> body.stream()
                    .filter(group -> group.getName().equals(pilot))
                    .map(GroupDTO::getId)
                    .findFirst()
                      .orElse(null))
              .orElse(null);
        } catch (HttpServerErrorException e) {
            log.error("HTTP server error during retrieval of group ID: {}", e.getMessage(), e);
            throw new CustomExceptions.KeycloakException("HTTP server error during retrieval of client ID", e);
        } catch (HttpClientErrorException e) {
          Map<String, Object> responseBody = e.getResponseBodyAs(new ParameterizedTypeReference<Map<String, Object>>() {});
          if (responseBody != null && responseBody.containsKey(ERROR_FIELD)) {
            throw new DataRetrievalException(responseBody.get(ERROR_FIELD).toString());
          }
          throw new DataRetrievalException(GROUP_NOT_FOUND_MESSAGE);
        } catch (RestClientException e) {
            log.error("Error during retrieval of group ID: {}", e.getMessage(), e);
            throw new CustomExceptions.KeycloakException("Error during retrieval of client ID", e);
        }
    }

    /**
     * Find a Role Representation By Name
     *
     * @param userRole : User role to retrieve
     * @param token : JWT Token value
     * @return RoleRepresentationDTO : Role Representation
     */
    public RoleRepresentationDTO findRoleRepresentationByName(String userRole, String clientId, String token) {
        // Set Headers
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        // Create the URI and make the POST request
        StringBuilder requestUri = new StringBuilder();
        requestUri.append(adminUri).append("/clients/").append(clientId).append("/roles/").append(userRole);
        try{
            ResponseEntity<RoleRepresentationDTO> response = restTemplate.exchange(
                    requestUri.toString(),
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            // Locate and return the Role Representation
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null )
                return response.getBody();

            // Invalid Response return null
            return null;
        } catch (HttpServerErrorException e) {
            log.error("HTTP server error during locating role information: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP server error during locating role information", e);
        } catch (HttpClientErrorException e) {
          Map<String, Object> responseBody = e.getResponseBodyAs(new ParameterizedTypeReference<Map<String, Object>>() {});
          if (responseBody != null && responseBody.containsKey(ERROR_FIELD)) {
            throw new DataRetrievalException(responseBody.get(ERROR_FIELD).toString());
          }
          throw new DataRetrievalException(ROLE_NOT_FOUND_MESSAGE);
        } catch (RestClientException e) {
            log.error("Error during locating role information: {}", e.getMessage(), e);
            throw new KeycloakException("Error during locating role information", e);
        }
    }
}
