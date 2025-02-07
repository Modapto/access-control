package gr.atc.modapto.service;

import java.util.Collections;
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
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.dto.UserRoleDTO;
import gr.atc.modapto.dto.keycloak.GroupDTO;
import gr.atc.modapto.dto.keycloak.RealmRoleDTO;
import gr.atc.modapto.dto.keycloak.RoleRepresentationDTO;
import gr.atc.modapto.dto.keycloak.UserRepresentationDTO;
import gr.atc.modapto.exception.CustomExceptions.DataRetrievalException;
import gr.atc.modapto.exception.CustomExceptions.KeycloakException;
import gr.atc.modapto.exception.CustomExceptions.ResourceAlreadyExistsException;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AdminService implements IAdminService {
    @Value("${keycloak.admin.uri}")
    private String adminUri;

    @Value("${keycloak.api.client-path:/clients}")
    private String clientPath;
    
    @Value("${keycloak.api.role-path:/roles}")
    private String rolePath;

    @Value("${keycloak.api.group-path:/groups}")
    private String groupPath;

    @Value("${keycloak.default.realm.role}")
    private String defaultRole;

    private final RestTemplate restTemplate = new RestTemplate();

    private final KeycloakSupportService keycloakSupportService;

    // Strings commonly used
    private final List<String> SUPER_ADMIN_EXCLUDED_ROLES = List.of(defaultRole, "uma_authorization", "offline_access");
    private final List<String> ADMIN_EXCLUDED_ROLES = List.of(defaultRole, "uma_authorization", "offline_access", "SUPER_ADMIN");
    private static final String ROLE_NOT_FOUND_MESSAGE = "User Role not found in Keycloak";
    private static final String CLIENT_NOT_FOUND_MESSAGE = "Client not found in Keycloak";
    private static final String GROUP_NOT_FOUND_MESSAGE = "Group not found in Keycloak";
    private static final String ERROR_FIELD = "errorMessage";

    public AdminService(KeycloakSupportService keycloakSupportService){
        this.keycloakSupportService = keycloakSupportService;
    }

    /**
     * Retrieve all Pilot Roles from Keycloak
     *
     * @param token : JWT Token value
     * @return List<String> : Pilot Roles
     */
    @Override
    public List<String> retrieveAllPilotRoles(String token, boolean isSuperAdmin) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            String requestUri = adminUri.concat(rolePath);
            ResponseEntity<List<RealmRoleDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            // Select the appropriate list according to whether pilot code was inserted or not
            List<String> excludedList = isSuperAdmin ? SUPER_ADMIN_EXCLUDED_ROLES : ADMIN_EXCLUDED_ROLES;
            
            // Parse response
            return Optional.ofNullable(response)
                    .filter(resp -> resp.getStatusCode().is2xxSuccessful())
                    .map(ResponseEntity::getBody)
                    .map(body -> body.stream()
                            .map(RealmRoleDTO::getName)
                            .filter(name -> !excludedList.contains(name))
                            .toList())
                    .orElse(Collections.emptyList());
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
     *
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

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            String requestUri = adminUri.concat(groupPath);
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
              .map(GroupDTO::getName)
                      .toList())
              .orElse(Collections.emptyList());
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieval of pilot codes: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP error during retrieval of pilot codes", e);
        } catch (RestClientException e) {
            log.error("Error during retrieval of pilot codes: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieval of pilot codes", e);
        }
    }

    /**
     * Retrieve all User Roles from Keycloak
     *
     * @param token : JWT Token value
     * @return List<String> : User Roles
     */
    @Override
    public List<UserRoleDTO> retrieveAllUserRoles(String token, String pilot) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            // Retrieve Client ID
            String clientId = keycloakSupportService.getClientId();
            if (clientId == null){
                log.error(CLIENT_NOT_FOUND_MESSAGE);
                return Collections.emptyList();
            }

            String requestUri = adminUri.concat(clientPath).concat("/").concat(clientId).concat("/roles?briefRepresentation=false");
            ResponseEntity<List<RoleRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            // Parse Response
            return Optional.ofNullable(response)
              .filter(resp -> resp.getStatusCode().is2xxSuccessful())
              .map(ResponseEntity::getBody)
              .map(body -> {
                  if (pilot.equals("ALL")) { // Case for SUPER_ADMIN
                      return body.stream()
                              .map(RoleRepresentationDTO::toUserRoleDTO)
                              .toList();
                  } else { // Case for ADMINS
                      return body.stream()
                              .map(RoleRepresentationDTO::toUserRoleDTO)
                              .filter(role -> pilot.equals(Optional.ofNullable(role.getPilotCode())
                                      .map(Object::toString)
                                      .orElse(null)))
                              .toList();
                  }
              })
              .orElse(Collections.emptyList());
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieval of user roles: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP error during retrieval of user roles", e);
        } catch (RestClientException e) {
            log.error("Error during retrieval of user roles: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieval of user roles", e);
        }
    }

    /**
     * Create a new User Role in Keycloak
     * Steps: 1) Create the Role in Keycloak
     *        2) Assign it to group according to its pilot code
     *
     * @param token : JWT Token
     * @param userRole : DTO with the User Role information
     * @return True on success, False on error
     */
    @Override
    public boolean createUserRole(String token, UserRoleDTO userRole) {
        try{
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            // Create the Representation
            RoleRepresentationDTO roleRepr = RoleRepresentationDTO.toRoleRepresentation(userRole, null);
            HttpEntity<RoleRepresentationDTO> entity = new HttpEntity<>(roleRepr, headers);

            // Retrieve clientId and check if is not null
            String clientId = keycloakSupportService.getClientId();
            if (clientId == null)
                throw new DataRetrievalException(CLIENT_NOT_FOUND_MESSAGE);

            // Create the URI and make the POST request
            String requestUri = adminUri.concat(clientPath).concat("/").concat(clientId).concat(rolePath);
            ResponseEntity<Void> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.POST,
                    entity,
                    Void.class
            );

            // Failed response - Return False
            if (!response.getStatusCode().is2xxSuccessful())
                return false;

            // Assign the Role to the Group (Pilot)
            return assignUserRoleToPilot(userRole.getName() , userRole.getPilotCode().toString(), clientId, token);
        } catch (HttpServerErrorException e) {
            log.error("HTTP server error during creating an new user role: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP server error during creating an new user role", e);
        } catch (HttpClientErrorException e) {
            Map<String, Object> responseBody = e.getResponseBodyAs(new ParameterizedTypeReference<Map<String, Object>>() {});
            if (responseBody != null && responseBody.containsKey(ERROR_FIELD)) {
                throw new ResourceAlreadyExistsException(responseBody.get(ERROR_FIELD).toString());
            }
            throw new ResourceAlreadyExistsException(e.getResponseBodyAsString());
        } catch (RestClientException e) {
            log.error("Error during creating an new user role: {}", e.getMessage(), e);
            throw new KeycloakException("Error during creating an new user role", e);
        }


    }

    /**
     * Retrieve a User Role from Keycloak given the inserted name
     *
     * @param tokenValue : JWT Token Value
     * @param roleName : Name of the requested user role
     * @throws DataRetrievalException : If user role not found in DB
     * @return UserRoleDTO
     */
    @Override
    public UserRoleDTO retrieveUserRole(String tokenValue, String roleName) {
        RoleRepresentationDTO existingRole = keycloakSupportService.findRoleRepresentationByNameAndClient(roleName, keycloakSupportService.getClientId(), tokenValue);
        if (existingRole == null)
            throw new DataRetrievalException(ROLE_NOT_FOUND_MESSAGE);
        return RoleRepresentationDTO.toUserRoleDTO(existingRole);
    }

    /**
     * Delete a User Role from Keycloak given the inserted name
     *
     * @param tokenValue : JWT Token Value
     * @param roleName   : Name to delete
     * @throws DataRetrievalException : If user role not found in DB
     * @return True on success, False on error
     */
    @Override
    public boolean deleteUserRole(String tokenValue, String roleName) {
        // Set Headers
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(tokenValue);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        // Retrieve clientId and check if is not null
        String clientId = keycloakSupportService.getClientId();
        if (clientId == null)
            throw new DataRetrievalException(CLIENT_NOT_FOUND_MESSAGE);

        // Create the URI and make the POST request
        StringBuilder requestUri = new StringBuilder();
        requestUri.append(adminUri).append(clientPath).append("/").append(clientId).append(rolePath).append("/").append(roleName);
        try{
            ResponseEntity<Void> response = restTemplate.exchange(
                    requestUri.toString(),
                    HttpMethod.DELETE,
                    entity,
                    Void.class
            );

            // Return true if response is Successful
            return response.getStatusCode().is2xxSuccessful();
        } catch (HttpServerErrorException e) {
            log.error("HTTP server error during deleting user role information: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP server error during deleting user role information", e);
        } catch (HttpClientErrorException e) {
          Map<String, Object> responseBody = e.getResponseBodyAs(new ParameterizedTypeReference<Map<String, Object>>() {});
          if (responseBody != null && responseBody.containsKey(ERROR_FIELD)) {
              throw new DataRetrievalException(responseBody.get(ERROR_FIELD).toString());
          }
          throw new DataRetrievalException("Unable to locate user role");
        } catch (RestClientException e) {
            log.error("Error during deleting user role information: {}", e.getMessage(), e);
            throw new KeycloakException("Error during deleting user role information", e);
        }
    }

    /**
     * Update a user role in Keycloak
     *
     * @param tokenValue : JWT Token Value
     * @param userRole : User Role variables to update
     * @param existingRoleName : Existing role name in Keycloak
     * @throws DataRetrievalException : If user role not found in DB or client id cannot be located
     * @return True on success, False on error
     */
    @Override
    public boolean updateUserRole(String tokenValue, UserRoleDTO userRole, String existingRoleName) {
        // Set Headers
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(tokenValue);
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Retrieve clientId and check if is not null
        String clientId = keycloakSupportService.getClientId();
        if (clientId == null)
            throw new DataRetrievalException(CLIENT_NOT_FOUND_MESSAGE);

        // Try locating the RoleRepresentation
        RoleRepresentationDTO existingRole = keycloakSupportService.findRoleRepresentationByNameAndClient(existingRoleName, clientId, tokenValue);
        if (existingRole == null)
            throw new DataRetrievalException(ROLE_NOT_FOUND_MESSAGE);

        // Create the Representation
        RoleRepresentationDTO roleRepr = RoleRepresentationDTO.toRoleRepresentation(userRole, existingRole);
        HttpEntity<RoleRepresentationDTO> entity = new HttpEntity<>(roleRepr, headers);

        // Create the URI and make the POST request
        StringBuilder requestUri = new StringBuilder();
        requestUri.append(adminUri).append(clientPath).append("/").append(clientId).append(rolePath).append("/").append(existingRoleName);
        try{
            ResponseEntity<Void> response = restTemplate.exchange(
                    requestUri.toString(),
                    HttpMethod.PUT,
                    entity,
                    Void.class
            );

            // Return true if response is Successful
            return response.getStatusCode().is2xxSuccessful();
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during updating user role information: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP error during updating user role information", e);
        } catch (RestClientException e) {
            log.error("Error during updating user role information: {}", e.getMessage(), e);
            throw new KeycloakException("Error during updating user role information", e);
        }
    }

    /**
     * Retrieve all user roles from Keycloak connected to a specific Group (Pilot Code)
     *
     * @param tokenValue : JWT token value
     * @param pilotCode : Pilot Code
     * @return List<String> of User Roles
     */
    @Override
    public List<String> retrieveAllUserRolesByPilot(String tokenValue, String pilotCode) {
        // Retrieve clientId and check if is not null
        String clientId = keycloakSupportService.getClientId();
        if (clientId == null)
            throw new DataRetrievalException(ROLE_NOT_FOUND_MESSAGE);

        // Retrieve Group ID
        String groupId = keycloakSupportService.retrievePilotCodeID(pilotCode, tokenValue);
        if (groupId == null)
            throw new DataRetrievalException(GROUP_NOT_FOUND_MESSAGE);

        // Set Headers
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(tokenValue);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        // Create the URI and make the GET request
        StringBuilder requestUri = new StringBuilder();
        requestUri.append(adminUri).append(groupPath).append("/").append(groupId).append("/role-mappings/clients/").append(clientId);
        try{
            ResponseEntity<List<RoleRepresentationDTO>> response = restTemplate.exchange(
                    requestUri.toString(),
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            // Parse Response
            return Optional.ofNullable(response)
                .filter(resp -> resp.getStatusCode().is2xxSuccessful())
                .map(ResponseEntity::getBody)
                .map(body -> body.stream()
                        .map(RoleRepresentationDTO::getName)
                        .toList())
                .orElse(Collections.emptyList());
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieving user role per pilot: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP error during retrieving user role per pilot", e);
        } catch (RestClientException e) {
            log.error("Error during retrieving user role per pilot: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieving user role per pilot", e);
        }
    }

    /**
     * Retrieve all users from Keycloak connected to a specific User Role (Client Role)
     *
     * @param tokenValue : JWT token value
     * @param userRole : Client Role
     * @return List<UserDTO> of Users
     */
    @Override
    public List<UserDTO> retrieveAllUsersByUserRole(String tokenValue, String userRole) {
        // Retrieve clientId and check if is not null
        String clientId = keycloakSupportService.getClientId();
        if (clientId == null)
            throw new DataRetrievalException(ROLE_NOT_FOUND_MESSAGE);


        // Set Headers
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(tokenValue);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        // Create the URI and make the GET request
        StringBuilder requestUri = new StringBuilder();
        requestUri.append(adminUri).append(clientPath).append("/").append(clientId).append(rolePath).append("/").append(userRole).append("/users");
        try{
            ResponseEntity<List<UserRepresentationDTO>> response = restTemplate.exchange(
                    requestUri.toString(),
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

             // Parse Response
             return Optional.ofNullable(response)
                .filter(resp -> resp.getStatusCode().is2xxSuccessful())
                .map(ResponseEntity::getBody)
                .map(body -> body.stream()
                .map(UserRepresentationDTO::toUserDTO)
                        .toList())
                .orElse(Collections.emptyList());
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieving users in specific role: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP error during retrieving users in specific role", e);
        } catch (RestClientException e) {
            log.error("Error during retrieving users in specific role: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieving users in specific role", e);
        }
    }

    /**
     * Assign a User Role to a specific Group - Pilot Code
     *
     * @param userRole : User Role to assign
     * @param pilotCode : Pilot Code associated with a Keycloak Group
     * @param token : JWT Token Value
     * @return True on success, False on error
     */
    @Override
    public boolean assignUserRoleToPilot(String userRole, String pilotCode, String clientId, String token) {
        // Retrieve Group ID
        String groupId = keycloakSupportService.retrievePilotCodeID(pilotCode, token);
        if (groupId == null)
            throw new DataRetrievalException(GROUP_NOT_FOUND_MESSAGE);

        // Retrieve Role Representation by Name
        RoleRepresentationDTO roleRepr = keycloakSupportService.findRoleRepresentationByNameAndClient(userRole, clientId, token);
        if (roleRepr == null)
            throw new DataRetrievalException(ROLE_NOT_FOUND_MESSAGE);

        // Set Headers
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<List<RoleRepresentationDTO>> entity = new HttpEntity<>(List.of(roleRepr), headers);

        // Create the URI and make the POST request
        StringBuilder requestUri = new StringBuilder();
        requestUri.append(adminUri).append(groupPath).append("/").append(groupId).append("/role-mappings/clients/").append(clientId);
        try{
            ResponseEntity<Void> response = restTemplate.exchange(
                    requestUri.toString(),
                    HttpMethod.POST,
                    entity,
                    Void.class
            );

            // Return true on success, false on error
            return response.getStatusCode().is2xxSuccessful();
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during assigning role to specific group: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP error during assigning role to specific group", e);
        } catch (RestClientException e) {
            log.error("Error during assigning role to specific group: {}", e.getMessage(), e);
            throw new KeycloakException("Error during assigning role to specific group", e);
        }
    }

}
