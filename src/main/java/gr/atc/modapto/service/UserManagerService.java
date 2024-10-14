package gr.atc.modapto.service;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import gr.atc.modapto.dto.keycloak.ClientRepresentationDTO;
import gr.atc.modapto.dto.keycloak.CredentialRepresentationDTO;
import gr.atc.modapto.dto.keycloak.RoleRepresentationDTO;
import gr.atc.modapto.dto.keycloak.UserRepresentationDTO;

import gr.atc.modapto.enums.PilotRole;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import gr.atc.modapto.dto.AuthenticationResponseDTO;
import gr.atc.modapto.dto.CredentialsDTO;
import gr.atc.modapto.dto.UserDTO;

import static gr.atc.modapto.exception.CustomExceptions.*;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class UserManagerService implements IUserManagerService {

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
    private static final String GRANT_TYPE_PASSWORD = "password";
    private static final String GRANT_TYPE = "grant_type";
    private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    private static final String CLIENT_ID = "client_id";
    private static final String CLIENT_SECRET = "client_secret";
    private static final String USERNAME = "username";
    private static final String SCOPE = "scope";
    private static final String PROTOCOL = "openid";

    // Arrays of realm-manage roles
    private static final List<String> USER_ROLES_MANAGEMENT_ARRAY = List.of("manage-users");
    private static final List<String> ADMIN_ROLES_MANAGEMENT_ARRAY = List.of("manage-users", "view-users", "query-users");
    private static final List<String> SUPER_ADMIN_ROLES_MANAGEMENT_ARRAY = List.of(
            "query-realms",
            "manage-realm",
            "manage-clients",
            "realm-admin",
            "manage-users",
            "query-users",
            "manage-authorization",
            "view-identity-providers",
            "view-users",
            "query-clients",
            "view-clients",
            "query-groups",
            "view-events",
            "view-authorization",
            "view-realm"
    );

    /**
     * Authenticate the User Credentials in Keycloak and return Token
     * Used also to refresh user's token
     *
     * @param refreshToken Token to refresh user's token (Null if not applicable)
     * @param credentials  User email and password
     * @return AuthenticationResponseDTO
     */
    @Override
    public AuthenticationResponseDTO authenticate(CredentialsDTO credentials, String refreshToken) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> entity = getMultiValueMapHttpEntity(credentials, refreshToken, headers);
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

                return AuthenticationResponseDTO.builder()
                        .accessToken((String) responseBody.get(TOKEN))
                        .expiresIn((Integer) responseBody.get("expires_in"))
                        .tokenType((String) responseBody.get("token_type"))
                        .refreshToken((String) responseBody.get(GRANT_TYPE_REFRESH_TOKEN))
                        .refreshExpiresIn((Integer) responseBody.get("refresh_expires_in"))
                        .build();
            }
            return null;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during authentication process: {}, Response body: {}", e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during authentication process", e);
        } catch (RestClientException e) {
            log.error("Unable to retrieve token information from Keycloak. Error: {}", e.getMessage());
            throw new KeycloakException("Unable to retrieve token information from Keycloak", e);
        }
    }

    /**
     * Create a new user in Keycloak
     *
     * @param user  : Data about the new user to create
     * @param token : JWT Token Value
     * @return True on success, False on error
     */
    @Override
    public String createUser(UserDTO user, String token) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<UserRepresentationDTO> entity = new HttpEntity<>(UserRepresentationDTO.fromUserDTO(user, null), headers);

            String requestUri = adminUri.concat("/users");
            ResponseEntity<Object> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.POST,
                    entity,
                    Object.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                // Extract the user ID from the Location header
                String location = Objects.requireNonNull(response.getHeaders().getLocation()).toString();
                return location.substring(location.lastIndexOf("/") + 1);
            } else {
                throw new KeycloakException("User creation failed with status: " + response.getStatusCode(), null);
            }
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during user creation: {}, Response body: {}", e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during user creation", e);
        } catch (RestClientException e) {
            log.error("Error during user creation: {}", e.getMessage(), e);
            throw new KeycloakException("Error during user creation", e);
        }
    }

    /**
     * Update an existing user in Keycloak
     *
     * @param user  : Data about the new user to create
     * @param token : JWT Token Value
     * @return True on success, False on error
     */
    @Override
    public boolean updateUser(UserDTO user, String userId, String token) {
        try{
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            UserRepresentationDTO existingUser = retrieveUserById(userId, token);
            if (existingUser == null)
                return false;

            HttpEntity<UserRepresentationDTO> entity = new HttpEntity<>(UserRepresentationDTO.fromUserDTO(user, existingUser), headers);

            String requestUri = adminUri.concat("/users/").concat(userId);
            ResponseEntity<Object> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.PUT,
                    entity,
                    Object.class
            );

            return response.getStatusCode().is2xxSuccessful();
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during changing password of user with id {} : {}, Response body: {}", userId, e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during retrieving user with id = ".concat(userId), e);
        } catch (RestClientException e) {
            log.error("Error during changing password of user with id {} : {}", userId, e.getMessage(), e);
            throw new KeycloakException("Error during retrieving user with id = ".concat(userId), e);
        }
    }

    /**
     * Retrieve all user from Keycloak
     *
     * @param token : JWT Token Value
     * @return List<UserDTO>
     */
    @Override
    public List<UserDTO> fetchUsers(String token) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<UserRepresentationDTO> entity = new HttpEntity<>(null, headers);

            String requestUri = adminUri.concat("/users");
            ResponseEntity<List<UserRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {
                    }
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null && !response.getBody().isEmpty())
                return response.getBody().stream().map(UserRepresentationDTO::toUserDTO).toList();

            return Collections.emptyList();
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieving users: {}, Response body: {}", e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during retrieving all users", e);
        } catch (RestClientException e) {
            log.error("Error during retrieving users: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieving all users", e);
        }
    }

    /**
     * Retrieve user by his id from Keycloak
     *
     * @param userId : User Id
     * @param token : JWT Token Value
     * @return UserDTO
     */
    @Override
    public UserDTO fetchUser(String userId, String token) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<UserRepresentationDTO> entity = new HttpEntity<>(null, headers);

            String requestUri = adminUri.concat("/users?id=").concat(userId);
            ResponseEntity<List<UserRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {
                    }
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null && !response.getBody().isEmpty())
                return UserRepresentationDTO.toUserDTO(response.getBody().getFirst());

            return null;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieving specific user with id {} : {}, Response body: {}", userId, e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during retrieving user with id = ".concat(userId), e);
        } catch (RestClientException e) {
            log.error("Error during retrieving specific user with id {} : {}", userId, e.getMessage(), e);
            throw new KeycloakException("Error during retrieving user with id = ".concat(userId), e);
        }
    }

    /**
     * Delete user by his id from Keycloak
     *
     * @param userId : User Id
     * @param token : JWT Token Value
     * @return UserDTO
     */
    @Override
    public boolean deleteUser(String userId, String token) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<UserRepresentationDTO> entity = new HttpEntity<>(null, headers);

            String requestUri = adminUri.concat("/users/").concat(userId);
            ResponseEntity<List<UserRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.DELETE,
                    entity,
                    new ParameterizedTypeReference<>() {
                    }
            );

            return response.getStatusCode().is2xxSuccessful();
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieving specific user with id {} : {}, Response body: {}", userId, e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during deleting user with id = ".concat(userId), e);
        } catch (RestClientException e) {
            log.error("Error during retrieving specific user with id {} : {}", userId, e.getMessage(), e);
            throw new KeycloakException("Error during deleting user with id = ".concat(userId), e);
        }
    }

    /**
     * Change user's password in Keycloak
     *
     * @param userId : User ID correlated with the JWT
     * @param token : JWT Token Value
     * @return True on success, False on error
     */
    @Override
    public boolean changePassword(String password, String userId, String token) {
        CredentialRepresentationDTO credentials = CredentialRepresentationDTO.builder()
                .temporary(false)
                .type(GRANT_TYPE_PASSWORD)
                .value(password)
                .build();
        try{
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<CredentialRepresentationDTO> entity = new HttpEntity<>(credentials, headers);

            String requestUri = adminUri.concat("/users/").concat(userId).concat("/reset-password");
            ResponseEntity<Object> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.PUT,
                    entity,
                    Object.class
            );

             return response.getStatusCode().is2xxSuccessful();
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during changing password of user with id {} : {}, Response body: {}", userId, e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during changing password of user with id = ".concat(userId), e);
        } catch (RestClientException e) {
            log.error("Error during changing password of user with id {} : {}", userId, e.getMessage(), e);
            throw new KeycloakException("Error during changing password of user with id = ".concat(userId), e);
        }
    }

    /**
     * Retrive a User Representation based on email parameters
     *
     * @param email : Email for query
     * @param token : JWT Token value
     * @return UserRepresentationDTO or null if error occured
     */
    @Override
    public UserRepresentationDTO retrieveUserByEmail(String email, String token) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Object> entity = new HttpEntity<>(headers);

            String requestUri = adminUri.concat("/users?email=").concat(email);
            ResponseEntity<List<UserRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {
                    }
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null && !response.getBody().isEmpty())
                return response.getBody().getFirst();

            return null;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error retrieving user by email: {}, Response body: {}", e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during retrieving user by email", e);
        } catch (RestClientException | NoSuchElementException e) {
            log.error("Error during retrieving user by email: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieving user by email", e);
        }
    }

    /**
     * Retrive a User Representation based on email parameters
     *
     * @param userId : ID of user
     * @param token : JWT Token value
     * @return UserRepresentationDTO or null if error occured
     */
    @Override
    public UserRepresentationDTO retrieveUserById(String userId, String token) {
        try {
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Object> entity = new HttpEntity<>(headers);

            String requestUri = adminUri.concat("/users/").concat(userId);
            ResponseEntity<UserRepresentationDTO> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    UserRepresentationDTO.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null)
                return response.getBody();

            return null;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error retrieving user by id: {}, Response body: {}", e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during retrieving user by id", e);
        } catch (RestClientException | NoSuchElementException e) {
            log.error("Error during retrieving user by id: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieving user by id", e);
        }
    }

    /**
     * Create the MultiValueMap for HttpEntity
     * @param credentials : User Credentials (if exist)
     * @param refreshToken : Refresh Token (if exist)
     * @param headers : Http Headers
     * @return HttpEntity
     */
    private HttpEntity<MultiValueMap<String, String>> getMultiValueMapHttpEntity(CredentialsDTO credentials, String refreshToken, HttpHeaders headers) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        if (refreshToken == null) {
            body.add(CLIENT_ID, clientId);
            body.add(CLIENT_SECRET, clientSecret);
            body.add(USERNAME, credentials.getEmail());
            body.add(GRANT_TYPE_PASSWORD, credentials.getPassword());
            body.add(GRANT_TYPE, GRANT_TYPE_PASSWORD);
            body.add(SCOPE, PROTOCOL);
        } else {
            body.add(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
            body.add(GRANT_TYPE_REFRESH_TOKEN, refreshToken);
            body.add(CLIENT_ID, clientId);
            body.add(CLIENT_SECRET, clientSecret);
            body.add(SCOPE, PROTOCOL);
        }

        return new HttpEntity<>(body, headers);
    }

    /**
     * Assign async the realm role of a new user
     *
     * @param pilotRole : Realm Role
     * @param userId : ID of user
     * @return Void
     */
    @Async
    public CompletableFuture<Void> assignRealmRoles(String pilotRole, String userId, String token) {
        return CompletableFuture.runAsync(() -> {
            try{
                RoleRepresentationDTO roleRepr = findRoleRepresentationByUserRole(pilotRole, token);
                if (roleRepr == null) {
                    log.error("Unable to retrieve realm roles from Keycloak");
                    return;
                }

                // Set Headers
                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(token);
                headers.setContentType(MediaType.APPLICATION_JSON);

                HttpEntity<List<RoleRepresentationDTO>> entity = new HttpEntity<>(List.of(roleRepr), headers);

                String requestUri = adminUri.concat("/users/").concat(userId).concat("/role-mappings/realm");
                ResponseEntity<Object> response = restTemplate.exchange(
                        requestUri,
                        HttpMethod.POST,
                        entity,
                        Object.class
                );

                if (!response.getStatusCode().is2xxSuccessful())
                    log.error("Error assigning role mapping to user");
            } catch (HttpClientErrorException | HttpServerErrorException e) {
                log.error("HTTP error during assigning realm role for user with id {} : {}, Response body: {}", userId, e.getMessage(), e.getResponseBodyAsString(), e);
                throw new KeycloakException("HTTP error during  assigning realm role for user with id = ".concat(userId), e);
            } catch (RestClientException e) {
                log.error("Error during assigning realm role for user with id {} : {}", userId, e.getMessage(), e);
                throw new KeycloakException("Error during assigning realm role for user with id = ".concat(userId), e);
            }
        });
    }

    /**
     * Locate a Role Representation from Keycloak
     *
     * @param pilotRole: Realm role
     * @param token: JWT token value
     * @return RoleRepresentation if exists, otherwise null
     */
    private RoleRepresentationDTO findRoleRepresentationByUserRole(String pilotRole, String token){
        try{
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Object> entity = new HttpEntity<>(null, headers);

            String requestUri = adminUri.concat("/roles");
            ResponseEntity<List<RoleRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {
                    }
            );

            if(response.getStatusCode().is2xxSuccessful() && response.getBody() != null && !response.getBody().isEmpty()){
                return response.getBody().stream().filter(role -> role.getName().equals(pilotRole)).findFirst().orElse(null);
            }

            return null;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieving realm roles : {}, Response body: {}", e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during retrieving realm roles", e);
        } catch (RestClientException e) {
            log.error("Error during retrieving realm roles : {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieving realm roles", e);
        }
    }

    /**
     * Assign async the realm-management roles to implement additional functionality per user
     *
     * @param pilotRole : Realm Role
     * @param userId : ID of user
     * @return Void
     */
    @Async
    public CompletableFuture<Void> assignRealmManagementRoles(String pilotRole, String userId, String token) {
        return CompletableFuture.runAsync(() -> {
            try {
                // Locate client's id
                String clientID = findClientIdPerClient("realm-management", token);
                if(clientID == null)
                    return;

                List<RoleRepresentationDTO> realmManagementRoles = findRealmManagementRoleRepresentationDependingOnUserRole(pilotRole, clientID, token);
                if (realmManagementRoles.isEmpty()) {
                    return;
                }

                // Set Headers
                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(token);
                headers.setContentType(MediaType.APPLICATION_JSON);

                HttpEntity<List<RoleRepresentationDTO>> entity = new HttpEntity<>(realmManagementRoles, headers);

                String requestUri = adminUri.concat("/users/").concat(userId).concat("/role-mappings/clients/").concat(clientID);
                ResponseEntity<Object> response = restTemplate.exchange(
                        requestUri,
                        HttpMethod.POST,
                        entity,
                        Object.class
                );

                if (!response.getStatusCode().is2xxSuccessful())
                    log.error("Unable to set realm-management roles to specific user");
            } catch (HttpClientErrorException | HttpServerErrorException e) {
                log.error("HTTP error during retrieving realm management roles : {}, Response body: {}", e.getMessage(), e.getResponseBodyAsString(), e);
                throw new KeycloakException("HTTP error during retrieving realm management roles", e);
            } catch (RestClientException e) {
                log.error("Error during retrieving realm management roles : {}", e.getMessage(), e);
                throw new KeycloakException("Error during retrieving realm management roles", e);
            }
        });
    }

    /**
     * Logout user from Keycloak
     *
     * @param userId: User ID
     * @param token: JWT Token value
     * @return Void
     */
    @Override
    @Async
    public CompletableFuture<Void> logoutUser(String userId, String token) {
        return CompletableFuture.runAsync(() -> {
            try {
                // Set Headers
                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(token);
                headers.setContentType(MediaType.APPLICATION_JSON);

                HttpEntity<Object> entity = new HttpEntity<>(null, headers);

                String requestUri = adminUri.concat("/users/").concat(userId).concat("/logout");
                ResponseEntity<Object> response = restTemplate.exchange(
                        requestUri,
                        HttpMethod.POST,
                        entity,
                        Object.class
                );

                if (!response.getStatusCode().is2xxSuccessful())
                    log.error("Unable to logout user with id = ".concat(userId).concat(" from Keycloak"));
            } catch (HttpClientErrorException | HttpServerErrorException e) {
                log.error("HTTP error during logout of user : {}, Response body: {}", e.getMessage(), e.getResponseBodyAsString(), e);
                throw new KeycloakException("HTTP error during logout of user", e);
            } catch (RestClientException e) {
                log.error("Error during logout of user : {}", e.getMessage(), e);
                throw new KeycloakException("Error during logout of user", e);
            }
        });
    }

    /**
     * Retrieve all corresponding realm-management roles depending on user role
     *e
     * @param pilotRole: Pilot role
     * @param token: JWT token value
     * @return List<RoleRepresentation if successful, otherwise null
     */
    private List<RoleRepresentationDTO> findRealmManagementRoleRepresentationDependingOnUserRole(String pilotRole, String clientID, String token){
        try{
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<CredentialRepresentationDTO> entity = new HttpEntity<>(null, headers);

            String requestUri = adminUri.concat("/clients/").concat(clientID).concat("/roles");
            ResponseEntity<List<RoleRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );


            // Assign realm roles according to the Realm Role of User
            if(response.getStatusCode().is2xxSuccessful() && response.getBody() != null && !response.getBody().isEmpty()){
                if (pilotRole.equals(PilotRole.SUPER_ADMIN.toString()))
                    return response.getBody().stream().filter(role -> SUPER_ADMIN_ROLES_MANAGEMENT_ARRAY.stream()
                                    .anyMatch(superAdminRole -> superAdminRole.equalsIgnoreCase(role.getName())))
                                    .toList();
                else if (pilotRole.equals(PilotRole.USER.toString()))
                    return response.getBody().stream().filter(role -> USER_ROLES_MANAGEMENT_ARRAY.stream()
                                    .anyMatch(pilotRoleManagement -> pilotRoleManagement.equalsIgnoreCase(role.getName())))
                                    .toList();
                else if (pilotRole.equals(PilotRole.ADMIN.toString()))
                    return response.getBody().stream().filter(role -> ADMIN_ROLES_MANAGEMENT_ARRAY.stream()
                                .anyMatch(pilotRoleManagement -> pilotRoleManagement.equalsIgnoreCase(role.getName())))
                                .toList();
                else
                    return Collections.emptyList();
            }

            return Collections.emptyList();
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieving realm roles : {}, Response body: {}", e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during retrieving realm roles", e);
        } catch (RestClientException e) {
            log.error("Error during retrieving realm roles : {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieving realm roles", e);
        }
    }

    /**
     * Retrieve all corresponding realm-management roles depending on user role
     *e
     * @param client: Client's name
     * @param token: JWT token value
     * @return List<RoleRepresentation if successful, otherwise null
     */
    @Override
    public String findClientIdPerClient(String client, String token){
        try{
            // Set Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Object> entity = new HttpEntity<>(null, headers);

            String requestUri = adminUri.concat("/clients?clientId=").concat(client);
            ResponseEntity<List<ClientRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            if(response.getStatusCode().is2xxSuccessful() && response.getBody() != null && !response.getBody().isEmpty()){
                return Objects.requireNonNull(response.getBody().stream().findFirst().orElse(null)).getId();
            }

            return null;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during retrieving client's id : {}, Response body: {}", e.getMessage(), e.getResponseBodyAsString(), e);
            throw new KeycloakException("HTTP error during retrieving client's id", e);
        } catch (RestClientException e) {
            log.error("Error during retrieving client's id : {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieving client's id", e);
        }
    }
}