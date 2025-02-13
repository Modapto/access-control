package gr.atc.modapto.service;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

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
import gr.atc.modapto.dto.PasswordDTO;
import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.dto.keycloak.CredentialRepresentationDTO;
import gr.atc.modapto.dto.keycloak.RoleRepresentationDTO;
import gr.atc.modapto.dto.keycloak.UserRepresentationDTO;
import gr.atc.modapto.enums.PilotRole;
import gr.atc.modapto.exception.CustomExceptions.DataRetrievalException;
import gr.atc.modapto.exception.CustomExceptions.InvalidActivationAttributesException;
import gr.atc.modapto.exception.CustomExceptions.InvalidAuthenticationCredentialsException;
import gr.atc.modapto.exception.CustomExceptions.InvalidResetTokenAttributesException;
import gr.atc.modapto.exception.CustomExceptions.KeycloakException;
import gr.atc.modapto.exception.CustomExceptions.ResourceAlreadyExistsException;
import gr.atc.modapto.exception.CustomExceptions.UserActivateStatusException;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class UserManagerService implements IUserManagerService {

  @Value("${keycloak.token-uri}")
  private String tokenUri;

  @Value("${keycloak.admin.uri}")
  private String adminUri;

  @Value("${keycloak.client-id}")
  private String clientName;

  @Value("${keycloak.client-secret}")
  private String clientSecret;

  @Value("${keycloak.api.user-path:/users}")
  private String userPath;

  private final RestTemplate restTemplate = new RestTemplate();

  private final KeycloakSupportService keycloakSupportService;

  private final IEmailService emailService;

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
  private static final String ACTIVATION_TOKEN = "activation_token";
  private static final String ACTIVATION_EXPIRY = "activation_expiry";
  private static final String RESET_TOKEN = "reset_token";
  private static final String ERROR_MESSAGE_FIELD = "errorMessage";

  // Arrays of realm-manage roles
  // Arrays of realm-manage roles
  private static final String REALM_MANAGEMENT_CLIENT = "realm-management";
  private static final String REALM_CLIENT = "realm";
  private static final String VIEW_USERS = "view-users";
  private static final String MANAGE_USERS = "manage-users";
  private static final String QUERY_USERS = "query-users";
  private static final String QUERY_REALMS = "query-realms";
  private static final String MANAGE_CLIENTS = "manage-clients";
  private static final String QUERY_CLIENTS = "query-clients";
  private static final String VIEW_CLIENTS = "view-clients";
  private static final String QUERY_GROUPS = "query-groups";
  private static final String MANAGE_REALM = "manage-groups";
  private static final String VIEW_REALM = "view-groups";
  private static final String MANAGE_AUTHORIZATION = "manage-authorization";

  private static final List<String> USER_ROLES_MANAGEMENT_ARRAY =
      List.of(MANAGE_USERS, QUERY_USERS, VIEW_USERS, VIEW_CLIENTS, QUERY_CLIENTS, QUERY_GROUPS, VIEW_REALM, QUERY_REALMS);
  private static final List<String> ADMIN_ROLES_MANAGEMENT_ARRAY =
      List.of(QUERY_REALMS, MANAGE_CLIENTS, MANAGE_USERS, QUERY_USERS, MANAGE_AUTHORIZATION,
          VIEW_USERS, QUERY_CLIENTS, VIEW_CLIENTS, QUERY_GROUPS, MANAGE_REALM, VIEW_REALM);
  private static final List<String> SUPER_ADMIN_ROLES_MANAGEMENT_ARRAY =
      List.of(QUERY_REALMS, MANAGE_REALM, MANAGE_CLIENTS, "realm-admin", MANAGE_USERS,
          QUERY_USERS, MANAGE_AUTHORIZATION, "view-identity-providers", VIEW_USERS, QUERY_CLIENTS,
          VIEW_CLIENTS, QUERY_GROUPS, "view-events", "view-authorization", VIEW_REALM);
          
  public UserManagerService(KeycloakSupportService keycloakSupportService,
      IEmailService emailService) {
    this.keycloakSupportService = keycloakSupportService;
    this.emailService = emailService;
  }

  /**
   * Authenticate the User Credentials in Keycloak and return Token Used also to refresh user's
   * token
   *
   * @param refreshToken Token to refresh user's token (Null if not applicable)
   * @param credentials User email and password
   * @return AuthenticationResponseDTO
   */
  @Override
  public AuthenticationResponseDTO authenticate(CredentialsDTO credentials, String refreshToken) {
    try {
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

      HttpEntity<MultiValueMap<String, String>> entity =
          getMultiValueMapHttpEntity(credentials, refreshToken, headers);

      ResponseEntity<Map<String, Object>> response = restTemplate.exchange(tokenUri,
          HttpMethod.POST, entity, new ParameterizedTypeReference<>() {});

      if (response.getStatusCode().is2xxSuccessful()) {
        Map<String, Object> responseBody = response.getBody();
        if (responseBody == null || responseBody.get(TOKEN) == null) {
          return null;
        }

        return AuthenticationResponseDTO.builder().accessToken((String) responseBody.get(TOKEN))
            .expiresIn((Integer) responseBody.get("expires_in"))
            .tokenType((String) responseBody.get("token_type"))
            .refreshToken((String) responseBody.get(GRANT_TYPE_REFRESH_TOKEN))
            .refreshExpiresIn((Integer) responseBody.get("refresh_expires_in")).build();
      }

      // Return null object
      return null;
    } catch (HttpServerErrorException e) {
      log.error("HTTP server error during authentication process: {}, Response body: {}",
          e.getMessage(), e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP server error during authentication process", e);
    } catch (RestClientException e) {
      log.error("Unable to retrieve token information from Keycloak. Error: {}", e.getMessage());
      throw new InvalidAuthenticationCredentialsException(
          "Unable to retrieve token information from Keycloak");
    }
  }

  /**
   * Create a new user in Keycloak
   *
   * @param user : Data about the new user to create
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

      HttpEntity<UserRepresentationDTO> entity =
          new HttpEntity<>(UserRepresentationDTO.toUserRepresentationDTO(user, null), headers);

      String requestUri = adminUri.concat(userPath);
      ResponseEntity<Map<String, Object>> response = restTemplate.exchange(requestUri,
          HttpMethod.POST, entity, new ParameterizedTypeReference<>() {});

      if (response.getStatusCode().is2xxSuccessful()) {
        // Extract the user ID from the Location header
        String location = Objects.requireNonNull(response.getHeaders().getLocation()).toString();
        return location.substring(location.lastIndexOf("/") + 1);
      }

      return null;
    } catch (HttpServerErrorException e) {
      log.error("HTTP server error during user creation: {}, Response body: {}", e.getMessage(),
          e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP sever error during user creation", e);
    } catch (HttpClientErrorException e) {
      Map<String, Object> responseBody = e.getResponseBodyAs(new ParameterizedTypeReference<>() {});
      if (responseBody != null && responseBody.containsKey(ERROR_MESSAGE_FIELD)) {
        throw new ResourceAlreadyExistsException(responseBody.get(ERROR_MESSAGE_FIELD).toString());
      }
      throw new ResourceAlreadyExistsException(e.getResponseBodyAsString());
    } catch (RestClientException e) {
      log.error("Error during user creation: {}", e.getMessage(), e);
      throw new KeycloakException("Error during user creation", e);
    }
  }

  /**
   * Update an existing user in Keycloak
   *
   * @param user : Data about the user to update
   * @param token : JWT Token Value
   * @return True on success, False on error
   */
  @Override
  public boolean updateUser(UserDTO user, String userId, String token) {
    try {
      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(token);
      headers.setContentType(MediaType.APPLICATION_JSON);

      // Retrieve the User Representation from Keycloak if exits
      UserRepresentationDTO existingUser = retrieveUserById(userId, token);
      if (existingUser == null)
        return false;

      HttpEntity<UserRepresentationDTO> entity = new HttpEntity<>(
          UserRepresentationDTO.toUserRepresentationDTO(user, existingUser), headers);

      String requestUri = adminUri.concat(userPath).concat("/").concat(userId);
      ResponseEntity<Object> response =
          restTemplate.exchange(requestUri, HttpMethod.PUT, entity, Object.class);

      return response.getStatusCode().is2xxSuccessful();
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during changing password of user with id {} : {}, Response body: {}",
          userId, e.getMessage(), e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error during retrieving user with id = ".concat(userId), e);
    } catch (RestClientException e) {
      log.error("Error during changing password of user with id {} : {}", userId, e.getMessage(),
          e);
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
  public List<UserDTO> fetchUsers(String token, String pilot) {
    try {
      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(token);
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri = adminUri.concat(userPath);
      ResponseEntity<List<UserRepresentationDTO>> response = restTemplate.exchange(requestUri,
          HttpMethod.GET, entity, new ParameterizedTypeReference<>() {});

      // Parse response
      return Optional.of(response).filter(r -> r.getStatusCode().is2xxSuccessful())
          .map(ResponseEntity::getBody).filter(body -> !body.isEmpty())
          .map(body -> body.stream().map(UserRepresentationDTO::toUserDTO)
              .filter(user -> "ALL".equals(pilot) || pilot.equals(user.getPilotCode().toString()))
              .toList())
          .orElse(Collections.emptyList());
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during retrieving users: {}, Response body: {}", e.getMessage(),
          e.getResponseBodyAsString(), e);
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

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri = adminUri.concat("/users/").concat(userId);
      ResponseEntity<UserRepresentationDTO> response = restTemplate.exchange(requestUri,
          HttpMethod.GET, entity, UserRepresentationDTO.class);

      // Parse response
      return Optional.of(response).filter(resp -> resp.getStatusCode().is2xxSuccessful())
          .map(ResponseEntity::getBody)
          .map(UserRepresentationDTO::toUserDTO)
          .orElse(null);
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during retrieving specific user with id {} : {}, Response body: {}",
          userId, e.getMessage(), e.getResponseBodyAsString(), e);
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

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri = adminUri.concat(userPath).concat("/").concat(userId);
      ResponseEntity<List<UserRepresentationDTO>> response = restTemplate.exchange(requestUri,
          HttpMethod.DELETE, entity, new ParameterizedTypeReference<>() {});

      return response.getStatusCode().is2xxSuccessful();
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during retrieving specific user with id {} : {}, Response body: {}",
          userId, e.getMessage(), e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error during deleting user with id = ".concat(userId), e);
    } catch (RestClientException e) {
      log.error("Error during retrieving specific user with id {} : {}", userId, e.getMessage(), e);
      throw new KeycloakException("Error during deleting user with id = ".concat(userId), e);
    }
  }

  /**
   * Change user's password in Keycloak
   *
   * @param passwords : Current and New Password
   * @param token : JWT Token Value
   * @return True on success, False on error
   */
  @Override
  public AuthenticationResponseDTO changePassword(PasswordDTO passwords, String userId,
      String token) {
    // Validate that current user's password match with the given one - Try locating him and then
    // try authenticate him
    UserRepresentationDTO user = retrieveUserById(userId, token);
    if (user == null)
      throw new DataRetrievalException("User with this ID not found in Keycloak");

    // If user can not authenticate with given current password then throw error
    AuthenticationResponseDTO userAuthentication =
        authenticate(new CredentialsDTO(user.getEmail(), passwords.getCurrentPassword()), null);
    if (userAuthentication == null)
      throw new DataRetrievalException("Provided current password is not correct");

    // Set the new Password
    CredentialRepresentationDTO credentials = CredentialRepresentationDTO.builder().temporary(false)
        .type(GRANT_TYPE_PASSWORD).value(passwords.getNewPassword()).build();
    try {
      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(userAuthentication.getAccessToken());
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<CredentialRepresentationDTO> entity = new HttpEntity<>(credentials, headers);

      String requestUri =
          adminUri.concat(userPath).concat("/").concat(userId).concat("/reset-password");
      ResponseEntity<Object> response =
          restTemplate.exchange(requestUri, HttpMethod.PUT, entity, Object.class);

      // Parse response
      return Optional.of(response).filter(resp -> resp.getStatusCode().is2xxSuccessful())
          .map(resp -> userAuthentication).orElse(null);
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during changing password of user with id {} : {}, Response body: {}",
          userId, e.getMessage(), e.getResponseBodyAsString(), e);
      throw new KeycloakException(
          "HTTP error during changing password of user with id = ".concat(userId), e);
    } catch (RestClientException e) {
      log.error("Error during changing password of user with id {} : {}", userId, e.getMessage(),
          e);
      throw new KeycloakException(
          "Error during changing password of user with id = ".concat(userId), e);
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

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri = adminUri.concat("/users?email=").concat(email);
      ResponseEntity<List<UserRepresentationDTO>> response = restTemplate.exchange(requestUri,
          HttpMethod.GET, entity, new ParameterizedTypeReference<>() {});

      // Parse response
      return Optional.of(response).filter(resp -> resp.getStatusCode().is2xxSuccessful())
          .map(ResponseEntity::getBody).filter(body ->!body.isEmpty())
          .map(List::getFirst).orElse(null);
    } catch (HttpServerErrorException e) {
      log.error("HTTP error retrieving user by email: {}, Response body: {}", e.getMessage(),
          e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error during retrieving user by email", e);
    } catch (HttpClientErrorException e) {
      Map<String, Object> responseBody = e.getResponseBodyAs(new ParameterizedTypeReference<>() {});
      if (responseBody != null && responseBody.containsKey(ERROR_MESSAGE_FIELD)) {
        throw new DataRetrievalException(responseBody.get(ERROR_MESSAGE_FIELD).toString());
      }
      throw new DataRetrievalException("User with this email not found in Keycloak");
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

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri = adminUri.concat(userPath).concat("/").concat(userId);
      ResponseEntity<UserRepresentationDTO> response =
          restTemplate.exchange(requestUri, HttpMethod.GET, entity, UserRepresentationDTO.class);

      if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null)
        return response.getBody();

      return null;
    } catch (HttpServerErrorException e) {
      log.error("HTTP error retrieving user by id: {}, Response body: {}", e.getMessage(),
          e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error during retrieving user by id", e);
    } catch (HttpClientErrorException e) {
      Map<String, Object> responseBody = e.getResponseBodyAs(new ParameterizedTypeReference<>() {});
      if (responseBody != null && responseBody.containsKey(ERROR_MESSAGE_FIELD)) {
        throw new DataRetrievalException(responseBody.get(ERROR_MESSAGE_FIELD).toString());
      }
      throw new DataRetrievalException("User with this ID not found in Keycloak");
    } catch (RestClientException | NoSuchElementException e) {
      log.error("Error during retrieving user by id: {}", e.getMessage(), e);
      throw new KeycloakException("Error during retrieving user by id", e);
    }
  }

  /**
   * Create the MultiValueMap for HttpEntity
   * 
   * @param credentials : User Credentials (if exist)
   * @param refreshToken : Refresh Token (if exist)
   * @param headers : Http Headers
   * @return HttpEntity
   */
  private HttpEntity<MultiValueMap<String, String>> getMultiValueMapHttpEntity(
      CredentialsDTO credentials, String refreshToken, HttpHeaders headers) {
    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
    if (refreshToken == null) {
      body.add(CLIENT_ID, clientName);
      body.add(CLIENT_SECRET, clientSecret);
      body.add(USERNAME, credentials.getEmail());
      body.add(GRANT_TYPE_PASSWORD, credentials.getPassword());
      body.add(GRANT_TYPE, GRANT_TYPE_PASSWORD);
      body.add(SCOPE, PROTOCOL);
    } else {
      body.add(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
      body.add(GRANT_TYPE_REFRESH_TOKEN, refreshToken);
      body.add(CLIENT_ID, clientName);
      body.add(CLIENT_SECRET, clientSecret);
      body.add(SCOPE, PROTOCOL);
    }

    return new HttpEntity<>(body, headers);
  }

  /**
   * Call functions to assign roles to user
   * 
   * @param newUserDetails : User details
   * @param existingUserDetails : User Representation
   * @param userId : User ID
   * @param token : JWT Token value
   */
  @Override
  @Async("asyncPoolTaskExecutor")
  public CompletableFuture<Void> assignRolesToUser(UserDTO newUserDetails,
      UserDTO existingUserDetails, String userId, String token) {
    return CompletableFuture.runAsync(() -> {
      // Trigger role assignments depending on use cases (Creation or Update)
      if (existingUserDetails == null) {
        // Assign Realm Role
        assignRealmRoles(newUserDetails.getPilotRole().toString().toUpperCase(), userId, token);

        // Assign Client Role
        assignClientRole(newUserDetails.getUserRole().toUpperCase(), userId, token);

        // Assign Realm-Management Roles
        assignRealmManagementRoles(newUserDetails.getPilotRole().toString().toUpperCase(), userId,
            token);
      } else {
        boolean updatedPilotRole = false;

        // Update Case
        if (newUserDetails.getPilotRole() != null && (existingUserDetails.getPilotRole() != null
            && newUserDetails.getPilotRole() != existingUserDetails.getPilotRole()))
          // Assign Realm Role
          updatedPilotRole =
              assignRealmRoles(newUserDetails.getPilotRole().toString().toUpperCase(), userId, token);

        if (newUserDetails.getUserRole() != null && (existingUserDetails.getUserRole() != null
            && !newUserDetails.getUserRole().equals(existingUserDetails.getUserRole())))
          // Assign Client Role
          assignClientRole(newUserDetails.getUserRole().toUpperCase(), userId, token);

        // Assign Realm-Management Roles
        if (updatedPilotRole)
          assignRealmManagementRoles(newUserDetails.getPilotRole().toString().toUpperCase(), userId,
              token);
      }
    });
  }


  /**
   * Function to assign Realm Role to user
   *
   * @param newPilotRole : New Realm Role
   * @param userId : ID of user
   * @param token : JWT Token
   * @return True on Success, False on Error
   */
  @Override
  public boolean assignRealmRoles(String newPilotRole, String userId, String token) {
    try {
      // Locate the User
      UserRepresentationDTO user = retrieveUserById(userId, token);
      if (user == null)
        return false;

      // Delete old realm roles if available
      if (!deleteUserRealmRoles(user, token))
        return false;

      // Locate the Role Representation
      RoleRepresentationDTO roleRepr = findRealmRoleRepresentationByRoleName(newPilotRole, token);
      if (roleRepr == null) {
        log.error("Unable to retrieve realm roles from Keycloak");
        return false;
      }

      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(token);
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<List<RoleRepresentationDTO>> entity = new HttpEntity<>(List.of(roleRepr), headers);

      String requestUri = adminUri.concat(userPath).concat("/").concat(userId)
          .concat("/role-mappings/").concat(REALM_CLIENT);
      ResponseEntity<Object> response =
          restTemplate.exchange(requestUri, HttpMethod.POST, entity, Object.class);

      return response.getStatusCode().is2xxSuccessful();
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error(
          "HTTP error during assigning realm role for user with id {} : {}, Response body: {}",
          userId, e.getMessage(), e.getResponseBodyAsString(), e);
      throw new KeycloakException(
          "HTTP error during  assigning realm role for user with id = ".concat(userId), e);
    } catch (RestClientException e) {
      log.error("Error during assigning realm role for user with id {} : {}", userId,
          e.getMessage(), e);
      throw new KeycloakException(
          "Error during assigning realm role for user with id = ".concat(userId), e);
    }
  }

  /**
   * Locate a Role Representation from Keycloak
   *
   * @param pilotRole: Realm role
   * @param token: JWT token value
   * @return RoleRepresentation if exists, otherwise null
   */
  private RoleRepresentationDTO findRealmRoleRepresentationByRoleName(String pilotRole, String token) {
    try {
      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(token);
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri = adminUri.concat("/roles");
      ResponseEntity<List<RoleRepresentationDTO>> response = restTemplate.exchange(requestUri,
          HttpMethod.GET, entity, new ParameterizedTypeReference<>() {});

      // Parse Response
      return Optional.of(response).filter(resp -> resp.getStatusCode().is2xxSuccessful())
              .map(ResponseEntity::getBody).flatMap(body -> body.stream()
                      .filter(role -> role.getName().equals(pilotRole)).findFirst())
          .orElse(null);
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during retrieving realm roles : {}, Response body: {}", e.getMessage(),
          e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error during retrieving realm roles", e);
    } catch (RestClientException e) {
      log.error("Error during retrieving realm roles : {}", e.getMessage(), e);
      throw new KeycloakException("Error during retrieving realm roles", e);
    }
  }

  /**
   * Assign realm-management roles to enable users access resources of Keycloak
   *
   * @param pilotRole : Realm Role
   * @param userId : ID of user
   * @param token : JWT Token
   * @return True on Success, False on Error
   */
  @Override
  public boolean assignRealmManagementRoles(String pilotRole, String userId, String token) {
    try {
      // Locate the User
      UserRepresentationDTO user = retrieveUserById(userId, token);
      if (user == null)
        return false;

      // Delete old realm roles if available
      if (!deleteUserRoleMappingsByClient(user, REALM_MANAGEMENT_CLIENT, token))
        return false;

      // Locate client's id
      String clientID = keycloakSupportService.retrieveClientId(token, REALM_MANAGEMENT_CLIENT);
      if (clientID == null)
        return false;

      List<RoleRepresentationDTO> realmManagementRoles =
          findRealmManagementRoleRepresentationDependingOnPilotRole(pilotRole, clientID, token);
      if (realmManagementRoles.isEmpty()) {
        return false;
      }

      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(token);
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<List<RoleRepresentationDTO>> entity =
          new HttpEntity<>(realmManagementRoles, headers);

      String requestUri = adminUri.concat(userPath).concat("/").concat(userId)
          .concat("/role-mappings/clients/").concat(clientID);
      ResponseEntity<Object> response =
          restTemplate.exchange(requestUri, HttpMethod.POST, entity, Object.class);

      return response.getStatusCode().is2xxSuccessful();
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during retrieving realm management roles : {}, Response body: {}",
          e.getMessage(), e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error during retrieving realm management roles", e);
    } catch (RestClientException e) {
      log.error("Error during retrieving realm management roles : {}", e.getMessage(), e);
      throw new KeycloakException("Error during retrieving realm management roles", e);
    }
  }

  /**
   * Assign a client role to a user
   * 
   * @param userRole : Client Role
   * @param userId : ID of user
   * @param token : JWT Token
   * @return True on Success, False on Error
   */
  @Override
  public boolean assignClientRole(String userRole, String userId, String token) {
    try {
      // Locate the User
      UserRepresentationDTO user = retrieveUserById(userId, token);
      if (user == null)
        return false;

      // Delete old realm roles if available
      if (!deleteUserRoleMappingsByClient(user, clientName, token))
        return false;

      // Locate client's id
      String clientID = keycloakSupportService.getClientId();
      if (clientID == null)
        return false;

      // Locate client role representation
      RoleRepresentationDTO clientRole =
          keycloakSupportService.findRoleRepresentationByNameAndClient(userRole, clientID, token);
      if (clientRole == null) {
        return false;
      }

      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(token);
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<List<RoleRepresentationDTO>> entity =
          new HttpEntity<>(List.of(clientRole), headers);

      String requestUri = adminUri.concat(userPath).concat("/").concat(userId)
          .concat("/role-mappings/clients/").concat(clientID);
      ResponseEntity<Object> response =
          restTemplate.exchange(requestUri, HttpMethod.POST, entity, Object.class);

      return response.getStatusCode().is2xxSuccessful();
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during retrieving client roles : {}, Response body: {}", e.getMessage(),
          e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error during retrieving client roles", e);
    } catch (RestClientException e) {
      log.error("Error during retrieving client roles : {}", e.getMessage(), e);
      throw new KeycloakException("Error during retrieving client roles", e);
    }
  }

  /**
   * Logout user from Keycloak
   *
   * @param userId: User ID
   * @param token: JWT Token value
   * @return Void
   */
  @Override
  @Async("asyncPoolTaskExecutor")
  public CompletableFuture<Void> logoutUser(String userId, String token) {
    return CompletableFuture.runAsync(() -> {
      try {
        // Set Headers
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        String requestUri = adminUri.concat(userPath).concat("/").concat(userId).concat("/logout");
        ResponseEntity<Object> response =
            restTemplate.exchange(requestUri, HttpMethod.POST, entity, Object.class);

        if (!response.getStatusCode().is2xxSuccessful())
          log.error("Unable to logout user with id = ".concat(userId).concat(" from Keycloak"));
      } catch (HttpClientErrorException | HttpServerErrorException e) {
        log.error("HTTP error during logout of user : {}, Response body: {}", e.getMessage(),
            e.getResponseBodyAsString(), e);
        throw new KeycloakException("HTTP error during logout of user", e);
      } catch (RestClientException e) {
        log.error("Error during logout of user : {}", e.getMessage(), e);
        throw new KeycloakException("Error during logout of user", e);
      }
    });
  }

  /**
   * Retrieve all users with a specific user role from Keycloak
   *
   * @param userRole: Client Role
   * @param tokenValue: JWT Token value
   * @return List<UserDTO>
   */
  @Override
  public List<UserDTO> fetchUsersByRole(String userRole, String tokenValue) {
    try {
      String clientID = keycloakSupportService.getClientId();
      if (clientID == null)
        throw new DataRetrievalException("Unable to locate requested client ID in Keycloak");

      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(tokenValue);
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri = adminUri.concat("/clients/").concat(clientID).concat("/roles/")
          .concat(userRole).concat(userPath);
      ResponseEntity<List<UserRepresentationDTO>> response = restTemplate.exchange(requestUri,
          HttpMethod.GET, entity, new ParameterizedTypeReference<>() {});

      // Parse Response
      return Optional.of(response).filter(resp -> resp.getStatusCode().is2xxSuccessful())
          .map(ResponseEntity::getBody)
          .map(body -> body.stream().map(UserRepresentationDTO::toUserDTO).toList())
          .orElse(Collections.emptyList());
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during retrieval of user per role : {}, Response body: {}",
          e.getMessage(), e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error retrieval of user per role", e);
    } catch (RestClientException e) {
      log.error("Error during retrieval of user per role : {}", e.getMessage(), e);
      throw new KeycloakException("Error during retrieval of user per role", e);
    }
  }

  /**
   * Retrieve all users from a specifi pilot from Keycloak
   *
   * @param pilotCode: Pilot Code
   * @param tokenValue: JWT Token value
   * @return List<UserDTO>
   */
  @Override
  public List<UserDTO> fetchUsersByPilotCode(String pilotCode, String tokenValue) {
    try {
      String groupId = keycloakSupportService.retrievePilotCodeID(pilotCode, tokenValue);
      if (groupId == null)
        throw new DataRetrievalException("Unable to locate requested group ID in Keycloak");

      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(tokenValue);
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri = adminUri.concat("/groups/").concat(groupId).concat("/members");
      ResponseEntity<List<UserRepresentationDTO>> response = restTemplate.exchange(requestUri,
          HttpMethod.GET, entity, new ParameterizedTypeReference<>() {});

      // Parse Response
      return Optional.of(response).filter(resp -> resp.getStatusCode().is2xxSuccessful())
          .map(ResponseEntity::getBody)
          .map(body -> body.stream().map(UserRepresentationDTO::toUserDTO).toList())
          .orElse(Collections.emptyList());
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error retrieval of user per pilot : {}, Response body: {}", e.getMessage(),
          e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error during retrieval of user per pilot", e);
    } catch (RestClientException e) {
      log.error("Error during retrieval of user per pilot : {}", e.getMessage(), e);
      throw new KeycloakException("Error during retrieval of user per pilot", e);
    }
  }

  /**
   * Activate user account by updating the information on the user
   *
   * @param userId : User ID
   * @param activationToken : Activation token automatically stored and generated in the user
   * @param password : User's password
   * @return True on success, False on Error
   */
  @Override
  public boolean activateUser(String userId, String activationToken, String password) {
    // Request token to access client
    String token = keycloakSupportService.retrieveComponentJwtToken();
    if (token == null)
      return false;

    // Retrieve the User Representation from Keycloak
    UserRepresentationDTO existingUser = retrieveUserById(userId, token);
    if (existingUser == null)
      return false;

    // Validate that user is inactive otherwise throw an exception
    if (existingUser.isEnabled()) {
      throw new UserActivateStatusException("User is already active");
    }

    // Validate the activation token and its expiry
    // - Ensure that both ACTIVATION_TOKEN and ACTIVATION_EXPIRY attributes exist in the user's
    // attributes.
    // - Verify that the ACTIVATION_TOKEN matches the provided activationToken.
    // - Check that the ACTIVATION_EXPIRY time has not passed.
    if (existingUser.getAttributes() == null
        || !existingUser.getAttributes().containsKey(ACTIVATION_EXPIRY)
        || !existingUser.getAttributes().containsKey(ACTIVATION_TOKEN)
        || !existingUser.getAttributes().get(ACTIVATION_TOKEN).getFirst().equals(activationToken)
        || existingUser.getAttributes().get(ACTIVATION_EXPIRY).getFirst()
            .compareTo(String.valueOf(System.currentTimeMillis())) < 0) {
      // If any condition is not met, throw an exception
      throw new InvalidActivationAttributesException(
          "Invalid activation token or activation expiry has passed. Please contact the admin of your organization.");
    }

    // Create a User DTO element and set the password
    UserDTO user = new UserDTO();
    user.setPassword(password);
    user.setTokenFlagRaised(true);
    user.setActivationToken(activationToken);

    // Update User's information
    return updateUser(user, userId, token);
  }

  /**
   * Forget password business logic to formulate reset token and send email to User
   * 
   * @param email : Email Address
   */
  @Override
  public void forgotPassword(String email) {
    // Retrieve client token
    String tempJWTToken = keycloakSupportService.retrieveComponentJwtToken();

    // Locate the user if exists
    UserRepresentationDTO existingUser = retrieveUserByEmail(email, tempJWTToken);
    if (existingUser == null)
      throw new DataRetrievalException("User with this email does not exist in Keycloak");

    // Retrieve the UserDTO
    UserDTO user = UserRepresentationDTO.toUserDTO(existingUser);

    // Validate that user is active otherwise throw an exception
    if (!existingUser.isEnabled()) {
      throw new UserActivateStatusException("User is not activated. Password can not be reset");
    }

    // Formulate reset token
    user.setResetToken(UUID.randomUUID().toString());
    user.setTokenFlagRaised(false);
    String resetToken = user.getUserId().concat("@").concat(user.getResetToken());

    // Update user with the addition of reset token
    updateUser(user, user.getUserId(), tempJWTToken);

    // Send email async
    emailService.sendResetPasswordLink(user.getUsername(), email, resetToken);
  }

  /**
   * Reset password business logic to validate reset token and change user's password
   * 
   * @param userId : User ID retrieved from Token
   * @param resetToken : Reset Token retrieved from Token
   * @param password : New Password
   * @return True on Success, False on Error
   */
  @Override
  public boolean resetPassword(String userId, String resetToken, String password) {
    // Request token to access client
    String token = keycloakSupportService.retrieveComponentJwtToken();
    if (token == null)
      return false;

    // Retrieve the User Representation from Keycloak
    UserRepresentationDTO existingUser = retrieveUserById(userId, token);
    if (existingUser == null)
      return false;

    // Validate that user is active otherwise throw an exception
    if (!existingUser.isEnabled()) {
      throw new UserActivateStatusException("User is not activated. Password can not be reset");
    }

    // Validate that user contains reset token field
    if (existingUser.getAttributes() == null
        || !existingUser.getAttributes().containsKey(RESET_TOKEN)
        || !existingUser.getAttributes().get(RESET_TOKEN).getFirst().equals(resetToken))
      // If any condition is not met, throw an exception
      throw new InvalidResetTokenAttributesException(
          "Reset token is wrong or there is no reset token for specific user. Please contact the admin of your organization");

    // Update user's password
    UserDTO user = new UserDTO();
    user.setPassword(password);
    user.setResetToken(resetToken);
    user.setTokenFlagRaised(true);

    return updateUser(user, userId, token);
  }

  /**
   * Retrieve all corresponding realm-management roles depending on pilot role e
   * 
   * @param pilotRole: Pilot role
   * @param token: JWT token value
   * @return List<RoleRepresentation if successful, otherwise null
   */
  private List<RoleRepresentationDTO> findRealmManagementRoleRepresentationDependingOnPilotRole(
      String pilotRole, String realmManagementClientID, String token) {
    try {
      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(token);
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri =
          adminUri.concat("/clients/").concat(realmManagementClientID).concat("/roles");
      ResponseEntity<List<RoleRepresentationDTO>> response = restTemplate.exchange(requestUri,
          HttpMethod.GET, entity, new ParameterizedTypeReference<>() {});

      // Assign realm roles according to the Realm Role of User
      if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null
          && !response.getBody().isEmpty()) {
        if (pilotRole.equalsIgnoreCase(PilotRole.SUPER_ADMIN.toString()))
          return response.getBody().stream()
              .filter(role -> SUPER_ADMIN_ROLES_MANAGEMENT_ARRAY.stream()
                  .anyMatch(superAdminRole -> superAdminRole.equalsIgnoreCase(role.getName())))
              .toList();
        else if (pilotRole.equalsIgnoreCase(PilotRole.USER.toString()))
          return response.getBody().stream()
              .filter(role -> USER_ROLES_MANAGEMENT_ARRAY.stream().anyMatch(
                  pilotRoleManagement -> pilotRoleManagement.equalsIgnoreCase(role.getName())))
              .toList();
        else if (pilotRole.equalsIgnoreCase(PilotRole.ADMIN.toString()))
          return response.getBody().stream()
              .filter(role -> ADMIN_ROLES_MANAGEMENT_ARRAY.stream().anyMatch(
                  pilotRoleManagement -> pilotRoleManagement.equalsIgnoreCase(role.getName())))
              .toList();
        else
          return Collections.emptyList();
      }

      return Collections.emptyList();
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during retrieving realm roles : {}, Response body: {}", e.getMessage(),
          e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error during retrieving realm roles", e);
    } catch (RestClientException e) {
      log.error("Error during retrieving realm roles : {}", e.getMessage(), e);
      throw new KeycloakException("Error during retrieving realm roles", e);
    }
  }

  /**
   * Delete User's Role Mappings for a Specified Client
   * 
   * @param existingUser : User Representation in Keycloak
   * @param client : Client Name
   * @token : JWT Token Value
   * @return True on Success, False on Error
   */
  private boolean deleteUserRoleMappingsByClient(UserRepresentationDTO existingUser, String client,
      String token) {
    try {
      // Retrieve Client ID
      String clientID = keycloakSupportService.retrieveClientId(token, client);
      if (clientID == null)
        return false;

      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(token);
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri = adminUri.concat(userPath).concat("/").concat(existingUser.getId())
          .concat("/role-mappings/clients/").concat(clientID);
      ResponseEntity<Object> response =
          restTemplate.exchange(requestUri, HttpMethod.DELETE, entity, Object.class);

      // Return true if successful - Parse response
      return Optional.of(response).filter(resp -> resp.getStatusCode().is2xxSuccessful())
          .map(resp -> true).orElse(false);
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during deleting user's role mappings : {}, Response body: {}",
          e.getMessage(), e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP server error during deleting user's role mappings", e);
    } catch (RestClientException e) {
      log.error("Error during during deleting user's role mappings : {}", e.getMessage(), e);
      throw new KeycloakException("Error during during deleting user's role mappings", e);
    }
  }

  /**
   * Delete User's Realm Role
   * 
   * @param existingUser : User Representation in Keycloak
   * @param token : JWT Token Value
   * @return True on Success, False on Error
   */
  private boolean deleteUserRealmRoles(UserRepresentationDTO existingUser, String token) {
    try {
      // Set Headers
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(token);
      headers.setContentType(MediaType.APPLICATION_JSON);

      HttpEntity<Void> entity = new HttpEntity<>(headers);

      String requestUri = adminUri.concat(userPath).concat("/").concat(existingUser.getId())
          .concat("/role-mappings/realm");
      ResponseEntity<Object> response =
          restTemplate.exchange(requestUri, HttpMethod.DELETE, entity, Object.class);

      // Return true if successful - Parse response
      return Optional.of(response).filter(resp -> resp.getStatusCode().is2xxSuccessful())
          .map(resp -> true).orElse(false);
    } catch (HttpClientErrorException | HttpServerErrorException e) {
      log.error("HTTP error during deleting user's realm role : {}, Response body: {}",
          e.getMessage(), e.getResponseBodyAsString(), e);
      throw new KeycloakException("HTTP error during deleting user's realm role", e);
    } catch (RestClientException e) {
      log.error("Error during during deleting user's realm role : {}", e.getMessage(), e);
      throw new KeycloakException("Error during during deleting user's realm role", e);
    }
  }
}
