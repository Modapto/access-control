package gr.atc.modapto.service;

import gr.atc.modapto.dto.AuthenticationResponseDTO;
import gr.atc.modapto.dto.CredentialsDTO;
import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.dto.keycloak.ClientRepresentationDTO;
import gr.atc.modapto.dto.keycloak.RoleRepresentationDTO;
import gr.atc.modapto.dto.keycloak.UserRepresentationDTO;
import gr.atc.modapto.exception.CustomExceptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserManagerServiceTests {

  @Value("${test.user.email}")
  private static String testUserEmail;

  @Value("${test.user.password}")
  private static String testUserPassword;

  @Mock
  private RestTemplate restTemplate;

  @Mock
  private KeycloakSupportService keycloakSupportService;

  @InjectMocks
  private UserManagerService userManagerService;

  private CredentialsDTO credentials;
  private UserRepresentationDTO userRepresentation;

  private static final String MOCK_TOKEN = "mock-token";
  private static final String MOCK_EMAIL = "mockemail@test.com";
  private static final String MOCK_ADMIN_URI = "http://mock-admin-uri";
  private static final String MOCK_TOKEN_URI = "http://mock-token-uri";
  private static final String MOCK_CLIENT_ID = "mock-client";
  private static final String MOCK_CLIENT_SECRET = "client-secret";

  // Strings commonly used
  private static final String TOKEN = "access_token";
  private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

  @BeforeEach
  void setup() {
    credentials = CredentialsDTO.builder().email(testUserEmail).password(testUserPassword).build();

    userRepresentation = UserRepresentationDTO.builder().id("123").email(MOCK_EMAIL).firstName("Test")
            .lastName("User").enabled(true).username("TestUser").build();

    ReflectionTestUtils.setField(userManagerService, "adminUri", MOCK_ADMIN_URI);
    ReflectionTestUtils.setField(userManagerService, "tokenUri", MOCK_TOKEN_URI);
    ReflectionTestUtils.setField(userManagerService, "clientId", MOCK_CLIENT_ID);
    ReflectionTestUtils.setField(userManagerService, "clientSecret", MOCK_CLIENT_SECRET);
    ReflectionTestUtils.setField(userManagerService, "restTemplate", restTemplate);
  }

  @DisplayName("Authenticate user: Success with credentials")
  @Test
  void givenCredentials_whenAuthenticate_thenReturnAuthenticationResponse() {
    // Given
    Map<String, Object> mockResponseBody = new HashMap<>();
    mockResponseBody.put(TOKEN, "mockAccessToken");
    mockResponseBody.put("expires_in", 1800);
    mockResponseBody.put("token_type", "JWT");
    mockResponseBody.put(GRANT_TYPE_REFRESH_TOKEN, "mockRefreshToken");
    mockResponseBody.put("refresh_expires_in", 1800);

    ResponseEntity<Map<String, Object>> mockResponse =
        new ResponseEntity<>(mockResponseBody, HttpStatus.OK);

    // When
    when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    AuthenticationResponseDTO result = userManagerService.authenticate(credentials, null);

    // Then
    assertNotNull(result);
    assertEquals("mockAccessToken", result.getAccessToken());
    assertEquals(1800, result.getExpiresIn());
    assertEquals("JWT", result.getTokenType());
    assertEquals("mockRefreshToken", result.getRefreshToken());
    assertEquals(1800, result.getRefreshExpiresIn());
  }

  @DisplayName("Authenticate user: Failure with RestClientException")
  @Test
  void givenCredentials_whenRestClientException_thenReturnNull() {
    // Given
    when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
        any(ParameterizedTypeReference.class)))
            .thenThrow(new RestClientException("Unable to connect"));

    // When - Then
    assertThrows(CustomExceptions.KeycloakException.class,
        () -> userManagerService.authenticate(credentials, null));
  }

  @DisplayName("Authenticate user: Success with refresh token")
  @Test
  void givenRefreshToken_whenAuthenticate_thenReturnAuthenticationResponse() {
    // Given
    String refreshToken = "mockRefreshToken";

    Map<String, Object> mockResponseBody = new HashMap<>();
    mockResponseBody.put(TOKEN, "mockAccessToken");
    mockResponseBody.put("expires_in", 1800);
    mockResponseBody.put("token_type", "JWT");
    mockResponseBody.put(GRANT_TYPE_REFRESH_TOKEN, "mockRefreshToken");
    mockResponseBody.put("refresh_expires_in", 1800);

    ResponseEntity<Map<String, Object>> mockResponse =
        new ResponseEntity<>(mockResponseBody, HttpStatus.OK);

    // When
    when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    AuthenticationResponseDTO result = userManagerService.authenticate(null, refreshToken);

    // Then
    assertNotNull(result);
    assertEquals("mockAccessToken", result.getAccessToken());
    assertEquals(1800, result.getExpiresIn());
    assertEquals("JWT", result.getTokenType());
    assertEquals("mockRefreshToken", result.getRefreshToken());
    assertEquals(1800, result.getRefreshExpiresIn());
  }

  @DisplayName("Retrieve user by email: Success")
  @Test
  void givenEmailAndJwt_whenRetrieveUserIdByEmail_thenReturnUserRepresentation() {
    // Given
    List<UserRepresentationDTO> mockResponseBody = List.of(userRepresentation);

    ResponseEntity<List<UserRepresentationDTO>> mockResponse =
        new ResponseEntity<>(mockResponseBody, HttpStatus.OK);

    String requestUri = MOCK_ADMIN_URI.concat("/users?email=").concat(MOCK_EMAIL);

    // When
    when(restTemplate.exchange(eq(requestUri), eq(HttpMethod.GET), any(HttpEntity.class),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    // Call the service method
    UserRepresentationDTO result = userManagerService.retrieveUserByEmail(MOCK_EMAIL, MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertEquals(MOCK_EMAIL, result.getEmail());
    assertEquals("Test", result.getFirstName());
    assertEquals("User", result.getLastName());
  }

  @DisplayName("Retrieve user by email: HTTP Client Error")
  @Test
  void givenEmailAndJwt_whenHttpClientErrorException_thenReturnNull() {
    // Given
    String requestUri = MOCK_ADMIN_URI.concat("/users?email=").concat(MOCK_EMAIL);

    // Simulate HTTP client error
    when(restTemplate.exchange(eq(requestUri), eq(HttpMethod.GET), any(HttpEntity.class),
        any(ParameterizedTypeReference.class)))
            .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Bad Request"));

    // When - Then
    assertThrows(CustomExceptions.KeycloakException.class,
        () -> userManagerService.retrieveUserByEmail(MOCK_EMAIL, MOCK_TOKEN));
  }

  @DisplayName("Retrieve user by email: HTTP Server Error")
  @Test
  void givenEmailAndJwt_whenHttpServerErrorException_thenReturnNull() {
    // Given
    String requestUri = MOCK_ADMIN_URI.concat("/users?email=").concat(MOCK_EMAIL);

    // Simulate HTTP server error
    when(restTemplate.exchange(eq(requestUri), eq(HttpMethod.GET), any(HttpEntity.class),
        any(ParameterizedTypeReference.class)))
            .thenThrow(new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error"));

    // When - Then
    assertThrows(CustomExceptions.KeycloakException.class,
        () -> userManagerService.retrieveUserByEmail(MOCK_EMAIL, MOCK_TOKEN));
  }

  @DisplayName("Create user: Success")
  @Test
  void givenUserDTO_whenCreateUser_thenReturnUserId() {
    // Given
    UserDTO userDTO = new UserDTO();
    userDTO.setEmail(MOCK_EMAIL);
    userDTO.setFirstName("Test");
    userDTO.setLastName("User");

    ResponseEntity<Object> mockResponse = new ResponseEntity<>(null, HttpStatus.CREATED);
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users"), eq(HttpMethod.POST),
        any(HttpEntity.class), eq(Object.class))).thenReturn(mockResponse);

    // Mock the Location header
    HttpHeaders headers = new HttpHeaders();
    headers.setLocation(java.net.URI.create(MOCK_ADMIN_URI + "/users/123"));
    ReflectionTestUtils.setField(mockResponse, "headers", headers);

    // When
    String result = userManagerService.createUser(userDTO, MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertEquals("123", result);
  }

  @DisplayName("Activate user: Success")
  @Test
  void givenValidActivationParams_whenActivateUser_thenReturnTrue() {
    // Add Attributes to user repsesentation
    Map<String, List<String>> tempMap = new HashMap<>();
    userRepresentation.setAttributes(tempMap);
    userRepresentation.getAttributes().put("activation_token", List.of("mock-token"));
    userRepresentation.getAttributes().put("activation_expiry", List.of("random-time"));

    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // Mock user retrieval
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/123"), eq(HttpMethod.GET),
            any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    // Mock user update
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/123"), eq(HttpMethod.PUT),
            any(HttpEntity.class), eq(Object.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // Use spy service
    boolean result = userManagerService.activateUser("123", MOCK_TOKEN, "newPassword");

    assertTrue(result);
  }

  @DisplayName("Activate User: Invalid Token - No Token Available")
  @Test
  void givenFailedTokenRetrieval_whenActivateUser_thenReturnFalse() {
    // Add Attributes to user repsesentation
    Map<String, List<String>> tempMap = new HashMap<>();
    userRepresentation.setAttributes(tempMap);
    userRepresentation.getAttributes().put("activation_expiry", List.of("random-time"));

    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // Mock user retrieval
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/123"), eq(HttpMethod.GET),
            any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    // When - Then
    assertThrows(CustomExceptions.InvalidActivationAttributes.class, () ->
            userManagerService.activateUser("123", MOCK_TOKEN, "test-password"));
  }

  @DisplayName("Activate User: User Not Found")
  @Test
  void givenNonExistentUser_whenActivateUser_thenReturnFalse() {
    // Given
    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // When
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/123"), eq(HttpMethod.GET),
            any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NOT_FOUND));

    // When
    boolean result = userManagerService.activateUser("123", "mock-activation-token", "test-password");

    // Then
    assertFalse(result);
  }

  @DisplayName("Update user: Success")
  @Test
  void givenUserInformation_whenUpdateUser_thenReturnTrue() {
    // Given
    UserDTO userDTO = new UserDTO();
    userDTO.setEmail(MOCK_EMAIL);
    userDTO.setFirstName("Updated");
    userDTO.setLastName("User");

    String userId = "123";

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/" + userId), eq(HttpMethod.GET),
            any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/" + userId), eq(HttpMethod.PUT),
            any(HttpEntity.class), eq(Object.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When
    boolean result = userManagerService.updateUser(userDTO, null, userId, MOCK_TOKEN);

    // Then
    assertTrue(result);
  }

  @DisplayName("Delete user: Success")
  @Test
  void givenUserId_whenDeleteUser_thenReturnTrue() {
    // Given
    String userId = "123";

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/" + userId), eq(HttpMethod.DELETE),
        any(HttpEntity.class), any(ParameterizedTypeReference.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When
    boolean result = userManagerService.deleteUser(userId, MOCK_TOKEN);

    // Then
    assertTrue(result);
  }

  @DisplayName("Change password: Success")
  @Test
  void givenNewPassword_whenChangePassword_thenReturnTrue() {
    // Given
    String userId = "123";
    String newPassword = "newPassword";

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/" + userId + "/reset-password"),
        eq(HttpMethod.PUT), any(HttpEntity.class), eq(Object.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When
    boolean result = userManagerService.changePassword(newPassword, userId, MOCK_TOKEN);

    // Then
    assertTrue(result);
  }

  @DisplayName("Logout user: Success")
  @Test
  void givenUserId_whenLogoutUser_thenComplete() {
    // Given
    String userId = "123";

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/" + userId + "/logout"),
        eq(HttpMethod.POST), any(HttpEntity.class), eq(Object.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When
    CompletableFuture<Void> result = userManagerService.logoutUser(userId, MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertDoesNotThrow(() -> result.get());
  }

  @DisplayName("Assign realm roles: Success")
  @SuppressWarnings("unchecked")
  @Test
  void givenPilotRoleAndUserId_whenAssignRealmRoles_thenCompleteSuccessfully() {
    // Given
    String pilotRole = "admin";
    String userId = "123";

    RoleRepresentationDTO roleRepresentationDTO = new RoleRepresentationDTO();
    roleRepresentationDTO.setName(pilotRole);

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/roles"), eq(HttpMethod.GET),
        any(HttpEntity.class), any(ParameterizedTypeReference.class)))
            .thenReturn(new ResponseEntity<>(List.of(roleRepresentationDTO), HttpStatus.OK));

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/" + userId + "/role-mappings/realm"),
        eq(HttpMethod.POST), any(HttpEntity.class), eq(Object.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When
    CompletableFuture<Void> result =
        userManagerService.assignRealmRoles(pilotRole, userId, MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertDoesNotThrow(() -> result.get());
  }

  @DisplayName("Assign realm management roles: Success")
  @SuppressWarnings("unchecked")
  @Test
  void givenPilotRoleAndUserId_whenAssignRealmManagementRoles_thenCompleteSuccessfully() {
    // Given
    String pilotRole = "admin";
    String userId = "123";
    String clientId = "realm-management-client-id";

    RoleRepresentationDTO roleRepresentationDTO = new RoleRepresentationDTO();
    roleRepresentationDTO.setName("manage-users");

    ClientRepresentationDTO clientRepresentationDTO = new ClientRepresentationDTO();
    clientRepresentationDTO.setId(clientId);

    Mockito.lenient()
        .when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/clients?clientId=realm-management"),
            eq(HttpMethod.GET), any(HttpEntity.class), any(ParameterizedTypeReference.class)))
        .thenReturn(new ResponseEntity<>(List.of(clientRepresentationDTO), HttpStatus.OK));

    Mockito.lenient()
        .when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/clients/" + clientId + "/roles"),
            eq(HttpMethod.GET), any(HttpEntity.class), any(ParameterizedTypeReference.class)))
        .thenReturn(new ResponseEntity<>(List.of(roleRepresentationDTO), HttpStatus.OK));

    Mockito.lenient()
        .when(restTemplate.exchange(
            eq(MOCK_ADMIN_URI + "/users/" + userId + "/role-mappings/clients/" + clientId),
            eq(HttpMethod.POST), any(HttpEntity.class), eq(Object.class)))
        .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When
    CompletableFuture<Void> result =
        userManagerService.assignRealmManagementRoles(pilotRole, userId, MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertDoesNotThrow(() -> result.get());
  }

  @DisplayName("Fetch user by email: Success")
  @SuppressWarnings("unchecked")
  @Test
  void givenEmailAndJwt_whenFetchUserByEmail_thenReturnUserRepresentation() {
    // Given
    List<UserRepresentationDTO> mockResponseBody = List.of(userRepresentation);

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users?email=" + MOCK_EMAIL),
        eq(HttpMethod.GET), any(HttpEntity.class), any(ParameterizedTypeReference.class)))
            .thenReturn(new ResponseEntity<>(mockResponseBody, HttpStatus.OK));

    // When
    UserRepresentationDTO result = userManagerService.retrieveUserByEmail(MOCK_EMAIL, MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertEquals(MOCK_EMAIL, result.getEmail());
    assertEquals("Test", result.getFirstName());
    assertEquals("User", result.getLastName());
  }

  @DisplayName("Fetch user by ID: Success")
  @Test
  void givenUserIdAndJwt_whenFetchUserById_thenReturnUserRepresentation() {
    // Given
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users/" + "123"), eq(HttpMethod.GET),
        any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    // When
    UserRepresentationDTO result = userManagerService.retrieveUserById("123", MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertEquals(MOCK_EMAIL, result.getEmail());
    assertEquals("Test", result.getFirstName());
    assertEquals("User", result.getLastName());
  }

  @DisplayName("Fetch users: Success")
  @SuppressWarnings("unchecked")
  @Test
  void givenJwt_whenFetchUsers_thenReturnListOfUsers() {
    // Given
    List<UserRepresentationDTO> mockResponseBody = List.of(userRepresentation);

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users"), eq(HttpMethod.GET),
        any(HttpEntity.class), any(ParameterizedTypeReference.class)))
            .thenReturn(new ResponseEntity<>(mockResponseBody, HttpStatus.OK));

    // When
    List<UserDTO> result = userManagerService.fetchUsers(MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertFalse(result.isEmpty());
    assertEquals(1, result.size());
    assertEquals(MOCK_EMAIL, result.getFirst().getEmail());
    assertEquals("Test", result.getFirst().getFirstName());
  }

  @SuppressWarnings("unchecked")
  @DisplayName("Fetch users by role: Success")
  @Test
  void givenValidRoleAndJwt_whenFetchUsersByRole_thenReturnUserDTOList() {
    // Given
    String clientIdRequestUri = MOCK_ADMIN_URI + "/clients?clientId=" + MOCK_CLIENT_ID;
    String fetchUsersRequestUri =
        MOCK_ADMIN_URI + "/clients/" + MOCK_CLIENT_ID + "/roles/OPERATOR/users";

    // Mock the response for finding the client ID
    when(keycloakSupportService.getClientId()).thenReturn(MOCK_CLIENT_ID);

    // Mock the response for fetching users by role
    ResponseEntity<List<UserRepresentationDTO>> fetchUsersResponse =
        new ResponseEntity<>(List.of(userRepresentation), HttpStatus.OK);

    // Simulate fetching users by role
    when(restTemplate.exchange(eq(fetchUsersRequestUri), eq(HttpMethod.GET), any(HttpEntity.class),
        any(ParameterizedTypeReference.class))).thenReturn(fetchUsersResponse);

    // When
    List<UserDTO> result = userManagerService.fetchUsersByRole("OPERATOR", MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertEquals(1, result.size());
    assertEquals(userRepresentation.getEmail(), result.getFirst().getEmail());
  }

  @SuppressWarnings("unchecked")
  @DisplayName("Fetch users by role: Empty response")
  @Test
  void givenValidRoleAndJwt_whenFetchUsersByRoleReturnsEmpty_thenReturnEmptyList() {
    // Given
    String clientIdRequestUri = MOCK_ADMIN_URI + "/clients?clientId=" + MOCK_CLIENT_ID;
    String fetchUsersRequestUri =
        MOCK_ADMIN_URI + "/clients/" + MOCK_CLIENT_ID + "/roles/OPERATOR/users";

    // Mock the response for finding the client ID
    when(keycloakSupportService.getClientId()).thenReturn(MOCK_CLIENT_ID);

    // Mock an empty response for fetching users
    ResponseEntity<List<UserRepresentationDTO>> fetchUsersResponse =
        new ResponseEntity<>(Collections.emptyList(), HttpStatus.OK);


    // Simulate fetching an empty list of users by role
    when(restTemplate.exchange(eq(fetchUsersRequestUri), eq(HttpMethod.GET), any(HttpEntity.class),
        any(ParameterizedTypeReference.class))).thenReturn(fetchUsersResponse);

    // When
    List<UserDTO> result = userManagerService.fetchUsersByRole("OPERATOR", MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertTrue(result.isEmpty());
  }
}

