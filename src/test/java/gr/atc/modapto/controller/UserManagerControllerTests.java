package gr.atc.modapto.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.hamcrest.CoreMatchers.is;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;

import gr.atc.modapto.dto.AuthenticationResponseDTO;
import gr.atc.modapto.dto.CredentialsDTO;
import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.dto.keycloak.UserRepresentationDTO;
import gr.atc.modapto.enums.PilotCode;
import gr.atc.modapto.enums.PilotRole;
import gr.atc.modapto.enums.UserRole;
import gr.atc.modapto.service.UserManagerService;

@SpringBootTest
@AutoConfigureMockMvc
class UserManagerControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserManagerService userManagerService;

    @Autowired
    private ObjectMapper objectMapper;

    private static CredentialsDTO credentials;
    private static AuthenticationResponseDTO authenticationResponse;
    private static UserDTO user;
    private static Jwt jwt;

    @BeforeAll
    static void setup() {
        credentials = CredentialsDTO.builder()
                .email("test@test.com")
                .password("TestPass123@")
                .build();

        authenticationResponse = AuthenticationResponseDTO.builder()
                .accessToken("accessToken")
                .expiresIn(1800)
                .tokenType("JWT")
                .refreshToken("refreshToken")
                .refreshExpiresIn(1800)
                .build();

        user = UserDTO.builder()
                .userId("12345")
                .email("test@test.com")
                .firstName("Test")
                .lastName("Test")
                .username("UserTest")
                .password("TestPass123@")
                .pilotCode(PilotCode.NONE)
                .pilotRole(PilotRole.NONE)
                .userRole(UserRole.NONE)
                .build();

        String tokenValue = "mock.jwt.token";
        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", Map.of("roles", List.of("SUPER_ADMIN")));
        claims.put("resource_access", Map.of("modapto", Map.of("roles", List.of("SUPER_ADMIN"))));
        claims.put("sub", "user");
        claims.put("pilot", "TEST");
        claims.put("pilot_role", "TEST");

        jwt = Jwt.withTokenValue(tokenValue)
                .headers(header -> header.put("alg", "HS256"))
                .claims(claim -> claim.putAll(claims))
                .build();

    }

    @WithMockUser(roles = "SUPER_ADMIN")
    @DisplayName("Authenticate User: Success")
    @Test
    void givenUserCredentials_whenAuthenticate_thenReturnAccessTokens() throws Exception {
        // Given
        given(userManagerService.authenticate(credentials, null)).willReturn(authenticationResponse);

        // When
        ResultActions response = mockMvc.perform(post("/api/users/authenticate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(credentials)));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success",
                        is(true)))
                .andExpect(jsonPath("$.message",
                        is("Authentication token generated successfully")))
                .andExpect(jsonPath("$.data.accessToken",
                        is(authenticationResponse.getAccessToken())));

    }

    @DisplayName("Refresh Token: Success")
    @Test
    void givenRefreshToken_whenRefreshToken_thenReturnNewAccessTokens() throws Exception {
        // Given
        given(userManagerService.authenticate(null, "test_token")).willReturn(authenticationResponse);

        // When
        ResultActions response = mockMvc.perform(post("/api/users/refresh-token")
                .contentType(MediaType.APPLICATION_JSON)
                .param("token", "test_token"));


        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success",
                        is(true)))
                .andExpect(jsonPath("$.message",
                        is("Authentication token generated successfully")))
                .andExpect(jsonPath("$.data.accessToken",
                        is(authenticationResponse.getAccessToken())));
    }

    @DisplayName("Authenticate User: Invalid Credentials")
    @Test
    void givenInvalidUserCredentials_whenAuthenticate_thenReturnBadRequest() throws Exception {

        // When
        ResultActions response = mockMvc.perform(post("/api/users/authenticate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new CredentialsDTO("email", "password"))));

        // Then
        response.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Validation failed")));
    }


    @DisplayName("Unauthorized Access: Failure")
    @Test
    void givenWrongCredentials_whenAuthenticate_thenReturnUnauthorized() throws Exception {
        // Given
        given(userManagerService.authenticate(credentials, null)).willReturn(null);

        // When
        ResultActions response = mockMvc.perform(post("/api/users/authenticate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(credentials)));

        // Then
        response.andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Authentication process failed")));
    }

    @DisplayName("No credentials given: Failure")
    @Test
    void givenNoInput_whenAuthenticate_thenReturnBadRequest() throws Exception {

        // When
        ResultActions response = mockMvc.perform(post("/api/users/authenticate")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Invalid request: either credentials or token must be provided!")));
    }

    @DisplayName("No token given: Failure")
    @Test
    void givenNoInput_whenRefreshToken_thenReturnBadRequest() throws Exception {

        // When
        ResultActions response = mockMvc.perform(post("/api/users/refresh-token")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Invalid request: either credentials or token must be provided!")));
    }

    @DisplayName("Logout User: Success")
    @Test
    void givenValidJwt_whenLogout_thenReturnSuccessMessage() throws Exception {
        // Given
        CompletableFuture<Void> completableFuture = new CompletableFuture<>();
        completableFuture.complete(null);
        given(userManagerService.logoutUser(anyString(), anyString())).willReturn(completableFuture);


        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(post("/api/users/logout")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User logged out successfully")));
    }

    @DisplayName("Create User: Success")
    @Test
    void givenValidUser_whenCreateUser_thenReturnSuccess() throws Exception {
        // Given
        CompletableFuture<Void> completableFuture = new CompletableFuture<>();
        completableFuture.complete(null);
        given(userManagerService.retrieveUserByEmail(anyString(), anyString())).willReturn(null);
        given(userManagerService.createUser(any(UserDTO.class), anyString())).willReturn("12345");
        given(userManagerService.assignRealmRoles(anyString(), anyString(), anyString())).willReturn(completableFuture);
        given(userManagerService.assignRealmManagementRoles(anyString(), anyString(), anyString())).willReturn(completableFuture);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(post("/api/users/create")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(user)));

        // Then
        response.andExpect(status().isCreated())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User created successfully in Keycloak")));
    }

    @DisplayName("Create User: Failed - Missing Values")
    @Test
    void givenIncompleteUser_whenCreateUser_thenReturnBadRequest() throws Exception {
        // Given
       UserDTO userDTO = new UserDTO();

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(post("/api/users/create")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userDTO)));

        // Then
        response.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("You should provide all fields to create a new user")));
    }

    @DisplayName("Create User: User Already Exists")
    @Test
    void givenExistingUser_whenCreateUser_thenReturnExpectationFailed() throws Exception {
        // Given
        UserRepresentationDTO userRepr = UserRepresentationDTO.fromUserDTO(user, null);
        given(userManagerService.retrieveUserByEmail(anyString(), anyString())).willReturn(userRepr);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(post("/api/users/create")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(user)));

        // Then
        response.andExpect(status().isExpectationFailed())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("User already exists in Keycloak")));
    }

    @DisplayName("Update User: Success")
    @Test
    void givenValidUser_whenUpdateUser_thenReturnSuccess() throws Exception {
        // Given
        given(userManagerService.updateUser(any(UserDTO.class), anyString(), anyString())).willReturn(true);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(put("/api/users/update")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(user))
                .param("userId", "12345"));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User updated successfully")));
    }

    @DisplayName("Update User: Failure")
    @Test
    void givenValidUser_whenUpdateUserFails_thenReturnServerError() throws Exception {
        // Given
        given(userManagerService.updateUser(any(UserDTO.class), anyString(), anyString())).willReturn(false);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(put("/api/users/update")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(user))
                .param("userId", "12345"));

        // Then
        response.andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unable to update user in Keycloak")));
    }

    @DisplayName("Change Password: Success")
    @Test
    void givenValidPassword_whenChangePassword_thenReturnSuccess() throws Exception {
        // Given
        UserDTO userDTO = new UserDTO();
        userDTO.setPassword("Password123@");
        given(userManagerService.changePassword(anyString(), anyString(), anyString())).willReturn(true);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(put("/api/users/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userDTO)));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User's password updated successfully")));
    }

    @DisplayName("Change Password: Missing Password")
    @Test
    void givenMissingPassword_whenChangePassword_thenReturnBadRequest() throws Exception {
        // Given
        UserDTO userDTO = new UserDTO(); // No password set

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(put("/api/users/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(userDTO)));

        // Then
        response.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Password is missing")));
    }

    @DisplayName("Fetch Users: Success")
    @Test
    void givenValidJwt_whenFetchUsers_thenReturnListOfUsers() throws Exception {
        // Given
        given(userManagerService.fetchUsers(anyString())).willReturn(List.of(user));

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(get("/api/users").contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Users retrieved successfully")))
                .andExpect(jsonPath("$.data[0].email", is("test@test.com")));
    }

    @DisplayName("Fetch User IDs: Success")
    @Test
    void givenValidJwt_whenGetAllUserIds_thenReturnListOfUserIds() throws Exception {
        // Given
        given(userManagerService.fetchUsers(anyString())).willReturn(List.of(user));

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(get("/api/users/ids").contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User IDs retrieved successfully")))
                .andExpect(jsonPath("$.data[0]", is("12345")));
    }

    @DisplayName("Fetch User IDs By Role: Success")
    @Test
    void givenValidJwt_whenGetAllUserIdsByUserRole_thenReturnListOfUserIds() throws Exception {
        // Given
        given(userManagerService.fetchUsersByRole(anyString(), anyString())).willReturn(List.of(user));

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(get("/api/users/ids/role/OPERATOR").contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User IDs for role OPERATOR retrieved successfully")))
                .andExpect(jsonPath("$.data[0]", is("12345")));
    }


    @DisplayName("Fetch User by ID: Success")
    @Test
    void givenValidUserId_whenFetchUser_thenReturnUser() throws Exception {
        // Given
        given(userManagerService.fetchUser(anyString(), anyString())).willReturn(user);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(get("/api/users/search")
                .param("userId", "12345"));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User retrieved successfully")))
                .andExpect(jsonPath("$.data.email", is("test@test.com")));
    }

    @DisplayName("Fetch User by ID: Not Found")
    @Test
    void givenInvalidUserId_whenFetchUser_thenReturnNull() throws Exception {
        // Given
        given(userManagerService.fetchUser(anyString(), anyString())).willReturn(null);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(get("/api/users/search")
                .param("userId", "invalid-id"));

        // Then
        response.andExpect(status().isOk()) // The API still returns OK but with a null response
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User retrieved successfully")))
                .andExpect(jsonPath("$.data").doesNotExist());
    }

    @DisplayName("Fetch User by ID: Internal Server Error")
    @Test
    void givenValidUserId_whenServerErrorOccurs_thenReturnInternalServerError() throws Exception {
        // Given
        given(userManagerService.fetchUser(anyString(), anyString())).willThrow(new RuntimeException("Server error"));

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(get("/api/users/search")
                .param("userId", "12345"));

        // Then
        response.andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("An unexpected error occurred")));
    }

    @DisplayName("Delete User: Success")
    @Test
    void givenValidJwt_whenDeleteUser_thenReturnSuccess() throws Exception {
        // Given
        given(userManagerService.deleteUser(anyString(), anyString())).willReturn(true);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(delete("/api/users/delete")
                .param("userId", "12345"));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User deleted successfully")));
    }

    @DisplayName("Delete User: Failure")
    @Test
    void givenValidJwt_whenDeleteUserFails_thenReturnServerError() throws Exception {
        // Given
        given(userManagerService.deleteUser(anyString(), anyString())).willReturn(false);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(delete("/api/users/delete")
                .param("userId", "12345"));

        // Then
        response.andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unable to delete user from Keycloak")));
    }
}
