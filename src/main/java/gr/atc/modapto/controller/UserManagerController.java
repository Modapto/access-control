package gr.atc.modapto.controller;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import gr.atc.modapto.dto.AuthenticationResponseDTO;
import gr.atc.modapto.dto.CredentialsDTO;
import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.dto.keycloak.UserRepresentationDTO;
import gr.atc.modapto.service.IUserManagerService;
import gr.atc.modapto.util.JwtUtils;
import gr.atc.modapto.validation.ValidUserRole;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@AllArgsConstructor
@RequestMapping("/api/users")
@Slf4j
public class UserManagerController {

    private final IUserManagerService userManagerService;

    /**
     * POST user credentials to generate a token from Keycloak or refresh token to generate a new access token
     *
     * @param credentials -> With email and password
     * @return AuthenticationResponse
     */
    @Operation(summary = "Authenticate user given credentials or refresh token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Authentication token generated successfully", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = AuthenticationResponseDTO.class))}),
            @ApiResponse(responseCode = "400", description = "Invalid request: either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed")
    })
    @PostMapping(value = {"/authenticate", "/refresh-token"})
    public ResponseEntity<ApiResponseInfo<AuthenticationResponseDTO>> authenticateOrRefreshToken(
            @Valid @RequestBody(required = false) CredentialsDTO credentials,
            @RequestParam(name = "token", required = false) String refreshToken) {

        AuthenticationResponseDTO response;

        // Check if credentials are provided for authentication, else use refreshToken
        if (credentials != null) {
            response = userManagerService.authenticate(credentials, null);
        } else if (refreshToken != null) {
            response = userManagerService.authenticate(null, refreshToken);
        } else {
            return new ResponseEntity<>(ApiResponseInfo.error("Invalid request: either credentials or token must be provided!"),
                    HttpStatus.BAD_REQUEST);
        }

        if (response != null) {
            return new ResponseEntity<>(ApiResponseInfo.success(response, "Authentication token generated successfully"),
                    HttpStatus.OK);
        } else {
            return new ResponseEntity<>(ApiResponseInfo.error("Authentication process failed"),
                    HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Logout user
     *
     * @param jwt  : JWT Token
     * @return message of success or failure
     */
    @Operation(summary = "Logout user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User logged out successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
    })
    @PostMapping(value = "/logout")
    public ResponseEntity<ApiResponseInfo<String>> logoutUser(
            @AuthenticationPrincipal Jwt jwt) {

        String token = jwt.getTokenValue();
        String userId = JwtUtils.extractUserId(jwt);
        userManagerService.logoutUser(userId, token);
        return new ResponseEntity<>(ApiResponseInfo.success(null, "User logged out successfully"),
                HttpStatus.OK);
    }

    /**
     * Creation of a new User by Super-Admin
     *
     * @param user : User information
     * @param jwt  : JWT Token
     * @return message of success or failure
     */
    @Operation(summary = "Create a new user in Keycloak")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User created successfully in Keycloak", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = AuthenticationResponseDTO.class))}),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "417", description = "User already exists in Keycloak"),
            @ApiResponse(responseCode = "500", description = "Unable to create user in Keycloak")
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @PostMapping(value = "/create")
    public ResponseEntity<ApiResponseInfo<String>> createUser(
            @Valid @RequestBody UserDTO user,
            @AuthenticationPrincipal Jwt jwt) {

        if (userMissingRequiredFields(user))
            return new ResponseEntity<>(ApiResponseInfo.error("You should provide all fields to create a new user"),
                    HttpStatus.BAD_REQUEST);

        // Ensure that user doesn't exist in Auth Server
        UserRepresentationDTO keycloakUser = userManagerService.retrieveUserByEmail(user.getEmail(), jwt.getTokenValue());
        if (keycloakUser != null)
            return new ResponseEntity<>(ApiResponseInfo.error("User already exists in Keycloak"),
                    HttpStatus.EXPECTATION_FAILED);

        String token = jwt.getTokenValue();
        String userId = userManagerService.createUser(user, token);
        if (userId != null) {
            // Assign the essential roles to the User Asynchronously
            assignRolesToUser(user.getPilotRole().toString(), userId, token);
            return new ResponseEntity<>(ApiResponseInfo.success(userId, "User created successfully in Keycloak"),
                    HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(ApiResponseInfo.error("Unable to create user in Keycloak"),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Update user's information in Keycloak
     *
     * @param user: UserDTO information
     * @param jwt: JWT Token
     * @return Message of success or failure
     */
    @Operation(summary = "Update user's information in Keycloak")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "500", description = "Unable to update user in Keycloak")
    })
     @PutMapping(value = "/update")
     public ResponseEntity<ApiResponseInfo<String>> updateUser(@Valid @RequestBody UserDTO user, @AuthenticationPrincipal Jwt jwt, @RequestParam String userId) {
        if (userManagerService.updateUser(user, userId, jwt.getTokenValue()))
            return new ResponseEntity<>(ApiResponseInfo.success(null, "User updated successfully"), HttpStatus.OK);
        else
            return new ResponseEntity<>(ApiResponseInfo.error("Unable to update user in Keycloak"),
                    HttpStatus.INTERNAL_SERVER_ERROR);
     }

    /**
     * Change user's password in Keycloak
     *
     * @param user: UserDTO information containing the password
     * @param jwt: JWT Token
     * @return Message of success or failure
     */
    @Operation(summary = "Change user's password in Keycloak")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User's password updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "400", description = "Password is missing"),
            @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "500", description = "Unable to update user's password in Keycloak")
    })
     @PutMapping(value = "/change-password")
     public ResponseEntity<ApiResponseInfo<String>> changePassword(@Valid @RequestBody UserDTO user, @AuthenticationPrincipal Jwt jwt) {
        // We utilize the Validation of password inside the UserDTO class. If password is missing then we return an error
         if (user.getPassword() == null)
             return new ResponseEntity<>(ApiResponseInfo.error("Password is missing"),
                     HttpStatus.BAD_REQUEST);

         String userId = JwtUtils.extractUserId(jwt);
         if (userManagerService.changePassword(user.getPassword(), userId, jwt.getTokenValue()))
             return new ResponseEntity<>(ApiResponseInfo.success(null,"User's password updated successfully"),
                 HttpStatus.OK);
         else
            return new ResponseEntity<>(ApiResponseInfo.error("Unable to update user's password in Keycloak"),
                 HttpStatus.INTERNAL_SERVER_ERROR);
     }

    /**
     * Retrieve all users from Keycloak - Only for Super Admins / Pilot Admins
     *
     * @param jwt: JWT Token
     * @return List<UserDTO>
     */
    @Operation(summary = "Retrieve all users from Keycloak")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = UserDTO.class))}),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @GetMapping
    public ResponseEntity<ApiResponseInfo<List<UserDTO>>> fetchUsers(@AuthenticationPrincipal Jwt jwt) {
        return new ResponseEntity<>(ApiResponseInfo.success(userManagerService.fetchUsers(jwt.getTokenValue()), "Users retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Search user by ID from Keycloak - Only for Super Admins / Pilot Admins
     *
     * @param userId: ID of the user
     * @param jwt: JWT Token
     * @return UserDTO
     */
    @Operation(summary = "Search user by ID from Keycloak")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User retrieved successfully", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = UserDTO.class))}),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @GetMapping("/search")
    public ResponseEntity<ApiResponseInfo<UserDTO>> fetchUser(@RequestParam String userId, @AuthenticationPrincipal Jwt jwt) {
        return new ResponseEntity<>(ApiResponseInfo.success(userManagerService.fetchUser(userId, jwt.getTokenValue()), "User retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Delete user from Keycloak - Only for Super Admins
     *
     * @param userId: ID of the user
     * @param jwt: JWT Token
     * @return Message of success or failure
     */
    @Operation(summary = "Delete a user by ID from Keycloak")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User deleted successfully", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = UserDTO.class))}),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "500", description = "Unable to delete user from Keycloak")
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @DeleteMapping("/delete")
    public ResponseEntity<ApiResponseInfo<String>> deleteUser(@RequestParam String userId, @AuthenticationPrincipal Jwt jwt) {
        if(userManagerService.deleteUser(userId, jwt.getTokenValue()))
            return new ResponseEntity<>(ApiResponseInfo.success(null, "User deleted successfully"),
                    HttpStatus.OK);
        else
            return new ResponseEntity<>(ApiResponseInfo.error("Unable to delete user from Keycloak"),
                    HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Retrieve all user IDs from Keycloak
     *
     * @param jwt: JWT Token
     * @return List<UserDTO>
     */
    @Operation(summary = "Retrieve all user IDs from Keycloak")
    @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User IDs retrieved successfully"),
      @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
      @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
      @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
    })
    @GetMapping("/ids")
    public ResponseEntity<ApiResponseInfo<List<String>>> getAllUserIds(@AuthenticationPrincipal Jwt jwt) {
      List<UserDTO> users = userManagerService.fetchUsers(jwt.getTokenValue());
      return new ResponseEntity<>(ApiResponseInfo.success(users.stream().map(UserDTO::getUserId).toList(), "User IDs retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Retrieve all user IDs from Keycloak
     *
     * @param jwt: JWT Token
     * @return List<UserDTO>
     */
    @Operation(summary = "Retrieve all user IDs from Keycloak")
    @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User IDs for role retrieved successfully"),
      @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
      @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
      @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "500", description = "Unable to locate requested client ID in Keycloak")
    })
    @GetMapping("/ids/role/{realmRole}")
    public ResponseEntity<ApiResponseInfo<List<String>>> getAllUserIdsByUserRole(@AuthenticationPrincipal Jwt jwt, @ValidUserRole @PathVariable String realmRole) {
      List<UserDTO> users = userManagerService.fetchUsersByRole(realmRole, jwt.getTokenValue());
      return new ResponseEntity<>(ApiResponseInfo.success(users.stream().map(UserDTO::getUserId).toList(), "User IDs for role " + realmRole + " retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Return the authentication information based on the inserted token
     *
     * @param authentication : JWT token
     * @return authentication information
     */
    @Operation(summary = "Retrieve Authentication Information based on the JWT token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Information about Authentication Information based on the JWT token", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = Authentication.class))}),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token")
    })
    @GetMapping(value = "/auth-info")
    public ResponseEntity<Authentication> getAuthInfo(Authentication authentication) {
        return new ResponseEntity<>(authentication, HttpStatus.OK);
    }

    /**
     * Validate that all fields are inserted to create a new User
     *
     * @param user : User information
     * @return True on success, False on error
     */
    private boolean userMissingRequiredFields(UserDTO user){
        return (user.getUsername() == null || user.getEmail() == null || user.getPassword() == null
                || user.getFirstName() == null || user.getLastName() == null || user.getUserRole() == null
                || user.getPilotRole() == null || user.getPilotCode() == null);
    }

    /**
     * Call async functions to assign roles to user
     * @param userRole : Created user role
     * @param userId : User ID
     * @param token : JWT Token value
     */
    private void assignRolesToUser(String userRole, String userId, String token){
        // Trigger async role assignments
        // Assign Realm Role
        CompletableFuture<Void> realmRolesFuture = userManagerService.assignRealmRoles(userRole, userId, token);

        // Assign Realm-Management Roles
        CompletableFuture<Void> managementRolesFuture = userManagerService.assignRealmManagementRoles(userRole, userId, token);

        // Wait for both futures to complete
        CompletableFuture.allOf(realmRolesFuture, managementRolesFuture)
                .thenRun(() -> log.info("All roles assigned for user: {}", userId))
                .exceptionally(ex -> {
                    log.error("Error assigning roles for user: {}", userId, ex);
                    return null;
                });
    }
}
