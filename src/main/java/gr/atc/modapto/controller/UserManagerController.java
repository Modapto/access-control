package gr.atc.modapto.controller;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
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
import gr.atc.modapto.enums.PilotRole;
import gr.atc.modapto.service.IEmailService;
import gr.atc.modapto.service.IUserManagerService;
import gr.atc.modapto.util.JwtUtils;
import gr.atc.modapto.validation.ValidPassword;
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

    private final IEmailService emailService;

    /**
     * POST user credentials to generate a token from Keycloak
     *
     * @param credentials : Email and password of user
     * @return AuthenticationResponse
     */
    @Operation(summary = "Authenticate user given credentials", security = @SecurityRequirement(name = ""))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Authentication token generated successfully", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = AuthenticationResponseDTO.class))}),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed")
    })
    @PostMapping(value = "/authenticate")
    public ResponseEntity<BaseResponse<AuthenticationResponseDTO>> authenticateUser(
            @Valid @RequestBody CredentialsDTO credentials){

        AuthenticationResponseDTO response = userManagerService.authenticate(credentials, null);

        if (response != null) {
            return new ResponseEntity<>(BaseResponse.success(response, "Authentication token generated successfully"),
                    HttpStatus.OK);
        } else {
            return new ResponseEntity<>(BaseResponse.error("Authentication process failed"),
                    HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * POST refresh token to refresh user's token before expiration
     *
     * @param refreshToken : Refresh Token
     * @return AuthenticationResponse
     */
    @Operation(summary = "Refresh user Token", security = @SecurityRequirement(name = ""))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Authentication token generated successfully", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = AuthenticationResponseDTO.class))}),
            @ApiResponse(responseCode = "400", description = "Invalid / No input was given for requested resource"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed")
    })
    @PostMapping(value = "/refresh-token")
    public ResponseEntity<BaseResponse<AuthenticationResponseDTO>> refreshToken(
            @RequestParam(name = "token") String refreshToken) {

        AuthenticationResponseDTO response = userManagerService.authenticate(null, refreshToken);

        if (response != null) {
            return new ResponseEntity<>(BaseResponse.success(response, "Authentication token generated successfully"),
                    HttpStatus.OK);
        } else {
            return new ResponseEntity<>(BaseResponse.error("Authentication process failed"),
                    HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Activate User and update his/her password
     *
     * @param token : Activation token with userId information and activation token stored in Keycloak
     * @param password : User's new password
     * @return message of success or failure
     */
    @Operation(summary = "Activate user", security = @SecurityRequirement(name = ""))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User activated and password updated successfully."),
            @ApiResponse(responseCode = "400", description = "Invalid token was given as parameter."),
            @ApiResponse(responseCode = "500", description = "Due to an internal error, user has not been activated!"),
    })
    @PostMapping(value = "/activate")
    public ResponseEntity<BaseResponse<String>> activateUser(
            @RequestParam String token, @ValidPassword @RequestBody String password) {

        // Split the User ID and the Keycloak Activation Token
        List<String> tokenData = List.of(token.split("@"));

        // Ensure token inserted is valid - UserID # Activation Token
        if (tokenData.size() != 2)
            return new ResponseEntity<>(BaseResponse.error("Invalid token was given as parameter."), HttpStatus.BAD_REQUEST);

        String userId = tokenData.getFirst();
        String activationToken = tokenData.getLast();

        if (userManagerService.activateUser(userId, activationToken, password))
            return new ResponseEntity<>(BaseResponse.success(null, "User activated and password updated successfully."),
                    HttpStatus.OK);
        else
            return new ResponseEntity<>(BaseResponse.error(null, "Due to an internal error, user has not been activated!"),
                    HttpStatus.INTERNAL_SERVER_ERROR);

    }

    /**
     * Logout user
     *
     * @param jwt  : JWT Token
     * @return message of success or failure
     */
    @Operation(summary = "Logout user", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User logged out successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
    })
    @PostMapping(value = "/logout")
    public ResponseEntity<BaseResponse<String>> logoutUser(
            @AuthenticationPrincipal Jwt jwt) {

        String token = jwt.getTokenValue();
        String userId = JwtUtils.extractUserId(jwt);
        userManagerService.logoutUser(userId, token);
        return new ResponseEntity<>(BaseResponse.success(null, "User logged out successfully"),
                HttpStatus.OK);
    }

    /**
     * Creation of a new User by Super-Admin or Admin
     * Depending on the type of User uses will be able to create new users
     * - Admins can only create personnel inside their organization
     * - Super Admins can create personnel for all pilots and create new Super Admins also
     *
     * @param user : User information
     * @param jwt  : JWT Token
     * @return message of success or failure
     */
    @Operation(summary = "Create a new user in Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User created successfully in Keycloak", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = AuthenticationResponseDTO.class))}),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "You should provide all fields to create a new user"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Only Super Admins can create other Super Admin roles."),
            @ApiResponse(responseCode = "403", description = "Admins can only create personnel inside their organization"),
            @ApiResponse(responseCode = "417", description = "User already exists in Keycloak"),
            @ApiResponse(responseCode = "500", description = "Unable to create user in Keycloak")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @PostMapping(value = "/create")
    public ResponseEntity<BaseResponse<String>> createUser(
            @RequestBody UserDTO user,
            @AuthenticationPrincipal Jwt jwt) {

        // Ensure that all required fields are given to create a new user
        if (userMissingRequiredFields(user))
            return new ResponseEntity<>(BaseResponse.error("You should provide all fields to create a new user"),
                    HttpStatus.BAD_REQUEST);

        // Ensure that if only Super Admins can create new Super Admins
        if(user.getPilotRole().equals(PilotRole.SUPER_ADMIN) && !JwtUtils.extractPilotRole(jwt).equalsIgnoreCase(PilotRole.SUPER_ADMIN.toString()))
            return new ResponseEntity<>(BaseResponse.error("Unauthorized action","Only Super Admins can create other Super Admin roles."),
                    HttpStatus.FORBIDDEN);

        // Ensure that Admins can create personnel only inside their organization
        if(JwtUtils.extractPilotRole(jwt).equals(PilotRole.ADMIN.toString()) && !JwtUtils.extractPilotCode(jwt).equalsIgnoreCase(user.getPilotCode().toString()))
            return new ResponseEntity<>(BaseResponse.error("Unauthorized action","Admins can only create personnel inside their organization"),
                    HttpStatus.FORBIDDEN);

        // Ensure that user doesn't exist in Auth Server
        UserRepresentationDTO keycloakUser = userManagerService.retrieveUserByEmail(user.getEmail(), jwt.getTokenValue());
        if (keycloakUser != null)
            return new ResponseEntity<>(BaseResponse.error("User already exists in Keycloak"),
                    HttpStatus.EXPECTATION_FAILED);

        // Create activation token
        user.setActivationToken(UUID.randomUUID().toString());
        user.setActivationExpiry(String.valueOf(System.currentTimeMillis() + 86400000)); // 24 Hours expiration time

        String token = jwt.getTokenValue();
        String userId = userManagerService.createUser(user, token);
        if (userId != null) {
            // Assign the essential roles to the User Asynchronously
            assignRolesToUser(user.getPilotRole().toString(), userId, token);

            // Send activation link async
            String activationToken = userId.concat("@").concat(user.getActivationToken()); // Token in activation Link will be: User ID + # + Activation Token
            emailService.sendActivationLink(user.getUsername(), user.getEmail(), activationToken);

            return new ResponseEntity<>(BaseResponse.success(userId, "User created successfully in Keycloak"),
                    HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(BaseResponse.error("Unable to create user in Keycloak"),
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
    @Operation(summary = "Update user's information in Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
            @ApiResponse(responseCode = "403", description = "Token is invalid. No information regarding user ID or role was found"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "User of type 'USER' can only update his personal information"),
            @ApiResponse(responseCode = "403", description = "User of type 'ADMIN' can only update user's inside their organization"),
            @ApiResponse(responseCode = "500", description = "Unable to update user in Keycloak")
    })
     @PutMapping(value = "/update")
     public ResponseEntity<BaseResponse<String>> updateUser(@RequestBody UserDTO user, @AuthenticationPrincipal Jwt jwt, @RequestParam String userId) {
        String jwtUserId = JwtUtils.extractUserId(jwt);
        String jwtRole = JwtUtils.extractPilotRole(jwt);
        String jwtPilot = JwtUtils.extractPilotCode(jwt);

        UserRepresentationDTO existingUser = userManagerService.retrieveUserById(userId,jwt.getTokenValue());
        if (existingUser == null)
            return new ResponseEntity<>(BaseResponse.error("User not found in Keycloak"),
                    HttpStatus.EXPECTATION_FAILED);

        UserDTO existingUserDTO = UserRepresentationDTO.toUserDTO(existingUser);

        // Validate that a user can only update his personal info or admins can update user's inside their organization
        if (jwtUserId == null || jwtRole == null || jwtPilot == null)
            return new ResponseEntity<>(BaseResponse.error("Token is invalid. No information regarding user ID or role was found"),
                    HttpStatus.FORBIDDEN);
        else if (jwtRole.equals(PilotRole.USER.toString()) && !jwtUserId.equals(userId))
            return new ResponseEntity<>(BaseResponse.error("User of type 'USER' can only update his personal information"),
                    HttpStatus.FORBIDDEN);
        else if (jwtRole.equals(PilotRole.ADMIN.toString()) && !jwtPilot.equalsIgnoreCase(existingUserDTO.getPilotCode().toString()))
            return new ResponseEntity<>(BaseResponse.error("User of type 'ADMIN' can only update user's inside their organization"),
                    HttpStatus.FORBIDDEN);

        // Update users
        if (userManagerService.updateUser(user, null, userId, jwt.getTokenValue()))
            return new ResponseEntity<>(BaseResponse.success(null, "User updated successfully"), HttpStatus.OK);
        else
            return new ResponseEntity<>(BaseResponse.error("Unable to update user in Keycloak"),
                    HttpStatus.INTERNAL_SERVER_ERROR);
     }

    /**
     * Change user's password in Keycloak
     *
     * @param user: UserDTO information containing the password
     * @param jwt: JWT Token
     * @return Message of success or failure
     */
    @Operation(summary = "Change user's password in Keycloak", security = @SecurityRequirement(name = "bearerToken"))
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
     public ResponseEntity<BaseResponse<String>> changePassword(@RequestBody UserDTO user, @AuthenticationPrincipal Jwt jwt) {
        // We utilize the Validation of password inside the UserDTO class. If password is missing then we return an error
         if (user.getPassword() == null)
             return new ResponseEntity<>(BaseResponse.error("Password is missing"),
                     HttpStatus.BAD_REQUEST);

         String userId = JwtUtils.extractUserId(jwt);
         if (userManagerService.changePassword(user.getPassword(), userId, jwt.getTokenValue()))
             return new ResponseEntity<>(BaseResponse.success(null,"User's password updated successfully"),
                 HttpStatus.OK);
         else
            return new ResponseEntity<>(BaseResponse.error("Unable to update user's password in Keycloak"),
                 HttpStatus.INTERNAL_SERVER_ERROR);
     }

    /**
     * Retrieve all users from Keycloak - Only for Super Admins / Pilot Admins
     *
     * @param jwt: JWT Token
     * @return List<UserDTO>
     */
    @Operation(summary = "Retrieve all users from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = UserDTO.class))}),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the pilot")
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @GetMapping
    public ResponseEntity<BaseResponse<List<UserDTO>>> fetchUsers(@AuthenticationPrincipal Jwt jwt) {
        String pilot = JwtUtils.extractPilotCode(jwt);
        if (pilot == null)
            return new ResponseEntity<>(BaseResponse.error("Token inserted is invalid. It does not contain any information about the pilot"), HttpStatus.FORBIDDEN);
        return new ResponseEntity<>(BaseResponse.success(userManagerService.fetchUsers(jwt.getTokenValue(), pilot), "Users retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Search user by ID from Keycloak - Only for Super Admins / Pilot Admins
     *
     * @param userId: ID of the user
     * @param jwt: JWT Token
     * @return UserDTO
     */
    @Operation(summary = "Search user by ID from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User retrieved successfully", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = UserDTO.class))}),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @GetMapping("/search")
    public ResponseEntity<BaseResponse<UserDTO>> fetchUser(@RequestParam String userId, @AuthenticationPrincipal Jwt jwt) {
        return new ResponseEntity<>(BaseResponse.success(userManagerService.fetchUser(userId, jwt.getTokenValue()), "User retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Delete user from Keycloak - Only for Super Admins
     *
     * @param userId: ID of the user
     * @param jwt: JWT Token
     * @return Message of success or failure
     */
    @Operation(summary = "Delete a user by ID from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
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
    public ResponseEntity<BaseResponse<String>> deleteUser(@RequestParam String userId, @AuthenticationPrincipal Jwt jwt) {
        if(userManagerService.deleteUser(userId, jwt.getTokenValue()))
            return new ResponseEntity<>(BaseResponse.success(null, "User deleted successfully"),
                    HttpStatus.OK);
        else
            return new ResponseEntity<>(BaseResponse.error("Unable to delete user from Keycloak"),
                    HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Retrieve all user IDs from Keycloak
     *
     * @param jwt: JWT Token
     * @return List<UserDTO>
     */
    @Operation(summary = "Retrieve all user IDs for a specific pilot from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User IDs retrieved successfully"),
      @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
      @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
      @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
      @ApiResponse(responseCode = "500", description = "Unable to locate requested group ID in Keycloak")
    })
    @GetMapping("/ids/pilot/{pilotCode}")
    public ResponseEntity<BaseResponse<List<String>>> getAllUserIdsByPilotCode(@AuthenticationPrincipal Jwt jwt, @PathVariable String pilotCode) {
        List<UserDTO> users = userManagerService.fetchUsersByPilotCode(pilotCode.toUpperCase(), jwt.getTokenValue());
        return new ResponseEntity<>(BaseResponse.success(users.stream().map(UserDTO::getUserId).toList(), "User IDs for pilot " + pilotCode + " retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Retrieve all user IDs from Keycloak filtered by a specific User Role
     *
     * @param jwt: JWT Token
     * @param userRole : User Role
     * @return List<UserDTO>
     */
    @Operation(summary = "Retrieve all user IDs per role from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User IDs for role retrieved successfully"),
      @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
      @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
      @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
      @ApiResponse(responseCode = "500", description = "Unable to locate requested client ID in Keycloak")
    })
    @GetMapping("/ids/role/{userRole}")
    public ResponseEntity<BaseResponse<List<String>>> getAllUserIdsByUserRole(@AuthenticationPrincipal Jwt jwt, @ValidUserRole @PathVariable String userRole) {
      List<UserDTO> users = userManagerService.fetchUsersByRole(userRole.toUpperCase(), jwt.getTokenValue());
      return new ResponseEntity<>(BaseResponse.success(users.stream().map(UserDTO::getUserId).toList(), "User IDs for role " + userRole + " retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Return the authentication information based on the inserted token
     *
     * @param authentication : JWT token
     * @return authentication information
     */
    @Operation(summary = "Retrieve Authentication Information based on the JWT token", security = @SecurityRequirement(name = "bearerToken"))
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
        return (user.getUsername() == null || user.getEmail() == null
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
