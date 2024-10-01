package gr.atc.modapto.service;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import gr.atc.modapto.dto.AuthenticationResponseDTO;
import gr.atc.modapto.dto.CredentialsDTO;
import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.dto.keycloak.UserRepresentationDTO;

public interface IUserManagerService {
  AuthenticationResponseDTO authenticate(CredentialsDTO credentials, String refreshToken);

  String createUser(UserDTO userDTO, String token);

  boolean updateUser(UserDTO userDTO, String userId, String token);

  List<UserDTO> fetchUsers(String token);

  UserDTO fetchUser(String userId, String token);

  boolean deleteUser(String userId, String token);

  boolean changePassword(String password, String userId, String token);

  UserRepresentationDTO retrieveUserByEmail(String email, String token);

  UserRepresentationDTO retrieveUserById(String userId, String token);

  String findClientIdPerClient(String client, String token);

  CompletableFuture<Void> assignRealmRoles(String userRole, String userId, String token);

  CompletableFuture<Void> assignRealmManagementRoles(String userRole, String userId, String token);

  CompletableFuture<Void> logoutUser(String userId, String token);
}
