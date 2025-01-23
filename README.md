# MODAPTO User Manager Component

## Overview

User manager is responsible to handle authentication process inside MODAPTO. It connects with Keycloak and routes all requests to authenticate
users, refresh tokens, manage users and request information regarding their authorization in the system.

It exploits OAuth2.0 and OpenID protocols integrated with Spring Security with configured Request Filters to increase the security of the application and generate JWT Tokens for users.

## Table of Contents

1. [Installation](#installation)
2. [Usage](#usage)
3. [Keycloak Configuration](#keycloak-configuration)
4. [Deployment](#deployment)
5. [License](#license)
6. [Contributors](#contributors)

### Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/Modapto/access-control.git
    cd access-control
    ```

2. Install the dependencies:

    ```sh
    mvn install
    ```

3. Instantiate an instance of Keycloak with PostgreSQL and configure the following variables in the application properties:

    ```sh
   spring.security.oauth2.resourceserver.jwt.issuer-uri=${KC_ISSUER_URI:###}
   spring.security.oauth2.resourceserver.jwt.jwk-set-uri=${spring.security.oauth2.resourceserver.jwt.issuer-uri}/protocol/openid-connect/certs
   keycloak.token-uri=${KC_TOKEN_URI:###}
   keycloak.admin.uri=${KC_ADMIN_URI:###}
   keycloak.client-id=${KC_CLIENT_ID:###}
   keycloak.client-secret=${KC_CLIENT_SECRET:###}
   keycloak.admin-username=${KC_ADMIN_USERNAME:###}
   keycloak.admin-password=${KC_ADMIN_PASSWORD:###}
   keycloak.realm=${KC_REALM:###}
   keycloak.auth-server-url=${KC_AUTH_SERVER:###}
   spring.mail.username = ${GMAIL_USERNAME:MODAPTO}
   spring.mail.password = ${GMAIL_APP_PASSWORD:###}
    ```

4. If deployed via Docker Compose file the following variables must be set in the .env file:

    ```sh
    POSTGRES_USER=
    POSTGRES_PASSWORD=
    KEYCLOAK_ADMIN_USER=
    KEYCLOAK_ADMIN_PASSWORD=
    PGADMIN_DEFAULT_EMAIL=
    PGADMIN_DEFAULT_PASSWORD=
    HOST_IP=
    MAIL_USERNAME=
    MAIL_PASSWORD=
    ```

5. Upon the usage of the Component, when creating a new User, an activation process is followed as displayed below:

    a. Super Admin / Admin creates a new User

    b. An activation token and expiration time are generated as attributes of User, which is initialized as disabled User

    c. An email is sent to the designated email address with the token value that must be passed along with the new password for the user to be enabled to MODAPTO system.

### Usage

1. Run the application after Keycloak is deployed:

    ```sh
    mvn spring-boot:run
    ```

2. The application will start on `http://localhost:8093`.

3. Access the OpenAPI documentation at `http://localhost:8093/api/user-manager/swagger-ui/index.html`.

4. Set up properly the Identity Manager described in the next section

5. **NOTE**: To use the app and its APIs a user must be initially authenticated in the platform (/api/users/authenticate). Depending on the action, some requests would require specific privileges according to the user type (Super Admin, Admin, User).

### Keycloak Configuration

On folder [Keycloak Realm Data](./Keycloak_Realm_Data) two files can be located:

1. **modapto-dev-realm.json** : Configuration of modapto-dev realm

2. **modapto-dev-users.json** : Two initial users for MODAPTO. More user can be created as requested

Upon the initialization of Keycloak container, we implement the following steps to initialize the realm:

1. Press to create a new Realm

2. Upload the **modapto-dev-realm.json**

3. Press create realm

To accordingly upload the initial users in the system:

1. Navigate to Realm Settings

2. On the top right corner of UI press "Action"

3. Select "Partial Import"

4. Upload the **modapto-dev-users.json** file

5. Select the box for user creation and set the resource strategy to overwrite / skip

6. Press "Import"

For the created Users you can use the following credentials (username / password):

1. **CRF User**: crf@test.com / CRF@user123@

2. **Super Admin**: superadmin@admin.com / S@admin123@

Current configuration of Keycloak Roles, User Attributes, Clients and Realm Roles is depicted in the following images.

#### Groups

![Keycloak Groups](../../blob/main/images/Groups.png)

#### Realm Roles

![Keycloak Realm Roles](../../blob/main/images/Realm_Roles.png)

#### User Attributes

![Keycloak User Attributes](../../blob/main/images/User_Attributes.png)

#### Client Roles

![Keycloak Client Roles](../../blob/main/images/Client_Roles.png)


### Deployment

For local deployment Docker containers can be utilized to deploy the microservice with the following procedure:

1. Ensure Docker is installed and running.

2. Build the maven project:

    ```sh
    mvn package
    ```

3. Build the Docker container:

    ```sh
    docker build -t modapto-user-manager .
    ```

4. Run the Docker container including the environmental variables:

    ```sh
    docker run -d -p 8093:8093 --name modapto-user-manager modapto-user-manager
    ```

5. To stop container run:

    ```sh
   docker stop modapto-user-manager
    ```

Along with the Spring Boot application docker container in the project repository there is a Docker Compose file to instantiate a local instance of Keycloak and PostgreSQL.
Create an .env file to include the corresponding environmental variables.

## License

This project has received funding from the European Union's Horizon 2022 research and innovation programm, under Grant Agreement 101091996.

For more details about the licence, see the [LICENSE](LICENSE) file.

## Contributors

- Alkis Aznavouridis (<a.aznavouridis@atc.gr>)
