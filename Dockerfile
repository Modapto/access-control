FROM maven:3.9.9-eclipse-temurin-21 AS build

WORKDIR /usr/src/app

# Download Dependencies and user Cache
COPY pom.xml .
RUN mvn -B dependency:go-offline

# Copy source code and Build the App
COPY src/ src/
RUN mvn -B -Dmaven.test.skip clean package

FROM openjdk:21-jdk
COPY --from=build /usr/src/app/target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
