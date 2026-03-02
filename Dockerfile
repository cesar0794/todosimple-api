FROM maven:3.8.3-openjdk-17

ENV PROJECT_HOME=/app

# Create destination directory
RUN mkdir -p $PROJECT_HOME
WORKDIR $PROJECT_HOME

# Bundle app source (Corrigido para . .)
COPY . .

# Package the application as a JAR file
RUN mvn clean package -DskipTests

# Move e renomeia o arquivo gerado de forma dinâmica (ignora a versão)
RUN cp target/*.jar todosimpleapp.jar

ENTRYPOINT ["java", "-jar", "-Dspring.profiles.active=prod", "todosimpleapp.jar"]