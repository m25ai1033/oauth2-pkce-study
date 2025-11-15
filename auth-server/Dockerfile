FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Copy the pre-built JAR (build it locally first)
COPY auth-server/build/libs/auth-server-*.jar app.jar

# Create non-root user
RUN addgroup -S spring && adduser -S spring -G spring
USER spring

# Expose port
EXPOSE 9000

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"]