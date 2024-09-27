# Utilizza l'immagine ufficiale OpenJDK come base
FROM amazoncorretto:17-alpine

# Imposta la directory di lavoro nel container
WORKDIR /app

# Copia il file JAR generato nella working directory del container
COPY target/*.jar app.jar

# Definisci variabili d'ambiente (opzionale, se vuoi valori predefiniti)
ENV PROFILE=prod
ENV RAMO=main
ENV SEQ=1
ENV JAVA_OPTS="-XX:MaxRAM=98m -XX:+UseSerialGC -Xss512k"

# Comando di avvio che utilizza le variabili d'ambiente
ENTRYPOINT ["java", "-jar", "/app/app.jar", "-Dspring.profiles.active=${PROFILE}", "-Dseq=${SEQ}", "-Dramo=${RAMO}", "${JAVA_OPTS}"]
