# Запуск готового артефакта. Исходники в репозиторий НЕ входят — их восстановление
# (декомпиляция) является частью задания.
FROM eclipse-temurin:11-jre
WORKDIR /app
COPY prebuilt/tickets.jar app.jar

# Флаги намеренно включают классическую эксплуатацию Log4Shell на новых JDK
# (загрузка удалённого класса по JNDI) — учебный уязвимый стенд.
ENV JAVA_TOOL_OPTIONS="-Dcom.sun.jndi.ldap.object.trustURLCodebase=true -Dcom.sun.jndi.rmi.object.trustURLCodebase=true"

EXPOSE 8080
CMD ["java", "-jar", "app.jar", "--server.port=8080"]
