# Intranet API - Escuela de Posgrado UNSAAC

API REST del sistema intranet para la Escuela de Posgrado de la Universidad Nacional de San Antonio Abad del Cusco.

## Tecnologías

- **Java 21**
- **Spring Boot 3.5.6**
  - Spring Data JPA
  - Spring Security
  - Spring Web
  - Spring Mail
  - Spring Validation
- **JWT (JSON Web Tokens)** - io.jsonwebtoken 0.12.7
- **SQL Server** - Base de datos
- **Thymeleaf** - Motor de plantillas para emails
- **Lombok** - Reducción de código boilerplate
- **Maven** - Gestión de dependencias
- **Docker** - Contenedorización

## Estructura del Proyecto

```
src/
├── main/
│   ├── java/com/posgrado/intranet/
│   │   ├── common/
│   │   │   ├── config/
│   │   │   ├── middlewares/
│   │   │   ├── properties/
│   │   │   └── utils/
│   │   ├── controllers/
│   │   ├── dtos/
│   │   ├── entities/
│   │   ├── repositories/
│   │   └── services/
│   └── resources/
│       ├── templates/
│       ├── application.properties
│       └── application.properties.example
└── test/
```

## Instalación

### Prerrequisitos

- Java 21 o superior
- Maven 3.9+
- SQL Server
- Git

### Pasos

1. Clonar el repositorio:

```bash
git clone <repository-url>
cd intranet
```

2. Copiar el archivo de configuración de ejemplo:

```bash
cp src/main/resources/application.properties.example src/main/resources/application.properties
```

3. Configurar las variables de entorno (ver sección siguiente)

4. Instalar dependencias:

```bash
./mvnw clean install
```

## Variables de Entorno

Crear o modifica un archivo `application.properties` con las siguientes variables:

### Base de Datos

```properties
DB_URL=jdbc:sqlserver://localhost:1433;databaseName=nombre_bd;encrypt=true;trustServerCertificate=true
DB_USER=usuario
DB_PASSWORD=contraseña
```

### JWT (JSON Web Tokens)

```properties
JWT_SECRET=tu-clave-secreta-muy-larga-y-segura-minimo-256-bits
JWT_ACCESS_EXPIRATION=300000          # 5 minutos en milisegundos
JWT_REFRESH_EXPIRATION=900000         # 15 minutos en milisegundos
```

### Cookies

```properties
# Desarrollo
COOKIE_SECURE=false
COOKIE_SAMESITE=None
COOKIE_ACCESS_MAX_AGE=300             # 5 minutos en segundos
COOKIE_REFRESH_MAX_AGE=900            # 15 minutos en segundos
COOKIE_PATH=/auth/refresh

# Producción (recomendado)
COOKIE_SECURE=true
COOKIE_SAMESITE=Strict
```

### Email (Gmail SMTP)

```properties
MAIL_USERNAME=tu-email@gmail.com
MAIL_PASSWORD=tu-app-password         # Contraseña de aplicación de Gmail
```

## Ejecución

### Desarrollo

```bash
# Usando Maven Wrapper
./mvnw spring-boot:run

# O con Maven instalado
mvn spring-boot:run
```

La aplicación estará disponible en `http://localhost:8080`

## Endpoints Principales

### Autenticación

- `POST /auth/login` - Iniciar sesión
- `POST /auth/refresh` - Refrescar token
- `POST /auth/forgot-password` - Solicitar recuperación de contraseña
- `PUT /auth/update-forgot-password` - Actualizar contraseña olvidada

### Estudiante (requiere rol ESTUDIANTE)

- `GET /estudiante/**` - Endpoints para estudiantes

### Protegidos (requiere autenticación)

- `GET /protected/**` - Recursos protegidos

### Público

- `GET /health` - Health check
- `GET /public` - Recurso público

## Configuración de Seguridad

### CORS

La aplicación está configurada para aceptar peticiones desde:

- `http://localhost:*` (desarrollo)
- `http://127.0.0.1:*` (desarrollo)

En producción añadir o modificar.

### Autenticación

- Sistema basado en JWT con tokens de acceso y refresh
- Access token almacenado en memory storage
- Refresh token almacenado en cookies HTTP-only
- Configuración de SameSite según entorno (Strict en producción, None en desarrollo)
