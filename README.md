# repodata - parche de seguridad

Este backend mantiene la estructura simple de `json-server`, pero corrige los problemas críticos encontrados en la versión original.

## Cambios principales

- Las contraseñas ya no se comparan en Angular ni se devuelven desde `/usuarios`.
- Las contraseñas se almacenan con `scrypt` + salt usando `crypto` de Node.
- Las contraseñas antiguas en texto plano se migran automáticamente al iniciar.
- El login crea una sesión aleatoria guardada como hash y una cookie `HttpOnly`.
- `/auth/me` es la fuente de verdad para los guards de Angular.
- Logout elimina la sesión del backend.
- CORS usa una lista de orígenes permitidos y `credentials: true`.
- Las operaciones con cookie están protegidas contra CSRF mediante validación estricta de `Origin`.
- `/db`, CRUD genérico de `/usuarios` y CRUD genérico de `/QR` están bloqueados.
- Los datos de usuario se responden sin `password`, hashes ni tokens de recuperación.
- Registro y actualización de perfil usan listas blancas de campos. El frontend no puede definir `role` ni `isactive`.
- Recuperación de contraseña usa tokens criptográficamente aleatorios, almacenados como hash, con expiración de 15 minutos y un solo uso.
- El token de recuperación ya no se devuelve en la respuesta HTTP.
- Al cambiar la contraseña se eliminan todas las sesiones activas del usuario.
- Se agregó rate limiting a login y recuperación.
- El QR ahora debe transportar solo un token opaco; la API guarda únicamente su hash y lo invalida tras usarlo.
- La credencial SMTP ya no está escrita en `index.js`.

## Instalación

```bash
npm install
npm start
```

`npm install` generará un `package-lock.json` nuevo. Se eliminó el lock antiguo porque fijaba dependencias antiguas, entre ellas una versión de Nodemailer que ya no conviene conservar.

## Variables de entorno

Copia los nombres de `.env.example` a las variables de entorno de Render. Este proyecto no carga `.env` automáticamente; Render las inyecta directamente.

Variables importantes:

- `NODE_ENV=production`
- `CORS_ORIGINS`: orígenes exactos del frontend, separados por coma.
- `SMTP_USER`: cuenta usada para enviar correos.
- `SMTP_PASS`: contraseña de aplicación NUEVA.
- `MAIL_FROM`: remitente.
- `BOOTSTRAP_ADMIN_USERNAME`: opcional para convertir una cuenta existente en admin al arrancar.

## Muy importante: credencial de Gmail expuesta

La versión anterior tenía una contraseña de aplicación Gmail dentro de `index.js`. Debes revocarla desde la cuenta Google y generar una nueva. No basta con borrarla del archivo, porque pudo quedar en el historial de Git.

Nunca subas la nueva contraseña al repositorio. Configúrala únicamente como `SMTP_PASS` en Render.

## Endpoints usados por el frontend corregido

- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/logout`
- `POST /usuarios`
- `GET /usuarios` (solo admin)
- `PUT /usuarios/me`
- `POST /recover-password`
- `POST /reset-password`
- `GET /eventos`
- `GET /eventos/:id`
- `POST /eventos`
- `PUT /eventos/:id`
- `DELETE /eventos/:id`
- `POST /QR/issue`
- `POST /QR/validate`

## Roles

Las cuentas nuevas se crean con `role: "user"`. El cliente nunca puede enviar un rol. Para promover una cuenta existente puedes definir temporalmente:

```text
BOOTSTRAP_ADMIN_USERNAME=nombre_del_usuario
```

y reiniciar el servicio. Después puedes quitar esa variable.

Actualmente, para conservar el comportamiento de tu aplicación existente, cualquier usuario autenticado y activo puede crear/modificar/eliminar eventos y validar QR. Si quieres separar estrictamente administrador/usuario, cambia las rutas de escritura para usar `requireAdmin`.

## Limitación importante de almacenamiento

`json-server` + `almacen.json` es adecuado para una demostración/prototipo, pero no es una base de datos de producción. En Render, el sistema de archivos del servicio puede ser efímero y además no ofrece transacciones ni un modelo robusto de concurrencia.

Para una versión real del proyecto, el siguiente paso debería ser mover usuarios, sesiones, eventos y QR a PostgreSQL u otra base de datos y usar un backend Express/Fastify/Nest dedicado.
