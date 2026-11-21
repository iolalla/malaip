# Especificación Técnica: SSH Guard GNOME (`ssh-watch-gnome`)

## 1. Resumen del Proyecto

**`ssh-watch-gnome`** es un demonio en segundo plano escrito en **Go** para Ubuntu Desktop (GNOME). Monitorea en tiempo real los intentos fallidos de autenticación en el servidor OpenSSH (`sshd`), realiza enriquecimiento de datos asíncrono vía `whois`, maneja un sistema de caché y control de frecuencia para evitar sobrecarga de alertas, y despliega notificaciones nativas en el escritorio mediante D-Bus.

---

## 2. Decisiones de Arquitectura (Go)

### 2.1 Stack Tecnológico
* **Lenguaje:** Go 1.22+
* **Lectura de Logs:** Streaming continuo desde `journalctl` mediante `os/exec.CommandContext` o integración directa con la tubería del sistema.
* **Integración D-Bus:** `github.com/godbus/dbus/v5` para comunicación nativa directa con `org.freedesktop.Notifications` (sin depender del binario `notify-send`).
* **Concurrencia:** *Goroutines* y *Channels* para procesar eventos de log y realizar consultas `whois` de manera totalmente asíncrona sin bloquear el hilo principal.
* **Caché y Cooldown:** Estructuras en memoria thread-safe (`sync.RWMutex` + `map`) con temporizadores `time.Timer` / `time.Ticker` para gestión de TTL y rate-limiting.

### 2.2 Ejecución en Espacio de Usuario (`systemd --user`)
* **Servicio:** `~/.config/systemd/user/ssh-watch-gnome.service`
* **Permisos:** El usuario de Ubuntu debe pertenecer al grupo `adm` o `systemd-journal` para poder leer el journal de `sshd` sin elevación de privilegios (`sudo`).
* **Entorno Gráfico:** Hereda automáticamente el socket D-Bus de la sesión activa (`DBUS_SESSION_BUS_ADDRESS`).

---

## 3. Requisitos Funcionales (RF)

### RF-01: Filtrado y Parseo de Intrusiones SSH
El sistema debe leer el flujo `journalctl -u ssh -u sshd -f -n 0 -o cat` y parsear en tiempo real los siguientes patrones mediante expresiones regulares compiladas (`regexp.Regexp`):
* `Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+`
* `Invalid user (?P<user>\S+) from (?P<ip>\S+) port \d+`
* `Connection closed by authenticating user (?P<user>\S+) (?P<ip>\S+) port \d+ \[preauth\]`
* `error: maximum authentication attempts exceeded for .* from (?P<ip>\S+)`

### RF-02: Validación y Whitelist de IPs
* Parseo y validación estricta usando el paquete estándar `net/netip` o `net`.
* Comprobar si la IP detectada pertenece a un rango excluido (`whitelist_cidrs`), ignorando inmediatamente el evento si coincide (ej. `127.0.0.1/8`, `::1/128`, subredes locales).

### RF-03: Consulta WHOIS Asíncrona y Caché de Respuestas
* **Ejecución Asíncrona:** Cada evento de IP desconocida dispara una *goroutine* con un `context.WithTimeout` de máximo **4 segundos**.
* **Extracción de campos:**
  * **Organización / ISP:** Claves `OrgName`, `org-name`, `descr`, `owner`.
  * **País:** Claves `Country`, `country`.
  * **ASN / CIDR:** Claves `OriginAS`, `origin`, `CIDR`, `route`.
* **Caché TTL:** Almacenar el resultado en una estructura thread-safe durante 24 horas (`whois_cache_ttl_hours`). Si la IP vuelve a intentar un login dentro de este periodo, se usa la información almacenada sin volver a consultar la red.

### RF-04: Control de Frecuencia (Rate Limiting / Debounce)
* Mantenimiento de una tabla de enfriamiento por IP.
* Si una IP genera múltiples eventos fallidos en menos de $N$ segundos (`cooldown_seconds`, por defecto 60s), suprimir pop-ups repetidos e incrementar un contador de ataques agrupados.

### RF-05: Emisión de Notificaciones en GNOME
* Conexión directa a D-Bus mediante el servicio `org.freedesktop.Notifications`.
* Parámetros de la notificación:
  * **AppName:** `ssh-watch-gnome`
  * **Urgency:** `2` (Critical - permanece visible en pantalla hasta interacción o descarte manual).
  * **Icon:** `dialog-warning` o `security-low`
* **Sanitización Pango Markup:** Escapar caracteres `<` (`&lt;`), `>` (`&gt;`), `&` (`&amp;`) mediante `html.EscapeString` antes de formatear el cuerpo del mensaje.
* **Formato del Pop-up:**
  ```text
  ⚠️ Intento fallido de SSH
  IP: 203.0.113.45 (CN)
  Usuario: root
  Organización: China Telecom (AS4134)
  Intentos detectados: 1
  ```

### RF-06: Configuración del Sistema
Soporte para cargar opciones desde `~/.config/ssh-watch-gnome/config.json`:
```json
{
  "cooldown_seconds": 60,
  "whois_cache_ttl_hours": 24,
  "whois_timeout_seconds": 4,
  "urgency": 2,
  "whitelist_cidrs": [
    "127.0.0.1/32",
    "::1/128",
    "192.168.1.0/24"
  ]
}
```

---

## 4. Requisitos No Funcionales (RNF)

* **Rendimiento:** Consumo de memoria RAM $< 15\text{ MB}$ y consumo de CPU $< 0.5\%$ en reposo.
* **Seguridad:** No ejecutar subprocesos con intérpretes de comandos (`sh -c`). Invocación directa de ejecutable `whois` con argumentos sanitizados en un slice `[]string`.
* **Concurrencia Segura:** Ausencia de condiciones de carrera (*race conditions*) comprobables con `go run -race .`.
* **Resiliencia:** El servicio `systemd` debe contar con `Restart=always` y retraso de reinicio de 5 segundos en caso de fallo.

---

## 5. Estructura del Proyecto Go

```text
ssh-watch-gnome/
├── spec.md                       # Especificación técnica
├── go.mod                        # Módulo Go
├── go.sum                        # Sumas de verificación de dependencias
├── config.example.json           # Plantilla de configuración JSON
├── Makefile                      # Comandos build, install, test
├── systemd/
│   └── ssh-watch-gnome.service   # Unidad systemd --user
├── cmd/
│   └── ssh-watch-gnome/
│       └── main.go               # Punto de entrada y orquestación
└── internal/
    ├── config/                   # Carga y parsing de config.json
    ├── logwatcher/               # Streaming y regex de journalctl
    ├── whois/                    # Cliente WHOIS con contexto y caché TTL
    ├── limiter/                  # Rate-limiting por IP
    └── notifier/                 # Conector D-Bus para GNOME Shell
```

---

## 6. Configuración de `systemd --user`

Archivo `systemd/ssh-watch-gnome.service`:

```ini
[Unit]
Description=SSH Guard GNOME Notifier
After=network.target graphical-session.target

[Service]
Type=simple
ExecStart=%h/.local/bin/ssh-watch-gnome
Restart=always
RestartSec=5s
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:%h/.local/bin

[Install]
WantedBy=default.target
```

---

## 7. Criterios de Aceptación (MVP)

1. **Compilación estática:** `go build` genera un único binario independiente sin errores ni advertencias del linter.
2. **Prueba de alerta:** Al forzar un login fallido simulado, la notificación de GNOME aparece en menos de 1 segundo.
3. **Resistencia a ataques de fuerza bruta:** Al generar 50 intentos seguidos en 2 segundos, solo se muestra **1 notificación** y se ejecuta **1 consulta WHOIS**.
4. **Persistencia:** Al reiniciar el sistema, el servicio inicia automáticamente al iniciar la sesión gráfica.