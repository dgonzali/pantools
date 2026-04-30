# Panorama API Scripts

Colección de scripts Python para automatizar tareas en **Palo Alto Networks Panorama** vía API XML.

---

## Scripts disponibles

| Script | Descripción |
|--------|-------------|
| [`01-rule_renamer.py`](#1-rule-renamer) | Renombra reglas de seguridad usando su UUID |
| [`02-objects_search.py`](#2-objects-search) | Busca objetos de red (address/group) en reglas de seguridad por IP/red |
| [`03-pan_device_admins.py`](#3-pan-device-admins) | Audita los administradores y roles de los firewalls conectados |

---

## Requisitos comunes

- Python 3.8+
- Acceso de red a Panorama (puerto 443)
- API Key con los permisos adecuados

### Instalación de dependencias

```bash
pip install -r requirements.txt
```

**Dependencias:**

| Paquete | Uso |
|---------|-----|
| `requests` | Llamadas HTTP a la API de Panorama |
| `python-dotenv` | Carga de variables de entorno desde `.env` |
| `urllib3` | Supresión de warnings SSL (certificado auto-firmado) |

---

## Configuración

Crea (o edita) el fichero `.env` en el directorio del proyecto:

```env
PAN_URL=https://<ip-o-hostname-panorama>
PAN_API_KEY=<tu-api-key>
```

> La API Key se puede obtener desde Panorama en **Device → Administrators** o vía API:
> ```
> GET /api/?type=keygen&user=<usuario>&password=<password>
> ```

---

## Estructura del proyecto

```
Pantools/
├── .env                        # Credenciales de Panorama (no subir a git)
├── 01-rule_renamer.py          # Renombrador de reglas por UUID
├── 02-objects_search.py        # Buscador de objetos por IP/red en reglas
├── 03-pan_device_admins.py     # Auditor de administradores en firewalls
├── requirements.txt            # Dependencias Python
└── README.md                   # Este fichero
```

---

---

# 1. Rule Renamer

Script Python para renombrar reglas de política de seguridad en Panorama usando el **UUID** de la regla como identificador de entrada.

## ¿Por qué este script?

La API XML de PAN-OS/Panorama expone el comando `rename`, pero **este comando requiere el nombre actual de la regla**, no su UUID. Sin embargo, en muchos flujos de automatización el identificador disponible es el UUID (inmutable, único globalmente).

Este script resuelve el problema en dos pasos:

1. **Resolver UUID → Nombre actual** mediante una consulta `get` con un predicado XPath sobre el atributo `@uuid`.
2. **Renombrar** la regla con el comando `rename` usando el nombre obtenido en el paso anterior.

## Flujo de ejecución

```
INPUT: uuid | device-group | new-name
          │
          ▼
┌─────────────────────────────────────┐
│  Paso 1: GET (config/get)           │
│  Busca la regla por @uuid           │
│  → Obtiene el nombre actual         │
│  → Detecta pre o post rulebase      │
└─────────────────┬───────────────────┘
                  │ nombre actual + rulebase
                  ▼
┌─────────────────────────────────────┐
│  Paso 2: GET (config/rename)        │
│  Renombra usando el nombre actual   │
│  → Aplica en candidate config       │
└─────────────────────────────────────┘
          │
          ▼
OUTPUT: Confirmación + aviso de commit pendiente
```

## Llamadas API

### Paso 1 — Buscar la regla por UUID

| Campo | Valor |
|-------|-------|
| Método | `GET` |
| Endpoint | `/api/` |
| `type` | `config` |
| `action` | `get` |
| `xpath` | Ver abajo |

**XPath — Device Group normal (pre-rulebase):**
```
/config/devices/entry[@name='localhost.localdomain']
  /device-group/entry[@name='{DEVICE_GROUP}']
    /pre-rulebase/security/rules/entry[@uuid='{UUID}']
```

**XPath — Shared (pre-rulebase):**
```
/config/shared
  /pre-rulebase/security/rules/entry[@uuid='{UUID}']
```

> ⚠️ Las reglas del nivel **Shared** en Panorama **no** se almacenan bajo
> `/device-group/entry[@name='Shared']`, sino directamente bajo `/config/shared/`.
> El script detecta automáticamente este caso cuando `--device-group Shared`.

Si no se encuentra en `pre-rulebase`, se reintenta con `post-rulebase` en la misma ruta base.

**Respuesta esperada (XML):**
```xml
<response status="success">
  <result>
    <entry name="Allow-HTTP-Viejo" uuid="12345678-abcd-...">
      ...
    </entry>
  </result>
</response>
```

### Paso 2 — Renombrar la regla

| Campo | Valor |
|-------|-------|
| Método | `GET` |
| Endpoint | `/api/` |
| `type` | `config` |
| `action` | `rename` |
| `xpath` | Ver abajo |
| `newname` | Nuevo nombre de la regla |

**XPath — Device Group normal:**
```
/config/devices/entry[@name='localhost.localdomain']
  /device-group/entry[@name='{DEVICE_GROUP}']
    /{pre-rulebase|post-rulebase}/security/rules/entry[@name='{NOMBRE_ACTUAL}']
```

**XPath — Shared:**
```
/config/shared
  /{pre-rulebase|post-rulebase}/security/rules/entry[@name='{NOMBRE_ACTUAL}']
```

**Respuesta esperada (XML):**
```xml
<response status="success">
  <msg>command succeeded</msg>
</response>
```

> ⚠️ **Importante:** El cambio se aplica únicamente en el **candidate config** de Panorama. Es necesario hacer **commit** en Panorama y, opcionalmente, un **push** a los firewalls gestionados.

## Uso

```bash
python 01-rule_renamer.py \
  --uuid "<UUID-DE-LA-REGLA>" \
  --device-group "<NOMBRE-DEL-DEVICE-GROUP>" \
  --new-name "<NUEVO-NOMBRE>"
```

### Parámetros

| Parámetro | Descripción |
|-----------|-------------|
| `--uuid` | UUID de la regla (formato `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) |
| `--device-group` | Nombre exacto del Device Group en Panorama |
| `--new-name` | Nuevo nombre que se aplicará a la regla |

### Ejemplo

```bash
python 01-rule_renamer.py \
  --uuid "a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  --device-group "DG-PRODUCCION" \
  --new-name "Allow-HTTP-Servidores-Web"
```

### Salida esperada

```
============================================================
  Panorama Rule Renamer
============================================================
  Panorama  : https://panorama.ejemplo.com
  UUID      : a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Dev Group : DG-PRODUCCION
  New Name  : Allow-HTTP-Servidores-Web
============================================================

[INFO] Buscando regla en pre-rulebase con XPath: ...
[INFO] Regla encontrada en pre-rulebase: 'Allow-HTTP-Viejo'

[INFO] Renombrando 'Allow-HTTP-Viejo' → 'Allow-HTTP-Servidores-Web'
       XPath: /config/devices/entry[...]/pre-rulebase/security/rules/entry[@name='Allow-HTTP-Viejo']
[OK] Rename ejecutado correctamente. Respuesta: command succeeded

[AVISO] El cambio está en el candidate config de Panorama.
        Recuerda hacer commit en Panorama (y push al firewall si es necesario).
```

---

---

# 2. Objects Search

Script Python para **buscar reglas de seguridad en Panorama** que referencien objetos de tipo `address` o `address-group` que incluyan (o se solapen con) una red IP determinada.

## Caso de uso

Panorama no ofrece de forma nativa un buscador de objetos por red IP que cruce los resultados con las reglas que los usan. Este script cubre ese hueco:

1. Localiza todos los `address objects` cuyo `ip-netmask` coincide con la red buscada.
2. Resuelve de forma recursiva los `address-groups` que los contienen.
3. Escanea las `pre-rulebase` y `post-rulebase` de todos (o un subset) de Device Groups e indica en qué reglas aparece cada objeto, tanto en `source` como en `destination`.

## Uso

```bash
# Buscar la red en todos los Device Groups + shared (modo overlapping por defecto)
python 02-objects_search.py --network 10.10.10.0/24

# Limitar la búsqueda a un Device Group concreto
python 02-objects_search.py --network 10.10.10.0/24 --device-group MiDeviceGroup

# Buscar solo en los objetos compartidos (shared)
python 02-objects_search.py --network 10.10.10.5/32 --device-group shared

# Modo exacto: solo objetos cuya red sea exactamente la indicada
python 02-objects_search.py --network 10.10.10.0/24 --exact

# Guardar el resultado en un fichero además de mostrarlo en pantalla
python 02-objects_search.py --network 10.10.10.0/24 --output resultado.txt
```

## Argumentos

| Argumento | Obligatorio | Descripción |
|-----------|-------------|-------------|
| `--network IP/MASK` | ✅ | Red en formato CIDR: `10.0.0.0/8`, `192.168.1.1/32`, etc. |
| `--device-group DG` | ❌ | Limitar el ámbito. Sin este argumento se busca en **todos** los DG y shared. Usa `shared` para solo objetos compartidos. |
| `--exact` | ❌ | Solo coincidencias exactas de red. Por defecto también incluye supernets y subnets. |
| `--output FILE` | ❌ | Fichero de texto donde guardar el resultado adicionalmente. |

## Modo de coincidencia (overlapping vs exacto)

| Modo | Qué incluye |
|------|-------------|
| **Overlapping** (por defecto) | Objetos cuya red es exactamente la buscada, la contiene o está contenida en ella. Ej: buscando `10.10.10.0/24` también aparece `10.10.0.0/16` (supernet) y `10.10.10.128/25` (subnet). |
| **Exacto** (`--exact`) | Solo objetos que tienen exactamente la misma red. |

## Ejemplo de salida

```
======================================================================
  Panorama Objects Search — Resultados
======================================================================
  Red buscada  : 10.10.10.0/24
  Modo         : Overlapping (contiene / está contenida)
  Ámbito       : Todos los Device Groups + shared
======================================================================

── OBJETOS ADDRESS COINCIDENTES ──────────────────────────────────
  [shared]
    • net-10.10.10.0_24
  [DG-PRODUCCION]
    • host-10.10.10.5

── ADDRESS-GROUPS QUE LOS INCLUYEN ───────────────────────────────
  [shared]
    • grp-redes-internas
  [DG-PRODUCCION]
    • grp-servidores-prod

── REGLAS DE SEGURIDAD AFECTADAS ─────────────────────────────────

  Device Group: DG-PRODUCCION
  --------------------------------------------------
  [pre-rulebase] Allow-HTTP-Interno
      Source → grp-redes-internas
  [pre-rulebase] Block-SSH-Externo
      Destination → host-10.10.10.5, grp-servidores-prod

======================================================================
  Total reglas encontradas: 2
======================================================================
```

---

---

# 3. Pan Device Admins

Script Python para obtener los **usuarios administradores y sus roles** configurados en todos los firewalls conectados a Panorama, utilizando Panorama como **proxy de API** (parámetro `target=<serial>`).

## Flujo de ejecución

```
 INPUT: [--sn | --device-name | --device-group | (ninguno)]
            |
            v
 +-----------------------------------------------+
 | Paso 1: show devices connected (op command)   |
 | Obtiene lista de firewalls conectados          |
 +-----------------------------------------------+
            |
            v
 +-----------------------------------------------+
 | Paso 2: config get device-group/entry         |
 | Construye mapa serial -> [Device Groups]       |
 +-----------------------------------------------+
            |
            v
 +-----------------------------------------------+
 | Paso 3: Filtra por --sn / --device-name /     |
 |         --device-group (o mantiene todos)      |
 +-----------------------------------------------+
            |
     Para cada dispositivo
            |
            v
 +-----------------------------------------------+
 | Paso 4: config get /config/mgt-config/users   |
 |         con target=<serial> (via Panorama)     |
 |         Extrae usuarios + tipo de rol          |
 +-----------------------------------------------+
            |
            v
 OUTPUT: Tabla por dispositivo en consola
         + CSV consolidado (si --output)
```

## Llamadas API

### Paso 1 — Dispositivos conectados

| Campo | Valor |
|-------|-------|
| `type` | `op` |
| `cmd` | `<show><devices><connected/></devices></show>` |

### Paso 2 — Mapa de Device Groups

| Campo | Valor |
|-------|-------|
| `type` | `config` |
| `action` | `get` |
| `xpath` | `/config/devices/entry[@name='localhost.localdomain']/device-group/entry` |

> Esta llamada es necesaria porque el comando operacional `show devices connected` no incluye la pertenencia a Device Groups en su respuesta XML. El script la obtiene separadamente de la configuración de Panorama.

### Paso 3 — Administradores del dispositivo (vía proxy)

| Campo | Valor |
|-------|-------|
| `type` | `config` |
| `action` | `get` |
| `xpath` | `/config/mgt-config/users/entry` |
| `target` | Serial number del firewall |

El parámetro `target` hace que Panorama actúe como proxy y enruta la petición directamente al firewall con ese serial number, sin necesidad de acceder directamente a cada equipo.

**Respuesta esperada (XML):**
```xml
<response status="success">
  <result>
    <entry name="admin">
      <permissions>
        <role-based>
          <superuser/>
        </role-based>
      </permissions>
    </entry>
    <entry name="readonly">
      <permissions>
        <role-based>
          <superreader/>
        </role-based>
      </permissions>
    </entry>
    <entry name="operador">
      <permissions>
        <role-based>
          <custom>
            <profile>mi-perfil-personalizado</profile>
          </custom>
        </role-based>
      </permissions>
    </entry>
  </result>
</response>
```

## Uso

```bash
# Todos los firewalls conectados
python 03-pan_device_admins.py

# Solo un firewall por serial number
python 03-pan_device_admins.py --sn 007957000675956

# Solo un firewall por nombre de host
python 03-pan_device_admins.py --device-name FW-MADRID-01

# Solo los firewalls de un Device Group
python 03-pan_device_admins.py --device-group DG-PRODUCCION

# Cualquier filtro + exportar a CSV
python 03-pan_device_admins.py --device-group DG-PRODUCCION --output admins.csv
```

### Argumentos

| Argumento | Descripción |
|-----------|-------------|
| *(ninguno)* | Consulta todos los firewalls conectados a Panorama |
| `--sn SERIAL` | Limita la consulta al firewall con ese serial number |
| `--device-name NOMBRE` | Limita la consulta al firewall con ese hostname |
| `--device-group DG` | Limita la consulta a los firewalls del Device Group indicado |
| `--output FICHERO.CSV` | Exporta los resultados consolidados a un fichero CSV |

> `--sn`, `--device-name` y `--device-group` son **mutuamente excluyentes**. `--output` es compatible con cualquiera de ellos.

### Roles soportados

| Valor interno | Descripción |
|---------------|-------------|
| `superuser` | Super User (acceso total a Panorama/firewall) |
| `superreader` | Super Reader (solo lectura) |
| `deviceadmin` | Device Administrator |
| `devicereader` | Device Reader (solo lectura) |
| `custom` | Rol personalizado (muestra el nombre del perfil) |

## Salida en consola

```
======================================================================
  Panorama Device Admins Checker
======================================================================
  Panorama : https://panorama.ejemplo.com
  Filtro   : Device Group = DG-PRODUCCION
======================================================================

[INFO] Consultando dispositivos conectados a Panorama...
[INFO] 3 dispositivo(s) conectado(s) encontrado(s).
[INFO] Consultando administradores en 1 dispositivo(s)...

[INFO] -> FW-MADRID-01 (007957000675956) ...

======================================================================
  RESULTADO: Administradores por dispositivo
======================================================================

  +- Dispositivo : FW-MADRID-01
  |  Serial      : 007957000675956
  |  Modelo      : PA-VM   PAN-OS: 11.1.6-h10
  |  IP gestion  : 10.3.0.4
  |  Device Group: DG-PRODUCCION
  |  Admins (4):
  |    * admin                     Super User (acceso total)
  |    * apirw                     Super User (acceso total)
  |    * readonly                  Super Reader (solo lectura)
  |    * operador                  Rol personalizado -> perfil: 'securityadmin'
  +-------------------------------------------------------------------

======================================================================
  Total dispositivos consultados : 1
  Total administradores encontrados: 4
======================================================================
[OK] Exportado a CSV: admins.csv
```

## Formato del CSV exportado

Cuando se usa `--output`, se genera un fichero CSV con **una fila por cada combinación dispositivo + administrador**:

| Columna | Descripción |
|---------|-------------|
| `device_name` | Hostname del firewall |
| `serial` | Serial number |
| `model` | Modelo del dispositivo |
| `sw_version` | Versión de PAN-OS |
| `ip` | IP de gestión |
| `device_groups` | Device Groups asignados (separados por `;` si hay varios) |
| `username` | Nombre del administrador |
| `role_type` | Tipo de rol interno (`superuser`, `custom`, etc.) |
| `role_label` | Descripción legible del rol |
| `role_profile` | Nombre del perfil si es un rol personalizado |

**Ejemplo:**
```
device_name,serial,model,sw_version,ip,device_groups,username,role_type,role_label,role_profile
FW-MADRID-01,007957000675956,PA-VM,11.1.6-h10,10.3.0.4,DG-PRODUCCION,admin,superuser,Super User (acceso total),
FW-MADRID-01,007957000675956,PA-VM,11.1.6-h10,10.3.0.4,DG-PRODUCCION,operador,custom,Rol personalizado,securityadmin
```

---

## Consideraciones de seguridad

- **No subas el `.env` a ningún repositorio.** Añádelo al `.gitignore`.
- El script deshabilita la verificación SSL (`verify=False`) para entornos con certificados auto-firmados. En producción, proporciona el certificado CA con `verify='/ruta/al/ca-bundle.crt'`.
- La API Key tiene el mismo nivel de acceso que el usuario administrador asociado. Usa cuentas con el **mínimo privilegio necesario**.
