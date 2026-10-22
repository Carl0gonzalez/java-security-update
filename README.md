# Java Security Update

Herramienta conservadora para auditar instalaciones Java en Ubuntu, Debian y derivados que usan APT, particularmente servidores iDempiere sin contenedores.

## Auditoría desde GitHub Raw (solo lectura)

```bash
curl -fsSL https://raw.githubusercontent.com/Carl0gonzalez/java-security-update/main/java-security-update.sh | bash -s -- --audit
```

Si la instalación de Java utiliza rutas no habituales, primero descarga el script y ejecuta `bash java-security-update.sh --audit --root /ruta`.

## Actualización segura

**No ejecutar `curl | sudo bash` en producción.** Descargar, verificar el hash publicado por un canal independiente y revisar el script antes de usar privilegios administrativos:

```bash
curl -fsSLo java-security-update.sh https://raw.githubusercontent.com/Carl0gonzalez/java-security-update/main/java-security-update.sh
sha256sum java-security-update.sh
bash -n java-security-update.sh
less java-security-update.sh
bash java-security-update.sh --audit
sudo bash java-security-update.sh --apply
```

SHA-256 correspondiente a la primera versión publicada:

```text
63bab4224c681feda4b36206ee642848ed3e653870e6b766b86142c39f818173  java-security-update.sh
```

### Comportamiento

- `--audit`: descubre binarios JDK/JRE, proveedores, ubicaciones, paquetes APT y procesos Java, sin modificar el sistema.
- `--apply`: consulta versiones disponibles, simula actualizaciones APT de paquetes Java y certificados ya instalados, muestra el plan y requiere escribir `ACTUALIZAR` para continuar.
- No sustituye instalaciones manuales de JDK y no cambia deliberadamente de versión mayor (11 a 17, por ejemplo).
- No reinicia iDempiere por sí mismo, aunque scripts postinstalación de APT podrían reiniciar servicios. Programar una ventana de mantenimiento.
- **No garantiza que una CVE particular esté mitigada.** Verificar avisos del fabricante de Java y almacenes de certificados.
- Los procesos Java existentes deben reiniciarse de forma controlada para cargar la JVM actualizada.
- El SHA-256 almacenado junto al script verifica integridad únicamente si el valor esperado fue obtenido de manera confiable; un atacante con control del repositorio podría sustituir ambos.

## Uso local

```bash
git clone git@github.com:Carl0gonzalez/java-security-update.git
cd java-security-update
sha256sum -c java-security-update.sh.sha256
bash java-security-update.sh --audit
```

El archivo Raw en `main` puede cambiar. En producción, es preferible fijar una revisión/commit conocido y verificar su SHA-256 por un canal distinto.
