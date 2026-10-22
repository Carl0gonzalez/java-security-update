#!/usr/bin/env bash
# Auditoría y actualización conservadora de Java en Ubuntu/Debian.
# Uso: bash java-security-update.sh --audit
#      sudo bash java-security-update.sh --apply
set -Eeuo pipefail
export LC_ALL=C
umask 077

MODE="audit"
declare -a EXTRA_ROOTS=()
declare -A SEEN_JAVA=()
declare -a JDK_BINARIES=()

usage() {
  cat <<'HELP'
Uso:
  bash java-security-update.sh --audit [--root /ruta]
  sudo bash java-security-update.sh --apply [--root /ruta]

--audit   Solo lectura: detecta JDK/JRE, paquetes APT y procesos Java.
--apply   Actualiza SOLAMENTE paquetes Java/CA instalados mediante APT.
          Muestra una simulación y exige confirmación antes de modificar.
--root    Agrega una ruta adicional al inventario (se puede repetir).

No actualiza JDK instalados manualmente ni reinicia iDempiere.
Puede invocarse desde GitHub Raw mediante curl | bash; el modo --apply
solicita confirmación por /dev/tty. En producción es preferible
descargar y verificar el script antes de ejecutarlo como root.
HELP
}
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
section() { printf '\n===== %s =====\n' "$*"; }

while (($#)); do
  case "$1" in
    --audit) MODE="audit"; shift ;;
    --apply) MODE="apply"; shift ;;
    --root)
      (($# >= 2)) || fail '--root requiere una ruta'
      [[ -d "$2" ]] || fail "No existe la ruta: $2"
      EXTRA_ROOTS+=("$2")
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Opción no reconocida: $1" ;;
  esac
done

[[ -r /etc/os-release ]] || fail 'No se pudo identificar el sistema operativo'
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-} ${ID_LIKE:-}" in
  *ubuntu*|*debian*|*pop*) ;;
  *) fail "Este script solo admite Debian/Ubuntu y derivados APT (SO: ${PRETTY_NAME:-desconocido})" ;;
esac
command -v dpkg-query >/dev/null || fail 'dpkg-query no está disponible'
command -v apt-cache >/dev/null || fail 'apt-cache no está disponible'

add_java() {
  local candidate="$1" resolved
  [[ -x "$candidate" ]] || return 0
  resolved="$(readlink -f -- "$candidate" 2>/dev/null || true)"
  [[ -n "$resolved" && -x "$resolved" ]] || return 0
  if [[ ! ${SEEN_JAVA["$resolved"]+existe} ]]; then
    SEEN_JAVA["$resolved"]=1
    JDK_BINARIES+=("$resolved")
  fi
}

discover_java() {
  local java_path base candidate
  if command -v java >/dev/null 2>&1; then
    java_path="$(command -v java)"
    add_java "$java_path"
  fi
  if [[ -n ${JAVA_HOME:-} ]]; then add_java "${JAVA_HOME}/bin/java"; fi
  if command -v update-alternatives >/dev/null 2>&1; then
    while IFS= read -r candidate; do
      [[ -n "$candidate" ]] && add_java "$candidate"
    done < <(update-alternatives --list java 2>/dev/null || true)
  fi

  local -a roots=(/usr/lib/jvm /opt /usr/local /srv /home /root "${EXTRA_ROOTS[@]}")
  for base in "${roots[@]}"; do
    [[ -d "$base" ]] || continue
    # No seguimos symlinks de directorios; omitimos caches de compilación.
    while IFS= read -r -d '' candidate; do
      add_java "$candidate"
    done < <(find "$base" -xdev -maxdepth 8 \
      \( -name .git -o -name node_modules -o -name .m2 -o -name target \) -prune -o \
      \( -type f -o -type l \) -name java -path '*/bin/java' -print0 2>/dev/null)
  done
}

owner_of() {
  local output
  output="$(dpkg-query -S -- "$1" 2>/dev/null | head -n 1 || true)"
  if [[ -n "$output" ]]; then
    printf 'APT: %s' "${output%%: *}"
  else
    printf 'MANUAL / NO GESTIONADO POR APT'
  fi
}

java_inventory() {
  section 'SISTEMA'
  printf 'Fecha: %s\nSO: %s\nKernel: %s\n' \
    "$(date -Is)" "${PRETTY_NAME:-desconocido}" "$(uname -r)"
  printf 'Java predeterminado: %s\n' "$(command -v java 2>/dev/null || printf 'no definido')"
  if [[ -n ${JAVA_HOME:-} ]]; then printf 'JAVA_HOME: %s\n' "$JAVA_HOME"; fi

  discover_java
  section 'INSTALACIONES JAVA (rutas físicas únicas)'
  if ((${#JDK_BINARIES[@]} == 0)); then
    printf 'No se encontraron binarios en las rutas revisadas.\n'
  else
    local exe home release version vendor
    for exe in "${JDK_BINARIES[@]}"; do
      home="$(dirname -- "$(dirname -- "$exe")")"
      release="$home/release"
      version='desconocida'; vendor='desconocido'
      if [[ -r "$release" ]]; then
        version="$(sed -n 's/^JAVA_VERSION="\(.*\)"$/\1/p' "$release" | head -n 1)"
        vendor="$(sed -n 's/^IMPLEMENTOR="\(.*\)"$/\1/p' "$release" | head -n 1)"
        version="${version:-desconocida}"
        vendor="${vendor:-desconocido}"
      fi
      printf '\nBinario : %s\nJAVA_HOME: %s\nVersión : %s\nProveedor: %s\nGestión : %s\n' \
        "$exe" "$home" "$version" "$vendor" "$(owner_of "$exe")"
    done
  fi

  section 'PROCESOS JAVA ACTIVOS (sin exponer argumentos ni credenciales)'
  local commfile pid exe count=0
  for commfile in /proc/[0-9]*/comm; do
    [[ -r "$commfile" ]] || continue
    [[ "$(<"$commfile")" == 'java' ]] || continue
    pid="${commfile%/comm}"; pid="${pid##*/}"
    exe="$(readlink -- "/proc/${pid}/exe" 2>/dev/null || true)"
    printf 'PID: %-8s Ejecutable: %s\n' "$pid" "${exe:-sin permiso o finalizado}"
    ((count+=1))
  done
  ((count > 0)) || printf 'No se detectaron procesos denominados java.\n'
}

is_target_pkg() {
  case "$1" in
    ca-certificates|ca-certificates-java|\
    openjdk-[0-9]*-*|temurin-[0-9]*-*|zulu[0-9]*-*|\
    msopenjdk-[0-9]*|bellsoft-java[0-9]*|\
    sapmachine-[0-9]*-*|oracle-java[0-9]*-*|oracle-jdk-[0-9]*|\
    jdk-[0-9]*|jre-[0-9]*|\
    graalvm-[0-9]*-*) return 0 ;;
    *) return 1 ;;
  esac
}

installed_target_packages() {
  local pkg state
  while IFS=$'\t' read -r pkg state; do
    [[ "$state" == 'install ok installed' ]] || continue
    if is_target_pkg "$pkg"; then printf '%s\n' "$pkg"; fi
  done < <(dpkg-query -W -f='${binary:Package}\t${Status}\n' 2>/dev/null || true)
}

apt_inventory() {
  section 'PAQUETES APT DE JAVA Y CERTIFICADOS'
  local -a pkgs=()
  mapfile -t pkgs < <(installed_target_packages | sort -u)
  if ((${#pkgs[@]} == 0)); then
    printf 'No se encontraron paquetes APT objetivo.\n'
    return 0
  fi
  local pkg installed candidate
  printf '%-35s %-30s %s\n' 'PAQUETE' 'INSTALADO' 'CANDIDATO APT'
  for pkg in "${pkgs[@]}"; do
    installed="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
    candidate="$(apt-cache policy "$pkg" | awk '/^[[:space:]]*Candidate:/{print $2; exit}')"
    printf '%-35s %-30s %s\n' "$pkg" "$installed" "${candidate:-sin datos}"
  done
  printf '\nNOTA: las versiones candidatas dependen de los repositorios y del último apt update.\n'
}

java_inventory
apt_inventory

section 'LIMITACIONES Y SIGUIENTES PASOS'
printf '%s\n' \
  'Los JDK manuales NO se actualizan. Revisa sus rutas y proveedor.' \
  'La búsqueda no incluye volúmenes montados fuera de rutas examinadas; usa --root.' \
  'Una actualización de APT puede disparar hooks y reinicios del sistema: usa ventana de mantenimiento.' \
  'Los procesos Java ya iniciados siguen usando su JVM anterior hasta reiniciarse.'

[[ "$MODE" == 'apply' ]] || exit 0

((EUID == 0)) || fail 'Para aplicar cambios ejecuta: sudo bash java-security-update.sh --apply'
[[ -r /dev/tty ]] || fail 'Se requiere una terminal interactiva (/dev/tty) para confirmar la actualización'
command -v apt-get >/dev/null || fail 'apt-get no disponible'

section 'ACTUALIZAR ÍNDICES APT (SIN INSTALAR PAQUETES)'
apt-get update

# No instala ramas mayores nuevas; solo actualiza paquetes Java ya instalados.
declare -a targets=() all_packages=()
mapfile -t all_packages < <(installed_target_packages | sort -u)
for pkg in "${all_packages[@]}"; do
  installed="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
  candidate="$(apt-cache policy "$pkg" | awk '/^[[:space:]]*Candidate:/{print $2; exit}')"
  if [[ -n "$candidate" && "$candidate" != '(none)' ]] && \
     dpkg --compare-versions "$candidate" gt "$installed"; then
    targets+=("$pkg")
  fi
done

if ((${#targets[@]} == 0)); then
  section 'RESULTADO'
  printf 'APT no ofrece actualizaciones para los paquetes Java/CA instalados.\n'
  printf 'Esto NO garantiza que los JDK manuales estén corregidos.\n'
  exit 0
fi

section 'SIMULACIÓN DE ACTUALIZACIÓN (SIN CAMBIOS)'
plan="$(mktemp)"
trap 'rm -f -- "${plan:-}"' EXIT
# --only-upgrade evita instalar nuevos paquetes objetivos y --no-remove evita eliminaciones.
if ! apt-get -s --no-remove --no-install-recommends --only-upgrade \
    install "${targets[@]}" >"$plan" 2>&1; then
  cat "$plan"
  fail 'APT no pudo simular la actualización; no se ha aplicado nada'
fi
cat "$plan"
if grep -Eq '^(Remv|Purg) ' "$plan"; then
  fail 'La simulación propone eliminar paquetes; operación cancelada'
fi
# Un "Inst foo (version...)" sin [versión anterior] indica un paquete nuevo.
if grep -Eq '^Inst [^ ]+ \(' "$plan"; then
  fail 'La simulación propone instalar paquetes adicionales; requiere revisión manual'
fi

printf '\nPaquetes objetivo: %s\n' "${targets[*]}"
printf 'No se cambiará la versión mayor de Java deliberadamente.\n'
printf 'ATENCIÓN: scripts de mantenimiento APT podrían reiniciar servicios.\n'
read -r -p 'Para aplicar escribe exactamente ACTUALIZAR: ' confirmation </dev/tty
[[ "$confirmation" == 'ACTUALIZAR' ]] || fail 'Cancelado por el operador'

logdir="$(mktemp -d /var/log/java-security-update.XXXXXXXX)"
printf 'Registro de la operación: %s\n' "$logdir"
{
  date -Is
  printf 'Servidor: %s\n' "$(hostname)"
  printf 'Paquetes seleccionados: %s\n' "${targets[*]}"
  dpkg-query -W -f='${binary:Package}\t${Version}\t${Status}\n'
} > "$logdir/packages-before.txt"
cp -- "$plan" "$logdir/apt-simulation.txt"

section 'APLICANDO ACTUALIZACIONES APT'
# NEEDRESTART_MODE=l solicita listar servicios en lugar de reiniciarlos cuando
# needrestart está presente; los scripts postinst de APT pueden actuar aparte.
if NEEDRESTART_MODE=l apt-get --no-remove --no-install-recommends \
    --only-upgrade -y install "${targets[@]}" 2>&1 | tee "$logdir/apt-install.log"; then
  printf 'APT finalizó correctamente.\n'
else
  fail "APT devolvió un error; revisar $logdir/apt-install.log"
fi

dpkg-query -W -f='${binary:Package}\t${Version}\t${Status}\n' > "$logdir/packages-after.txt"
section 'RESULTADO FINAL'
for pkg in "${targets[@]}"; do
  dpkg-query -W -f='${binary:Package} ${Version}\n' "$pkg" || true
done
printf '\nRevisa JDK manuales y programa reinicio CONTROLADO de iDempiere si aplica.\n'
printf 'Registros: %s\n' "$logdir"
