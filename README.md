# USB Safe Scanner

Escáner educativo y seguro para archivos en unidades USB de Windows. Solo lee archivos y calcula hashes o busca una firma de prueba; no crea payloads, no se propaga y no ejecuta archivos encontrados.

## Que hace

- Escanea directorios o unidades desmontables.
- Detecta el patrón de prueba EICAR sin usar malware real.
- Permite mantener una lista local de hashes SHA-256 prohibidos.
- Puede mover coincidencias a una carpeta de cuarentena local.
- Produce salida JSON opcional.

## Uso

```powershell
py -m pip install -r requirements.txt
py scanner.py --usb
py scanner.py "E:\"
py scanner.py "E:\" --quarantine
py scanner.py "E:\" --json
```

Por defecto la herramienta solo informa coincidencias. `--quarantine` mueve los archivos detectados fuera de la unidad a una carpeta local.

## Dependencias

- Python 3.10+
- `psutil` para detectar unidades desmontables

## Prueba segura

Crea un archivo de prueba EICAR con el siguiente contenido de 68 bytes y escanealo:

```text
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

La cadena EICAR es un marcador antivirus estándar de pruebas, no contiene código malicioso.

## Pruebas

```powershell
py -m unittest discover -s tests -v
```

## Limitaciones

Este proyecto es educativo. No sustituye a un antivirus real, no ofrece proteccion en tiempo real y no garantiza detección de amenazas desconocidas. Usa firmas conocidas y hashes verificados como apoyo de aprendizaje.
