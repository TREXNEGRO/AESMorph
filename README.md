# AESMorph

Este repositorio contiene dos versiones de un ransomware que funcionan como estructura base.

---

1. Versión C++

- Encriptación AES de archivos específicos en un directorio.
- Detección básica de máquinas virtuales y herramientas EDR.
- Auto-mutación simple añadiendo bytes aleatorios al final del ejecutable.
- Uso de la API Windows `bcrypt` para cifrado.
- Registro de archivos cifrados en una carpeta `logs`.

Compilación:
cl ransomware.cpp /link ntdll.lib bcrypt.lib psapi.lib

---

2. Versión Go

- Persistencia avanzada copiándose a %APPDATA% y añadiéndose al registro de inicio.
- Anti-debugging avanzado con múltiples técnicas:
  - IsDebuggerPresent
  - NtQueryInformationProcess
  - CheckRemoteDebuggerPresent
  - Comprobación de timing para detectar trampas de Sleep
- Auto-mutación avanzada en memoria, mutando cadenas ASCII para ofuscación.
- Encriptación AES-CBC con padding PKCS7 para archivos objetivo.
- Detección simple de máquinas virtuales basada en CPUs y RAM.

Compilación:
go get golang.org/x/sys/windows
go build -o ransomware.exe main.go

---

Disclaimer:
El autor no se hace responsable del uso indebido de este código.
