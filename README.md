# Spoofcheck

# 🔍 SpoofCheck - Verifica la seguridad del correo de un dominio
SpoofCheck es una herramienta de código abierto para analizar registros **SPF, DKIM y DMARC**, evaluando si un dominio es vulnerable a ataques de spoofing.

## 📜 Características
- ✅ Verifica registros **SPF** para comprobar si están bien configurados.
- ✅ Analiza **DKIM** para verificar su existencia en el dominio.
- ✅ Inspecciona **DMARC** y evalúa si el dominio es vulnerable a spoofing.
- 🔎 Muestra los resultados en la terminal con colores para mejor visibilidad.

## 📦 Instalación

### **1️⃣ Requisitos**
- Python **3.7 o superior**
- Dependencia `dnspython` (se instala automáticamente con el siguiente paso).

### **2️⃣ Instalación**
Clona el repositorio y navega al directorio del proyecto:
```bash
git clone https://github.com/haak-cybersecurity/spoofcheck.git
cd spoofcheck

pip install -r requirements.txt

python spoofcheck.py -d ejemplo.com

🔍 Análisis de seguridad en ejemplo.com
✅ SPF: v=spf1 include:_spf.google.com ~all
✅ DKIM: p=MIIBIjANBgk...
✅ DMARC: v=DMARC1; p=reject; rua=mailto:dmarc-reports@ejemplo.com
🔎 Evaluación de Spoofing: 🟢 NO vulnerable a spoofing (DMARC: reject)

🔐 Notas de seguridad
	•	⚠️ Úsalo solo en dominios de tu propiedad o con autorización.
	•	Este script es solo para auditoría y pruebas de seguridad.
