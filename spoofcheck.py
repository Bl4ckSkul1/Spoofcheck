import dns.resolver
import argparse

# Definimos colores ANSI para mejorar la visualización en la terminal
RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"

BANNER = r"""
  █████████                                 ██████    █████████  █████                        █████     
 ███░░░░░███                               ███░░███  ███░░░░░███░░███                        ░░███      
░███    ░░░  ████████   ██████   ██████   ░███ ░░░  ███     ░░░  ░███████    ██████   ██████  ░███ █████
░░█████████ ░░███░░███ ███░░███ ███░░███ ███████   ░███          ░███░░███  ███░░███ ███░░███ ░███░░███ 
 ░░░░░░░░███ ░███ ░███░███ ░███░███ ░███░░░███░    ░███          ░███ ░███ ░███████ ░███ ░░░  ░██████░  
 ███    ░███ ░███ ░███░███ ░███░███ ░███  ░███     ░░███     ███ ░███ ░███ ░███░░░  ░███  ███ ░███░░███ 
░░█████████  ░███████ ░░██████ ░░██████   █████     ░░█████████  ████ █████░░██████ ░░██████  ████ █████
 ░░░░░░░░░   ░███░░░   ░░░░░░   ░░░░░░   ░░░░░       ░░░░░░░░░  ░░░░ ░░░░░  ░░░░░░   ░░░░░░  ░░░░ ░░░░░ 
             ░███                                                                                       
             █████                                                                                      
            ░░░░░                                                                                       

                      By Haak Cybersecurity (Adrian Martinez)
"""

def format_multiline(record):
    """ Formatea registros SPF y DMARC con saltos de línea para mejorar la legibilidad """
    return "\n   ".join(record.split())

def check_spf(domain):
    """ Verifica el registro SPF de un dominio y lo formatea """
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if "v=spf1" in txt_record:
                return format_multiline(txt_record)
        return "No SPF record found"
    except Exception:
        return "SPF record not found"

def check_dkim(domain, selector="default"):
    """ Verifica el registro DKIM de un dominio """
    dkim_domain = f"{selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        return answers[0].to_text().strip('"')
    except Exception:
        return "DKIM record not found"

def check_dmarc(domain):
    """ Verifica el registro DMARC de un dominio y lo formatea """
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_record = answers[0].to_text().strip('"')
        return format_multiline(dmarc_record)
    except Exception:
        return "DMARC record not found"

def analyze_dmarc(dmarc_record):
    """ Analiza la política DMARC y determina vulnerabilidad a spoofing """
    if "p=reject" in dmarc_record:
        return f"{GREEN}🟢 NO vulnerable a spoofing (DMARC: reject){RESET}"
    elif "p=quarantine" in dmarc_record:
        return f"{YELLOW}🟡 Posible spoofing, Recomendación: Usar 'p=reject'{RESET}"
    elif "p=none" in dmarc_record:
        return f"{RED}🔴 Posible spoofing (DMARC en modo monitoring){RESET}"
    else:
        return f"{RED}🔴 VULNERABLE a spoofing (No DMARC configurado){RESET}"

def main():
    parser = argparse.ArgumentParser(description="SpoofCheck - Verifica SPF, DKIM y DMARC en un dominio.")
    parser.add_argument("-d", "--domain", required=True, help="Dominio a analizar")
    args = parser.parse_args()

    print(BANNER)
    
    domain = args.domain
    spf = check_spf(domain)
    dkim = check_dkim(domain)
    dmarc = check_dmarc(domain)
    
    dmarc_analysis = analyze_dmarc(dmarc) if "DMARC record not found" not in dmarc else f"{RED}🔴 VULNERABLE a spoofing (No DMARC configurado){RESET}"

    print(f"\n🔍 {CYAN}Análisis de seguridad en {domain}{RESET}")
    print(f"\n{GREEN}✅ SPF:{RESET} \n   {spf}")
    print(f"\n{GREEN}✅ DKIM:{RESET} \n   {dkim}")
    print(f"\n{GREEN}✅ DMARC:{RESET} \n   {dmarc}")
    print(f"\n{CYAN}🔎 Evaluación de Spoofing:{RESET} {dmarc_analysis}\n")

if __name__ == "__main__":
    main()
