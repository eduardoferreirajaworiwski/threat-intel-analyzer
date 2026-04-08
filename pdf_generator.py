"""
pdf_generator.py
----------------
Generates a PDF report summarizing Threat Intel.
Uses FPDF2 to draw custom graphs and sections that visually align with
the Streamlit dashboard (Cybersecurity Dark theme).
"""

from pathlib import Path
from io import BytesIO
from fpdf import FPDF
import pandas as pd
import datetime

# Constantes de cores idênticas ao CSS do dashboard (RGB para FPDF)
BG_COLOR = (7, 9, 15)          # #07090f
TEXT_PRIMARY = (226, 232, 240) # #e2e8f0
TEXT_MUTED = (160, 174, 192)   # #a0aec0
ACCENT_GREEN = (0, 255, 136)   # #00ff88
ACCENT_BLUE = (0, 212, 255)    # #00d4ff
ACCENT_RED = (255, 71, 87)     # #ff4757


class ThreatIntelPDF(FPDF):
    def header(self):
        # Background escuro para a página toda
        self.set_fill_color(*BG_COLOR)
        self.rect(0, 0, 210, 297, "F")

        # Linha verde de topo fina
        self.set_fill_color(*ACCENT_GREEN)
        self.rect(0, 0, 210, 2, "F")

        # Título
        self.set_font('helvetica', 'B', 20)
        self.set_text_color(*ACCENT_GREEN)
        self.cell(0, 15, 'THREAT INTEL ANALYZER', ln=1, align='L')

        # Subtítulo (monospace)
        self.set_font('courier', '', 10)
        self.set_text_color(*TEXT_MUTED)
        self.cell(0, 5, '$ threat-intelligence-report', ln=1, align='L')
        self.cell(0, 5, f"> generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC", ln=1, align='L')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('courier', 'I', 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f'Page {self.page_no()} / {{nb}} - Strictly Confidential', align='C')

    def chapter_title(self, title):
        self.set_font('helvetica', 'B', 14)
        self.set_text_color(*ACCENT_BLUE)
        self.cell(0, 10, title.upper(), ln=1, align='L')
        
        # Divider sutil
        self.set_fill_color(30, 30, 40)
        y = self.get_y()
        self.rect(10, y, 190, 0.5, "F")
        self.ln(5)

    def metric_blocks(self, df: pd.DataFrame):
        total_ips = df["source_ip"].nunique()
        total_events = len(df)
        deny_count = len(df[df["action"].isin(["DENY", "DROP"])])
        
        has_intel = "malicious_votes" in df.columns
        mal_ips = 0
        if has_intel:
            mal_df = df.groupby("source_ip")["malicious_votes"].max().reset_index()
            mal_ips = (mal_df["malicious_votes"] > 0).sum()

        self.set_font('helvetica', 'B', 12)
        
        # Três caixas de métricas alinhadas horizontalmente
        # (Total, Malicious, Blocked)
        y_ini = self.get_y()
        w = 60
        gap = 5
        x_ini = 10
        
        metrics = [
            ("TOTAL UNIQUE IPs", str(total_ips), TEXT_PRIMARY),
            ("MALICIOUS IPs", str(mal_ips) if has_intel else "N/A", ACCENT_RED),
            ("BLOCKED EVENTS", str(deny_count), (255, 165, 2))
        ]
        
        for i, (title, val, color) in enumerate(metrics):
            x = x_ini + (w + gap) * i
            
            # Box bg
            self.set_fill_color(20, 24, 35)
            self.rect(x, y_ini, w, 22, "F")
            
            self.set_xy(x, y_ini + 3)
            self.set_font('courier', 'B', 8)
            self.set_text_color(*TEXT_MUTED)
            self.cell(w, 5, title, align='C', ln=1)
            
            self.set_x(x)
            self.set_font('helvetica', 'B', 16)
            self.set_text_color(*color)
            self.cell(w, 10, val, align='C', ln=1)

        self.set_y(y_ini + 30)

    def top_ports_table(self, df: pd.DataFrame):
        self.chapter_title("Attack Vectors: Top Targeted Ports")
        
        port_counts = df["destination_port"].value_counts().head(5)
        
        self.set_font('helvetica', 'B', 10)
        self.set_fill_color(30, 35, 50)
        self.set_text_color(*ACCENT_GREEN)
        
        self.cell(60, 8, "Target Port", border=0, fill=True)
        self.cell(60, 8, "Protocol/Service", border=0, fill=True)
        self.cell(70, 8, "Event Count", border=0, fill=True, ln=1)
        
        services = {80: "HTTP", 443: "HTTPS", 22: "SSH", 3389: "RDP", 8080: "HTTP-Alt", 21: "FTP"}
        
        self.set_font('courier', '', 10)
        for port, count in port_counts.items():
            srv = services.get(port, "Unknown")
            
            self.set_text_color(*TEXT_PRIMARY)
            self.cell(60, 8, str(port), border=0)
            self.cell(60, 8, srv, border=0)
            
            # Highlight count
            self.set_text_color(*ACCENT_BLUE)
            self.cell(70, 8, str(count), border=0, ln=1)
            
        self.ln(10)

    def top_attackers_table(self, df: pd.DataFrame):
        self.chapter_title("Critical Threat Actors")
        
        if "malicious_votes" not in df.columns:
            self.set_font('courier', 'I', 10)
            self.set_text_color(*TEXT_MUTED)
            self.cell(0, 10, "No VirusTotal Intelligence available. Run enrichment first.", ln=1)
            return

        df_bad = df[df["malicious_votes"] > 0]
        
        if df_bad.empty:
            self.set_font('courier', 'I', 10)
            self.set_text_color(*TEXT_MUTED)
            self.cell(0, 10, "[OK] No malicious IPs detected in this temporal window.", ln=1)
            return
            
        # Agrupa pelo IP e pega o Max de votos
        summary = df_bad.groupby("source_ip").agg(
            votos_vt=("malicious_votes", "max"),
            eventos=("action", "count"),
            org=("attacker_org", "first")
        ).reset_index().sort_values("votos_vt", ascending=False).head(10)

        self.set_font('helvetica', 'B', 9)
        self.set_fill_color(30, 35, 50)
        self.set_text_color(*ACCENT_RED)
        
        self.cell(40, 8, "Attacker IP", fill=True)
        self.cell(20, 8, "VT Score", fill=True, align="C")
        self.cell(25, 8, "Events", fill=True, align="C")
        self.cell(105, 8, "Attacker Org / ISP", fill=True, ln=1)
        
        self.set_font('courier', '', 9)
        for _, row in summary.iterrows():
            self.set_text_color(*TEXT_PRIMARY)
            self.cell(40, 8, str(row['source_ip']))
            
            self.set_text_color(*ACCENT_RED)
            self.set_font('courier', 'B', 9)
            self.cell(20, 8, str(int(row['votos_vt'])), align="C")
            
            self.set_font('courier', '', 9)
            self.set_text_color(*TEXT_MUTED)
            self.cell(25, 8, str(row['eventos']), align="C")
            
            self.set_text_color(*TEXT_PRIMARY)
            org_str = str(row['org'])
            if len(org_str) > 40:
                org_str = org_str[:37] + "..."
            self.cell(105, 8, org_str, ln=1)


def generate_pdf_report(df: pd.DataFrame) -> bytes:
    """Gera um PDF report e retorna os bytes do arquivo para o Streamlit."""
    pdf = ThreatIntelPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    pdf.metric_blocks(df)
    pdf.top_ports_table(df)
    pdf.top_attackers_table(df)
    
    # Retorna array de bytes sem salvar no disco (convertido para o stream_bytes suportado pelo st.download_button)
    return bytes(pdf.output())
