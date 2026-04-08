"""
app.py
------
Dashboard de Threat Intelligence — Threat Intel Analyzer

Frontend Streamlit com tema cybersecurity dark para visualização de logs
de servidor enriquecidos com dados de VirusTotal e Shodan.

Dependências:
    pip install streamlit plotly pandas python-dotenv requests shodan
"""

import os
import io
import time

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

import column_detector
import pdf_generator

load_dotenv()

# =============================================================================
# CONFIGURAÇÃO DA PÁGINA — deve ser a PRIMEIRA chamada Streamlit
# =============================================================================

st.set_page_config(
    page_title="Threat Intel Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =============================================================================
# TEMA E ESTILOS GLOBAIS (Cybersecurity Dark)
# =============================================================================

CUSTOM_CSS = """
<style>
  /* ── Google Font ────────────────────────────────── */
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&family=JetBrains+Mono:wght@400;700&display=swap');

  /* ── Reset global ───────────────────────────────── */
  html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
  }

  /* ── Fundo principal ────────────────────────────── */
  .stApp {
    background: #07090f;
    background-image:
      radial-gradient(ellipse at 20% 10%, rgba(0,255,136,0.04) 0%, transparent 60%),
      radial-gradient(ellipse at 80% 80%, rgba(99,102,241,0.06) 0%, transparent 60%);
  }

  /* ── Sidebar ────────────────────────────────────── */
  section[data-testid="stSidebar"] {
    background: #0d111d;
    border-right: 1px solid rgba(0,255,136,0.12);
  }
  section[data-testid="stSidebar"] * {
    color: #a0aec0 !important;
  }
  section[data-testid="stSidebar"] h1,
  section[data-testid="stSidebar"] h2,
  section[data-testid="stSidebar"] h3 {
    color: #00ff88 !important;
  }

  /* ── Cabeçalho do dashboard ─────────────────────── */
  .dash-header {
    padding: 2rem 0 1.5rem 0;
    border-bottom: 1px solid rgba(0,255,136,0.15);
    margin-bottom: 2rem;
  }
  .dash-title {
    font-size: 2.4rem;
    font-weight: 900;
    letter-spacing: -0.5px;
    background: linear-gradient(135deg, #00ff88 0%, #00d4ff 50%, #6366f1 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin: 0;
    line-height: 1.2;
  }
  .dash-subtitle {
    color: #4a5568;
    font-size: 0.95rem;
    margin-top: 0.4rem;
    font-family: 'JetBrains Mono', monospace;
  }

  /* ── Metric Cards ───────────────────────────────── */
  .metric-card {
    background: linear-gradient(135deg, #0d111d 0%, #111827 100%);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 16px;
    padding: 1.5rem 1.8rem;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
  }
  .metric-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }
  .metric-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    border-radius: 16px 16px 0 0;
  }
  .metric-card.blue::before  { background: linear-gradient(90deg, #00d4ff, #6366f1); }
  .metric-card.red::before   { background: linear-gradient(90deg, #ff4757, #ff6b6b); }
  .metric-card.orange::before{ background: linear-gradient(90deg, #ffa502, #ff6348); }

  .metric-icon {
    font-size: 1.8rem;
    margin-bottom: 0.8rem;
    display: block;
  }
  .metric-label {
    color: #4a5568;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 0.4rem;
    font-family: 'JetBrains Mono', monospace;
  }
  .metric-value {
    font-size: 2.8rem;
    font-weight: 900;
    line-height: 1;
    margin: 0;
  }
  .metric-value.blue   { color: #00d4ff; }
  .metric-value.red    { color: #ff4757; }
  .metric-value.orange { color: #ffa502; }
  .metric-delta {
    font-size: 0.78rem;
    color: #4a5568;
    margin-top: 0.6rem;
    font-family: 'JetBrains Mono', monospace;
  }

  /* ── Section headers ────────────────────────────── */
  .section-header {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin: 2rem 0 1rem 0;
    padding-bottom: 0.6rem;
    border-bottom: 1px solid rgba(255,255,255,0.06);
  }
  .section-header h3 {
    color: #e2e8f0;
    font-size: 1rem;
    font-weight: 600;
    margin: 0;
    letter-spacing: 0.3px;
  }
  .section-badge {
    background: rgba(0,255,136,0.1);
    color: #00ff88;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 1px;
    font-family: 'JetBrains Mono', monospace;
  }

  /* ── Alert banners ──────────────────────────────── */
  .alert-warning {
    background: rgba(255, 165, 2, 0.08);
    border: 1px solid rgba(255, 165, 2, 0.3);
    border-left: 3px solid #ffa502;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    color: #ffa502;
    font-size: 0.88rem;
    margin: 1rem 0;
  }
  .alert-info {
    background: rgba(0, 212, 255, 0.06);
    border: 1px solid rgba(0, 212, 255, 0.2);
    border-left: 3px solid #00d4ff;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    color: #00d4ff;
    font-size: 0.88rem;
    margin: 1rem 0;
  }
  .alert-success {
    background: rgba(0, 255, 136, 0.06);
    border: 1px solid rgba(0, 255, 136, 0.2);
    border-left: 3px solid #00ff88;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    color: #00ff88;
    font-size: 0.88rem;
    margin: 1rem 0;
  }

  /* ── Dataframe container ────────────────────────── */
  .stDataFrame {
    border-radius: 12px;
    overflow: hidden;
    border: 1px solid rgba(255,255,255,0.06) !important;
  }

  /* ── Botões ─────────────────────────────────────── */
  .stButton > button {
    background: linear-gradient(135deg, #00ff88, #00d4ff);
    color: #07090f;
    font-weight: 700;
    border: none;
    border-radius: 10px;
    padding: 0.7rem 2rem;
    font-size: 0.9rem;
    letter-spacing: 0.3px;
    transition: opacity 0.2s, transform 0.2s;
    width: 100%;
  }
  .stButton > button:hover {
    opacity: 0.9;
    transform: translateY(-1px);
  }

  /* ── File uploader ──────────────────────────────── */
  [data-testid="stFileUploader"] {
    background: rgba(255,255,255,0.02);
    border: 1px dashed rgba(0,255,136,0.25);
    border-radius: 10px;
    padding: 0.5rem;
  }

  /* ── Divider ────────────────────────────────────── */
  hr {
    border-color: rgba(255,255,255,0.06) !important;
  }

  /* ── Scrollbar ──────────────────────────────────── */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: #07090f; }
  ::-webkit-scrollbar-thumb { background: #1a2234; border-radius: 3px; }
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# =============================================================================
# HELPERS
# =============================================================================

def metric_card(label: str, value, color: str, icon: str, delta: str = "") -> str:
    """Gera o HTML de um metric card estilizado."""
    return f"""
    <div class="metric-card {color}">
      <span class="metric-icon">{icon}</span>
      <div class="metric-label">{label}</div>
      <div class="metric-value {color}">{value}</div>
      {'<div class="metric-delta">' + delta + '</div>' if delta else ''}
    </div>
    """


def section_header(title: str, badge: str = "") -> str:
    badge_html = f'<span class="section-badge">{badge}</span>' if badge else ""
    return f"""
    <div class="section-header">
      <h3>{title}</h3>
      {badge_html}
    </div>
    """


def check_api_keys() -> tuple[bool, list[str]]:
    """Verifica quais chaves de API estão configuradas."""
    missing = []
    if not os.getenv("VT_API_KEY"):
        missing.append("VT_API_KEY")
    if not os.getenv("SHODAN_API_KEY"):
        missing.append("SHODAN_API_KEY")
    return len(missing) == 0, missing


def highlight_malicious(row: pd.Series) -> list[str]:
    """
    Aplica estilo vermelho às linhas onde malicious_votes > 0.
    Compatível com pandas Styler via df.apply(axis=1).
    """
    if "malicious_votes" in row.index:
        votes = row["malicious_votes"]
        try:
            if pd.notna(votes) and float(votes) > 0:
                return ["background-color: rgba(255,71,87,0.15); color: #ff6b6b;"] * len(row)
        except (ValueError, TypeError):
            pass
    return [""] * len(row)


@st.cache_data(show_spinner=False)
def load_csv(source: str | bytes) -> pd.DataFrame:
    """Carrega CSV de arquivo local ou upload, com cache."""
    if isinstance(source, bytes):
        return pd.read_csv(io.BytesIO(source))
    return pd.read_csv(source)


def run_analysis(log_file_path: str) -> pd.DataFrame | None:
    """
    Executa o ThreatIntelAnalyzer com feedback visual de progresso.
    Retorna None se a análise falhar.
    """
    # Importação local para evitar erro de módulos ausentes no carregamento inicial
    try:
        from analyzer import ThreatIntelAnalyzer
    except ImportError as e:
        st.error(f"❌ Erro ao importar analyzer.py: {e}")
        return None

    try:
        analyzer = ThreatIntelAnalyzer(log_file=log_file_path)
    except EnvironmentError as e:
        st.error(str(e))
        return None
    except FileNotFoundError as e:
        st.error(str(e))
        return None

    # Lê IPs únicos para estimar o tempo
    df_raw = pd.read_csv(log_file_path)
    ips = df_raw["source_ip"].unique().tolist()
    total = len(ips)
    rate_limit_sec = 15

    st.markdown(
        f'<div class="alert-info">⏱️ Analisando <strong>{total} IPs únicos</strong>. '
        f'Tempo estimado: ~{total * rate_limit_sec // 60} min {total * rate_limit_sec % 60} s '
        f'(rate limit VirusTotal: {rate_limit_sec}s/req)</div>',
        unsafe_allow_html=True,
    )

    progress_bar = st.progress(0, text="Iniciando análise de Threat Intelligence...")
    status_box = st.empty()

    resultados = []
    VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    VT_KEY = os.getenv("VT_API_KEY")
    SHODAN_KEY = os.getenv("SHODAN_API_KEY")

    import requests, shodan as shodan_lib

    shodan_client = shodan_lib.Shodan(SHODAN_KEY)

    for idx, ip in enumerate(ips):
        status_box.markdown(
            f'<div class="alert-info">🔍 [{idx+1}/{total}] Consultando: <code>{ip}</code></div>',
            unsafe_allow_html=True,
        )

        # VirusTotal
        time.sleep(rate_limit_sec)
        malicious_votes = -1
        try:
            resp = requests.get(VT_URL.format(ip=ip), headers={"x-apikey": VT_KEY}, timeout=10)
            resp.raise_for_status()
            malicious_votes = (
                resp.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("malicious", 0)
            )
        except Exception:
            pass

        # Shodan
        attacker_os, attacker_org, open_ports = "Unknown", "Unknown", "None"
        try:
            host = shodan_client.host(ip)
            attacker_os = host.get("os") or "Unknown"
            attacker_org = host.get("org", "Unknown")
            ports = host.get("ports", [])
            open_ports = ", ".join(map(str, ports)) if ports else "None"
        except Exception:
            pass

        resultados.append({
            "source_ip": ip,
            "malicious_votes": malicious_votes,
            "attacker_org": attacker_org,
            "attacker_os": attacker_os,
            "open_ports": open_ports,
        })

        progress_bar.progress((idx + 1) / total, text=f"Analisado {idx+1}/{total} IPs...")

    df_intel = pd.DataFrame(resultados)
    df_final = df_raw.merge(df_intel, on="source_ip", how="left")
    df_final.to_csv("threat_intel_report.csv", index=False)

    progress_bar.progress(1.0, text="✅ Análise concluída!")
    status_box.empty()

    return df_final


# =============================================================================
# SIDEBAR
# =============================================================================

with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 1rem 0 1.5rem 0;">
      <div style="font-size:2.5rem;">🛡️</div>
      <div style="color:#00ff88; font-weight:700; font-size:1rem; letter-spacing:0.5px;">
        THREAT INTEL
      </div>
      <div style="color:#2d3748; font-size:0.7rem; font-family:'JetBrains Mono',monospace;">
        v1.0.0 — SecOps Dashboard
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 📂 Fonte de Dados")

    data_source = st.radio(
        "Selecione a origem dos dados:",
        options=["Usar arquivo local", "Upload de CSV"],
        help="Use o arquivo gerado pelo generate_logs.py ou faça upload de um CSV personalizado.",
    )

    uploaded_df = None

    if data_source == "Upload de CSV":
        uploaded_file = st.file_uploader(
            "Arraste ou selecione o CSV",
            type=["csv"],
            help="O CSV deve conter as colunas: timestamp, source_ip, destination_port, action",
        )
        if uploaded_file:
            raw_df = load_csv(uploaded_file.read())
            mapping, info = column_detector.auto_map_columns(raw_df)
            uploaded_df = column_detector.normalize_dataframe(raw_df, mapping)
            warnings_list = column_detector.validate_dataframe(uploaded_df, mapping)
            for w in warnings_list:
                st.warning(w)
            st.success(f"✅ {len(uploaded_df)} registros carregados (Com autodetect de colunas)")
    else:
        local_files = {
            "📊 Relatório enriquecido (threat_intel_report.csv)": "threat_intel_report.csv",
            "📋 Logs brutos (server_logs.csv)": "server_logs.csv",
        }
        selected_local = st.selectbox("Arquivo local:", list(local_files.keys()))
        local_path = local_files[selected_local]

        if os.path.exists(local_path):
            raw_df = load_csv(local_path)
            mapping, info = column_detector.auto_map_columns(raw_df)
            uploaded_df = column_detector.normalize_dataframe(raw_df, mapping)
            warnings_list = column_detector.validate_dataframe(uploaded_df, mapping)
            for w in warnings_list:
                st.warning(w)
            st.success(f"✅ {len(uploaded_df)} registros carregados")
        else:
            st.warning(f"⚠️ `{local_path}` não encontrado. Execute `generate_logs.py` primeiro.")

    st.markdown("---")
    st.markdown("### ⚙️ Análise de Threat Intel")

    api_ok, missing_keys = check_api_keys()

    if not api_ok:
        st.markdown(
            f'<div class="alert-warning">⚠️ Chaves ausentes no <code>.env</code>:<br>'
            f'<strong>{", ".join(missing_keys)}</strong></div>',
            unsafe_allow_html=True,
        )
        st.caption("Configure o arquivo `.env` para habilitar o enriquecimento de IPs.")
    else:
        st.markdown(
            '<div class="alert-success">🔑 APIs configuradas e prontas</div>',
            unsafe_allow_html=True,
        )

    run_analysis_btn = st.button(
        "🚀 Executar Análise Completa",
        disabled=not api_ok or uploaded_df is None,
        help="Enriquece cada IP único com dados do VirusTotal e Shodan.",
    )

    st.markdown("---")
    st.markdown("### ℹ️ Sobre")
    st.caption(
        "Threat Intel Analyzer enriquece logs de servidor com dados de "
        "reputação (VirusTotal) e infraestrutura de atacantes (Shodan)."
    )


# =============================================================================
# ÁREA PRINCIPAL
# =============================================================================

# Cabeçalho
st.markdown("""
<div class="dash-header">
  <h1 class="dash-title">🛡️ Threat Intel Analyzer</h1>
  <p class="dash-subtitle">$ real-time network threat intelligence dashboard // powered by VirusTotal + Shodan</p>
</div>
""", unsafe_allow_html=True)

# ── Sem dados carregados ──────────────────────────────────────────────────────
if uploaded_df is None:
    st.markdown("""
    <div style="text-align:center; padding: 5rem 2rem;">
      <div style="font-size: 4rem; margin-bottom: 1rem;">📡</div>
      <h2 style="color: #2d3748; font-weight:700;">Nenhum dado carregado</h2>
      <p style="color: #1a2234; font-family:'JetBrains Mono',monospace; font-size:0.85rem;">
        Use a sidebar para selecionar ou fazer upload de um arquivo CSV de logs.
      </p>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

df = uploaded_df.copy()

# ── Execução da análise (quando botão é pressionado) ─────────────────────────
if run_analysis_btn:
    # Salva CSV temporário se veio de upload
    tmp_path = "server_logs.csv"
    df.to_csv(tmp_path, index=False)

    with st.spinner(""):
        result = run_analysis(tmp_path)

    if result is not None:
        df = result
        st.markdown(
            '<div class="alert-success">✅ Análise concluída! Relatório salvo em <code>threat_intel_report.csv</code></div>',
            unsafe_allow_html=True,
        )
        st.rerun()

# ── Detecta se temos dados enriquecidos ──────────────────────────────────────
has_intel = "malicious_votes" in df.columns

if not has_intel:
    st.markdown(
        '<div class="alert-info">ℹ️ Exibindo dados brutos de logs. '
        'Para ver o enriquecimento de Threat Intelligence, execute a análise completa na sidebar.</div>',
        unsafe_allow_html=True,
    )
else:
    pdf_bytes = pdf_generator.generate_pdf_report(df)
    st.download_button(
        label="📄 Exportar Relatório PDF",
        data=pdf_bytes,
        file_name=f"threat_intel_report_{int(time.time())}.pdf",
        mime="application/pdf",
    )

# =============================================================================
# SEÇÃO 1 — METRIC CARDS
# =============================================================================

st.markdown(section_header("Visão Geral", "LIVE"), unsafe_allow_html=True)

total_ips = df["source_ip"].nunique()
total_registros = len(df)
deny_count = int((df["action"] == "DENY").sum()) + int((df["action"] == "DROP").sum())

if has_intel:
    mal_df = df.groupby("source_ip")["malicious_votes"].max().reset_index()
    malicious_ips = int((mal_df["malicious_votes"] > 0).sum())
else:
    malicious_ips = "—"

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown(
        metric_card(
            "IPs Únicos Analisados", total_ips, "blue", "🌐",
            f"{total_registros} eventos no total"
        ),
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        metric_card(
            "IPs Maliciosos Detectados",
            malicious_ips if has_intel else "—",
            "red", "🚨",
            "Baseado em votos VirusTotal" if has_intel else "Execute a análise para obter"
        ),
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        metric_card(
            "Ações Bloqueadas (DENY+DROP)", deny_count, "orange", "🔒",
            f"{deny_count/total_registros*100:.1f}% do tráfego total"
        ),
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)

# =============================================================================
# SEÇÃO 2 — GRÁFICOS
# =============================================================================

chart_col, dist_col = st.columns([3, 2])

# ── Gráfico de barras: portas mais atacadas ───────────────────────────────────
with chart_col:
    st.markdown(section_header("🎯 Portas de Destino Mais Atacadas", "TOP TARGETS"), unsafe_allow_html=True)

    port_counts = (
        df.groupby("destination_port")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )

    # Mapeamento de nomes de serviços comuns
    port_names = {80: "HTTP", 443: "HTTPS", 22: "SSH", 3389: "RDP", 8080: "HTTP-Alt", 21: "FTP"}
    port_counts["service"] = port_counts["destination_port"].map(
        lambda p: f"{p} ({port_names.get(p, 'Unknown')})"
    )

    fig_ports = go.Figure(
        go.Bar(
            x=port_counts["service"],
            y=port_counts["count"],
            marker=dict(
                color=port_counts["count"],
                colorscale=[[0, "#1a2234"], [0.5, "#6366f1"], [1.0, "#00ff88"]],
                showscale=False,
                line=dict(color="rgba(0,255,136,0.2)", width=1),
            ),
            text=port_counts["count"],
            textposition="outside",
            textfont=dict(color="#a0aec0", size=12, family="JetBrains Mono"),
            hovertemplate="<b>%{x}</b><br>Eventos: %{y}<extra></extra>",
        )
    )

    fig_ports.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter", color="#a0aec0"),
        margin=dict(l=10, r=10, t=20, b=10),
        xaxis=dict(
            showgrid=False,
            tickfont=dict(size=11, color="#4a5568"),
            linecolor="rgba(255,255,255,0.06)",
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="rgba(255,255,255,0.04)",
            tickfont=dict(size=11, color="#4a5568"),
            zeroline=False,
        ),
        hoverlabel=dict(
            bgcolor="#111827",
            bordercolor="rgba(0,255,136,0.3)",
            font=dict(color="#e2e8f0"),
        ),
        height=320,
    )

    st.plotly_chart(fig_ports, use_container_width=True, config={"displayModeBar": False})


# ── Gráfico de pizza: distribuição de ações ───────────────────────────────────
with dist_col:
    st.markdown(section_header("⚡ Distribuição de Ações", "BREAKDOWN"), unsafe_allow_html=True)

    action_counts = df["action"].value_counts().reset_index()
    action_counts.columns = ["action", "count"]

    color_map = {"ALLOW": "#00ff88", "DENY": "#ff4757", "DROP": "#ffa502"}
    colors = [color_map.get(a, "#6366f1") for a in action_counts["action"]]

    fig_actions = go.Figure(
        go.Pie(
            labels=action_counts["action"],
            values=action_counts["count"],
            hole=0.6,
            marker=dict(
                colors=colors,
                line=dict(color="#07090f", width=3),
            ),
            textfont=dict(size=12, color="#e2e8f0", family="JetBrains Mono"),
            hovertemplate="<b>%{label}</b><br>%{value} eventos (%{percent})<extra></extra>",
        )
    )

    fig_actions.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter", color="#a0aec0"),
        margin=dict(l=10, r=10, t=20, b=10),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#4a5568", size=11),
            orientation="h",
            y=-0.1,
        ),
        annotations=[dict(
            text=f"<b>{total_registros}</b><br><span style='font-size:10px'>eventos</span>",
            x=0.5, y=0.5,
            font=dict(size=16, color="#e2e8f0", family="Inter"),
            showarrow=False,
        )],
        hoverlabel=dict(
            bgcolor="#111827",
            bordercolor="rgba(255,255,255,0.1)",
            font=dict(color="#e2e8f0"),
        ),
        height=320,
    )

    st.plotly_chart(fig_actions, use_container_width=True, config={"displayModeBar": False})

# =============================================================================
# SEÇÃO 3 — TABELA INTERATIVA COM HIGHLIGHT
# =============================================================================

st.markdown(section_header("📋 Log de Eventos — Detalhes", "INTERACTIVE"), unsafe_allow_html=True)

# Filtros inline
filter_col1, filter_col2, filter_col3 = st.columns([2, 2, 3])

with filter_col1:
    action_filter = st.multiselect(
        "Filtrar por Ação",
        options=df["action"].unique().tolist(),
        default=df["action"].unique().tolist(),
        key="action_filter",
    )

with filter_col2:
    port_filter = st.multiselect(
        "Filtrar por Porta",
        options=sorted(df["destination_port"].unique().tolist()),
        default=sorted(df["destination_port"].unique().tolist()),
        key="port_filter",
    )

with filter_col3:
    if has_intel:
        show_only_malicious = st.checkbox(
            "🚨 Mostrar apenas IPs maliciosos", value=False, key="mal_filter"
        )
    else:
        show_only_malicious = False
        st.caption("")

# Aplica filtros
df_filtered = df[
    df["action"].isin(action_filter) &
    df["destination_port"].isin(port_filter)
].copy()

if has_intel and show_only_malicious:
    df_filtered = df_filtered[df_filtered["malicious_votes"] > 0]

# Reordena colunas para melhor legibilidade
cols_priority = ["timestamp", "source_ip", "destination_port", "action"]
if has_intel:
    cols_priority += ["malicious_votes", "attacker_org", "attacker_os", "open_ports"]

cols_display = [c for c in cols_priority if c in df_filtered.columns]
df_display = df_filtered[cols_display]

# ── Renomeia para exibição amigável ──────────────────────────────────────────
rename_map = {
    "timestamp": "Timestamp",
    "source_ip": "IP de Origem",
    "destination_port": "Porta Dest.",
    "action": "Ação",
    "malicious_votes": "Votos Maliciosos",
    "attacker_org": "Organização (ISP)",
    "attacker_os": "OS Atacante",
    "open_ports": "Portas Abertas",
}
df_display = df_display.rename(columns=rename_map)

# ── Aplica highlight nas linhas maliciosas ────────────────────────────────────
if has_intel and "Votos Maliciosos" in df_display.columns:
    styled_df = df_display.style.apply(highlight_malicious, axis=1)
    styled_df = styled_df.format({"Votos Maliciosos": lambda v: f"⚠️ {int(v)}" if pd.notna(v) and v > 0 else ("—" if v == -1 else str(int(v)) if pd.notna(v) else "—")})
else:
    styled_df = df_display.style

st.dataframe(
    styled_df,
    use_container_width=True,
    height=420,
    hide_index=True,
)

st.caption(f"Exibindo {len(df_filtered)} de {len(df)} registros")

# =============================================================================
# SEÇÃO 4 — TOP IPs SUSPEITOS (somente com intel)
# =============================================================================

if has_intel:
    st.markdown(section_header("🎯 Top IPs de Maior Risco", "THREAT ACTORS"), unsafe_allow_html=True)

    df_ip_summary = (
        df.groupby("source_ip")
        .agg(
            total_eventos=("action", "count"),
            malicious_votes=("malicious_votes", "max"),
            acoes_negadas=("action", lambda x: (x.isin(["DENY", "DROP"])).sum()),
            attacker_org=("attacker_org", "first"),
            attacker_os=("attacker_os", "first"),
            open_ports=("open_ports", "first"),
        )
        .reset_index()
        .sort_values(["malicious_votes", "acoes_negadas"], ascending=False)
        .head(10)
    )

    df_ip_summary = df_ip_summary.rename(columns={
        "source_ip": "IP",
        "total_eventos": "Eventos",
        "malicious_votes": "Votos VT",
        "acoes_negadas": "Bloqueios",
        "attacker_org": "Organização",
        "attacker_os": "OS",
        "open_ports": "Portas Abertas",
    })

    def highlight_top_ips(row):
        if pd.notna(row.get("Votos VT")) and row.get("Votos VT", 0) > 0:
            return ["background-color: rgba(255,71,87,0.12); color: #ff6b6b;"] * len(row)
        return [""] * len(row)

    st.dataframe(
        df_ip_summary.style.apply(highlight_top_ips, axis=1),
        use_container_width=True,
        hide_index=True,
        height=300,
    )

# =============================================================================
# RODAPÉ
# =============================================================================

st.markdown("---")
st.markdown("""
<div style="text-align:center; padding: 1rem 0; color: #1a2234; font-size: 0.75rem; font-family:'JetBrains Mono',monospace;">
  🛡️ Threat Intel Analyzer &nbsp;|&nbsp; Powered by VirusTotal API v3 + Shodan &nbsp;|&nbsp; Built with Streamlit
</div>
""", unsafe_allow_html=True)
