import datetime
import email
from email.header import decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import imaplib
import json
import os
import re
import smtplib
import time
import urllib.parse
import bcrypt
from fpdf import FPDF
import google.generativeai as genai
import pandas as pd
import psycopg2
import psycopg2.extras
from pypdf import PdfReader
import streamlit as st

# ==============================================================================
# --- CONFIGURATION DU THÈME VISUEL (DOIT ÊTRE AU TOUT DÉBUT) ---
# ==============================================================================
st.set_page_config(
    page_title="OmniRecrut IA", layout="wide", initial_sidebar_state="expanded"
)

st.markdown(
    """
    <style>
    .stApp { background-color: #1a202c; color: #e2e8f0; }
    section[data-testid="stSidebar"] { background-color: #242f41 !important; border-right: 1px solid #4a5568; }
    section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p, section[data-testid="stSidebar"] span { color: #ffffff !important; font-weight: 500 !important; }
    h1, h2, h3, h4 { color: #ffb703 !important; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; }
    label, [data-testid="stWidgetLabel"] p { color: #ffffff !important; font-weight: 600 !important; font-size: 1rem !important; }
    div.stButton > button:first-child { background-color: #fb8500 !important; color: #111622 !important; font-weight: bold; border: none; border-radius: 4px; padding: 0.5rem 2rem; }
    div.stButton > button:first-child:hover { background-color: #ffb703 !important; color: #111622 !important; }
    div[data-testid="stTextInput"] input,
    div[data-testid="stTextArea"] textarea,
    div[data-testid="stNumberInput"] input,
    div[data-testid="stDateInput"] input,
    div[data-testid="stSelectbox"] div[data-baseweb="select"] > div,
    div[data-testid="stMultiSelect"] div[data-baseweb="select"] > div {
        color: #ffffff !important;
        background-color: #2d3748 !important;
        border: 1px solid #4a5568 !important;
    }
    </style>
""",
    unsafe_allow_html=True,
)

# ==============================================================================
# --- CONNEXION POOLÉE ET INITIALISATION STRUCTURATION DB ---
# ==============================================================================
@st.cache_resource(show_spinner=False)
def get_connection():
    """Conserve une connexion unique réutilisée. Reconnecte si coupée."""
    url = st.secrets["connections"]["supabase"]["url"]
    conn_pg = psycopg2.connect(url)
    conn_pg.autocommit = True
    return conn_pg

def get_db_cursor():
    """Retourne un curseur valide en vérifiant la connexion."""
    try:
        conn = get_connection()
        # Test rapide de santé de la connexion
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
        return conn, conn.cursor()
    except Exception:
        # En cas de perte de connexion, réinitialise la ressource en cache
        st.cache_resource.clear()
        conn = get_connection()
        return conn, conn.cursor()

@st.cache_resource(show_spinner="Initialisation des tables Supabase...")
def init_db():
    """Exécuté UNE SEULE FOIS au démarrage pour éviter de ralentir chaque interaction."""
    conn, c = get_db_cursor()
    
    # Table Utilisateurs
    c.execute("""CREATE TABLE IF NOT EXISTS utilisateurs (
                    id SERIAL PRIMARY KEY,
                    email TEXT UNIQUE,
                    password TEXT,
                    date_fin_essai TEXT,
                    est_admin INTEGER DEFAULT 0,
                    mail_perso TEXT DEFAULT '',
                    mail_password TEXT DEFAULT '',
                    mail_imap TEXT DEFAULT 'imap.gmail.com',
                    nb_requetes_ia INTEGER DEFAULT 0,
                    quota_max INTEGER DEFAULT 300,
                    statut_abonnement TEXT DEFAULT 'GRATUIT'
                )""")

    for col, dtype in [
        ("mail_perso", "TEXT DEFAULT ''"),
        ("mail_password", "TEXT DEFAULT ''"),
        ("mail_imap", "TEXT DEFAULT 'imap.gmail.com'"),
        ("nb_requetes_ia", "INTEGER DEFAULT 0"),
        ("quota_max", "INTEGER DEFAULT 300"),
        ("statut_abonnement", "TEXT DEFAULT 'GRATUIT'")
    ]:
        try:
            c.execute(f"ALTER TABLE utilisateurs ADD COLUMN {col} {dtype}")
        except Exception:
            pass

    # Table Candidats
    c.execute("""CREATE TABLE IF NOT EXISTS candidats 
                 (id SERIAL PRIMARY KEY, nom TEXT, poste TEXT, competences TEXT, 
                 statut TEXT, categorie_ia TEXT, avis_ia TEXT, score_matching TEXT, secteur_metier TEXT DEFAULT 'Non spécifié', cv_texte TEXT DEFAULT '')""")

    for col, dtype in [
        ("type_rdv", "TEXT"),
        ("date_rdv", "TEXT"),
        ("cv_texte", "TEXT DEFAULT ''"),
        ("competences_transferables", "TEXT"),
        ("profil_riasec", "TEXT"),
        ("metiers_cibles", "TEXT"),
        ("date_ajout", "TEXT")
    ]:
        try:
            c.execute(f"ALTER TABLE candidats ADD COLUMN {col} {dtype}")
        except Exception:
            pass

    # Table Clients
    c.execute("""CREATE TABLE IF NOT EXISTS clients 
                 (id SERIAL PRIMARY KEY, entreprise TEXT, secteur TEXT, contact TEXT, 
                 secteur_activite TEXT DEFAULT 'Non spécifié', tel TEXT, email TEXT, priorite TEXT, notes TEXT)""")

    try:
        c.execute("ALTER TABLE clients ADD COLUMN secteur_geo TEXT DEFAULT 'Béziers'")
    except Exception:
        pass

    # Table Besoins Clients & Alertes Matching
    c.execute("""CREATE TABLE IF NOT EXISTS besoins_clients (
        id SERIAL PRIMARY KEY,
        entreprise TEXT,
        secteur TEXT,
        description TEXT,
        statut TEXT DEFAULT 'Ouvert',
        date_creation TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS alertes_matching (
        id SERIAL PRIMARY KEY,
        candidat_id INTEGER,
        candidat_nom TEXT,
        besoin_id INTEGER,
        besoin_entreprise TEXT,
        besoin_description TEXT,
        score INTEGER,
        raison TEXT,
        lue INTEGER DEFAULT 0,
        date_alerte TEXT
    )""")

    # Table Contrats & Suivi Heures
    c.execute("""CREATE TABLE IF NOT EXISTS contrats (
                    id SERIAL PRIMARY KEY,
                    candidat_nom TEXT,
                    entreprise_nom TEXT,
                    type_contrat TEXT,
                    poste TEXT,
                    date_debut TEXT,
                    convention_collective TEXT,
                    statut_medecine TEXT DEFAULT 'À planifier',
                    date_limite_medecine TEXT,
                    date_fin TEXT,
                    suivi_medical_notes TEXT,
                    suggestion_ia_medecine TEXT
                )""")

    c.execute("""CREATE TABLE IF NOT EXISTS suivi_heures (
                    id SERIAL PRIMARY KEY,
                    candidat_nom TEXT,
                    entreprise_nom TEXT,
                    semaine TEXT,
                    heures_normales REAL DEFAULT 0,
                    heures_sup_25 REAL DEFAULT 0,
                    heures_sup_50 REAL DEFAULT 0
                )""")

    # Création du compte Admin par défaut si nécessaire
    c.execute("SELECT COUNT(*) FROM utilisateurs")
    if c.fetchone()[0] == 0:
        mdp_admin_clair = st.secrets.get("APP_PASSWORD")
        if mdp_admin_clair:
            mdp_admin_hash = bcrypt.hashpw(mdp_admin_clair.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            default_mail = st.secrets.get("EMAIL_USER", "")
            default_pwd = st.secrets.get("EMAIL_PASSWORD", "")
            default_imap = st.secrets.get("EMAIL_IMAP", "imap.gmail.com")
            c.execute(
                """INSERT INTO utilisateurs (email, password, date_fin_essai, est_admin, mail_perso, mail_password, mail_imap, nb_requetes_ia, quota_max, statut_abonnement) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                ("admin@omnirecrut.fr", mdp_admin_hash, "2099-12-31", 1, default_mail, default_pwd, default_imap, 0, 999999, "PRO"),
            )
    return True

# Initialisation unique de la DB au lancement
init_db()

# ==============================================================================
# --- FONCTIONS CACHÉES DE LECTURE (SANS LATENCE RÉSEAU RÉPÉTÉE) ---
# ==============================================================================
@st.cache_data(ttl=60, show_spinner=False)
def fetch_vivier_candidats():
    """Récupère l'ensemble des candidats en cache pour 60 secondes."""
    conn, c = get_db_cursor()
    c.execute("SELECT id, nom, poste, competences, statut, categorie_ia, avis_ia, score_matching, secteur_metier FROM candidats ORDER BY id DESC")
    return c.fetchall()

@st.cache_data(ttl=60, show_spinner=False)
def fetch_stats_vivier():
    """Statistiques globales du vivier."""
    conn, c = get_db_cursor()
    c.execute("SELECT COUNT(*), SUM(CASE WHEN statut LIKE '%Disponible%' THEN 1 ELSE 0 END), SUM(CASE WHEN statut LIKE '%mission%' THEN 1 ELSE 0 END) FROM candidats")
    stats = c.fetchone()
    total = stats[0] if stats and stats[0] else 0
    dispo = stats[1] if stats and stats[1] else 0
    mission = stats[2] if stats and stats[2] else 0
    return total, dispo, mission

@st.cache_data(ttl=30, show_spinner=False)
def fetch_user_quota_info(email_user):
    """Charge le quota et le statut abonnement de l'utilisateur."""
    if not email_user:
        return 0, 300, "GRATUIT"
    conn, c = get_db_cursor()
    c.execute("SELECT nb_requetes_ia, quota_max, statut_abonnement FROM utilisateurs WHERE email = %s", (email_user,))
    res = c.fetchone()
    if res:
        return res[0] or 0, res[1] or 300, res[2] or "GRATUIT"
    return 0, 300, "GRATUIT"

@st.cache_data(ttl=30, show_spinner=False)
def fetch_alertes_matching():
    """Charge le nombre d'alertes non lues et la liste des alertes récents."""
    conn, c = get_db_cursor()
    c.execute("SELECT COUNT(*) FROM alertes_matching WHERE lue = 0")
    nb_non_lues = c.fetchone()[0] or 0
    c.execute("""SELECT id, candidat_nom, besoin_entreprise, besoin_description, score, raison, lue
                 FROM alertes_matching ORDER BY lue ASC, id DESC LIMIT 15""")
    lignes = c.fetchall()
    return nb_non_lues, lignes

# ==============================================================================
# --- SÉCURITÉ & QUOTAS IA ---
# ==============================================================================
LIMITE_REQUETES_IA = 300

def peut_utiliser_ia(email_utilisateur):
    if st.session_state.get("is_admin") or st.session_state.get("user_statut") == "PRO":
        return True
    nb_actuel, q_max, statut = fetch_user_quota_info(email_utilisateur)
    if statut == "PRO":
        return True
    return nb_actuel < q_max

def incrémenter_quota_ia(email_utilisateur):
    if not st.session_state.get("is_admin") and email_utilisateur:
        try:
            conn, c = get_db_cursor()
            c.execute("UPDATE utilisateurs SET nb_requetes_ia = COALESCE(nb_requetes_ia, 0) + 1 WHERE email = %s", (email_utilisateur,))
            st.cache_data.clear() # Invalide le cache pour refléter le nouveau quota
        except Exception:
            pass

def reinitialiser_quota_ia(email_utilisateur):
    try:
        conn, c = get_db_cursor()
        c.execute("UPDATE utilisateurs SET nb_requetes_ia = 0 WHERE email = %s", (email_utilisateur,))
        st.cache_data.clear()
        return True
    except Exception:
        return False

# --- SÉCURITÉ : HACHAGE DES MOTS DE PASSE ---
def hacher_mdp(mot_de_passe_clair):
    return bcrypt.hashpw(mot_de_passe_clair.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verifier_mdp(mot_de_passe_saisi, valeur_stockee):
    if not valeur_stockee:
        return False
    try:
        if valeur_stockee.startswith(("$2b$", "$2a$", "$2y$")):
            return bcrypt.checkpw(mot_de_passe_saisi.encode("utf-8"), valeur_stockee.encode("utf-8"))
    except Exception:
        return False
    return mot_de_passe_saisi == valeur_stockee

def mdp_est_hashe(valeur_stockee):
    return bool(valeur_stockee) and valeur_stockee.startswith(("$2b$", "$2a$", "$2y$"))

# --- AUTHENTIFICATION ---
def check_password():
    for key, val in [("password_correct", False), ("user_email", ""), ("is_admin", False), ("user_statut", "GRATUIT"), ("user_config_email", {})]:
        if key not in st.session_state:
            st.session_state[key] = val

    if not st.session_state["password_correct"]:
        st.markdown(
            """
            <div style="text-align: center; padding: 50px 0px 20px 0px;">
                <h1 style="color: #ffb703 !important; font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 46px; font-weight: 700; letter-spacing: 2px; margin-bottom: 5px;">
                    OMNIRECRUT IA
                </h1>
                <p style="color: #a3b1cc; font-size: 16px; margin-top: 0px; font-weight: 300;">
                    Solution Tout-en-Un de Sourcing Intelligent & Gestion de Vivier
                </p>
                <hr style="border-color: #4a5568; margin: 25px auto; width: 40%;">
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.form("form_login"):
            email_saisi = st.text_input("Adresse e-mail :").strip().lower()
            pwd_saisi = st.text_input("Mot de passe :", type="password")
            btn_connexion = st.form_submit_button("Accéder à l'outil")

            if btn_connexion:
                if not email_saisi or not pwd_saisi:
                    st.error("Veuillez remplir votre e-mail et votre mot de passe.")
                else:
                    try:
                        conn, c = get_db_cursor()
                        c.execute(
                            "SELECT password, date_fin_essai, est_admin, mail_perso, mail_password, mail_imap, statut_abonnement FROM utilisateurs WHERE email = %s",
                            (email_saisi,),
                        )
                        res = c.fetchone()

                        if res:
                            db_password, db_date_fin, db_is_admin, m_perso, m_pass, m_imap, db_statut = res
                            if verifier_mdp(pwd_saisi, db_password):
                                if not mdp_est_hashe(db_password):
                                    c.execute("UPDATE utilisateurs SET password = %s WHERE email = %s", (hacher_mdp(pwd_saisi), email_saisi))

                                date_exp = datetime.date.fromisoformat(db_date_fin)
                                if db_is_admin == 1 or datetime.date.today() <= date_exp:
                                    st.session_state["password_correct"] = True
                                    st.session_state["user_email"] = email_saisi
                                    st.session_state["is_admin"] = bool(db_is_admin == 1)
                                    st.session_state["user_statut"] = db_statut or "GRATUIT"
                                    st.session_state["user_config_email"] = {
                                        "email": m_perso or email_saisi,
                                        "password": m_pass,
                                        "imap": m_imap or "imap.gmail.com",
                                    }
                                    st.rerun()
                                else:
                                    st.error(f"⏳ Votre période d'essai a expiré le {date_exp.strftime('%d/%m/%Y')}.")
                            else:
                                st.error("Mot de passe incorrect.")
                        else:
                            st.error("Aucun compte associé à cet e-mail.")
                    except Exception as err:
                        st.error(f"Erreur technique de connexion : {err}")
        return False
    return True

if not check_password():
    st.stop()

# --- IMPORT CONFIGURATION GEMINI ---
try:
    gemini_key = st.secrets["GEMINI_API_KEY"]
    genai.configure(api_key=gemini_key)
except Exception:
    pass

# ==============================================================================
# --- AGENT IA D'ANALYSE ENRICHIE DE CV ---
# ==============================================================================
def _save_candidate_to_sqlite(
    nom_complet: str,
    diplomes: list,
    hard_skills: list,
    soft_skills_transferables: list,
    traits_dominants: list,
    indices_parcours_pro: str,
    indices_centres_interet: str,
    coherence_projet_pro: str,
    metiers_cibles: list,
    pourcentage_adequation: int,
    compte_rendu: str,
    secteur_metier: str = "Non spécifié",
    cv_texte: str = "",
) -> dict:
    conn, c = get_db_cursor()
    poste_cible = metiers_cibles[0] if metiers_cibles else "Profil Analysé"
    competences_resume = ", ".join(hard_skills + diplomes) if (hard_skills or diplomes) else "Non spécifié"
    profil_comportemental = {
        "traits_dominants": traits_dominants,
        "indices_parcours_pro": indices_parcours_pro,
        "indices_centres_interet": indices_centres_interet,
        "coherence_projet_pro": coherence_projet_pro,
    }

    c.execute(
        """INSERT INTO candidats
           (nom, poste, competences, statut, categorie_ia, avis_ia, score_matching,
            secteur_metier, cv_texte, competences_transferables, profil_riasec, metiers_cibles, date_ajout)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
           RETURNING id""",
        (
            nom_complet,
            poste_cible,
            competences_resume,
            "Nouveau",
            (traits_dominants[0] if traits_dominants else "À Classer"),
            compte_rendu,
            f"{pourcentage_adequation} %",
            secteur_metier,
            cv_texte,
            json.dumps(soft_skills_transferables, ensure_ascii=False),
            json.dumps(profil_comportemental, ensure_ascii=False),
            json.dumps(metiers_cibles, ensure_ascii=False),
            datetime.datetime.now().isoformat(),
        ),
    )
    candidat_id = c.fetchone()[0]
    st.cache_data.clear() # Invalidation du cache du vivier

    alertes = _matcher_candidat_vs_besoins_ouverts(candidat_id, nom_complet, poste_cible, competences_resume, secteur_metier)
    message = f"Candidat '{nom_complet}' enregistré dans le vivier."
    if alertes:
        message += f" {len(alertes)} correspondance(s) détectée(s) avec des besoins clients ouverts."
    return {"status": "success", "message": message, "alertes": alertes}

_AGENT_TOOLS = {"save_candidate_to_sqlite": _save_candidate_to_sqlite}

def _proto_to_python(value):
    if isinstance(value, (list,)) or type(value).__name__ == "RepeatedComposite":
        return [_proto_to_python(v) for v in value]
    if isinstance(value, dict) or type(value).__name__ == "MapComposite":
        return {k: _proto_to_python(v) for k, v in value.items()}
    return value

_tool_save_candidate = genai.protos.Tool(
    function_declarations=[
        genai.protos.FunctionDeclaration(
            name="save_candidate_to_sqlite",
            description="Enregistre le profil complet et enrichi d'un candidat dans la base du vivier.",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "nom_complet": genai.protos.Schema(type=genai.protos.Type.STRING),
                    "diplomes": genai.protos.Schema(type=genai.protos.Type.ARRAY, items=genai.protos.Schema(type=genai.protos.Type.STRING)),
                    "hard_skills": genai.protos.Schema(type=genai.protos.Type.ARRAY, items=genai.protos.Schema(type=genai.protos.Type.STRING)),
                    "soft_skills_transferables": genai.protos.Schema(type=genai.protos.Type.ARRAY, items=genai.protos.Schema(type=genai.protos.Type.STRING)),
                    "traits_dominants": genai.protos.Schema(type=genai.protos.Type.ARRAY, items=genai.protos.Schema(type=genai.protos.Type.STRING)),
                    "indices_parcours_pro": genai.protos.Schema(type=genai.protos.Type.STRING),
                    "indices_centres_interet": genai.protos.Schema(type=genai.protos.Type.STRING),
                    "coherence_projet_pro": genai.protos.Schema(type=genai.protos.Type.STRING),
                    "metiers_cibles": genai.protos.Schema(type=genai.protos.Type.ARRAY, items=genai.protos.Schema(type=genai.protos.Type.STRING)),
                    "pourcentage_adequation": genai.protos.Schema(type=genai.protos.Type.INTEGER),
                    "compte_rendu": genai.protos.Schema(type=genai.protos.Type.STRING),
                },
                required=[
                    "nom_complet", "diplomes", "hard_skills", "soft_skills_transferables",
                    "traits_dominants", "indices_parcours_pro", "indices_centres_interet",
                    "coherence_projet_pro", "metiers_cibles", "pourcentage_adequation", "compte_rendu",
                ],
            ),
        )
    ]
)

_SYSTEM_PROMPT_AGENT = """
Tu es un agent IA expert en analyse de profils professionnels pour un cabinet de recrutement.
Ta mission : analyser un CV brut, SANS offre d'emploi de référence, pour enrichir un vivier de candidats.
Tu dois être rigoureux, factuel, et ne jamais inventer d'informations absentes du CV.
Appelle SYSTÉMATIQUEMENT la fonction save_candidate_to_sqlite une fois l'analyse terminée.
"""

_agent_model = genai.GenerativeModel(
    model_name="gemini-2.5-flash",
    system_instruction=_SYSTEM_PROMPT_AGENT,
    tools=[_tool_save_candidate],
    generation_config={"temperature": 0.3},
)

def analyser_cv_avec_agent(texte_cv: str, secteur_metier: str, max_tentatives: int = 3) -> dict:
    for tentative in range(1, max_tentatives + 1):
        try:
            chat = _agent_model.start_chat(enable_automatic_function_calling=False)
            response = chat.send_message(f"Voici un CV brut à analyser et à enregistrer dans le vivier :\n\n{texte_cv}")
            donnees_structurees = None

            while True:
                finish_reason = response.candidates[0].finish_reason
                if str(finish_reason).endswith("MALFORMED_FUNCTION_CALL"):
                    raise ValueError("MALFORMED_FUNCTION_CALL")

                function_call = next((p.function_call for p in response.candidates[0].content.parts if p.function_call), None)
                if function_call is None:
                    return {"compte_rendu": response.text, "donnees_structurees": donnees_structurees}

                fn_name = function_call.name
                fn_args = _proto_to_python(dict(function_call.args))
                if fn_name == "save_candidate_to_sqlite":
                    fn_args["secteur_metier"] = secteur_metier
                    fn_args["cv_texte"] = texte_cv
                donnees_structurees = fn_args

                result = _AGENT_TOOLS.get(fn_name, lambda **_: {"status": "error", "message": "Fonction inconnue"})(**fn_args)

                response = chat.send_message(
                    genai.protos.Content(parts=[genai.protos.Part(
                        function_response=genai.protos.FunctionResponse(name=fn_name, response={"result": result})
                    )])
                )
        except Exception:
            if tentative == max_tentatives:
                raise
            time.sleep(1.5 * tentative)
            continue

SEUIL_ALERTE_MATCHING = 70

def _extraire_json_liste(texte_brut: str) -> list:
    txt = texte_brut.strip().replace("```json", "").replace("```", "").strip()
    if "[" in txt and "]" in txt:
        txt = txt[txt.find("["): txt.rfind("]") + 1]
    try:
        return json.loads(txt)
    except Exception:
        return []

def _matcher_candidat_vs_besoins_ouverts(candidat_id: int, nom: str, poste: str, competences: str, secteur: str) -> list:
    conn, c = get_db_cursor()
    c.execute("SELECT id, entreprise, description FROM besoins_clients WHERE secteur = %s AND statut = 'Ouvert'", (secteur,))
    besoins = c.fetchall()
    if not besoins:
        return []

    besoins_data = [{"besoin_id": b[0], "entreprise": b[1], "description": b[2]} for b in besoins]
    try:
        model_match = genai.GenerativeModel("gemini-2.5-flash")
        prompt = f"""Compare ce candidat à chacun des besoins clients ci-dessous.
Candidat : poste cible '{poste}', compétences : {competences}.
Besoins : {json.dumps(besoins_data, ensure_ascii=False)}
Renvoie STRICTEMENT un tableau JSON avec 'besoin_id', 'score' (entier 0-100), 'raison'."""
        response = model_match.generate_content(prompt)
        resultats = _extraire_json_liste(response.text)
    except Exception:
        return []

    besoins_par_id = {b[0]: b for b in besoins}
    alertes_creees = []
    for r in resultats:
        score = int(r.get("score", 0))
        besoin_id = r.get("besoin_id")
        if score >= SEUIL_ALERTE_MATCHING and besoin_id in besoins_par_id:
            b = besoins_par_id[besoin_id]
            c.execute(
                """INSERT INTO alertes_matching (candidat_id, candidat_nom, besoin_id, besoin_entreprise, besoin_description, score, raison, date_alerte)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (candidat_id, nom, besoin_id, b[1], b[2], score, r.get("raison", ""), datetime.datetime.now().isoformat()),
            )
            alertes_creees.append({"besoin_entreprise": b[1], "score": score, "raison": r.get("raison", "")})
    st.cache_data.clear()
    return alertes_creees

def generer_digest_quotidien() -> dict:
    conn, c = get_db_cursor()
    digest = {}
    try:
        c.execute("SELECT COUNT(*) FROM alertes_matching WHERE lue = 0")
        digest["alertes_non_lues"] = c.fetchone()[0] or 0
    except Exception:
        digest["alertes_non_lues"] = 0

    try:
        aujourd_hui = datetime.date.today().isoformat()
        limite_medecine = (datetime.date.today() + datetime.timedelta(days=15)).isoformat()
        c.execute("SELECT candidat_nom, date_limite_medecine FROM contrats WHERE date_limite_medecine BETWEEN %s AND %s ORDER BY date_limite_medecine ASC", (aujourd_hui, limite_medecine))
        digest["visites_medecine_proches"] = c.fetchall()
    except Exception:
        digest["visites_medecine_proches"] = []

    try:
        limite_fin_contrat = (datetime.date.today() + datetime.timedelta(days=7)).isoformat()
        c.execute("SELECT candidat_nom, date_fin, entreprise_nom FROM contrats WHERE date_fin BETWEEN %s AND %s ORDER BY date_fin ASC", (aujourd_hui, limite_fin_contrat))
        digest["fins_de_contrat_proches"] = c.fetchall()
    except Exception:
        digest["fins_de_contrat_proches"] = []

    try:
        seuil_dormance = (datetime.date.today() - datetime.timedelta(days=30)).isoformat()
        c.execute("SELECT id, nom, poste FROM candidats WHERE statut = 'Disponible' AND (date_ajout IS NULL OR date_ajout <= %s)", (seuil_dormance,))
        digest["candidats_dormants"] = c.fetchall()
    except Exception:
        digest["candidats_dormants"] = []

    return digest

def generer_brouillon_relance(nom_candidat: str, poste: str) -> str:
    try:
        model_relance = genai.GenerativeModel("gemini-2.5-flash")
        prompt = f"Rédige un e-mail court et chaleureux de relance pour {nom_candidat}, candidat sur le poste de {poste}, pour savoir s'il/elle est toujours disponible. Signe 'L'équipe OmniRecrut IA'."
        return model_relance.generate_content(prompt).text
    except Exception as e:
        return f"Erreur lors de la génération : {e}"

# ==============================================================================
# --- GESTION DU RETOUR DE PAIEMENT STRIPE ---
# ==============================================================================
if st.query_params.get("payment") == "success":
    user_email = st.session_state.get("user_email")
    if user_email:
        conn, c = get_db_cursor()
        c.execute("UPDATE utilisateurs SET statut_abonnement = 'PRO', quota_max = 999999 WHERE email = %s", (user_email,))
        st.session_state['user_statut'] = 'PRO'
        st.cache_data.clear()
        st.balloons()
        st.success("🎉 Félicitations ! Votre abonnement PRO Illimité est actif.")
        st.query_params.clear()

# ==============================================================================
# --- SIDEBAR (PANNEAU LATÉRAL) ---
# ==============================================================================
with st.sidebar:
    nb_alertes_non_lues, lignes_alertes = fetch_alertes_matching()
    with st.expander(f"🔔 Alertes de matching ({nb_alertes_non_lues})", expanded=(nb_alertes_non_lues > 0)):
        if not lignes_alertes:
            st.caption("Aucune alerte pour le moment.")
        else:
            conn, c = get_db_cursor()
            for alerte_id, cand_nom, entreprise, desc_besoin, score_al, raison_al, lue in lignes_alertes:
                badge = "🟢" if not lue else "⚪"
                st.markdown(f"{badge} **{cand_nom}** ↔ **{entreprise}** — {score_al}%")
                st.caption(raison_al or desc_besoin[:80])
                if not lue:
                    if st.button("✅ Marquer comme lue", key=f"lue_{alerte_id}", use_container_width=True):
                        c.execute("UPDATE alertes_matching SET lue = 1 WHERE id = %s", (alerte_id,))
                        st.cache_data.clear()
                        st.rerun()
                st.markdown("---")

    st.markdown("<h3 style='color: #ffffff !important;'>⚙️ Mon Compte</h3>", unsafe_allow_html=True)
    user_email = st.session_state.get("user_email", "")
    
    quota_utilise, quota_max, statut_abonnement = fetch_user_quota_info(user_email)
    LIEN_STRIPE_CHECKOUT = "https://buy.stripe.com/test_cNi28rd0UfUW5xMdRFbsc00"
    
    if statut_abonnement == "PRO" or st.session_state.get("user_statut") == "PRO":
        st.markdown("""
            <div style="background-color: #2e7d32; padding: 12px; border-radius: 8px; text-align: center; color: white; font-weight: bold; margin-bottom: 15px;">
                👑 COMPTE PRO ILLIMITÉ
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("<h5 style='color: #ffb703 !important; margin-bottom: 5px;'>📊 Quotas IA Mensuels</h5>", unsafe_allow_html=True)
        pct_utilise = min(1.0, quota_utilise / quota_max) if quota_max > 0 else 0.0
        st.progress(pct_utilise)
        st.markdown(f"<p style='color: #e2e8f0; font-size: 14px; margin-top: 5px;'>Utilisation : <b>{quota_utilise} / {quota_max}</b> requêtes</p>", unsafe_allow_html=True)
        st.link_button("💳 S'abonner (Accès Illimité)", LIEN_STRIPE_CHECKOUT, type="primary", use_container_width=True)
        
    st.markdown("---")

LISTE_SECTEURS = [
    "Tous", "Restauration / Hôtellerie", "Tertiaire / Bureau / PME",
    "Transport / Logistique", "Bâtiment / TP", "Industrie / Technique", "Autre"
]

st.markdown(
    """
    <div style="text-align: center; padding: 10px 0px 25px 0px;">
        <h1 style="color: #ffb703 !important; font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 42px; font-weight: 700; letter-spacing: 2px; margin-bottom: 5px;">
            🤖 OMNIRECRUT IA
        </h1>
        <p style="color: #a3b1cc; font-size: 16px; margin-top: 0px; font-weight: 300;">
            Solution Tout-en-Un de Sourcing Intelligent & Gestion de Vivier
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

if "offre_transferee" not in st.session_state: st.session_state["offre_transferee"] = ""
if "page_active" not in st.session_state: st.session_state["page_active"] = "🗃️ VIVIER DE CANDIDATS"

options_menu = [
    "🧭 TABLEAU DE BORD", "🗃️ VIVIER DE CANDIDATS", "🎯 MATCHING IA OFFRES & CV",
    "🏢 PORTEFEUILLE CLIENTS", "✍️ RÉDACTION ANNONCES IA", "🖥️ TRI & CLASSEMENT IA",
    "🤝 MATCHING & OPPORTUNITÉS", "📊 PIPELINE DE RECRUTEMENT",
    "🏹 SOURCING EXTERNE & CHASSE", "📋 GESTION ADMINISTRATIVE & RH"
]
index_actuel = options_menu.index(st.session_state['page_active']) if st.session_state['page_active'] in options_menu else 0
menu = st.sidebar.radio("MENU PRINCIPAL", options_menu, index=index_actuel)
st.session_state['page_active'] = menu

# ==============================================================================
# --- ONGLET 0 : TABLEAU DE BORD ---
# ==============================================================================
if st.session_state['page_active'] == "🧭 TABLEAU DE BORD":
    st.header("🧭 Tableau de Bord — Synthèse Quotidienne")
    st.caption("Généré à partir des données existantes — aucune action n'est prise automatiquement.")

    digest = generer_digest_quotidien()
    col_d1, col_d2, col_d3 = st.columns(3)
    with col_d1: st.metric("🔔 Alertes non lues", digest["alertes_non_lues"])
    with col_d2: st.metric("🩺 Visites médecine < 15j", len(digest["visites_medecine_proches"]))
    with col_d3: st.metric("⏳ Fins contrat < 7j", len(digest["fins_de_contrat_proches"]))

    st.markdown("---")
    col_alertes_dig, col_dormants_dig = st.columns(2)

    with col_alertes_dig:
        st.subheader("🩺 Échéances à surveiller")
        if digest["visites_medecine_proches"]:
            for nom_m, date_m in digest["visites_medecine_proches"]:
                st.markdown(f"- **{nom_m}** — visite médicale le {date_m}")
        else:
            st.caption("Aucune visite médicale urgente.")

    with col_dormants_dig:
        st.subheader("💤 Candidats dormants (> 30 jours)")
        if not digest["candidats_dormants"]:
            st.caption("Aucun candidat dormant.")
        else:
            for cand_id_dorm, nom_dorm, poste_dorm in digest["candidats_dormants"]:
                st.markdown(f"**{nom_dorm}** — {poste_dorm or 'Non précisé'}")
                if st.button(f"✍️ Générer relance", key=f"brouillon_{cand_id_dorm}"):
                    if peut_utiliser_ia(st.session_state.get("user_email")):
                        brouillon = generer_brouillon_relance(nom_dorm, poste_dorm or "votre secteur")
                        incrémenter_quota_ia(st.session_state.get("user_email"))
                        st.session_state[f"brouillon_{cand_id_dorm}"] = brouillon
                    else:
                        st.error("Quota IA atteint.")
                if st.session_state.get(f"brouillon_{cand_id_dorm}"):
                    st.info(st.session_state[f"brouillon_{cand_id_dorm}"])

# ==============================================================================
# --- ONGLET 1 : VIVIER DE CANDIDATS ---
# ==============================================================================
elif st.session_state['page_active'] == "🗃️ VIVIER DE CANDIDATS":
    st.header("🗃️ Gestion et Pilotage du Vivier Interne")
    
    total_cand, dispo_cand, mission_cand = fetch_stats_vivier()
    col_kpi1, col_kpi2, col_kpi3 = st.columns(3)
    with col_kpi1: st.metric(label="👥 Total Talents", value=total_cand)
    with col_kpi2: st.metric(label="🟢 Disponibles", value=dispo_cand)
    with col_kpi3: st.metric(label="🔵 En Mission", value=mission_cand)

    st.markdown("---")
    with st.expander("🧠 Analyse enrichie d'un CV (Agent IA)", expanded=False):
        fichier_cv_agent = st.file_uploader("CV au format PDF :", type=["pdf"], key="uploader_cv_agent")
        secteur_cv_agent = st.selectbox("Secteur :", LISTE_SECTEURS[1:], key="secteur_cv_agent")

        if st.button("🚀 Lancer l'analyse", key="btn_agent_cv"):
            if not fichier_cv_agent:
                st.error("⚠️ Merci de déposer un CV PDF.")
            elif not peut_utiliser_ia(st.session_state.get("user_email")):
                st.error("⚠️ Quota IA mensuel atteint.")
            else:
                try:
                    reader = PdfReader(fichier_cv_agent)
                    texte_cv = "".join([p.extract_text() for p in reader.pages if p.extract_text()])
                    with st.spinner("Analyse par l'agent IA en cours..."):
                        res_agent = analyser_cv_avec_agent(texte_cv, secteur_cv_agent)
                    incrémenter_quota_ia(st.session_state.get("user_email"))
                    st.session_state["dernier_rapport_agent"] = res_agent
                    st.success("✅ Candidat enregistré dans le vivier !")
                except Exception as e:
                    st.error(f"Erreur d'analyse : {e}")

    st.markdown("---")
    st.subheader("🔍 Filtrage des Talents par Secteur")
    secteur_filtre = st.selectbox("Secteur :", LISTE_SECTEURS)
    
    donnees = fetch_vivier_candidats()
    if donnees:
        df_vivier = pd.DataFrame(donnees, columns=["ID", "Nom", "Poste", "Coordonnées / Compétences", "Statut", "Catégorie", "Avis IA", "Score Match", "Secteur Métier"])
        if secteur_filtre != "Tous":
            df_vivier = df_vivier[df_vivier["Secteur Métier"].str.strip() == secteur_filtre.strip()]
        
        if not df_vivier.empty:
            st.success(f"📊 {len(df_vivier)} profil(s) affiché(s)")
            edited_df = st.data_editor(
                df_vivier, 
                use_container_width=True, 
                hide_index=True,
                key="editor_vivier",
                column_config={
                    "ID": st.column_config.NumberColumn("ID", disabled=True, width="small"),
                    "Nom": st.column_config.TextColumn("Nom", disabled=True),
                    "Statut": st.column_config.SelectboxColumn("Statut", options=["Disponible", "Non disponible", "En mission"], required=True),
                    "Catégorie": st.column_config.SelectboxColumn("Catégorie", options=["À Classer", "⭐ Top Profil", "✅ Profil Confirmé", "🌱 Junior", "⏳ À Recontacter", "❌ Ne pas retenir"], required=True)
                }
            )

            if st.session_state.get("editor_vivier") and st.session_state["editor_vivier"]["edited_rows"]:
                conn, c = get_db_cursor()
                for index, modifications in st.session_state["editor_vivier"]["edited_rows"].items():
                    id_candidat = int(df_vivier.iloc[index]["ID"])
                    for colonne, val in modifications.items():
                        col_sql = {"Statut": "statut", "Catégorie": "categorie_ia"}.get(colonne)
                        if col_sql:
                            c.execute(f"UPDATE candidats SET {col_sql} = %s WHERE id = %s", (val, id_candidat))
                st.cache_data.clear()
                st.success("Modifications enregistrées !")
                st.rerun()

# ==============================================================================
# --- ONGLET 2 : MATCHING AUTOMATISÉ ---
# ==============================================================================
elif st.session_state['page_active'] == "🎯 MATCHING IA OFFRES & CV":
    st.header("🎯 Module de Matching & Scoring Prédictif")
    col_offre, col_cvs = st.columns(2)
    with col_offre: 
        texte_offre = st.text_area("Annonce / Fiche de poste :", value=st.session_state.get('offre_transferee', ''), height=250)
    with col_cvs: 
        fichiers_cv = st.file_uploader("Sélectionnez des CV (PDF)", type=["pdf"], accept_multiple_files=True)

    if st.button("🚀 LANCER LE MATCHING INTELLIGENT"):
        if not texte_offre or not fichiers_cv: 
            st.error("⚠️ Offre ou CV manquant.")
        elif not peut_utiliser_ia(st.session_state.get("user_email")):
            st.error("⚠️ Quota IA atteint.")
        else:
            with st.spinner("Analyse comparative par l'IA..."):
                model = genai.GenerativeModel("gemini-2.5-flash")
                for f in fichiers_cv:
                    reader = PdfReader(f)
                    txt = "".join([p.extract_text() for p in reader.pages if p.extract_text()])
                    prompt = f"Évalue l'adéquation de ce CV par rapport à l'offre :\nOFFRE:\n{texte_offre}\n\nCV:\n{txt}"
                    res = model.generate_content(prompt)
                    st.markdown(f"### Résultats pour {f.name}")
                    st.write(res.text)
            incrémenter_quota_ia(st.session_state.get("user_email"))
# ==============================================================================
# --- ONGLET 3 : PORTEFEUILLE CLIENTS ---
# ==============================================================================
elif st.session_state['page_active'] == "🏢 PORTEFEUILLE CLIENTS":
    st.header("🏢 Portefeuille Clients & Besoins de Sourcing")
    conn, c = get_db_cursor()

    tab_entreprises, tab_besoins = st.tabs(["🏢 Entreprises Partenaires", "🎯 Besoins de Sourcing"])

    with tab_entreprises:
        with st.expander("➕ Ajouter un nouveau client", expanded=False):
            with st.form("form_add_client"):
                col_c1, col_c2 = st.columns(2)
                with col_c1:
                    nom_ent = st.text_input("Nom de l'entreprise *")
                    secteur_ent = st.selectbox("Secteur d'activité", LISTE_SECTEURS[1:])
                    contact_ent = st.text_input("Nom du contact principal")
                with col_c2:
                    tel_ent = st.text_input("Téléphone")
                    email_ent = st.text_input("E-mail contact")
                    prio_ent = st.selectbox("Priorité client", ["Normale", "⭐ Haute", "🔥 URGENT"])
                
                notes_ent = st.text_area("Notes / Spécificités")
                btn_cli = st.form_submit_button("Enregistrer le Client")

                if btn_cli:
                    if not nom_ent:
                        st.error("Le nom de l'entreprise est obligatoire.")
                    else:
                        c.execute(
                            """INSERT INTO clients (entreprise, secteur, contact, tel, email, priorite, notes, secteur_activite)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                            (nom_ent, secteur_ent, contact_ent, tel_ent, email_ent, prio_ent, notes_ent, secteur_ent)
                        )
                        st.cache_data.clear()
                        st.success(f"Entreprise '{nom_ent}' ajoutée avec succès !")
                        st.rerun()

        st.subheader("📋 Liste des Clients")
        c.execute("SELECT id, entreprise, secteur_activite, contact, tel, email, priorite, notes FROM clients ORDER BY id DESC")
        clients = c.fetchall()
        if clients:
            df_cli = pd.DataFrame(clients, columns=["ID", "Entreprise", "Secteur", "Contact", "Tél", "Email", "Priorité", "Notes"])
            st.dataframe(df_cli, use_container_width=True, hide_index=True)
        else:
            st.info("Aucun client enregistré pour le moment.")

    with tab_besoins:
        st.subheader("🎯 Besoins de Sourcing Ouverts")
        with st.expander("➕ Publier un nouveau besoin client", expanded=False):
            with st.form("form_add_besoin"):
                c.execute("SELECT entreprise FROM clients ORDER BY entreprise ASC")
                liste_ents = [r[0] for r in c.fetchall()] or ["Client Général"]
                
                besoin_ent = st.selectbox("Entreprise cliente", liste_ents)
                besoin_secteur = st.selectbox("Secteur métier recherché", LISTE_SECTEURS[1:])
                besoin_desc = st.text_area("Description du besoin / Postes / Compétences clés recherchées *")
                btn_bes = st.form_submit_button("Publier le Besoin & Déclencher le Matching")

                if btn_bes:
                    if not besoin_desc:
                        st.error("La description est obligatoire.")
                    else:
                        c.execute(
                            """INSERT INTO besoins_clients (entreprise, secteur, description, date_creation)
                               VALUES (%s, %s, %s, %s) RETURNING id""",
                            (besoin_ent, besoin_secteur, besoin_desc, datetime.datetime.now().isoformat())
                        )
                        besoin_id = c.fetchone()[0]
                        st.cache_data.clear()
                        st.success("Besoin publié en base !")
                        st.rerun()

        c.execute("SELECT id, entreprise, secteur, description, statut, date_creation FROM besoins_clients ORDER BY id DESC")
        besoins = c.fetchall()
        if besoins:
            df_bes = pd.DataFrame(besoins, columns=["ID", "Entreprise", "Secteur", "Description", "Statut", "Date"])
            st.dataframe(df_bes, use_container_width=True, hide_index=True)

# ==============================================================================
# --- ONGLET 4 : RÉDACTION ANNONCES IA ---
# ==============================================================================
elif st.session_state['page_active'] == "✍️ RÉDACTION ANNONCES IA":
    st.header("✍️ Générateur d'Annonces de Recrutement IA")
    
    col_g1, col_g2 = st.columns(2)
    with col_g1:
        titre_poste = st.text_input("Intitulé du poste *")
        secteur_annonce = st.selectbox("Secteur d'activité", LISTE_SECTEURS[1:])
        type_contrat = st.selectbox("Type de contrat", ["CDI", "CDD", "Intérim", "Alternance", "Freelance"])
    with col_g2:
        lieu_poste = st.text_input("Lieu de travail", value="Béziers / Région")
        remuneration = st.text_input("Rémunération / Avantages", value="Selon profil + Primes")
        ton_annonce = st.selectbox("Ton de l'annonce", ["Professionnel & Détaillé", "Dynamique & Attractif", "Inspirant / Corporate"])

    mots_cles = st.text_area("Compétences indispensables & Précisions sur la mission :")

    if st.button("🪄 RÉDIGER L'ANNONCE DÉTAILLÉE"):
        if not titre_poste:
            st.error("Veuillez renseigner au moins l'intitulé du poste.")
        elif not peut_utiliser_ia(st.session_state.get("user_email")):
            st.error("Quota IA mensuel atteint.")
        else:
            with st.spinner("Rédaction optimisée SEO & Attrition par Gemini..."):
                model = genai.GenerativeModel("gemini-2.5-flash")
                prompt = f"""Rédige une fiche d'offre d'emploi complète et attrayante pour :
Poste : {titre_poste}
Secteur : {secteur_annonce}
Contrat : {type_contrat}
Lieu : {lieu_poste}
Rémunération : {remuneration}
Ton : {ton_annonce}
Mots-clés / Spécificités : {mots_cles}

Structure l'annonce avec :
1. Titre percutant
2. Présentation de l'entreprise & du cadre
3. Missions principales
4. Profil recherché & Compétences requises
5. Avantages & Modalités
6. Appel à l'action pour postuler."""

                res = model.generate_content(prompt)
                incrémenter_quota_ia(st.session_state.get("user_email"))
                
                st.session_state['offre_transferee'] = res.text
                st.success("Annonce générée avec succès !")
                st.markdown(res.text)

# ==============================================================================
# --- ONGLET 5 : TRI & CLASSEMENT IA ---
# ==============================================================================
elif st.session_state['page_active'] == "🖥️ TRI & CLASSEMENT IA":
    st.header("🖥️ Tri Automatique & Qualification de Candidatures")
    
    cvs_lot = st.file_uploader("Importer des CV en masse (PDF)", type=["pdf"], accept_multiple_files=True, key="lot_cvs")
    sec_tri = st.selectbox("Assigner au secteur :", LISTE_SECTEURS[1:], key="sec_tri")

    if st.button("⚡ QUALIFIER & CLASSER LE LOT DE CV"):
        if not cvs_lot:
            st.error("Sélectionnez au moins un fichier PDF.")
        elif not peut_utiliser_ia(st.session_state.get("user_email")):
            st.error("Quota IA atteint.")
        else:
            barre_prog = st.progress(0)
            model = genai.GenerativeModel("gemini-2.5-flash")
            conn, c = get_db_cursor()

            for i, f in enumerate(cvs_lot):
                try:
                    reader = PdfReader(f)
                    txt = "".join([p.extract_text() for p in reader.pages if p.extract_text()])
                    
                    prompt = f"""Analyse ce CV brut et extrais sous forme de JSON strict :
{{
  "nom": "Nom du candidat s'il apparait, sinon 'Inconnu'",
  "poste": "Poste principal ou métier identifié",
  "skills": "Top 5 compétences techniques clés",
  "categorie": "⭐ Top Profil OR ✅ Profil Confirmé OR 🌱 Junior OR ⏳ À Recontacter",
  "avis": "Un avis synthétique de 2 phrases sur les forces du profil"
}}
CV: {txt}"""

                    res = model.generate_content(prompt)
                    txt_clean = res.text.replace("```json", "").replace("```", "").strip()
                    data = json.loads(txt_clean)

                    c.execute(
                        """INSERT INTO candidats (nom, poste, competences, statut, categorie_ia, avis_ia, score_matching, secteur_metier, cv_texte, date_ajout)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (
                            data.get("nom", "Inconnu"),
                            data.get("poste", "Non spécifié"),
                            data.get("skills", ""),
                            "Disponible",
                            data.get("categorie", "À Classer"),
                            data.get("avis", ""),
                            "80 %",
                            sec_tri,
                            txt,
                            datetime.datetime.now().isoformat()
                        )
                    )
                except Exception as e:
                    st.warning(f"Erreur sur le CV {f.name} : {e}")

                barre_prog.progress((i + 1) / len(cvs_lot))

            st.cache_data.clear()
            incrémenter_quota_ia(st.session_state.get("user_email"))
            st.success("✅ Lot de CV qualifié et intégré au Vivier !")

# ==============================================================================
# --- ONGLET 6 : MATCHING & OPPORTUNITÉS ---
# ==============================================================================
elif st.session_state['page_active'] == "🤝 MATCHING & OPPORTUNITÉS":
    st.header("🤝 Moteur de Recommandation & Opportunités Sourcing")
    
    conn, c = get_db_cursor()
    c.execute("SELECT id, nom, poste, competences FROM candidats WHERE statut = 'Disponible' ORDER BY id DESC")
    cands = c.fetchall()
    
    c.execute("SELECT id, entreprise, description FROM besoins_clients WHERE statut = 'Ouvert' ORDER BY id DESC")
    besoins = c.fetchall()

    if not cands or not besoins:
        st.info("💡 Vous devez avoir au moins 1 candidat disponible et 1 besoin client ouvert pour utiliser ce module.")
    else:
        st.write(f"📊 **Analyse comparative :** {len(cands)} candidat(s) dispo ↔ {len(besoins)} besoin(s) ouvert(s)")
        if st.button("🔍 CALCULER LES MEILLEURES CORRESPONDANCES (CROSS-MATCH)"):
            if not peut_utiliser_ia(st.session_state.get("user_email")):
                st.error("Quota IA atteint.")
            else:
                with st.spinner("Alignement matriciel par l'IA..."):
                    model = genai.GenerativeModel("gemini-2.5-flash")
                    prompt = f"""Tu es un expert sourcing. Fais le matching global entre ces candidats et ces besoins :
CANDIDATS : {json.dumps([{'id': r[0], 'nom': r[1], 'poste': r[2], 'skills': r[3]} for r in cands], ensure_ascii=False)}
BESOINS : {json.dumps([{'id': r[0], 'entreprise': r[1], 'besoin': r[2]} for r in besoins], ensure_ascii=False)}

Affiche les 5 meilleurs duos Candidat ↔ Entreprise sous forme de tableau comparatif clair avec le % d'adéquation et la raison principale."""

                    res = model.generate_content(prompt)
                    incrémenter_quota_ia(st.session_state.get("user_email"))
                    st.markdown(res.text)

# ==============================================================================
# --- ONGLET 7 : PIPELINE DE RECRUTEMENT ---
# ==============================================================================
elif st.session_state['page_active'] == "📊 PIPELINE DE RECRUTEMENT":
    st.header("📊 Pipeline Kanban des Candidatures")
    
    conn, c = get_db_cursor()
    c.execute("SELECT id, nom, poste, statut, categorie_ia FROM candidats ORDER BY id DESC")
    rows = c.fetchall()

    colonnes_kanban = ["Disponible", "Non disponible", "En mission"]
    col_k1, col_k2, col_k3 = st.columns(3)
    dict_cols = {"Disponible": col_k1, "Non disponible": col_k2, "En mission": col_k3}

    for col_name, col_obj in dict_cols.items():
        with col_obj:
            st.subheader(f"📌 {col_name}")
            items = [r for r in rows if r[3] == col_name]
            st.caption(f"{len(items)} candidat(s)")
            
            for item_id, item_nom, item_poste, item_stat, item_cat in items:
                with st.container(border=True):
                    st.markdown(f"**{item_nom}**")
                    st.caption(f"💼 {item_poste or 'N/A'}")
                    st.caption(f"🏷️ {item_cat or 'À Classer'}")
                    
                    nouveau_stat = st.selectbox(
                        "Déplacer vers :",
                        [c for c in colonnes_kanban if c != col_name],
                        key=f"kanban_{item_id}"
                    )
                    if st.button("Mettre à jour", key=f"btn_k_{item_id}"):
                        c.execute("UPDATE candidats SET statut = %s WHERE id = %s", (nouveau_stat, item_id))
                        st.cache_data.clear()
                        st.rerun()

# ==============================================================================
# --- ONGLET 8 : SOURCING EXTERNE & CHASSE ---
# ==============================================================================
elif st.session_state['page_active'] == "🏹 SOURCING EXTERNE & CHASSE":
    st.header("🏹 Générateur de Requetes Sourcing & Chasse (Boolean Search)")
    
    col_s1, col_s2 = st.columns(2)
    with col_s1:
        metier_chasse = st.text_input("Métier / Intitulé recherché *", value="Chef de partie")
        ville_chasse = st.text_input("Localisation / Région", value="Béziers")
    with col_s2:
        mots_obligatoires = st.text_input("Mots-clés indispensables (ex: HACCP, Extranet)", value="HACCP")
        plateforme = st.multiselect("Plateformes cibles", ["LinkedIn", "Google", "Indeed"], default=["LinkedIn", "Google"])

    if st.button("🔍 GÉNÉRER LES STRINGS DE RECHERCHE BOOLEENNE"):
        query_base = f'"{metier_chasse}" AND "{ville_chasse}"'
        if mots_obligatoires:
            query_base += f' AND "{mots_obligatoires}"'

        st.subheader("🛠️ Liens direct de recherche (X-Ray Search) :")
        
        if "LinkedIn" in plateforme:
            url_li = f"https://www.google.com/search?q=site:linkedin.com/in/+{urllib.parse.quote(query_base)}"
            st.markdown(f"👉 [Lancer la recherche X-Ray **LinkedIn**]({url_li})")
            st.code(f"site:linkedin.com/in/ {query_base}")

        if "Google" in plateforme:
            url_goog = f"https://www.google.com/search?q={urllib.parse.quote(query_base + ' CV filetype:pdf')}"
            st.markdown(f"👉 [Rechercher des **CV PDF en ligne sur Google**]({url_goog})")
            st.code(f"{query_base} CV filetype:pdf")

# ==============================================================================
# --- ONGLET 9 : GESTION ADMINISTRATIVE & RH ---
# ==============================================================================
elif st.session_state['page_active'] == "📋 GESTION ADMINISTRATIVE & RH":
    st.header("📋 Suivi Administratif, Contrats & Médecine du Travail")
    conn, c = get_db_cursor()

    tab_contrats, tab_heures, tab_admin = st.tabs(["📄 Contrats & Suivi Médical", "⏱️ Saisie des Heures", "⚙️ Administration Compte"])

    with tab_contrats:
        with st.expander("➕ Créer une nouvelle fiche contrat", expanded=False):
            with st.form("form_contrat"):
                col_ct1, col_ct2 = st.columns(2)
                with col_ct1:
                    ct_cand = st.text_input("Nom du candidat *")
                    ct_ent = st.text_input("Entreprise cliente *")
                    ct_type = st.selectbox("Type de contrat", ["Intérim", "CDD", "CDI"])
                    ct_poste = st.text_input("Poste occupé")
                with col_ct2:
                    ct_debut = st.date_input("Date de début", value=datetime.date.today())
                    ct_fin = st.date_input("Date de fin prévue", value=datetime.date.today() + datetime.timedelta(days=30))
                    ct_med_limite = st.date_input("Date limite Visite Médicale", value=datetime.date.today() + datetime.timedelta(days=15))
                    ct_med_statut = st.selectbox("Statut Médecine du travail", ["À planifier", "Visite Effectuée", "Aptitude Validée", "Sursis / À revoir"])

                btn_ct = st.form_submit_button("Enregistrer le contrat")
                if btn_ct:
                    c.execute(
                        """INSERT INTO contrats (candidat_nom, entreprise_nom, type_contrat, poste, date_debut, date_fin, date_limite_medecine, statut_medecine)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                        (ct_cand, ct_ent, ct_type, ct_poste, ct_debut.isoformat(), ct_fin.isoformat(), ct_med_limite.isoformat(), ct_med_statut)
                    )
                    st.cache_data.clear()
                    st.success("Contrat enregistré avec succès !")
                    st.rerun()

        st.subheader("📄 Registre des Contrats & Échéances")
        c.execute("SELECT id, candidat_nom, entreprise_nom, type_contrat, poste, date_debut, date_fin, date_limite_medecine, statut_medecine FROM contrats ORDER BY id DESC")
        contrats = c.fetchall()
        if contrats:
            df_ct = pd.DataFrame(contrats, columns=["ID", "Candidat", "Entreprise", "Type", "Poste", "Début", "Fin", "Limite Visite Médicale", "Statut Médical"])
            st.dataframe(df_ct, use_container_width=True, hide_index=True)

    with tab_heures:
        st.subheader("⏱️ Relevé Hebdomadaire des Heures")
        with st.form("form_heures"):
            col_h1, col_h2 = st.columns(2)
            with col_h1:
                h_cand = st.text_input("Nom du salarié")
                h_ent = st.text_input("Nom de l'entreprise")
                h_sem = st.text_input("Semaine (ex: S32-2026)", value=f"S{datetime.date.today().isocalendar()[1]}-2026")
            with col_h2:
                h_norm = st.number_input("Heures normales (35h)", value=35.0, step=0.5)
                h_25 = st.number_input("Heures supp. 25%", value=0.0, step=0.5)
                h_50 = st.number_input("Heures supp. 50%", value=0.0, step=0.5)

            btn_h = st.form_submit_button("Saisir le relevé d'heures")
            if btn_h:
                c.execute(
                    """INSERT INTO suivi_heures (candidat_nom, entreprise_nom, semaine, heures_normales, heures_sup_25, heures_sup_50)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (h_cand, h_ent, h_sem, h_norm, h_25, h_50)
                )
                st.cache_data.clear()
                st.success("Heures enregistrées !")

        c.execute("SELECT id, candidat_nom, entreprise_nom, semaine, heures_normales, heures_sup_25, heures_sup_50 FROM suivi_heures ORDER BY id DESC")
        heures = c.fetchall()
        if heures:
            df_h = pd.DataFrame(heures, columns=["ID", "Candidat", "Entreprise", "Semaine", "Heures 100%", "HS 25%", "HS 50%"])
            st.dataframe(df_h, use_container_width=True, hide_index=True)

    with tab_admin:
        st.subheader("⚙️ Administration & Gestion des Utilisateurs")
        user_mail = st.session_state.get("user_email")
        
        if st.session_state.get("is_admin"):
            st.write("👑 **Panneau Administrateur**")
            c.execute("SELECT id, email, est_admin, statut_abonnement, nb_requetes_ia, quota_max FROM utilisateurs ORDER BY id ASC")
            users = c.fetchall()
            df_u = pd.DataFrame(users, columns=["ID", "Email", "Admin", "Statut", "Requêtes IA", "Quota Max"])
            st.dataframe(df_u, use_container_width=True, hide_index=True)

            st.markdown("---")
            st.write("🔄 **Réinitialisation manuelle de Quota IA**")
            target_user = st.selectbox("Sélectionner l'utilisateur à réinitialiser :", [u[1] for u in users])
            if st.button("Réinitialiser à 0 requêtes"):
                if reinitialiser_quota_ia(target_user):
                    st.success(f"Quota IA réinitialisé pour {target_user}")
                    st.rerun()
        else:
            st.info(f"Connecté sous l'identifiant : **{user_mail}**")
