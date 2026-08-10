
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
import psycopg2
import psycopg2.extras
import time
import urllib.parse
import bcrypt
from fpdf import FPDF
import google.generativeai as genai
import pandas as pd
from pypdf import PdfReader
import streamlit as st

# ==============================================================================
# --- CONNEXION SÉCURISÉE À SUPABASE (PostgreSQL) ---
# Remplace l'ancienne base SQLite locale. L'URL de connexion est lue depuis
# les secrets Streamlit (jamais codée en dur), au format attendu dans
# .streamlit/secrets.toml :
#
#   [connections.supabase]
#   url = "postgresql://postgres:VOTRE_MOT_DE_PASSE@db.xxxxxxxx.supabase.co:5432/postgres"
#
# (URL de connexion "Session pooler" ou directe, disponible dans
# Supabase > Project Settings > Database > Connection string).
#
# st.cache_resource garantit qu'une seule connexion est ouverte et réutilisée
# entre les reruns Streamlit, au lieu d'en recréer une à chaque appel comme
# le faisait le code SQLite d'origine.
# ==============================================================================
@st.cache_resource(show_spinner=False)
def get_connection():
    url = st.secrets["connections"]["supabase"]["url"]
    conn_pg = psycopg2.connect(url)
    # Autocommit : chaque instruction est validée immédiatement. C'est le choix
    # le plus proche du comportement SQLite d'origine (isolation_level=None,
    # càd autocommit) et surtout le plus sûr ici : de nombreux blocs du code
    # font "try: c.execute(...) except Exception: pass" (ex. migrations de
    # colonnes ALTER TABLE). En PostgreSQL, sans autocommit, une requête en
    # échec invalide toute la transaction en cours tant qu'un ROLLBACK n'est
    # pas exécuté — ce qui casserait les requêtes suivantes sur cette même
    # connexion. L'autocommit évite ce piège sans toucher à la logique métier.
    conn_pg.autocommit = True
    return conn_pg

# --- CONFIGURATION DU THÈME VISUEL (DOIT ÊTRE AU TOUT DÉBUT) ---
st.set_page_config(
    page_title="OmniRecrut IA", layout="wide", initial_sidebar_state="expanded"
)

st.markdown(
    """
    <style>
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
# --- SÉCURITÉ & QUOTAS IA ---
# ==============================================================================
LIMITE_REQUETES_IA = 300  # Quota mensuel par défaut pour l'offre gratuite

def peut_utiliser_ia(email_utilisateur):
    """Vérifie si l'utilisateur n'a pas dépassé sa limite mensuelle."""
    if st.session_state.get("is_admin") or st.session_state.get("user_statut") == "PRO":
        return True
    
    try:
        conn_q = get_connection()
        c_q = conn_q.cursor()
        c_q.execute("SELECT nb_requetes_ia, quota_max, statut_abonnement FROM utilisateurs WHERE email = %s", (email_utilisateur,))
        res = c_q.fetchone()
        
        if res:
            nb_actuel = res[0] if res[0] is not None else 0
            q_max = res[1] if res[1] is not None else LIMITE_REQUETES_IA
            statut = res[2] if res[2] is not None else "GRATUIT"
            
            if statut == "PRO":
                return True
            return nb_actuel < q_max
        return True
    except Exception:
        return True

def incrémenter_quota_ia(email_utilisateur):
    """Incrémente le compteur de requêtes IA de l'utilisateur."""
    if not st.session_state.get("is_admin") and email_utilisateur:
        try:
            conn_q = get_connection()
            c_q = conn_q.cursor()
            c_q.execute("UPDATE utilisateurs SET nb_requetes_ia = COALESCE(nb_requetes_ia, 0) + 1 WHERE email = %s", (email_utilisateur,))
            conn_q.commit()
        except Exception:
            pass

def reinitialiser_quota_ia(email_utilisateur):
    """Remet le compteur de requêtes IA d'un utilisateur à 0."""
    try:
        conn_q = get_connection()
        c_q = conn_q.cursor()
        c_q.execute("UPDATE utilisateurs SET nb_requetes_ia = 0 WHERE email = %s", (email_utilisateur,))
        conn_q.commit()
        return True
    except Exception:
        return False


# --- FONCTION DE GÉNÉRATION PDF (VERSION UTF-8 COMPATIBLE) ---
def creer_pdf_annonce(titre, contenu):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(200, 10, txt=f"Annonce : {titre}", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(0, 10, txt=contenu)
    chemin = f"Annonce_{titre[:15].replace(' ', '_')}.pdf"
    pdf.output(chemin)
    return chemin


def creer_pdf_candidat(nom, poste, date_rdv, details):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(200, 10, txt=f"Fiche Candidat : {nom}", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", size=12)
    pdf.cell(200, 10, txt=f"Poste cible : {poste}", ln=True)
    pdf.cell(200, 10, txt=f"Suivi / RDV : {date_rdv}", ln=True)
    pdf.ln(5)
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(0, 10, txt=details)
    chemin = f"Fiche_{nom.replace(' ', '_')}.pdf"
    pdf.output(chemin)
    return chemin


def relever_et_analyser_emails(email_user, pwd_user, imap_server):
    if not email_user or not pwd_user or not imap_server:
        return None
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_user, pwd_user)
        mail.select("inbox")
        status, messages = mail.search(None, "UNSEEN")
        liste_ids = messages[0].split()
        if not liste_ids:
            return None
        dernier_id = liste_ids[-1]
        res, msg_data = mail.fetch(dernier_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                for part in msg.walk():
                    if part.get("Content-Disposition") is None:
                        continue
                    nom_fichier = part.get_filename()
                    if nom_fichier and nom_fichier.lower().endswith(".pdf"):
                        contenu_pdf = part.get_payload(decode=True)
                        chemin_temporaire = os.path.join(".", nom_fichier)
                        with open(chemin_temporaire, "wb") as f:
                            f.write(contenu_pdf)
                        mail.logout()
                        return chemin_temporaire
        mail.logout()
        return None
    except:
        return None


# --- FONCTION D'ENVOI D'EMAIL AUTOMATIQUE DYNAMIQUE ---
def envoyer_email_candidat(to_email, sujet, corps_message, email_user, pwd_user):
    if not email_user or not pwd_user:
        st.error(
            "⚠️ Configuration de messagerie manquante. Veuillez renseigner vos"
            " identifiants e-mail dans la barre latérale."
        )
        return False
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        if "outlook" in email_user or "hotmail" in email_user or "live" in email_user:
            smtp_server = "smtp.office365.com"
        elif "yahoo" in email_user:
            smtp_server = "smtp.mail.yahoo.com"

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(email_user, pwd_user)
        msg = MIMEMultipart()
        msg["From"] = email_user
        msg["To"] = to_email
        msg["Subject"] = sujet
        msg.attach(MIMEText(corps_message, "plain"))
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        st.error(f"Erreur technique SMTP lors de l'envoi : {e}")
        return False


# --- SÉCURITÉ : HACHAGE DES MOTS DE PASSE (bcrypt) ---
def hacher_mdp(mot_de_passe_clair):
    """Retourne le hash bcrypt (str) d'un mot de passe en clair."""
    return bcrypt.hashpw(mot_de_passe_clair.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verifier_mdp(mot_de_passe_saisi, valeur_stockee):
    """
    Vérifie un mot de passe saisi contre la valeur stockée en base.
    Supporte la transition en douceur depuis d'anciens mots de passe en clair :
    - si la valeur stockée est un hash bcrypt valide -> vérification bcrypt
    - sinon (ancien compte, mot de passe encore en clair) -> comparaison directe,
      et le code appelant se charge de migrer le mot de passe vers un hash.
    """
    if not valeur_stockee:
        return False
    try:
        if valeur_stockee.startswith("$2b$") or valeur_stockee.startswith("$2a$") or valeur_stockee.startswith("$2y$"):
            return bcrypt.checkpw(mot_de_passe_saisi.encode("utf-8"), valeur_stockee.encode("utf-8"))
    except Exception:
        return False
    # Ancien format (mot de passe en clair) - comparaison directe pour ne pas bloquer les comptes existants
    return mot_de_passe_saisi == valeur_stockee


def mdp_est_hashe(valeur_stockee):
    return bool(valeur_stockee) and valeur_stockee.startswith(("$2b$", "$2a$", "$2y$"))


# --- SYSTEME D'AUTHENTIFICATION ET GESTION DES ACCÈS & MESSAGERIE UTILISATEUR ---
def check_password():
    if "password_correct" not in st.session_state:
        st.session_state["password_correct"] = False
    if "user_email" not in st.session_state:
        st.session_state["user_email"] = ""
    if "is_admin" not in st.session_state:
        st.session_state["is_admin"] = False
    if "user_statut" not in st.session_state:
        st.session_state["user_statut"] = "GRATUIT"
    if "user_config_email" not in st.session_state:
        st.session_state["user_config_email"] = {}

    try:
        conn_auth = get_connection()
        c_auth = conn_auth.cursor()
        c_auth.execute("""CREATE TABLE IF NOT EXISTS utilisateurs (
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

        # Mises à jour progressives de la table
        for col, dtype in [
            ("mail_perso", "TEXT DEFAULT ''"),
            ("mail_password", "TEXT DEFAULT ''"),
            ("mail_imap", "TEXT DEFAULT 'imap.gmail.com'"),
            ("nb_requetes_ia", "INTEGER DEFAULT 0"),
            ("quota_max", "INTEGER DEFAULT 300"),
            ("statut_abonnement", "TEXT DEFAULT 'GRATUIT'")
        ]:
            try:
                c_auth.execute(f"ALTER TABLE utilisateurs ADD COLUMN {col} {dtype}")
            except Exception:
                pass

        # Création de l'accès Admin par défaut si la table est vide
        c_auth.execute("SELECT COUNT(*) FROM utilisateurs")
        if c_auth.fetchone()[0] == 0:
            mdp_admin_clair = st.secrets.get("APP_PASSWORD")
            if not mdp_admin_clair:
                st.error(
                    "⚠️ Aucun mot de passe admin défini. Ajoutez APP_PASSWORD dans les "
                    "secrets de l'application (Streamlit Cloud > Settings > Secrets) avant "
                    "de continuer."
                )
                st.stop()

            mdp_admin_hash = hacher_mdp(mdp_admin_clair)
            default_mail = st.secrets.get("EMAIL_USER", "")
            default_pwd = st.secrets.get("EMAIL_PASSWORD", "")
            default_imap = st.secrets.get("EMAIL_IMAP", "imap.gmail.com")
            c_auth.execute(
                """INSERT INTO utilisateurs (email, password, date_fin_essai, est_admin, mail_perso, mail_password, mail_imap, nb_requetes_ia, quota_max, statut_abonnement) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    "admin@omnirecrut.fr",
                    mdp_admin_hash,
                    "2099-12-31",
                    1,
                    default_mail,
                    default_pwd,
                    default_imap,
                    0,
                    999999,
                    "PRO"
                ),
            )
            conn_auth.commit()
    except Exception as e:
        st.error(f"Erreur d'initialisation du système d'authentification : {e}")

 # Style CSS écran de connexion
    st.markdown(
        """
        <style>
        .stApp { background-color: #1a202c; color: #e2e8f0; }
        label, [data-testid="stWidgetLabel"] p { color: #ffffff !important; font-weight: 600 !important; }
        div[data-testid="stTextInput"] input, div[data-testid="stTextArea"] textarea { background-color: #2d3748 !important; color: #ffffff !important; border: 1px solid #4a5568 !important; }
        </style>
    """,
        unsafe_allow_html=True,
    )

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
                        conn_chk = get_connection()
                        c_chk = conn_chk.cursor()
                        c_chk.execute(
                            "SELECT password, date_fin_essai, est_admin, mail_perso,"
                            " mail_password, mail_imap, statut_abonnement FROM utilisateurs WHERE email = %s",
                            (email_saisi,),
                        )
                        res = c_chk.fetchone()

                        if res:
                            (
                                db_password,
                                db_date_fin,
                                db_is_admin,
                                m_perso,
                                m_pass,
                                m_imap,
                                db_statut,
                            ) = res
                            if verifier_mdp(pwd_saisi, db_password):
                                # Migration silencieuse : si l'ancien mot de passe était
                                # stocké en clair, on le remplace par un hash bcrypt.
                                if not mdp_est_hashe(db_password):
                                    try:
                                        conn_mig = get_connection()
                                        c_mig = conn_mig.cursor()
                                        c_mig.execute(
                                            "UPDATE utilisateurs SET password = %s WHERE email = %s",
                                            (hacher_mdp(pwd_saisi), email_saisi),
                                        )
                                        conn_mig.commit()
                                    except Exception:
                                        pass

                                date_exp = datetime.date.fromisoformat(db_date_fin)
                                aujourdhui = datetime.date.today()

                                if db_is_admin == 1 or aujourdhui <= date_exp:
                                    st.session_state["password_correct"] = True
                                    st.session_state["user_email"] = email_saisi
                                    st.session_state["is_admin"] = True if db_is_admin == 1 else False
                                    st.session_state["user_statut"] = db_statut if db_statut else "GRATUIT"

                                    st.session_state["user_config_email"] = {
                                        "email": m_perso if m_perso else email_saisi,
                                        "password": m_pass,
                                        "imap": m_imap if m_imap else "imap.gmail.com",
                                    }
                                    st.rerun()
                                else:
                                    st.error(
                                        f"⏳ Votre période d'essai a expiré le"
                                        f" {date_exp.strftime('%d/%m/%Y')}. Contactez-nous pour"
                                        " renouveler votre accès."
                                    )
                            else:
                                st.error("Mot de passe incorrect.")
                        else:
                            st.error("Aucun compte associé à cet e-mail.")
                    except Exception as err:
                        st.error(f"Erreur technique de connexion : {err}")

        return False
    return True

# --- DÉMARRAGE DE L'APPLICATION ---
if not check_password():
    st.stop()

# --- IMPORT SECURISÉ DU MODULE PDF ---
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    REPORTLAB_DISPO = True
except ModuleNotFoundError:
    REPORTLAB_DISPO = False

# ==============================================================================
# 1. CONNEXION ET INITIALISATION DE LA BASE DE DONNÉES SUPABASE / PostgreSQL (définition de c)
# ==============================================================================
conn = get_connection()
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS candidats 
             (id SERIAL PRIMARY KEY, nom TEXT, poste TEXT, competences TEXT, 
             statut TEXT, categorie_ia TEXT, avis_ia TEXT, score_matching TEXT, secteur_metier TEXT DEFAULT 'Non spécifié', cv_texte TEXT DEFAULT '')""")

try:
    c.execute("ALTER TABLE candidats ADD COLUMN type_rdv TEXT")
    c.execute("ALTER TABLE candidats ADD COLUMN date_rdv TEXT")
except Exception:
    pass

try:
    c.execute("ALTER TABLE candidats ADD COLUMN cv_texte TEXT DEFAULT ''")
except Exception:
    pass

# --- Colonnes étendues pour l'agent d'analyse enrichie (vivier, sans offre) ---
for _col, _type in {
    "competences_transferables": "TEXT",
    "profil_riasec": "TEXT",
    "metiers_cibles": "TEXT",
    "date_ajout": "TEXT",
}.items():
    try:
        c.execute(f"ALTER TABLE candidats ADD COLUMN {_col} {_type}")
    except Exception:
        pass

# ==============================================================================
# --- AGENT IA D'ANALYSE ENRICHIE DE CV (function calling Gemini) ---
# Analyse un CV brut SANS offre de référence : hard skills, diplômes,
# compétences transférables justifiées, profil RIASEC, métiers cibles.
# L'agent enregistre lui-même le résultat dans la table candidats via un tool.
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
    """Tool exécuté par l'agent : enregistre le profil enrichi dans la table candidats existante.
    NB : la colonne 'profil_riasec' est conservée pour compatibilité base de données, mais stocke
    désormais un profil comportemental basé sur le parcours et les centres d'intérêt (pas un test
    RIASEC formel)."""
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
    conn.commit()

    alertes = _matcher_candidat_vs_besoins_ouverts(candidat_id, nom_complet, poste_cible, competences_resume, secteur_metier)
    message = f"Candidat '{nom_complet}' enregistré dans le vivier."
    if alertes:
        message += f" {len(alertes)} correspondance(s) détectée(s) avec des besoins clients ouverts."
    return {"status": "success", "message": message, "alertes": alertes}


_AGENT_TOOLS = {"save_candidate_to_sqlite": _save_candidate_to_sqlite}


def _proto_to_python(value):
    """Convertit récursivement les types protobuf renvoyés par function_call.args
    (MapComposite, RepeatedComposite) en dict/list Python natifs, sinon json.dumps
    et les opérations sur listes (+) plantent silencieusement."""
    if isinstance(value, (list,)) or type(value).__name__ == "RepeatedComposite":
        return [_proto_to_python(v) for v in value]
    if isinstance(value, dict) or type(value).__name__ == "MapComposite":
        return {k: _proto_to_python(v) for k, v in value.items()}
    return value

# Schéma volontairement APLATI (pas de liste d'objets, pas d'objet imbriqué) :
# gemini-2.5-flash est beaucoup moins fiable que pro sur les schémas de tools
# fortement imbriqués, ce qui déclenche des finish_reason MALFORMED_FUNCTION_CALL.
_tool_save_candidate = genai.protos.Tool(
    function_declarations=[
        genai.protos.FunctionDeclaration(
            name="save_candidate_to_sqlite",
            description="Enregistre le profil complet et enrichi d'un candidat dans la base du vivier.",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "nom_complet": genai.protos.Schema(type=genai.protos.Type.STRING),
                    "diplomes": genai.protos.Schema(
                        type=genai.protos.Type.ARRAY,
                        items=genai.protos.Schema(type=genai.protos.Type.STRING),
                    ),
                    "hard_skills": genai.protos.Schema(
                        type=genai.protos.Type.ARRAY,
                        items=genai.protos.Schema(type=genai.protos.Type.STRING),
                    ),
                    "soft_skills_transferables": genai.protos.Schema(
                        type=genai.protos.Type.ARRAY,
                        items=genai.protos.Schema(type=genai.protos.Type.STRING),
                        description=(
                            "Une compétence transférable par ligne, au format : "
                            "'compétence — issue de [expérience précise du CV] — [pourquoi c'est un atout]'."
                        ),
                    ),
                    "traits_dominants": genai.protos.Schema(
                        type=genai.protos.Type.ARRAY,
                        items=genai.protos.Schema(type=genai.protos.Type.STRING),
                        description=(
                            "3 à 5 traits de personnalité/savoir-être plausibles (ex: 'autonomie', "
                            "'esprit d'équipe', 'rigueur'), déduits du parcours et des centres d'intérêt — "
                            "jamais une liste de compétences techniques déjà citées ailleurs."
                        ),
                    ),
                    "indices_parcours_pro": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description=(
                            "Justification courte : quels choix de postes, missions ou évolutions du "
                            "parcours professionnel appuient les traits dominants identifiés."
                        ),
                    ),
                    "indices_centres_interet": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description=(
                            "Justification courte basée sur les loisirs/centres d'intérêt/engagements "
                            "personnels déclarés dans le CV. Si le CV n'en mentionne aucun, l'indiquer "
                            "explicitement plutôt que d'inventer."
                        ),
                    ),
                    "coherence_projet_pro": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description=(
                            "Évaluation courte de la logique globale du parcours (reconversion cohérente, "
                            "montée en compétences progressive, fils conducteurs entre les expériences, etc.)."
                        ),
                    ),
                    "metiers_cibles": genai.protos.Schema(
                        type=genai.protos.Type.ARRAY,
                        items=genai.protos.Schema(type=genai.protos.Type.STRING),
                    ),
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

Procède dans cet ordre exact :
1. ANALYSE TECHNIQUE : liste les diplômes/certifications et les compétences dures (hard skills),
   outils, logiciels, langages, méthodes, habilitations. Sois précis, évite les généralités.
2. COMPÉTENCES TRANSFÉRABLES : pour chaque expérience (même hors secteur cible), identifie les
   compétences généralistes/transversales. Formule chaque compétence en UNE SEULE phrase au format
   'compétence — issue de [expérience précise du CV] — [pourquoi c'est un atout dans un nouveau métier]'.
3. INDICES DE PERSONNALITÉ (parcours + centres d'intérêt) : SANS jamais nommer ni faire référence à
   un test ou modèle psychométrique connu, déduis 3 à 5 traits de personnalité/savoir-être plausibles
   à partir de deux sources distinctes du CV :
   a) le PARCOURS PROFESSIONNEL : cohérence des transitions, type de missions recherchées ou obtenues
      (encadrement, autonomie, technique, relationnel), rythme et nature des évolutions de poste ;
   b) les CENTRES D'INTÉRÊT ET ENGAGEMENTS PERSONNELS explicitement mentionnés dans le CV (loisirs,
      sport, bénévolat, activités associatives ou créatives). Si le CV n'en mentionne aucun, dis-le
      explicitement plutôt que d'en inventer.
   Utilise ces repères de lecture, à croiser avec le contenu réel du CV (jamais appliqués mécaniquement) :
   - sport collectif, associatif, bénévolat/encadrement → esprit d'équipe, sens du service, leadership
   - activités créatives (musique, arts, écriture) → créativité, sensibilité, autonomie de pensée
   - activités techniques/solitaires (bricolage, informatique, lecture spécialisée) → rigueur, goût du
     détail, autonomie
   - sport individuel de performance → discipline, dépassement de soi
   - stabilité vs diversité des expériences → capacité d'adaptation vs recherche de stabilité
   Pour chaque trait retenu, distingue clairement ce qui vient du parcours pro de ce qui vient des
   centres d'intérêt (deux champs séparés), et ajoute une courte évaluation de la cohérence globale
   du projet professionnel (reconversion logique, montée en compétences, fils conducteurs). Formule
   toujours ces éléments comme des hypothèses argumentées à valider en entretien, jamais comme un
   diagnostic définitif.
4. SYNTHÈSE & MÉTIERS CIBLES : rédige un compte-rendu détaillé et structuré (plusieurs paragraphes,
   pas un simple résumé de 3-4 lignes) qui reprend et argumente chacun des points précédents :
   le profil général du candidat, l'analyse de son parcours, la lecture de ses compétences
   transférables, les indices de personnalité dégagés du parcours et des centres d'intérêt, puis la
   logique derrière les métiers cibles proposés. Ce texte doit se suffire à lui-même pour qu'un
   recruteur comprenne le raisonnement sans avoir à relire le CV. Propose ensuite une liste de
   métiers cibles cohérents classés par pertinence, et calcule un pourcentage d'adéquation global
   argumenté.
5. ENREGISTREMENT : appelle SYSTÉMATIQUEMENT et une seule fois la fonction save_candidate_to_sqlite
   avec tous les champs remplis (champs à plat, pas d'objets imbriqués), une fois l'analyse complète.

Contraintes : n'invente jamais un diplôme, une compétence ou une expérience absente du CV ; si une
information est ambiguë ou manquante, dis-le explicitement plutôt que de la deviner. Reste neutre et
professionnel, sans jugement de valeur sur le parcours du candidat. Les indices de personnalité sont
des pistes de lecture, pas un verdict — ne jamais les présenter comme un résultat de test validé.
"""

_agent_model = genai.GenerativeModel(
    model_name="gemini-2.5-flash",
    system_instruction=_SYSTEM_PROMPT_AGENT,
    tools=[_tool_save_candidate],
    generation_config={"temperature": 0.3},
)


def analyser_cv_avec_agent(texte_cv: str, secteur_metier: str, max_tentatives: int = 3) -> dict:
    """Lance l'agent sur un CV brut. Le tool enregistre lui-même le candidat en base.
    Retourne {'compte_rendu': str, 'donnees_structurees': dict | None}.
    Réessaie automatiquement en cas de MALFORMED_FUNCTION_CALL (limite connue des modèles flash
    sur des schémas de tools complexes)."""
    for tentative in range(1, max_tentatives + 1):
        try:
            chat = _agent_model.start_chat(enable_automatic_function_calling=False)
            response = chat.send_message(
                f"Voici un CV brut à analyser et à enregistrer dans le vivier :\n\n{texte_cv}"
            )
            donnees_structurees = None

            while True:
                finish_reason = response.candidates[0].finish_reason
                if str(finish_reason).endswith("MALFORMED_FUNCTION_CALL"):
                    raise ValueError("MALFORMED_FUNCTION_CALL")

                function_call = next(
                    (p.function_call for p in response.candidates[0].content.parts if p.function_call),
                    None,
                )
                if function_call is None:
                    return {"compte_rendu": response.text, "donnees_structurees": donnees_structurees}

                fn_name = function_call.name
                fn_args = _proto_to_python(dict(function_call.args))
                if fn_name == "save_candidate_to_sqlite":
                    fn_args["secteur_metier"] = secteur_metier
                    fn_args["cv_texte"] = texte_cv
                donnees_structurees = fn_args

                result = _AGENT_TOOLS.get(
                    fn_name, lambda **_: {"status": "error", "message": "Fonction inconnue"}
                )(**fn_args)

                response = chat.send_message(
                    genai.protos.Content(parts=[genai.protos.Part(
                        function_response=genai.protos.FunctionResponse(name=fn_name, response={"result": result})
                    )])
                )
        except Exception as e:
            if tentative == max_tentatives:
                raise
            time.sleep(1.5 * tentative)
            continue


c.execute("""CREATE TABLE IF NOT EXISTS clients 
             (id SERIAL PRIMARY KEY, entreprise TEXT, secteur TEXT, contact TEXT, 
             secteur_activite TEXT DEFAULT 'Non spécifié', tel TEXT, email TEXT, priorite TEXT, notes TEXT)""")

try:
    c.execute("SELECT secteur_geo FROM clients LIMIT 1")
except Exception:
    try:
        c.execute("ALTER TABLE clients ADD COLUMN secteur_geo TEXT DEFAULT 'Béziers'")
    except Exception:
        pass

# ==============================================================================
# --- VEILLE PROACTIVE : besoins clients persistés + alertes de matching ---
# Un besoin client est désormais enregistré en base (au lieu d'être éphémère).
# Dès qu'un nouveau candidat est ajouté au vivier (via l'agent) OU qu'un nouveau
# besoin est enregistré, l'IA compare automatiquement l'un à l'autre et crée
# une alerte si le score dépasse SEUIL_ALERTE_MATCHING.
# ==============================================================================

SEUIL_ALERTE_MATCHING = 70  # score mini (0-100) pour déclencher une alerte

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
conn.commit()


def _extraire_json_liste(texte_brut: str) -> list:
    """Extrait un tableau JSON d'une réponse Gemini, même entourée de texte ou de balises markdown."""
    txt = texte_brut.strip().replace("```json", "").replace("```", "").strip()
    if "[" in txt and "]" in txt:
        txt = txt[txt.find("["): txt.rfind("]") + 1]
    try:
        return json.loads(txt)
    except Exception:
        return []


def _matcher_candidat_vs_besoins_ouverts(candidat_id: int, nom: str, poste: str, competences: str, secteur: str) -> list:
    """Déclenchée automatiquement après l'ajout d'un candidat : le compare à tous les
    besoins ouverts du même secteur et crée une alerte pour chaque score suffisant."""
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
Renvoie STRICTEMENT un tableau JSON, un objet par besoin, avec les clés :
'besoin_id' (reprends l'id fourni), 'score' (entier 0-100), 'raison' (une phrase courte)."""
        response = model_match.generate_content(prompt)
        resultats = _extraire_json_liste(response.text)
    except Exception:
        return []

    besoins_par_id = {b[0]: b for b in besoins}
    alertes_creees = []
    for r in resultats:
        try:
            score = int(r.get("score", 0))
        except Exception:
            score = 0
        besoin_id = r.get("besoin_id")
        if score >= SEUIL_ALERTE_MATCHING and besoin_id in besoins_par_id:
            b = besoins_par_id[besoin_id]
            c.execute(
                """INSERT INTO alertes_matching
                   (candidat_id, candidat_nom, besoin_id, besoin_entreprise, besoin_description, score, raison, date_alerte)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (candidat_id, nom, besoin_id, b[1], b[2], score, r.get("raison", ""), datetime.datetime.now().isoformat()),
            )
            alertes_creees.append({"besoin_entreprise": b[1], "score": score, "raison": r.get("raison", "")})
    if alertes_creees:
        conn.commit()
    return alertes_creees


def matcher_besoin_vs_vivier(besoin_id: int, secteur: str, description: str) -> list:
    """Appelée quand un nouveau besoin client est enregistré : le compare à tous les
    candidats du vivier du même secteur et crée une alerte pour chaque score suffisant."""
    c.execute("SELECT id, nom, poste, competences FROM candidats WHERE secteur_metier = %s", (secteur,))
    candidats = c.fetchall()
    if not candidats:
        return []

    candidats_data = [{"candidat_id": cd[0], "nom": cd[1], "poste": cd[2], "competences": cd[3]} for cd in candidats]
    try:
        model_match = genai.GenerativeModel("gemini-2.5-flash")
        prompt = f"""Compare ce besoin client à chacun des candidats ci-dessous.
Besoin : {description}
Candidats : {json.dumps(candidats_data, ensure_ascii=False)}
Renvoie STRICTEMENT un tableau JSON, un objet par candidat, avec les clés :
'candidat_id' (reprends l'id fourni), 'score' (entier 0-100), 'raison' (une phrase courte)."""
        response = model_match.generate_content(prompt)
        resultats = _extraire_json_liste(response.text)
    except Exception:
        return []

    c.execute("SELECT entreprise FROM besoins_clients WHERE id = %s", (besoin_id,))
    entreprise_row = c.fetchone()
    entreprise = entreprise_row[0] if entreprise_row else "Client"

    candidats_par_id = {cd[0]: cd for cd in candidats}
    alertes_creees = []
    for r in resultats:
        try:
            score = int(r.get("score", 0))
        except Exception:
            score = 0
        candidat_id = r.get("candidat_id")
        if score >= SEUIL_ALERTE_MATCHING and candidat_id in candidats_par_id:
            cd = candidats_par_id[candidat_id]
            c.execute(
                """INSERT INTO alertes_matching
                   (candidat_id, candidat_nom, besoin_id, besoin_entreprise, besoin_description, score, raison, date_alerte)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (candidat_id, cd[1], besoin_id, entreprise, description, score, r.get("raison", ""), datetime.datetime.now().isoformat()),
            )
            alertes_creees.append({"candidat_nom": cd[1], "score": score, "raison": r.get("raison", "")})
    if alertes_creees:
        conn.commit()
    return alertes_creees

# ==============================================================================
# --- AUTOMATISATIONS IA SUPPLÉMENTAIRES — DOCTRINE DE SÉCURITÉ ---
#
# Règle appliquée à TOUTES les fonctions ci-dessous, sans exception :
#   ✅ L'IA peut LIRE des données et CALCULER des indicateurs déterministes.
#   ✅ L'IA peut RÉDIGER des brouillons (e-mails, suggestions, résumés).
#   ❌ L'IA ne peut JAMAIS, de sa propre initiative :
#        - envoyer un e-mail réel à un candidat ou un client
#        - modifier/supprimer un contrat, un candidat ou un besoin existant
#        - lancer une action de sourcing externe
#        - faire passer une suggestion réglementaire en note officielle validée
#   Chacune de ces actions engageantes reste déclenchée par un clic humain
#   explicite, après relecture du brouillon ou de la suggestion à l'écran.
# ==============================================================================

def generer_digest_quotidien() -> dict:
    """Purement déterministe — AUCUN appel IA ici. Agrège des faits déjà en base,
    ne prend et ne suggère aucune décision."""
    digest = {}
    try:
        c.execute("SELECT COUNT(*) FROM alertes_matching WHERE lue = 0")
        digest["alertes_non_lues"] = c.fetchone()[0] or 0
    except Exception:
        digest["alertes_non_lues"] = 0

    try:
        aujourd_hui = datetime.date.today().isoformat()
        limite_medecine = (datetime.date.today() + datetime.timedelta(days=15)).isoformat()
        c.execute(
            """SELECT candidat_nom, date_limite_medecine FROM contrats
               WHERE date_limite_medecine BETWEEN %s AND %s ORDER BY date_limite_medecine ASC""",
            (aujourd_hui, limite_medecine),
        )
        digest["visites_medecine_proches"] = c.fetchall()
    except Exception:
        digest["visites_medecine_proches"] = []

    try:
        limite_fin_contrat = (datetime.date.today() + datetime.timedelta(days=7)).isoformat()
        c.execute(
            """SELECT candidat_nom, date_fin, entreprise_nom FROM contrats
               WHERE date_fin BETWEEN %s AND %s ORDER BY date_fin ASC""",
            (aujourd_hui, limite_fin_contrat),
        )
        digest["fins_de_contrat_proches"] = c.fetchall()
    except Exception:
        digest["fins_de_contrat_proches"] = []

    try:
        seuil_dormance = (datetime.date.today() - datetime.timedelta(days=30)).isoformat()
        c.execute(
            """SELECT id, nom, poste FROM candidats
               WHERE statut = 'Disponible' AND (date_ajout IS NULL OR date_ajout <= %s)""",
            (seuil_dormance,),
        )
        digest["candidats_dormants"] = c.fetchall()
    except Exception:
        digest["candidats_dormants"] = []

    return digest


def generer_brouillon_relance(nom_candidat: str, poste: str) -> str:
    """Génère UNIQUEMENT un texte de brouillon, jamais envoyé automatiquement.
    L'envoi reste un clic humain explicite (ouverture du client mail via mailto)."""
    try:
        model_relance = genai.GenerativeModel("gemini-2.5-flash")
        prompt = f"Rédige un e-mail court et chaleureux de relance pour {nom_candidat}, candidat de notre vivier sur le poste de {poste}, pour savoir s'il/elle est toujours disponible. Signe 'L'équipe OmniRecrut IA'."
        response = model_relance.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Erreur lors de la génération du brouillon : {e}"


def generer_suggestion_medecine(poste: str) -> str:
    """Génère UNIQUEMENT une suggestion de suivi. Stockée à part (colonne
    suggestion_ia_medecine), jamais injectée automatiquement dans les notes
    officielles — l'injection reste un clic humain explicite."""
    try:
        model_med = genai.GenerativeModel("gemini-2.5-flash")
        prompt = f"Donne sous forme de puces courtes les 2 principales obligations de sécurité/EPI pour un poste de {poste}."
        response = model_med.generate_content(prompt)
        return response.text
    except Exception:
        return ""


def analyser_cv_preview(texte_cv: str):
    """Analyse un CV et renvoie les données structurées SANS JAMAIS écrire en base.
    Utilisée pour les CV récupérés automatiquement par e-mail : contrairement à
    l'upload manuel (où le clic de l'utilisateur vaut déjà validation), un CV arrivé
    par e-mail n'a pas été choisi individuellement — l'ajout au vivier reste donc une
    confirmation humaine explicite (voir bouton dédié dans l'UI)."""
    try:
        model_preview = genai.GenerativeModel("gemini-2.5-flash")
        prompt = f"""{_SYSTEM_PROMPT_AGENT}

Renvoie UNIQUEMENT un objet JSON valide (aucun texte autour, aucun appel de fonction) avec
exactement les clés : nom_complet, diplomes, hard_skills, soft_skills_transferables,
traits_dominants, indices_parcours_pro, indices_centres_interet, coherence_projet_pro,
metiers_cibles, pourcentage_adequation, compte_rendu.

CV à analyser :
{texte_cv}"""
        response = model_preview.generate_content(prompt)
        txt = response.text.strip().replace("```json", "").replace("```", "").strip()
        return json.loads(txt)
    except Exception:
        return None

# ==============================================================================
# 2. GESTION DU RETOUR DE PAIEMENT STRIPE (REDIRECTION DÉTECTÉE)
# ==============================================================================
query_params = st.query_params
if query_params.get("payment") == "success":
    user_email = st.session_state.get("user_email")
    if user_email:
        c.execute("UPDATE utilisateurs SET statut_abonnement = 'PRO', quota_max = 999999 WHERE email = %s", (user_email,))
        st.session_state['user_statut'] = 'PRO'
        st.balloons()
        st.success("🎉 Félicitations ! Votre abonnement PRO Illimité est actif.")
        st.query_params.clear()

# ==============================================================================
# 3. PANNEAU LATÉRAL (SIDEBAR) : QUOTAS & BOUTON STRIPE
# ==============================================================================
with st.sidebar:
    # --- 🔔 ALERTES DE MATCHING (veille proactive) ---
    try:
        c.execute("SELECT COUNT(*) FROM alertes_matching WHERE lue = 0")
        nb_alertes_non_lues = c.fetchone()[0] or 0
    except Exception:
        nb_alertes_non_lues = 0

    with st.expander(f"🔔 Alertes de matching ({nb_alertes_non_lues})", expanded=(nb_alertes_non_lues > 0)):
        try:
            c.execute("""SELECT id, candidat_nom, besoin_entreprise, besoin_description, score, raison, lue
                         FROM alertes_matching ORDER BY lue ASC, id DESC LIMIT 15""")
            lignes_alertes = c.fetchall()
        except Exception:
            lignes_alertes = []

        if not lignes_alertes:
            st.caption("Aucune alerte pour le moment.")
        else:
            for alerte_id, cand_nom, entreprise, desc_besoin, score_al, raison_al, lue in lignes_alertes:
                badge = "🟢" if not lue else "⚪"
                st.markdown(f"{badge} **{cand_nom}** ↔ **{entreprise}** — {score_al}%")
                st.caption(raison_al or desc_besoin[:80])
                if not lue:
                    if st.button("✅ Marquer comme lue", key=f"lue_{alerte_id}", use_container_width=True):
                        c.execute("UPDATE alertes_matching SET lue = 1 WHERE id = %s", (alerte_id,))
                        conn.commit()
                        st.rerun()
                st.markdown("---")

    st.markdown("<h3 style='color: #ffffff !important;'>⚙️ Mon Compte</h3>", unsafe_allow_html=True)
    user_email = st.session_state.get("user_email", "")
    
    # Récupération de l'état du quota et du statut
    c.execute("SELECT nb_requetes_ia, quota_max, statut_abonnement FROM utilisateurs WHERE email = %s", (user_email,))
    res_u = c.fetchone()
    
    quota_utilise = res_u[0] if res_u and res_u[0] is not None else 0
    quota_max = res_u[1] if res_u and res_u[1] is not None else 300
    statut_abonnement = res_u[2] if res_u and res_u[2] is not None else "GRATUIT"
    
    # Lien Stripe (Remplace par ton propre lien Stripe Payment Link)
    LIEN_STRIPE_CHECKOUT = "https://buy.stripe.com/test_cNi28rd0UfUW5xMdRFbsc00"
    
    if statut_abonnement == "PRO" or st.session_state.get("user_statut") == "PRO":
        st.markdown("""
            <div style="background-color: #2e7d32; padding: 12px; border-radius: 8px; text-align: center; color: white; font-weight: bold; margin-bottom: 15px;">
                👑 COMPTE PRO ILLIMITÉ
            </div>
        """, unsafe_allow_html=True)
    else:
        # Affichage structuré du Quota puis du Bouton en dessous
        st.markdown("<h5 style='color: #ffb703 !important; margin-bottom: 5px;'>📊 Quotas IA Mensuels</h5>", unsafe_allow_html=True)
        
        pct_utilise = min(1.0, quota_utilise / quota_max) if quota_max > 0 else 0.0
        st.progress(pct_utilise)
        
        st.markdown(f"<p style='color: #e2e8f0; font-size: 14px; margin-top: 5px;'>Utilisation : <b>{quota_utilise} / {quota_max}</b> requêtes</p>", unsafe_allow_html=True)
        
        st.write("") # Petit espace visuel
        
        # Bouton d'abonnement Stripe placé strictement sous le quota
        st.link_button(
            "💳 S'abonner (Accès Illimité)", 
            LIEN_STRIPE_CHECKOUT, 
            type="primary", 
            use_container_width=True
        )
        
    st.markdown("---")

# --- TABLES RH & ADMINISTRATIVES ---
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
                suivi_medical_notes TEXT
            )""")

try:
  c.execute("ALTER TABLE contrats ADD COLUMN date_fin TEXT")
except Exception:
  pass

try:
  c.execute("ALTER TABLE contrats ADD COLUMN suivi_medical_notes TEXT")
except Exception:
  pass

try:
  c.execute("ALTER TABLE contrats ADD COLUMN suggestion_ia_medecine TEXT")
except Exception:
  pass

c.execute("""CREATE TABLE IF NOT EXISTS suivi_heures (
                id SERIAL PRIMARY KEY,
                candidat_nom TEXT,
                entreprise_nom TEXT,
                semaine TEXT,
                heures_normales REAL DEFAULT 0,
                heures_sup_25 REAL DEFAULT 0,
                heures_sup_50 REAL DEFAULT 0
            )""")

LISTE_SECTEURS = [
    "Tous",
    "Restauration / Hôtellerie",
    "Tertiaire / Bureau / PME",
    "Transport / Logistique",
    "Bâtiment / TP",
    "Industrie / Technique",
    "Autre",
]

# 2. APPLICATION DU CONFIGURATION THÈME VISUEL ORIGINAL
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
    div[data-testid="stMultiSelect"] div[data-baseweb="select"] > div { background-color: #2d3748 !important; color: #ffffff !important; border: 1px solid #4a5568 !important; }
    </style>
""",
    unsafe_allow_html=True,
)

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

if "offre_transferee" not in st.session_state:
  st.session_state["offre_transferee"] = ""
if "page_active" not in st.session_state:
  st.session_state["page_active"] = "🗃️ VIVIER DE CANDIDATS"

# --- CHARGEMENT AUTOMATIQUE VIA SECRETS.TOML ---
try:
  gemini_key = st.secrets["GEMINI_API_KEY"]
  genai.configure(api_key=gemini_key)
  st.sidebar.success("🔒 Clé API Gemini chargée (.secrets)")
except Exception:
  st.sidebar.warning("⚠️ Clé non trouvée dans secrets.toml")
  api_key_input = st.sidebar.text_input(
      "Collez votre clé API Google ici :", type="password"
  )
  if api_key_input:
    genai.configure(api_key=api_key_input)

st.sidebar.markdown("---")
st.sidebar.subheader("✉️ MA BOÎTE MAIL (ENVOIS & RECEPTION)")

# Récupération et sauvegarde des identifiants e-mail propres à l'utilisateur connecté
curr_mail_cfg = st.session_state.get("user_config_email", {})

val_mail = curr_mail_cfg.get("email", st.session_state.get("user_email", ""))
val_pwd = curr_mail_cfg.get("password", "")
val_imap = curr_mail_cfg.get("imap", "imap.gmail.com")

with st.sidebar.form("form_cfg_mail"):
  email_utilisateur = st.text_input("Adresse e-mail d'envoi :", value=val_mail)
  password_email = st.text_input(
      "Mot de passe d'application :", type="password", value=val_pwd
  )
  serveur_imap = st.text_input("Serveur IMAP :", value=val_imap)
  btn_save_mail = st.form_submit_button("Enregistrer ma boîte mail")

  if btn_save_mail:
    try:
      conn_u = get_connection()
      c_u = conn_u.cursor()
      c_u.execute(
          """UPDATE utilisateurs 
                         SET mail_perso = %s, mail_password = %s, mail_imap = %s 
                         WHERE email = %s""",
          (
              email_utilisateur,
              password_email,
              serveur_imap,
              st.session_state["user_email"],
          ),
      )
      conn_u.commit()

      st.session_state["user_config_email"] = {
          "email": email_utilisateur,
          "password": password_email,
          "imap": serveur_imap,
      }
      st.success("✅ Configuration e-mail sauvegardée !")
    except Exception as e_m:
      st.error(f"Erreur de sauvegarde : {e_m}")

# Raccourcis globaux pour le reste de l'application
email_utilisateur = st.session_state["user_config_email"].get(
    "email", email_utilisateur
)
password_email = st.session_state["user_config_email"].get(
    "password", password_email
)
serveur_imap = st.session_state["user_config_email"].get("imap", serveur_imap)

st.sidebar.markdown("---")

# --- PANNEAU D'ADMINISTRATION POUR CRÉER ET GÉRER LES ACCÈS PROSPECTS ---
if st.session_state.get("is_admin", False):
    st.sidebar.subheader("👑 GESTION DES ACCÈS (ADMIN)")
    
    # --- 1. SOUS-MENU : CRÉATION DE COMPTE ---
    with st.sidebar.expander("➕ Créer un accès Prospect"):
        with st.form("form_nouveau_prospect"):
            p_email = st.text_input("E-mail prospect :").strip().lower()
            p_pwd = st.text_input("Mot de passe temporaire :")
            p_jours = st.number_input(
                "Durée de l'essai (jours) :", min_value=1, value=30
            )
            btn_creer = st.form_submit_button("Créer l'accès")

            if btn_creer:
                if p_email and p_pwd:
                    try:
                        date_fin_calc = (
                            datetime.date.today() + datetime.timedelta(days=p_jours)
                        ).isoformat()
                        conn_add = get_connection()
                        c_add = conn_add.cursor()
                        c_add.execute(
                            """INSERT INTO utilisateurs (email, password, date_fin_essai, est_admin, nb_requetes_ia)
                               VALUES (%s, %s, %s, 0, 0)""",
                            (p_email, hacher_mdp(p_pwd), date_fin_calc),
                        )
                        conn_add.commit()
                        st.success(
                            f"Accès créé pour {p_email} jusqu'au"
                            f" {datetime.date.fromisoformat(date_fin_calc).strftime('%d/%m/%Y')} ! "
                            f"Mot de passe à communiquer au prospect : **{p_pwd}**"
                        )
                    except psycopg2.IntegrityError:
                        st.error("Cet e-mail possède déjà un compte.")
                    except Exception as e_adm:
                        st.error(f"Erreur : {e_adm}")
                else:
                    st.error("Champs manquants.")

    # --- 1bis. SOUS-MENU : CHANGER SON PROPRE MOT DE PASSE ---
    with st.sidebar.expander("🔑 Changer mon mot de passe"):
        with st.form("form_changer_mdp_admin"):
            nouveau_mdp_1 = st.text_input("Nouveau mot de passe :", type="password")
            nouveau_mdp_2 = st.text_input("Confirmer le nouveau mot de passe :", type="password")
            btn_changer_mdp = st.form_submit_button("Mettre à jour le mot de passe")

            if btn_changer_mdp:
                if not nouveau_mdp_1 or not nouveau_mdp_2:
                    st.error("Merci de remplir les deux champs.")
                elif nouveau_mdp_1 != nouveau_mdp_2:
                    st.error("Les deux mots de passe ne correspondent pas.")
                elif len(nouveau_mdp_1) < 8:
                    st.error("Le mot de passe doit faire au moins 8 caractères.")
                else:
                    try:
                        conn_pwd = get_connection()
                        c_pwd = conn_pwd.cursor()
                        c_pwd.execute(
                            "UPDATE utilisateurs SET password = %s WHERE email = %s",
                            (hacher_mdp(nouveau_mdp_1), st.session_state.get("user_email")),
                        )
                        conn_pwd.commit()
                        st.success(
                            "✅ Mot de passe mis à jour. Il sera actif dès ta prochaine connexion."
                        )
                    except Exception as e_pwd:
                        st.error(f"Erreur lors de la mise à jour : {e_pwd}")

    # --- 2. SOUS-MENU : SUIVI & RÉINITIALISATION DES QUOTAS IA ---
    with st.sidebar.expander("📊 Quotas IA & Remise à 0"):
        try:
            conn_q = get_connection()
            c_q = conn_q.cursor()
            c_q.execute("SELECT email, COALESCE(nb_requetes_ia, 0) FROM utilisateurs WHERE est_admin = 0")
            prospects_data = c_q.fetchall()

            if prospects_data:
                # Affichage de la consommation de chaque prospect
                for email_p, nb_p in prospects_data:
                    st.caption(f"👤 **{email_p}** : {nb_p} / {LIMITE_REQUETES_IA} requêtes")

                st.markdown("---")
                
                # Formulaire de réinitialisation
                liste_emails = [p[0] for p in prospects_data]
                target_user = st.selectbox("Réinitialiser l'utilisateur :", liste_emails, key="sb_reset_quota_sb")
                
                if st.button("🔄 Remettre le quota à 0", key="btn_reset_quota_sb"):
                    conn_res = get_connection()
                    c_res = conn_res.cursor()
                    c_res.execute("UPDATE utilisateurs SET nb_requetes_ia = 0 WHERE email = %s", (target_user,))
                    conn_res.commit()
                    st.success(f"Quota réinitialisé pour {target_user} !")
                    st.rerun()
            else:
                st.info("Aucun prospect enregistré.")
        except Exception as e_quota:
            st.error(f"Erreur quota : {e_quota}")

    st.sidebar.markdown("---")

    # --- 3. SOUS-MENU : SUPPRESSION D'UN PROSPECT ---
    with st.sidebar.expander("🗑️ Supprimer un Prospect"):
        try:
            conn_del_list = get_connection()
            c_dl = conn_del_list.cursor()
            c_dl.execute("SELECT email FROM utilisateurs WHERE est_admin = 0")
            prospects_suppr = [row[0] for row in c_dl.fetchall()]

            if prospects_suppr:
                user_a_supprimer = st.selectbox("Choisir le prospect à supprimer :", prospects_suppr, key="sb_delete_user")
                
                if st.button("🗑️ Supprimer définitivement", key="btn_confirm_delete", type="primary"):
                    conn_del = get_connection()
                    c_d = conn_del.cursor()
                    c_d.execute("DELETE FROM utilisateurs WHERE email = %s", (user_a_supprimer,))
                    conn_del.commit()
                    st.success(f"Le prospect {user_a_supprimer} a été supprimé.")
                    st.rerun()
            else:
                st.info("Aucun prospect à supprimer.")
        except Exception as e_del:
            st.error(f"Erreur lors de la suppression : {e_del}")

options_menu = [
    "🧭 TABLEAU DE BORD",
    "🗃️ VIVIER DE CANDIDATS", 
    "🎯 MATCHING IA OFFRES & CV",
    "🏢 PORTEFEUILLE CLIENTS",
    "✍️ RÉDACTION ANNONCES IA", 
    "🖥️ TRI & CLASSEMENT IA",
    "🤝 MATCHING & OPPORTUNITÉS",
    "📊 PIPELINE DE RECRUTEMENT",
    "🏹 SOURCING EXTERNE & CHASSE",
    "📋 GESTION ADMINISTRATIVE & RH"
]
index_actuel = options_menu.index(st.session_state['page_active']) if st.session_state['page_active'] in options_menu else 0
menu = st.sidebar.radio("MENU PRINCIPAL", options_menu, index=index_actuel)
st.session_state['page_active'] = menu

# --- ONGLET 0 : TABLEAU DE BORD (digest quotidien + relance dormants) ---
if st.session_state['page_active'] == "🧭 TABLEAU DE BORD":
    st.header("🧭 Tableau de Bord — Synthèse Quotidienne")
    st.caption("Généré à partir des données existantes — aucune action n'est prise automatiquement, tout reste à valider par vous.")

    digest = generer_digest_quotidien()

    col_d1, col_d2, col_d3 = st.columns(3)
    with col_d1: st.metric("🔔 Alertes de matching non lues", digest["alertes_non_lues"])
    with col_d2: st.metric("🩺 Visites médecine < 15 jours", len(digest["visites_medecine_proches"]))
    with col_d3: st.metric("⏳ Fins de contrat < 7 jours", len(digest["fins_de_contrat_proches"]))

    st.markdown("---")

    col_alertes_dig, col_dormants_dig = st.columns(2)

    with col_alertes_dig:
        st.subheader("🩺 Échéances à surveiller")
        if digest["visites_medecine_proches"]:
            for nom_m, date_m in digest["visites_medecine_proches"]:
                st.markdown(f"- **{nom_m}** — visite médicale limite le {date_m}")
        else:
            st.caption("Aucune visite médicale urgente.")
        if digest["fins_de_contrat_proches"]:
            st.markdown("**Fins de mission proches :**")
            for nom_f, date_f, entr_f in digest["fins_de_contrat_proches"]:
                st.markdown(f"- **{nom_f}** chez {entr_f} — fin le {date_f}")

    with col_dormants_dig:
        st.subheader("💤 Candidats dormants (Disponible depuis > 30 jours)")
        if not digest["candidats_dormants"]:
            st.caption("Aucun candidat dormant détecté.")
        else:
            for cand_id_dorm, nom_dorm, poste_dorm in digest["candidats_dormants"]:
                with st.container():
                    st.markdown(f"**{nom_dorm}** — {poste_dorm or 'Poste non précisé'}")
                    if st.button(f"✍️ Générer un brouillon de relance", key=f"brouillon_{cand_id_dorm}"):
                        if not peut_utiliser_ia(st.session_state.get("user_email")):
                            st.error("⚠️ Quota IA mensuel atteint.")
                        else:
                            with st.spinner("Rédaction du brouillon..."):
                                brouillon = generer_brouillon_relance(nom_dorm, poste_dorm or "un poste correspondant à son profil")
                            incrémenter_quota_ia(st.session_state.get("user_email"))
                            st.session_state[f"brouillon_relance_{cand_id_dorm}"] = brouillon

                    if st.session_state.get(f"brouillon_relance_{cand_id_dorm}"):
                        st.markdown(f"""<div style="background-color:#262730; padding:14px; border-radius:8px; color:white; white-space:pre-wrap; font-size:13px;">{st.session_state[f"brouillon_relance_{cand_id_dorm}"]}</div>""", unsafe_allow_html=True)
                        c.execute("SELECT competences FROM candidats WHERE id = %s", (cand_id_dorm,))
                        coord_row = c.fetchone()
                        email_dorm = extraire_email(coord_row[0]) if coord_row and coord_row[0] else None
                        if email_dorm:
                            mailto_dorm = f"mailto:{email_dorm}?subject={urllib.parse.quote('Toujours disponible ?')}&body={urllib.parse.quote(st.session_state[f'brouillon_relance_{cand_id_dorm}'])}"
                            st.link_button("✉️ Ouvrir dans mon client mail pour envoyer", mailto_dorm, use_container_width=True)
                        else:
                            st.caption("⚠️ Aucun e-mail détecté pour ce candidat — envoi manuel nécessaire.")
                    st.markdown("---")

# --- ONGLET 1 : CONSULTATION DU VIVIER ---
elif st.session_state['page_active'] == "🗃️ VIVIER DE CANDIDATS":
    st.header("🗃️ Gestion et Pilotage du Vivier Interne")
    
    try:
        c.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
            ("candidats",),
        )
        colonnes_existantes = [info[0] for info in c.fetchall()]
        
        colonnes_requises = {
            "nom": "TEXT",
            "poste": "TEXT",
            "competences": "TEXT",
            "statut": "TEXT DEFAULT 'Disponible'",
            "categorie_ia": "TEXT DEFAULT 'À Classer'",
            "avis_ia": "TEXT",
            "score_matching": "REAL",
            "secteur_metier": "TEXT",
            "type_rdv": "TEXT",
            "date_rdv": "TEXT"
        }
        
        for col, type_col in colonnes_requises.items():
            if col not in colonnes_existantes:
                if col == "poste" and ("poste_cible" in colonnes_existantes or "metier" in colonnes_existantes):
                    continue
                c.execute(f"ALTER TABLE candidats ADD COLUMN {col} {type_col}")
                
        nom_colonne_poste = "poste"
        if "poste" not in colonnes_existantes:
            if "poste_cible" in colonnes_existantes:
                nom_colonne_poste = "poste_cible"
            elif "metier" in colonnes_existantes:
                nom_colonne_poste = "metier"
    except Exception:
        nom_colonne_poste = "poste"

    try:
        c.execute("SELECT COUNT(*), SUM(CASE WHEN statut LIKE '%Disponible%' THEN 1 ELSE 0 END), SUM(CASE WHEN statut LIKE '%mission%' THEN 1 ELSE 0 END) FROM candidats")
        stats = c.fetchone()
        total_cand = stats[0] if stats[0] else 0
        dispo_cand = stats[1] if stats[1] else 0
        mission_cand = stats[2] if stats[2] else 0
    except Exception:
        total_cand, dispo_cand, mission_cand = 0, 0, 0

    col_kpi1, col_kpi2, col_kpi3 = st.columns(3)
    with col_kpi1: st.metric(label="👥 Total Talents en Base", value=total_cand)
    with col_kpi2: st.metric(label="🟢 Profils Disponibles", value=dispo_cand)
    with col_kpi3: st.metric(label="🔵 En Mission / Placement", value=mission_cand)

    st.markdown("---")
    with st.expander("🧠 Nouvel Agent IA — Analyse enrichie d'un CV (sans offre de référence)", expanded=False):
        st.caption("Diplômes, compétences dures, compétences transférables justifiées, indices de personnalité (parcours & centres d'intérêt) et métiers cibles — enregistrés automatiquement dans le vivier.")
        fichier_cv_agent = st.file_uploader("CV au format PDF :", type=["pdf"], key="uploader_cv_agent")
        secteur_cv_agent = st.selectbox("Secteur d'affectation :", LISTE_SECTEURS[1:], key="secteur_cv_agent")

        if st.button("🚀 Lancer l'agent d'analyse", key="btn_agent_cv"):
            if not fichier_cv_agent:
                st.error("⚠️ Merci de déposer un CV au format PDF.")
            elif not peut_utiliser_ia(st.session_state.get("user_email")):
                st.error("⚠️ Vous avez atteint votre quota mensuel de requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
            else:
                try:
                    reader_agent = PdfReader(fichier_cv_agent)
                    texte_cv_agent = "".join([p.extract_text() for p in reader_agent.pages if p.extract_text()])
                    with st.spinner("Analyse en cours par l'agent IA..."):
                        resultat_agent = analyser_cv_avec_agent(texte_cv_agent, secteur_cv_agent)
                    incrémenter_quota_ia(st.session_state.get("user_email"))
                    st.session_state["dernier_rapport_agent"] = resultat_agent
                    st.success("✅ Analyse terminée et candidat enregistré dans le vivier !")
                except Exception as e:
                    st.error(f"Erreur lors de l'analyse : {e}")

        # --- RAPPORT DÉTAILLÉ STYLÉ (même codes visuels que le module de matching) ---
        if st.session_state.get("dernier_rapport_agent"):
            d = st.session_state["dernier_rapport_agent"].get("donnees_structurees") or {}
            compte_rendu_txt = st.session_state["dernier_rapport_agent"].get("compte_rendu", "")

            nom_cand = d.get("nom_complet", "Candidat")
            score = int(d.get("pourcentage_adequation", 0) or 0)
            metiers = d.get("metiers_cibles", [])
            hard_skills = d.get("hard_skills", [])
            diplomes = d.get("diplomes", [])
            transferables = d.get("soft_skills_transferables", [])
            traits_dom = d.get("traits_dominants", [])
            indices_parcours = d.get("indices_parcours_pro", "")
            indices_interets = d.get("indices_centres_interet", "")
            coherence = d.get("coherence_projet_pro", "")

            if score >= 70:
                couleur_badge = "#2e7d32"  # vert
            elif score >= 40:
                couleur_badge = "#f59e0b"  # orange
            else:
                couleur_badge = "#c53030"  # rouge

            st.markdown(f"""
                <div style="background-color: #2d3748; border-radius: 10px; padding: 22px; margin-top: 18px; margin-bottom: 14px; border-left: 5px solid {couleur_badge};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-size: 22px; font-weight: 700; color: #ffffff;">🧑‍💼 {nom_cand}</span>
                        <span style="background-color: {couleur_badge}; color: white; padding: 6px 18px; border-radius: 20px; font-weight: 700; font-size: 16px;">{score}%</span>
                    </div>
                    <div style="color: #a3b1cc; font-size: 13px; margin-top: 4px;">Adéquation globale du profil — secteur {secteur_cv_agent}</div>
                </div>
            """, unsafe_allow_html=True)

            st.caption("📈 Adéquation globale estimée")
            st.progress(min(1.0, score / 100))

            if metiers:
                st.markdown("**🎯 Métiers cibles recommandés**")
                st.markdown(" ".join([
                    f'<span style="background-color:#374151; color:#e2e8f0; padding:5px 12px; border-radius:14px; margin-right:6px; font-size:13px; display:inline-block; margin-bottom:6px;">{m}</span>'
                    for m in metiers
                ]), unsafe_allow_html=True)

            st.markdown("---")
            col_rapport_gauche, col_rapport_droite = st.columns(2)

            with col_rapport_gauche:
                st.markdown("##### 🎓 Diplômes & formations")
                if diplomes:
                    for dip in diplomes:
                        st.markdown(f"- {dip}")
                else:
                    st.caption("Non renseigné dans le CV.")

                st.markdown("##### 🛠️ Compétences dures")
                if hard_skills:
                    for hs in hard_skills:
                        st.markdown(f"- {hs}")
                else:
                    st.caption("Non renseigné dans le CV.")

            with col_rapport_droite:
                st.markdown("##### 🌱 Compétences transférables")
                if transferables:
                    for comp in transferables:
                        st.markdown(f"- {comp}")
                else:
                    st.caption("Aucune compétence transférable notable détectée.")

                st.markdown("##### 🧭 Indices de personnalité (parcours &amp; centres d'intérêt)")
                if traits_dom:
                    st.markdown(" ".join([
                        f'<span style="background-color:#374151; color:#e2e8f0; padding:4px 10px; border-radius:12px; margin-right:6px; font-size:12px; display:inline-block; margin-bottom:6px;">{t}</span>'
                        for t in traits_dom
                    ]), unsafe_allow_html=True)
                if indices_parcours:
                    st.markdown(f"**Issus du parcours pro :** {indices_parcours}")
                if indices_interets:
                    st.markdown(f"**Issus des centres d'intérêt :** {indices_interets}")
                if coherence:
                    st.markdown(f"**Cohérence du projet pro :** {coherence}")
                st.caption("💡 Indices déduits du CV, à valider en entretien — ne remplacent pas un échange direct avec le candidat.")

            st.markdown("---")
            st.markdown("##### 📝 Compte-rendu de l'agent IA")
            st.markdown(f"""
                <div style="background-color: #1a202c; padding: 18px; border-radius: 10px; color: #e2e8f0; white-space: pre-wrap; line-height: 1.6;">
                    {compte_rendu_txt}
                </div>
            """, unsafe_allow_html=True)

            if st.button("🗑️ Effacer ce rapport", key="btn_clear_rapport_agent"):
                del st.session_state["dernier_rapport_agent"]
                st.rerun()

    st.markdown("---")
    st.subheader("🔍 Filtrage des Talents par Secteur d'Activité")
    secteur_filtre = st.selectbox("Sélectionnez le secteur à afficher :", LISTE_SECTEURS)
    
    try:
        c.execute(f"SELECT id, nom, {nom_colonne_poste}, competences, statut, categorie_ia, avis_ia, score_matching, secteur_metier FROM candidats")
        donnees = c.fetchall()
        if donnees:
            df_vivier = pd.DataFrame(donnees, columns=["ID", "Nom", "Poste", "Coordonnées / Compétences", "Statut", "Catégorie", "Avis IA", "Score Match", "Secteur Métier"])
            if secteur_filtre != "Tous":
                df_vivier = df_vivier[df_vivier["Secteur Métier"].str.strip() == secteur_filtre.strip()]
            
            if not df_vivier.empty:
                st.success(f"📊 {len(df_vivier)} profil(s) trouvé(s) pour le secteur : {secteur_filtre}")
                
                def extraire_email(texte):
                    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', str(texte))
                    return emails[0] if emails else None

                df_vivier["Email_Brut"] = df_vivier["Coordonnées / Compétences"].apply(extraire_email)
                df_vivier["Email"] = df_vivier["Email_Brut"].apply(lambda x: f"mailto:{x}" if x else None)
                # Nettoyage robuste et extraction du vrai score global
                df_vivier["Score_Affiche"] = df_vivier["Score Match"].apply(lambda x: f"{int(float(''.join([c for c in str(x) if c.isdigit() or c == '.'])))} %" if pd.notnull(x) and any(c.isdigit() for c in str(x)) else "0 %")

                # L'Avis IA (compte-rendu complet, potentiellement plusieurs paragraphes) est
                # illisible dans une cellule de grille : on garde le texte intégral à part
                # (Avis_IA_Complet) et on n'affiche qu'un résumé court dans le tableau.
                df_vivier["Avis_IA_Complet"] = df_vivier["Avis IA"]
                df_vivier["Avis IA"] = df_vivier["Avis IA"].apply(
                    lambda x: (str(x)[:140].rsplit(" ", 1)[0] + "…") if pd.notnull(x) and len(str(x)) > 140 else (x if pd.notnull(x) else "")
                )

                # Affichage du data_editor avec des largeurs maîtrisées pour éviter le scroll infini
                edited_df = st.data_editor(
                    df_vivier.drop(columns=["Email_Brut", "Score Match", "Avis_IA_Complet"]), 
                    use_container_width=True, 
                    hide_index=True,
                    key="editor_vivier",
                    column_config={
                        "ID": st.column_config.NumberColumn("ID", disabled=True, width="small"),
                        "Nom": st.column_config.TextColumn("Nom", disabled=True),
                        "Poste": st.column_config.TextColumn("Poste", disabled=True),
                        "Coordonnées / Compétences": st.column_config.TextColumn("Coordonnées / Compétences", width="medium"),
                        "Statut": st.column_config.SelectboxColumn("Statut", options=["Disponible", "Non disponible", "En mission"], required=True),
                        "Catégorie": st.column_config.SelectboxColumn("Catégorie", options=["À Classer", "⭐ Top Profil", "✅ Profil Confirmé", "🌱 Junior / Débutant", "⏳ À Recontacter", "❌ Ne pas retenir"], required=True),
                        "Score_Affiche": st.column_config.TextColumn("Score Match 🎯", disabled=True, width="small"),
                        "Avis IA": st.column_config.TextColumn("Avis IA 🤖 (résumé)", disabled=True, width="medium", help="Résumé tronqué — voir le compte-rendu complet dans le panneau de suivi ci-dessous."),
                        "Secteur Métier": st.column_config.TextColumn("Secteur Métier", disabled=True),
                        "Email": st.column_config.LinkColumn("Action", display_text="✉️ Contacter")
                    }
                )

                if st.session_state.get("editor_vivier") and st.session_state["editor_vivier"]["edited_rows"]:
                    vivier_modifie = False
                    for index, modifications in st.session_state["editor_vivier"]["edited_rows"].items():
                        id_candidat = int(df_vivier.iloc[index]["ID"])
                        for colonne, nouvelle_valeur in modifications.items():
                            nom_colonne_sql = {"Statut": "statut", "Catégorie": "categorie_ia"}.get(colonne)
                            if nom_colonne_sql:
                                c.execute(f"UPDATE candidats SET {nom_colonne_sql} = %s WHERE id = %s", (nouvelle_valeur, id_candidat))
                                vivier_modifie = True
                    if vivier_modifie:
                        st.success("Modifications du vivier enregistrées !")
                        st.rerun()

                st.markdown("---")
                st.subheader("⚡ Suivi & Actions Administratives")
                liste_candidats_filtres = df_vivier["Nom"].tolist()
                candidat_selectionne = st.selectbox("Sélectionnez un candidat pour gérer ses démarches :", liste_candidats_filtres)

                if candidat_selectionne:
                    infos_candidat = df_vivier[df_vivier["Nom"] == candidat_selectionne].iloc[0]
                    id_selectionne = int(infos_candidat["ID"])
                    statut_actuel = infos_candidat["Statut"]
                    email_candidat = df_vivier[df_vivier["Nom"] == candidat_selectionne].iloc[0]["Email_Brut"]
                    score_suivi = infos_candidat["Score_Affiche"]
                    
                    col_info, col_bouton_urssaf = st.columns([2, 1])
                    with col_info:
                        st.markdown(f"👤 **Profil :** {candidat_selectionne} — *{infos_candidat['Poste']}*")
                        st.markdown(f"📌 **Statut :** `{statut_actuel}` | **Score de correspondance :** `{score_suivi}`")

                    avis_complet = infos_candidat.get("Avis_IA_Complet", "")
                    if pd.notnull(avis_complet) and str(avis_complet).strip():
                        with st.expander("🤖 Voir le compte-rendu IA complet"):
                            st.markdown(f"""
                                <div style="background-color: #1a202c; padding: 16px; border-radius: 8px; color: #e2e8f0; white-space: pre-wrap; line-height: 1.6;">
                                    {avis_complet}
                                </div>
                            """, unsafe_allow_html=True)
                    
                    with col_bouton_urssaf:
                        if statut_actuel == "En mission":
                            st.link_button("📝 Faire la DPAE (URSSAF)", url="https://www.declaration.urssaf.fr/", use_container_width=True, type="primary")
                        else:
                            st.link_button("🌐 Accéder à l'URSSAF", url="https://www.declaration.urssaf.fr/", use_container_width=True)
                    
                    # --- ZONE DE SUPPRESSION (ÉPURÉE) ---
                    confirmer_suppression = st.checkbox(f"Je confirme vouloir supprimer définitivement {candidat_selectionne} de la base", key=f"conf_del_{id_selectionne}")
                    if st.button(f"❌ Supprimer le candidat", type="primary", disabled=not confirmer_suppression, use_container_width=True):
                        try:
                            c.execute("DELETE FROM candidats WHERE id = %s", (id_selectionne,))
                            conn.commit()
                            st.success(f"Le candidat {candidat_selectionne} a été supprimé.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erreur : {e}")
                    
                    st.markdown("### 🗓️ Gestion des Rendez-vous & Relances")
                    c.execute("SELECT type_rdv, date_rdv FROM candidats WHERE nom = %s", (candidat_selectionne,))
                    rdv_id = c.fetchone()
                    current_type_rdv = rdv_id[0] if rdv_id else None
                    current_date_rdv = rdv_id[1] if rdv_id else None

                    if current_type_rdv and current_date_rdv:
                        st.info(f"📅 **RDV Planifié : {current_type_rdv}** prévu le `{current_date_rdv}`")
                        if st.button("🗑️ Annuler / Supprimer le RDV", type="primary", use_container_width=True):
                            c.execute("UPDATE candidats SET type_rdv = NULL, date_rdv = NULL WHERE nom = %s", (candidat_selectionne,))
                            conn.commit()
                            st.success(f"RDV supprimé pour {candidat_selectionne} !")
                            st.rerun()
                    else:
                        col_rdv1, col_rdv2, col_rdv3 = st.columns(3)
                        with col_rdv1: type_rdv = st.selectbox("Type d'action :", ["Entretien Téléphonique", "Entretien Physique", "Relance Candidat"], key=f"type_rdv_{candidat_selectionne}")
                        with col_rdv2: date_rdv = st.date_input("Date :", key=f"date_{candidat_selectionne}")
                        with col_rdv3: heure_rdv = st.text_input("Heure (ex: 14:30) :", value="09:00", max_chars=5, key=f"heure_{candidat_selectionne}")
                        
                        if st.button("📅 Enregistrer l'action de suivi", use_container_width=True, type="secondary"):
                            datetime_rdv = f"{date_rdv.strftime('%Y-%m-%d')} à {heure_rdv}"
                            c.execute("UPDATE candidats SET type_rdv = %s, date_rdv = %s WHERE nom = %s", (type_rdv, datetime_rdv, candidat_selectionne))
                            conn.commit()
                            st.success(f"Action enregistrée pour {candidat_selectionne} le {datetime_rdv} !")
                            st.rerun()

                        st.markdown("---")
                        st.markdown("##### 🤖 Génération de Convocation par IA")
                        
                        if not email_candidat:
                            st.warning("⚠️ Aucun e-mail valide détecté pour ce candidat.")
                        else:
                            st.caption(f"Destinataire : `{email_candidat}`")
                            if st.button("🧠 Rédiger l'e-mail avec l'IA", use_container_width=True, type="primary"):
                                with st.spinner("L'IA prépare le message..."):
                                    try:
                                        model = genai.GenerativeModel("gemini-2.5-flash")
                                        prompt_mail = f"Rédige un e-mail professionnel de convocation pour {candidat_selectionne} pour le poste de {infos_candidat['Poste']} ({type_rdv} le {date_rdv.strftime('%Y-%m-%d')} à {heure_rdv}). Signe 'L\'équipe OmniRecrut IA'."
                                        response_mail = model.generate_content(prompt_mail)
                                        st.session_state["mail_genere_texte"] = response_mail.text
                                        st.session_state["mail_genere_sujet"] = f"Votre {type_rdv} - OmniRecrut IA"
                                    except Exception as e: st.error(f"Erreur Gemini : {e}")
                            
                            if "mail_genere_texte" in st.session_state:
                                st.markdown("🔹 **Aperçu du message rédigé par l'IA :**")
                                st.markdown(f'<div style="background-color: #262730; padding: 20px; border-radius: 10px; color: white; white-space: pre-wrap;">{st.session_state["mail_genere_texte"]}</div>', unsafe_allow_html=True)
                                
                                mailto_url = f"mailto:{email_candidat}?subject={urllib.parse.quote(st.session_state['mail_genere_sujet'])}&body={urllib.parse.quote(st.session_state['mail_genere_texte'])}"
                                col_action1, col_action2 = st.columns([3, 1])
                                with col_action1: st.link_button("✉️ Ouvrir Gmail & Envoyer", url=mailto_url, use_container_width=True, type="primary")
                                with col_action2:
                                    if st.button("🗑️ Effacer", use_container_width=True):
                                        del st.session_state["mail_genere_texte"]
                                        st.rerun()
            else:
                st.info("Le vivier est actuellement vide.")
    except Exception as e:
        st.error(f"Erreur Vivier : {e}")

# --- ONGLET 2 : MATCHING AUTOMATISÉ ---
elif st.session_state['page_active'] == "🎯 MATCHING IA OFFRES & CV":
    st.header("🎯 Module de Matching & Scoring Prédictif")
    if 'derniers_matchs' not in st.session_state: st.session_state['derniers_matchs'] = []
    
    valeur_par_defaut_offre = st.session_state['offre_transferee'] if st.session_state['offre_transferee'] else ""
    if st.session_state['offre_transferee']:
        st.info("💡 Une offre a été pré-chargée depuis l'onglet de rédaction.")
        if st.button("🗑️ Effacer l'offre importée"):
            st.session_state['offre_transferee'] = ""
            st.rerun()

    col_offre, col_cvs = st.columns(2)
    with col_offre: texte_offre = st.text_area("Annonce ou description du poste cible :", value=valeur_par_defaut_offre, height=250)
    with col_cvs: fichiers_cv = st.file_uploader("Sélectionnez un ou plusieurs CV (Format PDF)", type=["pdf"], accept_multiple_files=True)

    if st.button("🚀 LANCER LE MATCHING INTELLIGENT"):
        if not texte_offre or not fichiers_cv: 
            st.error("⚠️ Offre ou CV manquant.")
        elif not peut_utiliser_ia(st.session_state.get("user_email")):
            st.error("⚠️ Vous avez atteint votre quota mensuel de 300 requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
        else:
            model = genai.GenerativeModel("gemini-2.5-flash")
            resultats_matching = []
            
            for index, fichier in enumerate(fichiers_cv):
                try:
                    reader = PdfReader(fichier)
                    texte_cv = "".join([page.extract_text() for page in reader.pages if page.extract_text()])
                    
                    # --- PROMPT ENRICHI : ANALYSE CONTEXTUELLE & COMPÉTENCES TRANSFÉRABLES ---
                    prompt = f"""
                    Tu es un Expert Recruteur et Chasseur de Têtes, spécialisé dans la détection de potentiel
                    au-delà du matching par mots-clés classique. Analyse ce CV par rapport à la fiche de poste fournie.

                    CONSIGNES CLÉS :
                    1. Ne te limite pas à la recherche stricte de mots-clés.
                    2. Analyse la trajectoire, la cohérence du parcours et le potentiel du candidat.
                    3. Détecte les compétences transférables et transversales (soft skills, organisation, relation
                       client, gestion du stress, rigueur) acquises dans d'autres secteurs. Pour CHAQUE compétence
                       transférable identifiée, indique explicitement de quelle expérience concrète du CV elle
                       provient (ex : "Gestion du stress sous forte contrainte de temps — issue de 5 ans en cuisine
                       de restauration rapide"). N'invente jamais une expérience qui ne figure pas dans le CV.
                    4. Si le parcours ne permet pas d'identifier de compétence transférable pertinente pour ce poste,
                       dis-le clairement plutôt que d'en inventer une pour combler.

                    Renvoie STRICTEMENT un objet JSON valide avec les clés suivantes :
                    - 'nom': Prénom et Nom du candidat (ou 'Inconnu')
                    - 'coordonnees': Téléphone et Email si présents
                    - 'competences_directes': Compétences techniques/métier directement alignées avec l'offre
                    - 'competences_transferables': Liste de compétences transférables, CHACUNE accompagnée de sa
                       source ("compétence — issue de [expérience précise du CV]")
                    - 'score_technique': Entier 0-100, adéquation sur les compétences techniques/mots-clés directs
                    - 'score_potentiel': Entier 0-100, adéquation sur la trajectoire et les compétences transférables
                    - 'score': Entier 0-100, score global pondéré (technique + potentiel)
                    - 'justification': Synthèse de 3-4 lignes expliquant pourquoi ce profil est pertinent au-delà
                       des simples mots-clés, en t'appuyant sur les éléments concrets identifiés ci-dessus.

                    OFFRE :
                    {texte_offre}

                    CV :
                    {texte_cv}
                    """
                    
                    response = model.generate_content(prompt)
                    txt = response.text.strip().replace("```json", "").replace("```", "").strip()
                    data = json.loads(txt)

                    competences_directes = data.get("competences_directes", "Non spécifié")
                    competences_transferables_liste = data.get("competences_transferables", [])
                    if isinstance(competences_transferables_liste, list):
                        competences_transferables_txt = " | ".join(competences_transferables_liste)
                    else:
                        competences_transferables_txt = str(competences_transferables_liste)

                    resume_competences = f"{competences_directes}"
                    if competences_transferables_txt:
                        resume_competences += f" — Transférables : {competences_transferables_txt}"

                    resultats_matching.append({
                        "nom": data.get("nom", "Inconnu"), 
                        "coordonnees": data.get("coordonnees", "Non spécifié"),
                        "competences": resume_competences,
                        "competences_directes": competences_directes,
                        "competences_transferables_liste": competences_transferables_liste if isinstance(competences_transferables_liste, list) else [],
                        "score_technique": str(data.get("score_technique", "0")),
                        "score_potentiel": str(data.get("score_potentiel", "0")),
                        "score": str(data.get("score", "0")),
                        "justification": data.get("justification", "Pas d'avis"), 
                        "cv_texte": texte_cv
                    })

                    # Incrémentation du compteur (+1 par CV traité)
                    incrémenter_quota_ia(st.session_state.get("user_email"))

                except Exception as e: 
                    st.error(f"Erreur fichier {fichier.name} : {e}")
                    
            st.session_state['derniers_matchs'] = resultats_matching
            st.success("Analyse terminée !")

    if st.session_state['derniers_matchs']:
        st.markdown("---")
        st.subheader("📊 Résultats de l'analyse")

        resultats_tries = sorted(
            st.session_state['derniers_matchs'],
            key=lambda x: int(x.get("score", "0") or 0),
            reverse=True
        )

        for i, cand in enumerate(resultats_tries):
            score_global = int(cand.get("score", "0") or 0)
            score_tech = int(cand.get("score_technique", "0") or 0)
            score_pot = int(cand.get("score_potentiel", "0") or 0)

            if score_global >= 70:
                couleur_badge = "#2e7d32"  # vert
            elif score_global >= 40:
                couleur_badge = "#f59e0b"  # orange
            else:
                couleur_badge = "#c53030"  # rouge

            with st.container():
                st.markdown(f"""
                    <div style="background-color: #2d3748; border-radius: 10px; padding: 18px; margin-bottom: 14px; border-left: 5px solid {couleur_badge};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 18px; font-weight: 700; color: #ffffff;">{cand.get('nom', 'Inconnu')}</span>
                            <span style="background-color: {couleur_badge}; color: white; padding: 4px 14px; border-radius: 20px; font-weight: 700;">{score_global}%</span>
                        </div>
                        <div style="color: #a3b1cc; font-size: 13px; margin-top: 4px;">{cand.get('coordonnees', 'Non spécifié')}</div>
                    </div>
                """, unsafe_allow_html=True)

                col_score1, col_score2 = st.columns(2)
                with col_score1:
                    st.caption("🎯 Adéquation technique (mots-clés directs)")
                    st.progress(min(1.0, score_tech / 100))
                with col_score2:
                    st.caption("🌱 Potentiel & compétences transférables")
                    st.progress(min(1.0, score_pot / 100))

                with st.expander(f"📋 Voir le détail du profil — {cand.get('nom', 'Inconnu')}"):
                    st.markdown("**Compétences directes**")
                    st.write(cand.get("competences_directes", "Non spécifié"))

                    liste_transf = cand.get("competences_transferables_liste", [])
                    if liste_transf:
                        st.markdown("**🌱 Compétences transférables détectées**")
                        for comp in liste_transf:
                            st.markdown(f"- {comp}")
                    else:
                        st.caption("Aucune compétence transférable notable détectée pour ce poste.")

                    st.markdown("**Synthèse du recruteur IA**")
                    st.write(cand.get("justification", "Pas d'avis"))

                st.markdown("<br>", unsafe_allow_html=True)
        
    st.markdown("---")
    st.subheader("📥 Enregistrement ciblé dans le Vivier")
    secteur_pour_import = st.selectbox("Assigner ces candidats au secteur :", LISTE_SECTEURS[1:])
    
    if st.button("📥 CONFIRMER L'ENREGISTREMENT DANS LE VIVIER"):
        if not st.session_state['derniers_matchs']: st.warning("⚠️ Aucun résultat d'analyse en mémoire.")
        else:
            try:
                for cand in st.session_state['derniers_matchs']:
                    c.execute("""INSERT INTO candidats (nom, poste, competences, statut, categorie_ia, avis_ia, score_matching, secteur_metier, cv_texte, date_ajout) 
                                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                              (cand["nom"], "Profil Analysé", f"{cand['coordonnees']} | {cand['competences']}", "Nouveau", "À Classer", cand["justification"], f"{cand['score']} %", secteur_pour_import, cand.get("cv_texte", ""), datetime.datetime.now().isoformat()))
                st.success(f"✅ Candidat(s) enregistré(s) dans le secteur '{secteur_pour_import}' !")
                st.session_state['derniers_matchs'] = []
                st.rerun()
            except Exception as e: st.error(f"Erreur d'enregistrement : {e}")

# --- ONGLET 3 : PORTEFEUILLE CLIENTS ---
elif st.session_state["page_active"] == "🏢 PORTEFEUILLE CLIENTS":
  st.header("🏢 Gestion du Portefeuille Clients")
  col_saisie, col_filtre = st.columns([1, 2])

  with col_saisie:
    st.subheader("➕ Ajouter un compte")
    nom = st.text_input("Entreprise :")
    ville = st.text_input("Ville :", value="Béziers")
    contact = st.text_input("Interlocuteur :")
    tel = st.text_input("Téléphone :")
    email = st.text_input("Email :")

    choix_secteurs = ["-- Sélectionner --"] + LISTE_SECTEURS[1:] + ["Autre"]
    secteur_selection = st.selectbox("Secteur d'activité :", choix_secteurs)
    secteur_act_client = (
        st.text_input("Précisez le secteur :")
        if secteur_selection == "Autre"
        else secteur_selection
    )

    priorite = st.select_slider(
        "Priorité :", options=["Froid", "Tiède", "Chaud", "VIP"]
    )
    notes = st.text_area("Notes pour l'IA :")

    if st.button("💾 ENREGISTRER"):
      if not nom or secteur_selection == "-- Sélectionner --":
        st.error("⚠️ Nom et secteur requis.")
      else:
        c.execute(
            """INSERT INTO clients (entreprise, secteur, contact, secteur_activite, tel, email, priorite, notes) 
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                nom,
                ville,
                contact,
                secteur_act_client,
                tel,
                email,
                priorite,
                notes,
            ),
        )
        st.success("Compte client ajouté !")
        st.rerun()

  with col_filtre:
    st.subheader("🔍 Vos Comptes")
    try:
      df_clients = pd.read_sql_query(
          "SELECT id, entreprise, secteur, contact, tel, email, secteur_activite,"
          " priorite, notes FROM clients",
          conn,
      )
      if not df_clients.empty:
        cols_to_show = df_clients[[
            "id",
            "entreprise",
            "secteur",
            "contact",
            "tel",
            "priorite",
            "notes",
        ]]
        edited_df = st.data_editor(
            cols_to_show,
            use_container_width=True,
            hide_index=True,
            column_config={
                "id": st.column_config.NumberColumn(disabled=True),
                "priorite": st.column_config.SelectboxColumn(
                    options=["Froid", "Tiède", "Chaud", "VIP"]
                ),
            },
        )

        if st.button("🔄 Sauvegarder les modifications"):
          for i, row in edited_df.iterrows():
            c.execute(
                """UPDATE clients SET entreprise=%s, secteur=%s, contact=%s, tel=%s, priorite=%s, notes=%s WHERE id=%s""",
                (
                    row["entreprise"],
                    row["secteur"],
                    row["contact"],
                    row["tel"],
                    row["priorite"],
                    row["notes"],
                    row["id"],
                ),
            )
          st.success("Modifications enregistrées !")
          st.rerun()

        st.write("---")

        # --- ACTION RAPIDE MAIL & SUPPRESSION ---
        col_mail, col_suppr = st.columns(2)

        with col_mail:
          st.markdown("### ✉️ Envoyer un mail")
          client_choisi = st.selectbox(
              "Client à contacter :",
              df_clients["entreprise"].tolist(),
              key="select_mail_client",
          )
          mail_dest = df_clients.loc[
              df_clients["entreprise"] == client_choisi, "email"
          ].values[0]
          st.link_button(
              f"Ouvrir mail pour {client_choisi}", f"mailto:{mail_dest}"
          )

        with col_suppr:
          st.markdown("### 🗑️ Supprimer un compte")
          client_a_supprimer = st.selectbox(
              "Client à supprimer :",
              df_clients["entreprise"].tolist(),
              key="select_suppr_client",
          )

          if st.button(
              f"❌ SUPPRIMER {client_a_supprimer.upper()}", type="primary"
          ):
            c.execute(
                "DELETE FROM clients WHERE entreprise = %s",
                (client_a_supprimer,),
            )
            st.success(f"Client {client_a_supprimer} supprimé avec succès !")
            st.rerun()

      else:
        st.info("Aucun client pour le moment.")
    except Exception as e:
      st.error(f"Erreur : {e}")

# --- ONGLET 4 : RÉDACTION ANNONCES IA (COMPLÉTÉ) ---
elif st.session_state['page_active'] in ["✍️ RÉDACTION ANNONCES IA", "🚨 RÉDACTION ANNONCES IA", "📝 RÉDACTION ANNONCES IA"]:
    st.header("✍️ Assistant de Rédaction d'Annonce Évolué")
    
    # 1. Chargement de la liste des clients existants
    try:
        c.execute("SELECT entreprise, secteur_activite FROM clients ORDER BY entreprise ASC")
        clients_existants = c.fetchall()
        options_clients = [
            "-- Choisir un client existant --", 
            "➕ Autre / Nouvelle entreprise (Saisie manuelle)"
        ] + [f"{cl[0]} ({cl[1]})" for cl in clients_existants]
    except Exception: 
        options_clients = ["-- Choisir un client existant --", "➕ Autre / Nouvelle entreprise (Saisie manuelle)"]

    client_selectionne = st.selectbox("Sélectionner l'entreprise pour l'offre :", options_clients, key="client_select_offre")
    
    # Réinitialisation du cache si le choix de l'entreprise change
    if 'ancien_client_selectionne' not in st.session_state: 
        st.session_state['ancien_client_selectionne'] = client_selectionne
        
    if client_selectionne != st.session_state['ancien_client_selectionne']:
        st.session_state['derniere_offre_generee'] = ""
        st.session_state['ancien_client_selectionne'] = client_selectionne
        st.rerun()
        
    entreprise_cible = ""
    ville_cible = "Béziers"

    # 2. Gestion de la saisie manuelle vs Sélecteur automatique
    if client_selectionne == "➕ Autre / Nouvelle entreprise (Saisie manuelle)":
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            entreprise_cible = st.text_input("🏢 Nom de l'entreprise :", placeholder="Ex: Restaurant Le Globe...")
        with col_m2:
            ville_cible = st.text_input("📍 Ville de l'offre :", value="Béziers", placeholder="Ex: Pézenas, Béziers...")
    
    elif client_selectionne != "-- Choisir un client existant --":
        entreprise_cible = client_selectionne.split(" (")[0]
        try:
            c.execute("SELECT secteur FROM clients WHERE entreprise=%s", (entreprise_cible,))
            res_ville = c.fetchone()
            if res_ville and res_ville[0]: 
                ville_cible = res_ville[0]
        except Exception: 
            pass
        st.caption(f"✨ Client actif : **{entreprise_cible}** basé à **{ville_cible}**")

    # 3. Champs du poste et compétences
    col_form1, col_form2 = st.columns(2)
    with col_form1: 
        poste = st.text_input("Intitulé exact du poste recherché :", placeholder="Ex: Second de cuisine...")
    with col_form2: 
        competences_requises = st.text_area("Pré-requis, diplômes et compétences clés :", placeholder="Ex: Maîtrise HACCP...")
        
    # 4. Génération par l'IA Gemini
    if st.button("✨ GÉNÉRER L'OFFRE PAR L'IA", type="primary", use_container_width=True):
        if not poste: 
            st.error("⚠️ Indiquez l'intitulé du poste.")
        else:
            # Vérification du quota IA
            if not peut_utiliser_ia(st.session_state.get("user_email")):
                st.error("⚠️ Vous avez atteint votre quota mensuel de 300 requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
            else:
                st.info("🧠 Rédaction de l'offre en cours...")
                try:
                    nom_ent_texte = f"pour l'entreprise {entreprise_cible}" if entreprise_cible else ""
                    model = genai.GenerativeModel("gemini-2.5-flash")
                    prompt = f"Rédige une offre d'emploi détaillée et attractive en français pour le poste de {poste} à {ville_cible} {nom_ent_texte}. Pré-requis : {competences_requises}. Structure claire avec Profil, Missions, Avantages."
                    response = model.generate_content(prompt)
                    st.session_state['derniere_offre_generee'] = response.text
                    
                    # Décompte du quota (+1)
                    incrémenter_quota_ia(st.session_state.get("user_email"))
                    st.rerun()

                except Exception as e: 
                    st.error(f"Erreur IA : {e}")

    # 5. Affichage et exports de l'offre générée
    if 'derniere_offre_generee' in st.session_state and st.session_state['derniere_offre_generee']:
        st.markdown("---")
        col_t, col_b = st.columns([3, 1])
        with col_t: 
            st.markdown("### 📋 Annonce rédigée par l'IA :")
        with col_b:
            if st.button("🗑️ Effacer l'offre", use_container_width=True):
                st.session_state['derniere_offre_generee'] = ""
                st.rerun()
                
        st.markdown(f'<div style="background-color: #2d3748; padding: 20px; border-radius: 8px; border: 1px solid #4a5568; margin-bottom: 20px; color: white; white-space: pre-wrap;">{st.session_state["derniere_offre_generee"]}</div>', unsafe_allow_html=True)

        col_action1, col_action2, col_action3, col_action4 = st.columns(4)
        with col_action1:
            html_export = f"<html><body><h1>Offre : {poste}</h1><pre>{st.session_state['derniere_offre_generee']}</pre></body></html>"
            st.download_button(label="📄 EXPORTER HTML", data=html_export, file_name=f"Offre_{poste}.html", mime="text/html", use_container_width=True)
        with col_action2:
            if st.button("📄 EXPORTER PDF", use_container_width=True):
                chemin = creer_pdf_annonce(poste if poste else "Offre", st.session_state['derniere_offre_generee'])
                with open(chemin, "rb") as f: 
                    st.download_button("⬇️ TÉLÉCHARGER PDF", f, file_name=os.path.basename(chemin), mime="application/pdf", use_container_width=True)
        with col_action3:
            if st.button("🎯 MATCHING", use_container_width=True):
                st.session_state['offre_transferee'] = st.session_state['derniere_offre_generee']
                st.session_state['page_active'] = "🎯 MATCHING IA OFFRES & CV"
                st.rerun()
        with col_action4:
            if st.button("🔍 SOURCING EXTERNE", use_container_width=True, type="primary"):
                st.session_state['recherche_bool_initiale'] = poste
                st.session_state['sourcing_ville_cible'] = ville_cible
                st.session_state['page_active'] = "🏹 SOURCING EXTERNE & CHASSE"
                st.rerun()

# --- 🤝 ONGLET : MATCHING & OPPORTUNITÉS (COMPLÉTÉ AVEC QUOTAS IA) ---
elif st.session_state['page_active'] == "🤝 MATCHING & OPPORTUNITÉS":
    st.header("🎯 Intelligence de Matching & Opportunités")
    tab_classique, tab_inverse = st.tabs(["📋 Matching Classique (Besoins vs Candidats)", "🚀 Matching Inversé (Placement Proactif)"])
    
    with tab_classique:
        st.subheader("🤝 Matching IA : Candidats vs Besoins")
        col_besoin, col_vivier = st.columns(2)
        with col_besoin:
            secteur_besoin = st.selectbox("Secteur métier :", LISTE_SECTEURS, key="secteur_match")
            entreprise_besoin = st.text_input("Entreprise cliente :", key="entreprise_match")
            besoin_details = st.text_area("Détails du poste recherchés :", height=150, key="details_match_text")
            st.caption("💾 Enregistrer active la veille automatique : chaque nouveau candidat ajouté au vivier sera comparé à ce besoin et générera une alerte si le profil correspond.")
            if st.button("💾 Enregistrer ce besoin & activer les alertes", use_container_width=True):
                if not besoin_details or secteur_besoin == "Tous" or not entreprise_besoin:
                    st.error("⚠️ Entreprise, secteur et détails du poste requis.")
                elif not peut_utiliser_ia(st.session_state.get("user_email")):
                    st.error("⚠️ Vous avez atteint votre quota mensuel de requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
                else:
                    c.execute(
                        "INSERT INTO besoins_clients (entreprise, secteur, description, date_creation) VALUES (%s, %s, %s, %s) RETURNING id",
                        (entreprise_besoin, secteur_besoin, besoin_details, datetime.datetime.now().isoformat()),
                    )
                    besoin_id_nouveau = c.fetchone()[0]
                    conn.commit()
                    with st.spinner("Comparaison avec le vivier existant..."):
                        alertes = matcher_besoin_vs_vivier(besoin_id_nouveau, secteur_besoin, besoin_details)
                    incrémenter_quota_ia(st.session_state.get("user_email"))
                    st.success(f"✅ Besoin enregistré et veille activée pour '{entreprise_besoin}'.")
                    if alertes:
                        st.info(f"🔔 {len(alertes)} candidat(s) du vivier correspond(ent) déjà à ce besoin — voir le panneau Alertes dans la barre latérale.")
                        st.session_state.pop("suggestion_sourcing", None)
                    else:
                        # Aucun match interne suffisant : l'IA se contente de SUGGÉRER le sourcing
                        # externe, elle ne le lance jamais elle-même — le clic reste humain.
                        st.session_state["suggestion_sourcing"] = {"poste": secteur_besoin, "entreprise": entreprise_besoin}
                    st.rerun()

            if st.session_state.get("suggestion_sourcing"):
                sugg = st.session_state["suggestion_sourcing"]
                st.warning(f"💡 Aucun candidat du vivier ne correspond suffisamment au besoin de **{sugg['entreprise']}**.")
                if st.button("🔍 Lancer un sourcing externe pour ce besoin", use_container_width=True):
                    st.session_state['page_active'] = "🏹 SOURCING EXTERNE & CHASSE"
                    st.session_state.pop("suggestion_sourcing", None)
                    st.rerun()

        with col_vivier:
            if st.button("🚀 LANCER LE MATCHING", type="primary", use_container_width=True):
                # 1. Vérification du quota IA
                if not peut_utiliser_ia(st.session_state.get("user_email")):
                    st.error("⚠️ Vous avez atteint votre quota mensuel de 300 requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
                else:
                    c.execute("SELECT nom, poste, competences FROM candidats WHERE secteur_metier = %s", (secteur_besoin,))
                    candidats_db = c.fetchall()
                    if not candidats_db: 
                        st.warning("Aucun candidat trouvé.")
                    else:
                        data_candidats = [{"nom": cand[0], "poste": cand[1], "competences": cand[2]} for cand in candidats_db]
                        try:
                            model = genai.GenerativeModel("gemini-2.5-flash")
                            prompt = f"Compare ces candidats au besoin : '{besoin_details}'. Renvoie UN TABLEAU JSON avec uniquement : 'nom', 'score', 'raison'. Liste : {data_candidats}"
                            response = model.generate_content(prompt)
                            txt = response.text.strip()
                            if "[" in txt: txt = txt[txt.find("[") : txt.rfind("]")+1]
                            
                            st.session_state["resultat_match_classique"] = json.loads(txt)
                            
                            # Incrémentation du quota (+1)
                            incrémenter_quota_ia(st.session_state.get("user_email"))

                        except Exception as e: 
                            st.error(f"Erreur IA : {e}")

            if "resultat_match_classique" in st.session_state:
                df_res = pd.DataFrame(st.session_state["resultat_match_classique"])
                st.dataframe(df_res, use_container_width=True, hide_index=True)

    with tab_inverse:
        st.markdown('<h3 style="color: #f6ad55;">💎 Placement Proactif de Pépites</h3>', unsafe_allow_html=True)
        try:
            c.execute("SELECT nom FROM candidats ORDER BY nom ASC")
            liste_candidats_inv = [row[0] for row in c.fetchall()]
        except Exception: 
            liste_candidats_inv = []

        candidat_pepite = st.selectbox("💎 Sélectionner la pépite à placer :", ["-- Choisir un candidat --"] + liste_candidats_inv)
        if candidat_pepite != "-- Choisir un candidat --":
            c.execute("SELECT poste, competences, cv_texte FROM candidats WHERE nom = %s", (candidat_pepite,))
            res_cand = c.fetchone()
            if res_cand:
                poste_cand, comp_cand, cv_cand = res_cand[0], res_cand[1], res_cand[2]
                st.info(f"🎯 Profil : {poste_cand} | Compétences : {comp_cand}")
                
                try:
                    c.execute("SELECT entreprise, secteur, secteur_activite FROM clients")
                    donnees_clients_inv = c.fetchall()
                    liste_entreprises_texte = "\n".join([f"- {r[0]} ({r[2]} - {r[1]})" for r in donnees_clients_inv])
                except Exception: 
                    liste_entreprises_texte = ""

                if st.button("🧠 Générer la stratégie de Placement Proactif", type="primary", use_container_width=True):
                    # 1. Vérification du quota IA
                    if not peut_utiliser_ia(st.session_state.get("user_email")):
                        st.error("⚠️ Vous avez atteint votre quota mensuel de 300 requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
                    else:
                        try:
                            model = genai.GenerativeModel("gemini-2.5-flash")
                            prompt_inverse = f"Analyse le profil du candidat ({poste_cand}, {comp_cand}) par rapport à notre portefeuille clients :\n{liste_entreprises_texte}\nIdentifie les meilleures cibles et rédige un pitch d'accroche commercial anonymisé percutant."
                            response_inverse = model.generate_content(prompt_inverse)
                            
                            st.session_state["resultat_matching_inverse"] = response_inverse.text
                            
                            # Incrémentation du quota (+1)
                            incrémenter_quota_ia(st.session_state.get("user_email"))

                        except Exception as e_inv:
                            st.error(f"Erreur IA : {e_inv}")

                if "resultat_matching_inverse" in st.session_state:
                    st.markdown(f'<div style="background-color: #1e1e24; padding:20px; border-radius:8px; color:white; white-space:pre-wrap;">{st.session_state["resultat_matching_inverse"]}</div>', unsafe_allow_html=True)

# --- 🖥️ ONGLET : TRI & CLASSEMENT IA ---
elif st.session_state['page_active'] == "🖥️ TRI & CLASSEMENT IA":
    st.header("🖥️ Tri de Masse & Sourcing Automatique")
    col_gauche, col_droite = st.columns(2)
    
    with col_gauche:
        st.subheader("📊 Classificateur de Fichiers (Excel, CSV, PDF)")
        fichiers_tri = st.file_uploader("Sélectionnez vos fichiers :", type=["xlsx", "csv", "pdf"], accept_multiple_files=True, key="uploader_masse")
        if fichiers_tri:
            st.success(f"📂 {len(fichiers_tri)} fichier(s) prêt(s) à être analysé(s).")
            secteur_cible_tri = st.selectbox("Secteur métier ciblé :", LISTE_SECTEURS[1:], key="secteur_tri_masse")
            critere_important = st.text_input("Exigence ou mot-clé prioritaire :", placeholder="Ex: Permis B...")

            if st.button("🚀 LANCER LE TRI DE MASSE"):
                # Vérification du quota IA
                if not peut_utiliser_ia(st.session_state.get("user_email")):
                    st.error("⚠️ Vous avez atteint votre quota mensuel de 300 requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
                else:
                    st.info("🧠 L'IA analyse les documents... Patientez.")
                    try:
                        donnees_analyse = []
                        for f in fichiers_tri:
                            if f.name.endswith('.pdf'):
                                reader = PdfReader(f)
                                texte = "".join([page.extract_text() for page in reader.pages if page.extract_text()])
                            else:
                                df_temp = pd.read_csv(f) if f.name.endswith('.csv') else pd.read_excel(f)
                                texte = df_temp.to_string()
                            donnees_analyse.append({"nom_fichier": f.name, "contenu": texte})

                        model = genai.GenerativeModel("gemini-2.5-flash")
                        prompt = f"Analyse cette liste par rapport au secteur '{secteur_cible_tri}' et le critère '{critere_important}'. Renvoie un tableau JSON avec : 'nom', 'poste_approprie', 'score_tri', 'points_forts'."
                        response = model.generate_content(prompt)
                        txt_clean = response.text.strip().replace("```json", "").replace("```", "").strip()
                        st.dataframe(pd.DataFrame(json.loads(txt_clean)), use_container_width=True)

                        # Décompte du quota (1 crédit par fichier analysé)
                        user_email_actuel = st.session_state.get("user_email")
                        for _ in range(len(fichiers_tri)):
                            incrémenter_quota_ia(user_email_actuel)

                    except Exception as e: 
                        st.error(f"Erreur de traitement : {e}")

    with col_droite:
        st.subheader("✉️ Récupération de CV par E-mail")
        if st.button("📥 RELEVER LES E-MAILS DE SOURCING", use_container_width=True):
            if not email_utilisateur or not password_email: 
                st.error("⚠️ Identifiants manquants.")
            else:
                fichier_recupere = relever_et_analyser_emails(email_utilisateur, password_email, serveur_imap)
                if fichier_recupere:
                    st.success(f"📎 Nouveau CV PDF récupéré : {os.path.basename(fichier_recupere)}")
                    # Auto-analyse en PRÉVISUALISATION uniquement : ce CV n'a pas été choisi
                    # individuellement par un humain (contrairement à l'upload manuel), donc
                    # aucune écriture en base tant qu'il n'a pas été validé ci-dessous.
                    try:
                        reader_mail = PdfReader(fichier_recupere)
                        texte_cv_mail = "".join([p.extract_text() for p in reader_mail.pages if p.extract_text()])
                        with st.spinner("Analyse automatique en aperçu..."):
                            apercu = analyser_cv_preview(texte_cv_mail)
                        st.session_state["apercu_cv_mail"] = apercu
                        st.session_state["texte_cv_mail"] = texte_cv_mail
                    except Exception as e:
                        st.error(f"Erreur lors de l'analyse de l'aperçu : {e}")
                else: 
                    st.info("📬 Aucun nouveau message non lu avec pièce jointe PDF trouvé.")

        if st.session_state.get("apercu_cv_mail"):
            apercu = st.session_state["apercu_cv_mail"]
            st.markdown("---")
            st.markdown(f"##### 🧠 Aperçu — {apercu.get('nom_complet', 'Candidat')} *(non enregistré, à valider)*")
            st.caption(f"Adéquation estimée : {apercu.get('pourcentage_adequation', 0)}% — Métiers cibles : {', '.join(apercu.get('metiers_cibles', []))}")
            with st.expander("Voir le compte-rendu complet avant validation"):
                st.markdown(apercu.get("compte_rendu", ""))

            secteur_cv_mail = st.selectbox("Secteur d'affectation :", LISTE_SECTEURS[1:], key="secteur_cv_mail")
            col_valid_mail, col_reject_mail = st.columns(2)
            with col_valid_mail:
                if st.button("✅ Confirmer l'ajout au vivier", key="btn_confirmer_cv_mail", use_container_width=True, type="primary"):
                    try:
                        resultat_mail = _save_candidate_to_sqlite(
                            nom_complet=apercu.get("nom_complet", "Inconnu"),
                            diplomes=apercu.get("diplomes", []),
                            hard_skills=apercu.get("hard_skills", []),
                            soft_skills_transferables=apercu.get("soft_skills_transferables", []),
                            traits_dominants=apercu.get("traits_dominants", []),
                            indices_parcours_pro=apercu.get("indices_parcours_pro", ""),
                            indices_centres_interet=apercu.get("indices_centres_interet", ""),
                            coherence_projet_pro=apercu.get("coherence_projet_pro", ""),
                            metiers_cibles=apercu.get("metiers_cibles", []),
                            pourcentage_adequation=apercu.get("pourcentage_adequation", 0),
                            compte_rendu=apercu.get("compte_rendu", ""),
                            secteur_metier=secteur_cv_mail,
                            cv_texte=st.session_state.get("texte_cv_mail", ""),
                        )
                        st.success(resultat_mail.get("message", "Candidat ajouté."))
                        del st.session_state["apercu_cv_mail"]
                        st.session_state.pop("texte_cv_mail", None)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Erreur lors de l'enregistrement : {e}")
            with col_reject_mail:
                if st.button("❌ Ignorer ce CV", key="btn_rejeter_cv_mail", use_container_width=True):
                    del st.session_state["apercu_cv_mail"]
                    st.session_state.pop("texte_cv_mail", None)
                    st.rerun()# --- 🤝 ONGLET : MATCHING & OPPORTUNITÉS (COMPLÉTÉ AVEC QUOTAS IA) ---
elif st.session_state['page_active'] == "🤝 MATCHING & OPPORTUNITÉS":
    st.header("🎯 Intelligence de Matching & Opportunités")
    tab_classique, tab_inverse = st.tabs(["📋 Matching Classique (Besoins vs Candidats)", "🚀 Matching Inversé (Placement Proactif)"])
    
    with tab_classique:
        st.subheader("🤝 Matching IA : Candidats vs Besoins")
        col_besoin, col_vivier = st.columns(2)
        with col_besoin:
            secteur_besoin = st.selectbox("Secteur métier :", LISTE_SECTEURS, key="secteur_match")
            besoin_details = st.text_area("Détails du poste recherchés :", height=150, key="details_match_text")
            
        with col_vivier:
            if st.button("🚀 LANCER LE MATCHING", type="primary", use_container_width=True):
                # 1. Vérification du quota IA
                if not peut_utiliser_ia(st.session_state.get("user_email")):
                    st.error("⚠️ Vous avez atteint votre quota mensuel de 300 requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
                else:
                    c.execute("SELECT nom, poste, competences FROM candidats WHERE secteur_metier = %s", (secteur_besoin,))
                    candidats_db = c.fetchall()
                    if not candidats_db: 
                        st.warning("Aucun candidat trouvé.")
                    else:
                        data_candidats = [{"nom": cand[0], "poste": cand[1], "competences": cand[2]} for cand in candidats_db]
                        try:
                            model = genai.GenerativeModel("gemini-2.5-flash")
                            prompt = f"Compare ces candidats au besoin : '{besoin_details}'. Renvoie UN TABLEAU JSON avec uniquement : 'nom', 'score', 'raison'. Liste : {data_candidats}"
                            response = model.generate_content(prompt)
                            txt = response.text.strip()
                            if "[" in txt: txt = txt[txt.find("[") : txt.rfind("]")+1]
                            
                            st.session_state["resultat_match_classique"] = json.loads(txt)
                            
                            # Incrémentation du quota (+1) sans rerun prématuré
                            incrémenter_quota_ia(st.session_state.get("user_email"))

                        except Exception as e: 
                            st.error(f"Erreur IA : {e}")

            if "resultat_match_classique" in st.session_state:
                df_res = pd.DataFrame(st.session_state["resultat_match_classique"])
                st.dataframe(df_res, use_container_width=True, hide_index=True)

    with tab_inverse:
        st.markdown('<h3 style="color: #f6ad55;">💎 Placement Proactif de Pépites</h3>', unsafe_allow_html=True)
        try:
            c.execute("SELECT nom FROM candidats ORDER BY nom ASC")
            liste_candidats_inv = [row[0] for row in c.fetchall()]
        except Exception: 
            liste_candidats_inv = []

        candidat_pepite = st.selectbox("💎 Sélectionner la pépite à placer :", ["-- Choisir un candidat --"] + liste_candidats_inv)
        if candidat_pepite != "-- Choisir un candidat --":
            c.execute("SELECT poste, competences, cv_texte FROM candidats WHERE nom = %s", (candidat_pepite,))
            res_cand = c.fetchone()
            if res_cand:
                poste_cand, comp_cand, cv_cand = res_cand[0], res_cand[1], res_cand[2]
                st.info(f"🎯 Profil : {poste_cand} | Compétences : {comp_cand}")
                
                try:
                    c.execute("SELECT entreprise, secteur, secteur_activite FROM clients")
                    donnees_clients_inv = c.fetchall()
                    liste_entreprises_texte = "\n".join([f"- {r[0]} ({r[2]} - {r[1]})" for r in donnees_clients_inv])
                except Exception: 
                    liste_entreprises_texte = ""

                if st.button("🧠 Générer la stratégie de Placement Proactif", type="primary", use_container_width=True):
                    # 1. Vérification du quota IA
                    if not peut_utiliser_ia(st.session_state.get("user_email")):
                        st.error("⚠️ Vous avez atteint votre quota mensuel de 300 requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
                    else:
                        try:
                            model = genai.GenerativeModel("gemini-2.5-flash")
                            prompt_inverse = f"Analyse le profil du candidat ({poste_cand}, {comp_cand}) par rapport à notre portefeuille clients :\n{liste_entreprises_texte}\nIdentifie les meilleures cibles et rédige un pitch d'accroche commercial anonymisé percutant."
                            response_inverse = model.generate_content(prompt_inverse)
                            
                            st.session_state["resultat_matching_inverse"] = response_inverse.text
                            
                            # Incrémentation du quota (+1)
                            incrémenter_quota_ia(st.session_state.get("user_email"))

                        except Exception as e_inv:
                            st.error(f"Erreur IA : {e_inv}")

                if "resultat_matching_inverse" in st.session_state:
                    st.markdown(f'<div style="background-color: #1e1e24; padding:20px; border-radius:8px; color:white; white-space:pre-wrap;">{st.session_state["resultat_matching_inverse"]}</div>', unsafe_allow_html=True)
                    
 # --- 📊 ONGLET : PIPELINE DE RECRUTEMENT ---
elif st.session_state['page_active'] == "📊 PIPELINE DE RECRUTEMENT":
    st.title("📊 PIPELINE DE RECRUTEMENT")
    st.subheader("Suivi visuel et gestion du vivier de talents en temps réel")

    # Injection CSS pour le design des colonnes et des cartes Kanban
    st.markdown("""
        <style>
            .kanban-column {
                background-color: #1e293b;
                border-radius: 8px;
                padding: 15px;
                margin: 5px;
                min-height: 500px;
                border: 1px solid #334155;
            }
            .kanban-header {
                font-size: 1.1rem;
                font-weight: bold;
                text-align: center;
                padding-bottom: 10px;
                margin-bottom: 15px;
                border-bottom: 2px solid #ff9800;
                color: #f8fafc;
            }
            .kanban-card {
                background-color: #0f172a;
                border-left: 4px solid #ff9800;
                border-radius: 6px;
                padding: 12px;
                margin-bottom: 12px;
                box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2);
            }
            .card-title {
                font-weight: bold;
                color: white;
                margin-bottom: 4px;
                font-size: 1rem;
            }
            .card-subtitle {
                color: #94a3b8;
                font-size: 0.85rem;
                margin-bottom: 6px;
            }
            .card-badge {
                background-color: #1e293b;
                color: #38bdf8;
                font-size: 0.75rem;
                padding: 2px 6px;
                border-radius: 4px;
                display: inline-block;
                margin-top: 4px;
            }
        </style>
    """, unsafe_allow_html=True)

    # 1. Extraction des profils du vivier
    try:
        c.execute("SELECT id, nom, poste, statut, categorie, score_match FROM candidats")
        candidats_pipeline = c.fetchall()
    except Exception as e:
        try:
            c.execute("SELECT id, nom, poste, statut FROM candidats")
            candidats_pipeline = [(row[0], row[1], row[2], row[3], "Profil Confirmé", "100%") for row in c.fetchall()]
        except Exception as err:
            st.error(f"Erreur base de données : {err}")
            candidats_pipeline = []

    # 2. Définition des 3 étapes clés du processus
    statuts_kanban = ["Disponible", "En entretien", "En mission"]
    
    # Tri des profils dans leurs colonnes respectives
    colonnes_data = {statut: [] for statut in statuts_kanban}
    for cand in candidats_pipeline:
        id_c, nom_c, poste_c, statut_c, cat_c, score_c = cand
        statut_clean = str(statut_c).strip() if statut_c else "Disponible"
        if statut_clean not in colonnes_data:
            statut_clean = "Disponible"
            
        colonnes_data[statut_clean].append({
            "id": id_c, 
            "nom": nom_c, 
            "poste": poste_c, 
            "categorie": cat_c if cat_c else "Profil Confirmé",
            "score": score_c if score_c else "100%"
        })

    # 3. Génération de l'affichage en 3 colonnes
    col_kanban1, col_kanban2, col_kanban3 = st.columns(3)
    cols_streamlit = [col_kanban1, col_kanban2, col_kanban3]

    for i, statut in enumerate(statuts_kanban):
        with cols_streamlit[i]:
            nb_candidats = len(colonnes_data[statut])
            st.markdown(f'<div class="kanban-header">📌 {statut} ({nb_candidats})</div>', unsafe_allow_html=True)
            
            if nb_candidats == 0:
                st.caption("Aucun profil à ce stade.")
            
            for candidat in colonnes_data[statut]:
                # Structure HTML de la fiche talent
                st.markdown(f"""
                    <div class="kanban-card">
                        <div class="card-title">👤 {candidat['nom']}</div>
                        <div class="card-subtitle">💼 {candidat['poste']}</div>
                        <div style="font-size: 0.8rem; color: #fbbf24;">🎯 Match : {candidat['score']}</div>
                        <div class="card-badge">🏷️ {candidat['categorie']}</div>
                    </div>
                """, unsafe_allow_html=True)
                
                # Sélecteur discret pour modifier l'état et déplacer la carte
                nouveau_statut = st.selectbox(
                    "Déplacer :",
                    statuts_kanban,
                    index=statuts_kanban.index(statut),
                    key=f"move_id_{candidat['id']}",
                    label_visibility="collapsed"
                )
                
                # Mise à jour immédiate en BDD en cas de changement
                if nouveau_statut != statut:
                    try:
                        c.execute("UPDATE candidats SET statut = %s WHERE id = %s", (nouveau_statut, candidat['id']))
                        conn.commit()
                        st.success(f"🔄 {candidat['nom']} mis à jour.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Erreur lors du déplacement : {e}")
                
                st.markdown("<div style='margin-bottom: 15px;'></div>", unsafe_allow_html=True)                   
                    
# --- ONGLET 5 : SOURCING EXTERNE ---
elif st.session_state['page_active'] == "🏹 SOURCING EXTERNE & CHASSE":
    st.title("🏹 SOURCING EXTERNE & CHASSE")
    
    # 1. Liens vers les Jobboards Partenaires (Haut de page)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.link_button("🌐 France Travail Recruteur", "https://www.francetravail.fr/region/grand-est/employeur.html/", use_container_width=True)
        st.link_button("🎯 Indeed Entreprises", "https://www.indeed.com/hire", use_container_width=True)
    with col2:
        st.link_button("💼 HelloWork Recruteur", "https://compte.hellowork.com/", use_container_width=True)
        st.link_button("🌤️ Meteojob Recruteur", "https://contact.meteojob.com/", use_container_width=True)
    with col3:
        st.link_button("🎓 Apec Recruteur", "https://www.apec.fr/recruteur.html", use_container_width=True)
        st.link_button("👹 Monster Employeurs", "https://www.monster.fr/recruter/", use_container_width=True)

    st.write("---")
    
    # 2. Formulaire de Chasse Directe
    st.markdown("### 🔍 Chasse Directe par IA (LinkedIn, Facebook, Indeed & Web)")
    poste_recherche = st.text_input("Poste recherché :", value=st.session_state.get('recherche_bool_initiale', ''))
    ville_recherche = st.text_input("Localisation :", value=st.session_state.get('sourcing_ville_cible', ''))
    mots_cles = st.text_input("Mots-clés (séparés par des virgules) :")
    
    # Bouton IA optionnel pour affiner la chaîne booléenne si besoin
    if st.button("🧠 GÉNERER CHAÎNE BOOLÉENNE PAR IA", use_container_width=True):
        if not peut_utiliser_ia(st.session_state.get("user_email")):
            st.error("⚠️ Vous avez atteint votre quota mensuel de 300 requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
        else:
            try:
                model = genai.GenerativeModel("gemini-2.5-flash")
                prompt_bool = f"Génère une chaîne de recherche booléenne optimisée pour Google X-Ray pour le poste '{poste_recherche}' à '{ville_recherche}' avec ces mots clés '{mots_cles}'."
                resp_bool = model.generate_content(prompt_bool)
                st.session_state["chaine_booleenne_ia"] = resp_bool.text
                
                # Décompte du quota (+1)
                incrémenter_quota_ia(st.session_state.get("user_email"))
            except Exception as e:
                st.error(f"Erreur IA : {e}")

    if "chaine_booleenne_ia" in st.session_state:
        st.info(f"💡 Suggestion d'optimisation IA : {st.session_state['chaine_booleenne_ia']}")

    # 3. Traitement et Génération des URLs
    if poste_recherche:
        poste_nettoye = poste_recherche.replace("/", " ").replace("(", "").replace(")", "").strip()
        loc_str = f'"{ville_recherche.strip()}"' if ville_recherche else ''
        
        # --- 1. REQUÊTE LINKEDIN ---
        criteres_li = f'"{poste_nettoye}"'
        if loc_str: 
            criteres_li += f' {loc_str}'
        if mots_cles:
            mots_cles_propres = mots_cles.replace(",", " ").strip()
            criteres_li += f' {mots_cles_propres}'
            
        query_linkedin = f'site:linkedin.com/in/ {criteres_li} -inurl:jobs -inurl:careers'
        url_linkedin = f"https://www.google.com/search?q={urllib.parse.quote(query_linkedin)}"

        # --- 2. REQUÊTE FACEBOOK (Groupes & Candidats) ---
        query_facebook = f'site:facebook.com/groups "{poste_nettoye}" {loc_str} ("cv" OR "cherche" OR "recherche") -inurl:jobs'
        url_facebook = f"https://www.google.com/search?q={urllib.parse.quote(query_facebook)}"

        # --- 3. REQUÊTE CVTHÈQUES OUVERTES & PDF (DoYouBuzz + PDF Web) ---
        query_cv_web = f'(site:doyoubuzz.com OR filetype:pdf) "{poste_nettoye}" {loc_str} "CV" -inurl:jobs -intitle:offre'
        url_cv_web = f"https://www.google.com/search?q={urllib.parse.quote(query_cv_web)}"
        
 # 4. Affichage des 3 Boutons d'Action
        st.write("") 
        col_btn1, col_btn2, col_btn3 = st.columns(3)
        
        with col_btn1:
            st.link_button("🌐 LINKEDIN (Profils)", url_linkedin, use_container_width=True, type="primary")
        with col_btn2:
            st.link_button("👥 FACEBOOK (Groupes Emploi)", url_facebook, use_container_width=True, type="secondary")
        with col_btn3:
            st.link_button("📄 CV WEB & DOYOUBUZZ (PDF)", url_cv_web, use_container_width=True)

# --- 📋 ONGLET : GESTION ADMINISTRATIVE & RH ---
elif st.session_state['page_active'] == "📋 GESTION ADMINISTRATIVE & RH":
    st.title("📋 GESTION ADMINISTRATIVE & CONTRATS")
    st.subheader("Pilotage RH, Suivi des Obligations Légales & Heures")
    
    # Injection CSS pour rendre les onglets internes ultra lisibles
    st.markdown("""
        <style>
            button[data-baseweb="tab"] {
                font-size: 18px !important;
                font-weight: bold !important;
                color: #cbd5e0 !important;
            }
            button[data-baseweb="tab"][aria-selected="true"] {
                color: #ff9800 !important;
                border-bottom-color: #ff9800 !important;
            }
        </style>
    """, unsafe_allow_html=True)
    
    # Barre d'onglets internes
    ss_onglet1, ss_onglet2, ss_onglet3 = st.tabs([
        "📄 Édition de Contrat & CCN", 
        "🩺 Suivi Médecine du Travail", 
        "⏱️ Relevés d'Heures Intérimaires"
    ])
    
    # Récupération dynamique globale des candidats et entreprises
    try:
        c.execute("SELECT nom, poste FROM candidats")
        candidats_bruts = c.fetchall()
        list_cand = [f"{row[0]} ({row[1]})" for row in candidats_bruts]
        noms_purs_candidats = [row[0] for row in candidats_bruts]
        
        c.execute("SELECT meta_entreprise FROM contrats LIMIT 1")  # Vérification colonne
        entreprise_col = "meta_entreprise"
    except Exception:
        entreprise_col = "entreprise_nom"

    try:
        c.execute("SELECT entreprise FROM clients")
        list_cli = [row[0] for row in c.fetchall()]
    except Exception:
        list_cli = []
        
    # ==============================================================================
    # SOUS-ONGLET 1 : ÉDITION DE CONTRAT & CCN (VERSION SÉCURISÉE)
    # ==============================================================================
    with ss_onglet1:
        st.markdown('<h3 style="color: white; margin-top: 10px;">📝 Génération Assistée du Contrat de Travail</h3>', unsafe_allow_html=True)
        
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            nom_salarie = st.selectbox("Sélectionner le salarié / intérimaire :", ["-- Choisir un profil --"] + list_cand, key="rh_salarie")
            type_ct = st.selectbox("Type de contrat :", ["CDI", "CDD", "CTT (Intérim)", "Alternance / Apprentissage"])
            date_embauche = st.date_input("🗓️ Date de début de contrat / mission :", key="rh_date_debut")
        with col_c2:
            nom_employeur = st.selectbox("Sélectionner l'entreprise utilisatrice/cliente :", ["-- Choisir une entreprise --"] + list_cli, key="rh_client")
            date_fin_m = st.date_input("🗓️ Date de fin de contrat / mission (Estimée) :", key="rh_date_fin_mission")
            salaire_brut = st.number_input("Rémunération brute mensuelle en € :", min_value=0.0, step=50.0)
        
        col_c3, col_c4 = st.columns(2)
        with col_c3:
            saisie_poste = st.text_input("Intitulé exact du poste de travail :", value="", placeholder="Ex: Cuisinier, Livreur...")
        with col_c4:
            periode_essai = st.number_input("Période d'essai (en jours) :", min_value=0, max_value=30, value=5)
        
        statut_mission = st.checkbox("Activer immédiatement la mission", value=True, key="rh_sync_statut")
        
        if st.button("🚀 Générer le Contrat PDF Professionnel", type="primary", use_container_width=True):
            if nom_salarie == "-- Choisir un profil --" or nom_employeur == "-- Choisir une entreprise --":
                st.error("⚠️ Veuillez sélectionner un salarié et une entreprise.")
            elif not saisie_poste.strip():
                st.error("⚠️ Veuillez saisir un intitulé de poste.")
            else:
                from fpdf import FPDF
                from datetime import timedelta
                
                salarie_clean = nom_salarie.split("(")[0].strip()
                dt_limite = date_embauche + timedelta(days=90)
                ccn_detectee = "Convention Collective Nationale de la Restauration Collective (IDCC 1266)" if any(x in saisie_poste.lower() for x in ["cuisinier", "chef", "restauration"]) else "Convention Collective Nationale applicable"
                
                # Enregistrement en base
                c.execute(f"INSERT INTO contrats (candidat_nom, {entreprise_col}, type_contrat, poste, date_debut, date_fin, convention_collective, date_limite_medecine) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                          (salarie_clean, nom_employeur, type_ct, saisie_poste, date_embauche.strftime('%Y-%m-%d'), date_fin_m.strftime('%Y-%m-%d'), ccn_detectee, dt_limite.strftime('%Y-%m-%d')))
                id_nouveau_contrat = c.fetchone()[0]
                c.execute("UPDATE candidats SET statut = %s, poste = %s WHERE nom = %s", ("En mission", saisie_poste, salarie_clean))
                conn.commit()

                # --- Veille réglementaire proactive : suggestion générée automatiquement,
                # stockée à part, JAMAIS injectée dans les notes officielles sans validation
                # humaine explicite (voir onglet Suivi Médecine du Travail).
                suggestion_med = generer_suggestion_medecine(saisie_poste)
                if suggestion_med:
                    c.execute("UPDATE contrats SET suggestion_ia_medecine = %s WHERE id = %s", (suggestion_med, id_nouveau_contrat))
                    conn.commit()

                # Création du PDF pro complet
                pdf = FPDF()
                pdf.add_page()
                
                # Titre
                pdf.set_font("Helvetica", 'B', 16)
                pdf.cell(0, 10, f"CONTRAT DE TRAVAIL {type_ct}", ln=True, align='C')
                pdf.ln(10)
                
                # Corps du texte structuré
                pdf.set_font("Helvetica", '', 11)
                contenu = f"""
Entre la société {nom_employeur} et M. {salarie_clean},

1. NATURE DU CONTRAT
Le présent contrat est conclu en tant que {type_ct}.

2. FONCTIONS ET LIEU DE TRAVAIL
Le salarié est engagé en qualité de {saisie_poste.upper()}. 
Il exercera ses fonctions sous la responsabilité de la direction.

3. DUREE ET REMUNERATION
Le contrat débute le {date_embauche.strftime('%d/%m/%Y')} et prendra fin le {date_fin_m.strftime('%d/%m/%Y')}.
La rémunération brute mensuelle est fixée à {salaire_brut:.2f} Euros.

4. PERIODE D'ESSAI
Le contrat prévoit une période d'essai de {periode_essai} jours.

5. DISPOSITIONS LEGALES
Le salarié déclare avoir pris connaissance des dispositions de la {ccn_detectee}.

Fait à Béziers, le {date_embauche.strftime('%d/%m/%Y')}.
Signature de l'employeur                 Signature du salarié
                """
                pdf.multi_cell(0, 7, contenu)
                
                # Conversion propre pour Streamlit
                pdf_data = pdf.output(dest='S')
                final_bytes = bytes(pdf_data) if isinstance(pdf_data, (bytearray, bytes)) else pdf_data.encode('latin-1')

                st.download_button(
                    label="📥 Télécharger le Contrat PDF officiel",
                    data=final_bytes,
                    file_name=f"Contrat_{salarie_clean}.pdf",
                    mime="application/pdf"
                )
                st.success("✅ Contrat enregistré et PDF généré !")

    # ====================================================
    # SOUS-ONGLET 2 : SUIVI MÉDECINE DU TRAVAIL
    # ====================================================
    with ss_onglet2:
        st.markdown('<h3 style="color: white; margin-top: 10px;">🩺 Registre Interactif de la Médecine du Travail</h3>', unsafe_allow_html=True)
        
        candidat_selectionne_filtre = st.selectbox(
            "🔍 Filtrer par candidat du vivier :", 
            ["-- Sélectionner un candidat pour afficher son dossier --"] + noms_purs_candidats, 
            key="filtre_rh_medical"
        )
        
        if candidat_selectionne_filtre == "-- Sélectionner un candidat pour afficher son dossier --":
            st.info("💡 Le tableau est actuellement vide. Veuillez sélectionner un candidat ci-dessus pour consulter ou modifier ses obligations médicales.")
        else:
            try:
                df_contrats = pd.read_sql_query(f"""
                    SELECT id, candidat_nom, {entreprise_col}, date_debut, date_fin, date_limite_medecine, statut_medecine, suivi_medical_notes, suggestion_ia_medecine 
                    FROM contrats 
                    WHERE candidat_nom = '{candidat_selectionne_filtre.replace("'", "''")}'
                """, conn)
                
                if not df_contrats.empty:
                    # --- Suggestions générées automatiquement à la création du contrat :
                    # jamais injectées seules, toujours soumises à validation humaine ici.
                    for _, ligne_sugg in df_contrats.iterrows():
                        if ligne_sugg.get("suggestion_ia_medecine"):
                            st.warning(f"🤖 **Suggestion IA non validée** générée à la création du contrat de {ligne_sugg['candidat_nom']} :")
                            st.markdown(ligne_sugg["suggestion_ia_medecine"])
                            col_valid_sugg, col_reject_sugg = st.columns(2)
                            with col_valid_sugg:
                                if st.button("✅ Valider et injecter dans les notes officielles", key=f"valider_sugg_{ligne_sugg['id']}", use_container_width=True):
                                    notes_actuelles = ligne_sugg.get("suivi_medical_notes") or ""
                                    nouvelles_notes_validees = f"{notes_actuelles}\n- [IA - validé par un humain] {ligne_sugg['suggestion_ia_medecine']}".strip()
                                    c.execute("UPDATE contrats SET suivi_medical_notes = %s, suggestion_ia_medecine = NULL WHERE id = %s", (nouvelles_notes_validees, int(ligne_sugg["id"])))
                                    conn.commit()
                                    st.rerun()
                            with col_reject_sugg:
                                if st.button("❌ Rejeter cette suggestion", key=f"rejeter_sugg_{ligne_sugg['id']}", use_container_width=True):
                                    c.execute("UPDATE contrats SET suggestion_ia_medecine = NULL WHERE id = %s", (int(ligne_sugg["id"]),))
                                    conn.commit()
                                    st.rerun()
                            st.markdown("---")

                    df_contrats = df_contrats.drop(columns=["suggestion_ia_medecine"])
                    df_contrats.columns = ["id", "Salarié", "Entreprise", "Début Mission", "Fin Mission", "Date Limite Visite", "Statut Visite", "Notes Médicales / Commentaires"]
                    
                    st.markdown('<p style="color: #cbd5e0; font-size: 0.9rem; margin-top: 10px;">💡 double-cliquez dans les cases ci-dessous pour éditer les notes, ajuster les périodes et sauvegarder.</p>', unsafe_allow_html=True)
                    
                    editor_key = f"editor_{candidat_selectionne_filtre.replace(' ', '_')}"
                    
                    edited_df = st.data_editor(
                        df_contrats,
                        use_container_width=True,
                        hide_index=True,
                        disabled=["id", "Salarié", "Entreprise"],
                        key=editor_key
                    )
                    
                    col_actions_1, col_actions_2 = st.columns(2)
                    
                    with col_actions_1:
                        if st.button("💾 Enregistrer les modifications", use_container_width=True, type="primary"):
                            for index, row in edited_df.iterrows():
                                c.execute("""
                                    UPDATE contrats 
                                    SET date_debut = %s, date_fin = %s, date_limite_medecine = %s, statut_medecine = %s, suivi_medical_notes = %s
                                    WHERE id = %s
                                """, (row["Début Mission"], row["Fin Mission"], row["Date Limite Visite"], row["Statut Visite"], row["Notes Médicales / Commentaires"], int(row["id"])))
                            conn.commit()
                            st.success("✅ Modifications enregistrées avec succès !")
                            time.sleep(1.0)
                            st.rerun()
                            
                    with col_actions_2:
                        if st.button("🗑️ Réinitialiser & Vider le tableau", use_container_width=True, type="secondary"):
                            c.execute("DELETE FROM contrats WHERE candidat_nom = %s", (candidat_selectionne_filtre,))
                            c.execute("UPDATE candidats SET statut = 'Disponible' WHERE nom = %s", (candidat_selectionne_filtre,))
                            conn.commit()
                            
                            if editor_key in st.session_state:
                                del st.session_state[editor_key]
                            if f"{editor_key}__output" in st.session_state:
                                del st.session_state[f"{editor_key}__output"]
                                
                            st.success("✅ Le tableau a été complètement réinitialisé et vidé !")
                            time.sleep(1.0)
                            st.rerun()
                            
                    st.markdown("---")
                    st.markdown("##### 🤖 Assistant d'Analyse Réglementaire (Gemini)")
                    
                    if st.button("🧠 Interroger Gemini sur les risques du poste", use_container_width=True):
                        # Vérification Quota IA
                        if not peut_utiliser_ia(st.session_state.get("user_email")):
                            st.error("⚠️ Vous avez atteint votre quota mensuel de 300 requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
                        else:
                            c.execute("SELECT poste FROM candidats WHERE nom = %s", (candidat_selectionne_filtre,))
                            p_res = c.fetchone()
                            poste_contexte = p_res[0] if p_res else "Général"
                            
                            with st.spinner("Analyse réglementaire en cours..."):
                                try:
                                    model = genai.GenerativeModel("gemini-2.5-flash")
                                    prompt_med = f"Donne sous forme de puces courtes les 2 principales obligations de sécurité/EPI pour un poste de {poste_contexte}."
                                    response_med = model.generate_content(prompt_med)
                                    st.session_state["proposition_ia_med"] = response_med.text
                                    
                                    # Décompte Quota IA
                                    incrémenter_quota_ia(st.session_state.get("user_email"))
                                except Exception as e:
                                    st.error(f"Erreur IA : {e}")

                    if "proposition_ia_med" in st.session_state:
                        st.warning("⚠️ **Proposition Gemini générée :**")
                        st.markdown(st.session_state["proposition_ia_med"])
                        if st.button("✅ Injecter directement cette proposition dans le tableau", type="secondary", use_container_width=True):
                            id_actuel = int(df_contrats["id"].iloc[0])
                            current_notes = df_contrats["Notes Médicales / Commentaires"].iloc[0]
                            current_notes = current_notes if current_notes else ""
                            nouvelles_notes = f"{current_notes}\n- [IA] {st.session_state['proposition_ia_med']}".strip()
                            
                            c.execute("UPDATE contrats SET suivi_medical_notes = %s WHERE id = %s", (nouvelles_notes, id_actuel))
                            conn.commit()
                            
                            if editor_key in st.session_state:
                                del st.session_state[editor_key]
                            del st.session_state["proposition_ia_med"]
                            st.rerun()
                else:
                    st.warning(f"⚠️ Aucun dossier actif ou contrat trouvé pour {candidat_selectionne_filtre} (Statut actuel : Disponible). Le tableau reste donc vide.")
            except Exception as e:
                st.error(f"Erreur d'affichage de la grille : {e}")

    # ====================================================
    # SOUS-ONGLET 3 : RELEVÉS D'HEURES INTÉRIMAIRES
    # ====================================================
    with ss_onglet3:
        st.markdown('<h3 style="color: white; margin-top: 10px;">⏱️ Saisie et Calcul de la Modulation des Heures</h3>', unsafe_allow_html=True)
        
        col_h1, col_h2, col_h3 = st.columns(3)
        with col_h1:
            salarie_h = st.selectbox("Intérimaire concerné :", ["-- Choisir --"] + [c.split(" (")[0] for c in list_cand], key="h_salarie_unique")
            semaine_h = st.text_input("Semaine de mission :", placeholder="Ex: S27 - 2026", key="h_semaine_unique")
        with col_h2:
            h_normales = st.number_input("Heures normales effectuées (Base 35h) :", min_value=0.0, max_value=35.0, value=35.0, key="h_norm_unique")
            h_25 = st.number_input("Heures supplémentaires à 25% :", min_value=0.0, value=0.0, key="h_25_unique")
        with col_h3:
            nom_ent_h = st.selectbox("Entreprise utilisatrice :", ["-- Choisir --"] + list_cli, key="h_client_unique")
            h_50 = st.number_input("Heures supplémentaires à 50% :", min_value=0.0, value=0.0, key="h_50_unique")
            
        if st.button("📊 Valider le relevé d'heures", type="primary", use_container_width=True, key="btn_heures_unique"):
            if salarie_h == "-- Choisir --" or nom_ent_h == "-- Choisir --" or not semaine_h:
                st.error("⚠️ Saisie incomplète pour le relevé d'heures.")
            else:
                try:
                    c.execute("""
                        INSERT INTO suivi_heures (candidat_nom, entreprise_nom, semaine, heures_normales, heures_sup_25, heures_sup_50) 
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (salarie_h, nom_ent_h, semaine_h, h_normales, h_25, h_50))
                    conn.commit()
                    heures_totales = h_normales + h_25 + h_50
                    st.success(f"✅ Relevé enregistré pour {salarie_h} ({semaine_h}) : Total {heures_totales} h.")
                    time.sleep(1.2)
                    st.rerun()
                except Exception as e:
                    st.error(f"Erreur enregistrement heures : {e}")
