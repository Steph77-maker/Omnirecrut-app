
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
import sqlite3
import time
import urllib.parse
from fpdf import FPDF
import google.generativeai as genai
import pandas as pd
from pypdf import PdfReader
import streamlit as st

# --- CONFIGURATION DU THÈME VISUEL (DOIT ÊTRE AU TOUT DÉBUT) ---
st.set_page_config(
    page_title="OmniRecrut IA", layout="wide", initial_sidebar_state="expanded"
)

st.markdown(
    """
    <style>
    .stTextInput>div>div>input, .stTextArea>div>div>textarea { 
        color: #ffffff !important; 
    }
    textarea, input {
        color: #ffffff !important;
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
        conn_q = sqlite3.connect("recrutement_ia.db", check_same_thread=False)
        c_q = conn_q.cursor()
        c_q.execute("SELECT nb_requetes_ia, quota_max, statut_abonnement FROM utilisateurs WHERE email = ?", (email_utilisateur,))
        res = c_q.fetchone()
        conn_q.close()
        
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
            conn_q = sqlite3.connect("recrutement_ia.db", check_same_thread=False)
            c_q = conn_q.cursor()
            c_q.execute("UPDATE utilisateurs SET nb_requetes_ia = COALESCE(nb_requetes_ia, 0) + 1 WHERE email = ?", (email_utilisateur,))
            conn_q.commit()
            conn_q.close()
        except Exception:
            pass

def reinitialiser_quota_ia(email_utilisateur):
    """Remet le compteur de requêtes IA d'un utilisateur à 0."""
    try:
        conn_q = sqlite3.connect("recrutement_ia.db", check_same_thread=False)
        c_q = conn_q.cursor()
        c_q.execute("UPDATE utilisateurs SET nb_requetes_ia = 0 WHERE email = ?", (email_utilisateur,))
        conn_q.commit()
        conn_q.close()
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
        conn_auth = sqlite3.connect("recrutement_ia.db", check_same_thread=False)
        c_auth = conn_auth.cursor()
        c_auth.execute("""CREATE TABLE IF NOT EXISTS utilisateurs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            mdp_admin = st.secrets.get("APP_PASSWORD", "Yamsteph2212")
            default_mail = st.secrets.get("EMAIL_USER", "")
            default_pwd = st.secrets.get("EMAIL_PASSWORD", "")
            default_imap = st.secrets.get("EMAIL_IMAP", "imap.gmail.com")
            c_auth.execute(
                """INSERT INTO utilisateurs (email, password, date_fin_essai, est_admin, mail_perso, mail_password, mail_imap, nb_requetes_ia, quota_max, statut_abonnement) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "admin@omnirecrut.fr",
                    mdp_admin,
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
        conn_auth.close()
    except Exception as e:
        st.error(f"Erreur d'initialisation du système d'authentification : {e}")

 # Style CSS écran de connexion
    st.markdown(
        """
        <style>
        .stApp { background-color: #1a202c; color: #e2e8f0; }
        label, [data-testid="stWidgetLabel"] p { color: #ffffff !important; font-weight: 600 !important; }
        .stTextInput>div>div>input { background-color: #2d3748 !important; color: #e2e8f0 !important; border: 1px solid #4a5568 !important; }
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
                        conn_chk = sqlite3.connect("recrutement_ia.db")
                        c_chk = conn_chk.cursor()
                        c_chk.execute(
                            "SELECT password, date_fin_essai, est_admin, mail_perso,"
                            " mail_password, mail_imap, statut_abonnement FROM utilisateurs WHERE email = ?",
                            (email_saisi,),
                        )
                        res = c_chk.fetchone()
                        conn_chk.close()

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
                            if pwd_saisi == db_password:
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
# 1. CONNEXION ET INITIALISATION DE LA BASE DE DONNÉES SQLite (définition de c)
# ==============================================================================
conn = sqlite3.connect(
    "recrutement_ia.db", check_same_thread=False, timeout=30, isolation_level=None
)
c = conn.cursor()
c.execute("PRAGMA journal_mode=WAL;")

c.execute("""CREATE TABLE IF NOT EXISTS candidats 
             (id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT, poste TEXT, competences TEXT, 
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

c.execute("""CREATE TABLE IF NOT EXISTS clients 
             (id INTEGER PRIMARY KEY AUTOINCREMENT, entreprise TEXT, secteur TEXT, contact TEXT, 
             secteur_activite TEXT DEFAULT 'Non spécifié', tel TEXT, email TEXT, priorite TEXT, notes TEXT)""")

try:
    c.execute("SELECT secteur_geo FROM clients LIMIT 1")
except sqlite3.OperationalError:
    try:
        c.execute("ALTER TABLE clients ADD COLUMN secteur_geo TEXT DEFAULT 'Béziers'")
    except sqlite3.OperationalError:
        pass

# ==============================================================================
# 2. GESTION DU RETOUR DE PAIEMENT STRIPE (REDIRECTION DÉTECTÉE)
# ==============================================================================
query_params = st.query_params
if query_params.get("payment") == "success":
    user_email = st.session_state.get("user_email")
    if user_email:
        c.execute("UPDATE utilisateurs SET statut_abonnement = 'PRO', quota_max = 999999 WHERE email = ?", (user_email,))
        st.session_state['user_statut'] = 'PRO'
        st.balloons()
        st.success("🎉 Félicitations ! Votre abonnement PRO Illimité est actif.")
        st.query_params.clear()

# ==============================================================================
# 3. PANNEAU LATÉRAL (SIDEBAR) : QUOTAS & BOUTON STRIPE
# ==============================================================================
with st.sidebar:
    st.markdown("<h3 style='color: #ffffff !important;'>⚙️ Mon Compte</h3>", unsafe_allow_html=True)
    user_email = st.session_state.get("user_email", "")
    
    # Récupération de l'état du quota et du statut
    c.execute("SELECT nb_requetes_ia, quota_max, statut_abonnement FROM utilisateurs WHERE email = ?", (user_email,))
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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

c.execute("""CREATE TABLE IF NOT EXISTS suivi_heures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    .stTextInput>div>div>input, .stTextArea>div>div>textarea, .stSelectbox>div>div>div { background-color: #2d3748 !important; color: #e2e8f0 !important; border: 1px solid #4a5568 !important; }
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
      conn_u = sqlite3.connect("recrutement_ia.db")
      c_u = conn_u.cursor()
      c_u.execute(
          """UPDATE utilisateurs 
                         SET mail_perso = ?, mail_password = ?, mail_imap = ? 
                         WHERE email = ?""",
          (
              email_utilisateur,
              password_email,
              serveur_imap,
              st.session_state["user_email"],
          ),
      )
      conn_u.commit()
      conn_u.close()

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
                        conn_add = sqlite3.connect("recrutement_ia.db")
                        c_add = conn_add.cursor()
                        c_add.execute(
                            """INSERT INTO utilisateurs (email, password, date_fin_essai, est_admin, nb_requetes_ia)
                               VALUES (?, ?, ?, 0, 0)""",
                            (p_email, p_pwd, date_fin_calc),
                        )
                        conn_add.commit()
                        conn_add.close()
                        st.success(
                            f"Accès créé pour {p_email} jusqu'au"
                            f" {datetime.date.fromisoformat(date_fin_calc).strftime('%d/%m/%Y')} !"
                        )
                    except sqlite3.IntegrityError:
                        st.error("Cet e-mail possède déjà un compte.")
                    except Exception as e_adm:
                        st.error(f"Erreur : {e_adm}")
                else:
                    st.error("Champs manquants.")

    # --- 2. SOUS-MENU : SUIVI & RÉINITIALISATION DES QUOTAS IA ---
    with st.sidebar.expander("📊 Quotas IA & Remise à 0"):
        try:
            conn_q = sqlite3.connect("recrutement_ia.db")
            c_q = conn_q.cursor()
            c_q.execute("SELECT email, COALESCE(nb_requetes_ia, 0) FROM utilisateurs WHERE est_admin = 0")
            prospects_data = c_q.fetchall()
            conn_q.close()

            if prospects_data:
                # Affichage de la consommation de chaque prospect
                for email_p, nb_p in prospects_data:
                    st.caption(f"👤 **{email_p}** : {nb_p} / {LIMITE_REQUETES_IA} requêtes")

                st.markdown("---")
                
                # Formulaire de réinitialisation
                liste_emails = [p[0] for p in prospects_data]
                target_user = st.selectbox("Réinitialiser l'utilisateur :", liste_emails, key="sb_reset_quota_sb")
                
                if st.button("🔄 Remettre le quota à 0", key="btn_reset_quota_sb"):
                    conn_res = sqlite3.connect("recrutement_ia.db")
                    c_res = conn_res.cursor()
                    c_res.execute("UPDATE utilisateurs SET nb_requetes_ia = 0 WHERE email = ?", (target_user,))
                    conn_res.commit()
                    conn_res.close()
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
            conn_del_list = sqlite3.connect("recrutement_ia.db")
            c_dl = conn_del_list.cursor()
            c_dl.execute("SELECT email FROM utilisateurs WHERE est_admin = 0")
            prospects_suppr = [row[0] for row in c_dl.fetchall()]
            conn_del_list.close()

            if prospects_suppr:
                user_a_supprimer = st.selectbox("Choisir le prospect à supprimer :", prospects_suppr, key="sb_delete_user")
                
                if st.button("🗑️ Supprimer définitivement", key="btn_confirm_delete", type="primary"):
                    conn_del = sqlite3.connect("recrutement_ia.db")
                    c_d = conn_del.cursor()
                    c_d.execute("DELETE FROM utilisateurs WHERE email = ?", (user_a_supprimer,))
                    conn_del.commit()
                    conn_del.close()
                    st.success(f"Le prospect {user_a_supprimer} a été supprimé.")
                    st.rerun()
            else:
                st.info("Aucun prospect à supprimer.")
        except Exception as e_del:
            st.error(f"Erreur lors de la suppression : {e_del}")

options_menu = [
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

# --- ONGLET 1 : CONSULTATION DU VIVIER ---
if st.session_state['page_active'] == "🗃️ VIVIER DE CANDIDATS":
    st.header("🗃️ Gestion et Pilotage du Vivier Interne")
    
    try:
        c.execute("PRAGMA table_info(candidats)")
        colonnes_existantes = [info[1] for info in c.fetchall()]
        
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

                # Affichage du data_editor avec des largeurs maîtrisées pour éviter le scroll infini
                edited_df = st.data_editor(
                    df_vivier.drop(columns=["Email_Brut", "Score Match"]), 
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
                        "Avis IA": st.column_config.TextColumn("Avis IA 🤖", disabled=True, width="medium"),
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
                                c.execute(f"UPDATE candidats SET {nom_colonne_sql} = ? WHERE id = ?", (nouvelle_valeur, id_candidat))
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
                    
                    with col_bouton_urssaf:
                        if statut_actuel == "En mission":
                            st.link_button("📝 Faire la DPAE (URSSAF)", url="https://www.declaration.urssaf.fr/", use_container_width=True, type="primary")
                        else:
                            st.link_button("🌐 Accéder à l'URSSAF", url="https://www.declaration.urssaf.fr/", use_container_width=True)
                    
                    # --- ZONE DE SUPPRESSION (ÉPURÉE) ---
                    confirmer_suppression = st.checkbox(f"Je confirme vouloir supprimer définitivement {candidat_selectionne} de la base", key=f"conf_del_{id_selectionne}")
                    if st.button(f"❌ Supprimer le candidat", type="primary", disabled=not confirmer_suppression, use_container_width=True):
                        try:
                            c.execute("DELETE FROM candidats WHERE id = ?", (id_selectionne,))
                            conn.commit()
                            st.success(f"Le candidat {candidat_selectionne} a été supprimé.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erreur : {e}")
                    
                    st.markdown("### 🗓️ Gestion des Rendez-vous & Relances")
                    c.execute("SELECT type_rdv, date_rdv FROM candidats WHERE nom = ?", (candidat_selectionne,))
                    rdv_id = c.fetchone()
                    current_type_rdv = rdv_id[0] if rdv_id else None
                    current_date_rdv = rdv_id[1] if rdv_id else None

                    if current_type_rdv and current_date_rdv:
                        st.info(f"📅 **RDV Planifié : {current_type_rdv}** prévu le `{current_date_rdv}`")
                        if st.button("🗑️ Annuler / Supprimer le RDV", type="primary", use_container_width=True):
                            c.execute("UPDATE candidats SET type_rdv = NULL, date_rdv = NULL WHERE nom = ?", (candidat_selectionne,))
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
                            c.execute("UPDATE candidats SET type_rdv = ?, date_rdv = ? WHERE nom = ?", (type_rdv, datetime_rdv, candidat_selectionne))
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
                    Tu es un Expert Recruteur et Chasseur de Têtes. Analyse ce CV par rapport à la fiche de poste fournis.
                    
                    CONSIGNES CLÉS :
                    1. Ne te limite pas à la recherche stricte de mots-clés.
                    2. Analyse la trajectoire, la cohérence du parcours et le potentiel du candidat.
                    3. Détecte les compétences transférables et transversales (soft skills, organisation, relation client, gestion du stress, rigueur) acquises dans d'autres secteurs.
                    
                    Renvoie STRICTEMENT un objet JSON valide avec les clés suivantes :
                    - 'nom': Prénom et Nom du candidat (ou 'Inconnu')
                    - 'coordonnees': Téléphone et Email si présents
                    - 'competences': Résumé des compétences clés + compétences transférables détectées
                    - 'score': Un entier entre 0 et 100 reflétant l'adéquation globale (comprenant le potentiel et la transférabilité)
                    - 'justification': Synthèse de 3-4 lignes expliquant les points forts du profil, ses compétences transférables et pourquoi sa candidature est pertinente au-delà des simples mots-clés.

                    OFFRE :
                    {texte_offre}

                    CV :
                    {texte_cv}
                    """
                    
                    response = model.generate_content(prompt)
                    txt = response.text.strip().replace("```json", "").replace("```", "").strip()
                    data = json.loads(txt)
                    
                    resultats_matching.append({
                        "nom": data.get("nom", "Inconnu"), 
                        "coordonnees": data.get("coordonnees", "Non spécifié"),
                        "competences": data.get("competences", "Non spécifié"), 
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
        df_res = pd.DataFrame(st.session_state['derniers_matchs']).drop(columns=["cv_texte"], errors='ignore')
        st.dataframe(df_res, use_container_width=True)
        
    st.markdown("---")
    st.subheader("📥 Enregistrement ciblé dans le Vivier")
    secteur_pour_import = st.selectbox("Assigner ces candidats au secteur :", LISTE_SECTEURS[1:])
    
    if st.button("📥 CONFIRMER L'ENREGISTREMENT DANS LE VIVIER"):
        if not st.session_state['derniers_matchs']: st.warning("⚠️ Aucun résultat d'analyse en mémoire.")
        else:
            try:
                for cand in st.session_state['derniers_matchs']:
                    c.execute("""INSERT INTO candidats (nom, poste, competences, statut, categorie_ia, avis_ia, score_matching, secteur_metier, cv_texte) 
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                              (cand["nom"], "Profil Analysé", f"{cand['coordonnees']} | {cand['competences']}", "Nouveau", "À Classer", cand["justification"], f"{cand['score']} %", secteur_pour_import, cand.get("cv_texte", "")))
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
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
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
                """UPDATE clients SET entreprise=?, secteur=?, contact=?, tel=?, priorite=?, notes=? WHERE id=?""",
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
                "DELETE FROM clients WHERE entreprise = ?",
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
            c.execute("SELECT secteur FROM clients WHERE entreprise=?", (entreprise_cible,))
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
            besoin_details = st.text_area("Détails du poste recherchés :", height=150, key="details_match_text")
            
        with col_vivier:
            if st.button("🚀 LANCER LE MATCHING", type="primary", use_container_width=True):
                # 1. Vérification du quota IA
                if not peut_utiliser_ia(st.session_state.get("user_email")):
                    st.error("⚠️ Vous avez atteint votre quota mensuel de 300 requêtes IA. Contactez l'administrateur pour débloquer votre accès.")
                else:
                    c.execute("SELECT nom, poste, competences FROM candidats WHERE secteur_metier = ?", (secteur_besoin,))
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
            c.execute("SELECT poste, competences, cv_texte FROM candidats WHERE nom = ?", (candidat_pepite,))
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
                else: 
                    st.info("📬 Aucun nouveau message non lu avec pièce jointe PDF trouvé.")# --- 🤝 ONGLET : MATCHING & OPPORTUNITÉS (COMPLÉTÉ AVEC QUOTAS IA) ---
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
                    c.execute("SELECT nom, poste, competences FROM candidats WHERE secteur_metier = ?", (secteur_besoin,))
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
            c.execute("SELECT poste, competences, cv_texte FROM candidats WHERE nom = ?", (candidat_pepite,))
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
                        c.execute("UPDATE candidats SET statut = ? WHERE id = ?", (nouveau_statut, candidat['id']))
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
                c.execute(f"INSERT INTO contrats (candidat_nom, {entreprise_col}, type_contrat, poste, date_debut, date_fin, convention_collective, date_limite_medecine) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                          (salarie_clean, nom_employeur, type_ct, saisie_poste, date_embauche.strftime('%Y-%m-%d'), date_fin_m.strftime('%Y-%m-%d'), ccn_detectee, dt_limite.strftime('%Y-%m-%d')))
                c.execute("UPDATE candidats SET statut = ?, poste = ? WHERE nom = ?", ("En mission", saisie_poste, salarie_clean))
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
                    SELECT id, candidat_nom, {entreprise_col}, date_debut, date_fin, date_limite_medecine, statut_medecine, suivi_medical_notes 
                    FROM contrats 
                    WHERE candidat_nom = '{candidat_selectionne_filtre.replace("'", "''")}'
                """, conn)
                
                if not df_contrats.empty:
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
                                    SET date_debut = ?, date_fin = ?, date_limite_medecine = ?, statut_medecine = ?, suivi_medical_notes = ?
                                    WHERE id = ?
                                """, (row["Début Mission"], row["Fin Mission"], row["Date Limite Visite"], row["Statut Visite"], row["Notes Médicales / Commentaires"], int(row["id"])))
                            conn.commit()
                            st.success("✅ Modifications enregistrées avec succès !")
                            time.sleep(1.0)
                            st.rerun()
                            
                    with col_actions_2:
                        if st.button("🗑️ Réinitialiser & Vider le tableau", use_container_width=True, type="secondary"):
                            c.execute("DELETE FROM contrats WHERE candidat_nom = ?", (candidat_selectionne_filtre,))
                            c.execute("UPDATE candidats SET statut = 'Disponible' WHERE nom = ?", (candidat_selectionne_filtre,))
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
                            c.execute("SELECT poste FROM candidats WHERE nom = ?", (candidat_selectionne_filtre,))
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
                            
                            c.execute("UPDATE contrats SET suivi_medical_notes = ? WHERE id = ?", (nouvelles_notes, id_actuel))
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
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (salarie_h, nom_ent_h, semaine_h, h_normales, h_25, h_50))
                    conn.commit()
                    heures_totales = h_normales + h_25 + h_50
                    st.success(f"✅ Relevé enregistré pour {salarie_h} ({semaine_h}) : Total {heures_totales} h.")
                    time.sleep(1.2)
                    st.rerun()
                except Exception as e:
                    st.error(f"Erreur enregistrement heures : {e}")
