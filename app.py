import csv
import io

import streamlit as st

import database
from predictor import analyze_message, detect_warning_signs
from url_scanner import analyze_url


# ==========================================================
# PAGE CONFIGURATION
# ==========================================================

st.set_page_config(
    page_title="ScamShield AI | Smart Digital Protection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ==========================================================
# DESIGN SYSTEM  —  "Aurora Glass"
# Dark glass UI, moving aurora background, radar hero,
# count-up numbers, animated gauges, glowing borders.
# ==========================================================

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@500;600;700;800;900&family=DM+Sans:wght@400;500;600;700&display=swap');

/* ---------- animatable numbers (count-up + gauge fill) ---------- */
@property --n { syntax: '<integer>'; inherits: false; initial-value: 0; }
@property --p { syntax: '<number>';  inherits: false; initial-value: 0; }

:root {
    --bg: #070B22;
    --text: #C9D0F7;
    --muted: #8D97C9;
    --white: #FFFFFF;
    --cyan: #22E5D4;
    --violet: #8B5CF6;
    --blue: #4F7CFF;
    --pink: #FF5C8A;
    --amber: #FFB547;
    --mint: #2BE3A0;
    --glass: rgba(18, 25, 66, .62);
    --glass-line: rgba(255, 255, 255, .10);
}

/* ---------- PAGE + MOVING AURORA ---------- */

html, body, .stApp { font-family: 'DM Sans', sans-serif; }

.stApp {
    background: var(--bg);
    color: var(--text);
}

[data-testid="stAppViewContainer"],
[data-testid="stMain"],
[data-testid="stHeader"],
header[data-testid="stHeader"] {
    background: transparent !important;
}

.stApp::before {
    content: "";
    position: fixed; inset: -25%;
    z-index: 0; pointer-events: none;
    background:
        radial-gradient(40% 40% at 20% 25%, rgba(139, 92, 246, .40), transparent 70%),
        radial-gradient(35% 35% at 80% 20%, rgba(34, 229, 212, .28), transparent 70%),
        radial-gradient(38% 38% at 65% 85%, rgba(255, 92, 138, .26), transparent 70%),
        radial-gradient(30% 30% at 10% 90%, rgba(79, 124, 255, .30), transparent 70%);
    animation: aurora 26s ease-in-out infinite alternate;
}

.stApp::after {
    content: "";
    position: fixed; inset: 0;
    z-index: 0; pointer-events: none;
    opacity: .5;
    background-image:
        linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
    background-size: 52px 52px;
    -webkit-mask-image: radial-gradient(ellipse at 50% 30%, #000, transparent 75%);
    mask-image: radial-gradient(ellipse at 50% 30%, #000, transparent 75%);
}

@keyframes aurora {
    0%   { transform: translate(0, 0) rotate(0deg) scale(1); }
    50%  { transform: translate(4%, -3%) rotate(8deg) scale(1.12); }
    100% { transform: translate(-4%, 4%) rotate(-6deg) scale(1.05); }
}

.block-container {
    position: relative; z-index: 1;
    max-width: 1320px;
    padding-top: 1.6rem; padding-bottom: 3rem;
}

h1, h2, h3, h4 {
    font-family: 'Outfit', sans-serif !important;
    color: var(--white) !important;
    font-weight: 700 !important;
    letter-spacing: -.02em;
}
h2 { font-size: 1.95rem !important; }

p, li, .stMarkdown, [data-testid="stMarkdownContainer"] { color: var(--text); line-height: 1.7; }
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] * { color: var(--muted) !important; }
[data-testid="stWidgetLabel"], [data-testid="stWidgetLabel"] * { color: #AEB8EA !important; font-weight: 600; }
[data-testid="stCheckbox"] label, [data-testid="stCheckbox"] label * { color: var(--text) !important; }
[data-testid="stSpinner"] * { color: var(--cyan) !important; }
hr { border-color: rgba(255,255,255,.10) !important; }
footer { visibility: hidden; }
[data-testid="stSidebarCollapseButton"] *, [data-testid="stExpandSidebarButton"] * { color: #fff !important; }

/* ---------- SIDEBAR ---------- */

[data-testid="stSidebar"] {
    background: rgba(8, 12, 38, .82);
    backdrop-filter: blur(18px);
    border-right: 1px solid var(--glass-line);
}
[data-testid="stSidebar"] * { color: #D5DBFF; }

.brand { display: flex; align-items: center; gap: 12px; padding: 6px 0 2px; }
.brand-logo {
    width: 48px; height: 48px; border-radius: 15px;
    display: flex; align-items: center; justify-content: center; font-size: 25px;
    background: linear-gradient(135deg, var(--violet), var(--cyan));
    box-shadow: 0 0 28px rgba(34,229,212,.45);
    animation: breathe 3.4s ease-in-out infinite;
}
.brand-name { font-family: 'Outfit', sans-serif; font-size: 1.35rem; font-weight: 800; color: #fff !important; line-height: 1.1; }
.brand-tag { font-size: 12px; color: var(--muted) !important; }
.side-title { font-family: 'Outfit', sans-serif; font-weight: 600; font-size: 14px; color: #fff !important; margin: 4px 0 10px; }

.side-stat {
    display: flex; align-items: center; justify-content: space-between;
    padding: 11px 14px; margin-bottom: 8px; border-radius: 14px;
    background: rgba(255,255,255,.05); border: 1px solid var(--glass-line);
    transition: transform .25s ease, background .25s ease;
}
.side-stat:hover { transform: translateX(5px); background: rgba(255,255,255,.09); }
.side-stat span:first-child { font-size: 13px; color: #AEB8EA !important; }
.side-stat span:last-child { font-family: 'Outfit', sans-serif; font-weight: 700; font-size: 18px; color: #fff !important; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 8px; box-shadow: 0 0 10px currentColor; }

.live-dot {
    width: 9px; height: 9px; border-radius: 50%; background: var(--mint); display: inline-block;
    animation: pulse 1.8s infinite;
}

/* ---------- HERO ---------- */

.hero {
    position: relative; overflow: hidden;
    border-radius: 34px; padding: 58px 56px; margin-bottom: 20px;
    background: linear-gradient(135deg, rgba(25,33,92,.78), rgba(12,17,52,.78));
    border: 1px solid var(--glass-line);
    box-shadow: 0 30px 70px rgba(0,0,0,.45), inset 0 0 80px rgba(139,92,246,.10);
    animation: rise .9s cubic-bezier(.2,.8,.2,1) both;
}
.hero::before {
    content: ""; position: absolute; inset: -2px; border-radius: 34px; padding: 2px; pointer-events: none;
    background: conic-gradient(from var(--ang, 0deg), transparent 0 70%, var(--cyan), var(--violet), transparent);
    -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
    -webkit-mask-composite: xor; mask-composite: exclude;
    animation: borderspin 7s linear infinite;
}
@property --ang { syntax: '<angle>'; inherits: false; initial-value: 0deg; }
@keyframes borderspin { to { --ang: 360deg; } }

.hero-inner { position: relative; z-index: 2; display: flex; align-items: center; justify-content: space-between; gap: 34px; flex-wrap: wrap; }
.hero-text { max-width: 660px; }

.hero-pill {
    display: inline-flex; align-items: center; gap: 10px;
    padding: 8px 16px; border-radius: 40px; margin-bottom: 22px;
    background: rgba(34,229,212,.10); border: 1px solid rgba(34,229,212,.35);
    font-size: 13px; font-weight: 600; color: #A8FFF6;
}

.hero-title {
    font-family: 'Outfit', sans-serif;
    font-size: clamp(36px, 5.2vw, 68px); line-height: 1.05; font-weight: 900;
    letter-spacing: -.035em; color: #fff !important; margin: 0 !important;
}
.hero-title .grad {
    display: inline-block; max-width: 100%;
    background: linear-gradient(90deg, #7DF3E8, #B79BFF, #FF9DB8, #7DF3E8);
    background-size: 250% 100%;
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
    animation: flow 5s linear infinite;
}
.typer {
    display: inline-block; overflow: hidden; white-space: nowrap; vertical-align: bottom;
    max-width: 100%; width: 0;
    border-right: 4px solid var(--cyan);
    animation: typing 2.6s steps(20) .6s forwards, caret .8s step-end infinite;
}
@keyframes typing { to { width: 20.5ch; } }
@keyframes caret { 50% { border-color: transparent; } }
@keyframes flow { to { background-position: -250% 0; } }

.hero-desc { color: #B9C2F0 !important; font-size: 17px; line-height: 1.75; margin-top: 20px; max-width: 540px; }
.hero-chips { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 26px; }
.hero-chip {
    padding: 9px 15px; border-radius: 13px; font-size: 13px; font-weight: 600; color: #fff;
    background: rgba(255,255,255,.07); border: 1px solid var(--glass-line);
    transition: transform .25s ease, background .25s ease, border-color .25s ease;
}
.hero-chip:hover { transform: translateY(-4px); background: rgba(34,229,212,.16); border-color: rgba(34,229,212,.5); }

/* radar */
.radar { position: relative; width: 260px; height: 260px; flex-shrink: 0; border-radius: 50%; }
.radar .ring { position: absolute; border-radius: 50%; border: 1px solid rgba(34,229,212,.35); }
.radar .r1 { inset: 0; }
.radar .r2 { inset: 42px; border-color: rgba(139,92,246,.45); }
.radar .r3 { inset: 84px; border-color: rgba(34,229,212,.35); }
.radar .pulse-ring { position: absolute; inset: 84px; border-radius: 50%; border: 2px solid var(--cyan); animation: ripple 3.2s ease-out infinite; }
.radar .pulse-ring.two { animation-delay: 1.6s; }
.radar .sweep {
    position: absolute; inset: 0; border-radius: 50%;
    background: conic-gradient(from 0deg, rgba(34,229,212,.55), rgba(34,229,212,0) 28%, transparent 28%);
    animation: spin 4s linear infinite;
}
.radar .core {
    position: absolute; inset: 88px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center; font-size: 44px;
    background: rgba(255,255,255,.10); border: 1px solid rgba(255,255,255,.28);
    box-shadow: 0 0 50px rgba(34,229,212,.55);
    animation: breathe 3s ease-in-out infinite;
}
.blip { position: absolute; width: 10px; height: 10px; border-radius: 50%; background: var(--pink); box-shadow: 0 0 14px var(--pink); animation: blip 4s ease-in-out infinite; }
.blip.b1 { top: 28px; left: 170px; animation-delay: .4s; }
.blip.b2 { top: 170px; left: 40px; background: var(--amber); box-shadow: 0 0 14px var(--amber); animation-delay: 1.6s; }
.blip.b3 { top: 190px; left: 200px; animation-delay: 2.7s; }

/* floating particles */
.spark { position: absolute; bottom: -10px; width: 6px; height: 6px; border-radius: 50%; background: rgba(255,255,255,.7); opacity: 0; animation: floatup 9s linear infinite; }

/* ---------- TICKER ---------- */

.ticker {
    overflow: hidden; margin: 0 0 22px; padding: 13px 0; border-radius: 16px;
    background: var(--glass); border: 1px solid var(--glass-line);
    -webkit-mask-image: linear-gradient(90deg, transparent, #000 8%, #000 92%, transparent);
    mask-image: linear-gradient(90deg, transparent, #000 8%, #000 92%, transparent);
}
.ticker-track { display: flex; width: max-content; animation: marquee 32s linear infinite; }
.ticker:hover .ticker-track { animation-play-state: paused; }
.ticker-item { padding: 0 30px; font-size: 14px; font-weight: 600; color: #C9D0F7; white-space: nowrap; }
.ticker-item b { color: var(--cyan); }

/* ---------- NOTICE ---------- */

.notice {
    display: flex; gap: 14px; align-items: flex-start; padding: 16px 20px; border-radius: 18px; margin-bottom: 28px;
    background: rgba(255,181,71,.09); border: 1px solid rgba(255,181,71,.30);
}
.notice p { margin: 0; color: #FFD89A !important; font-size: 14px; line-height: 1.6; }

/* ---------- LABELS ---------- */

.section-label {
    display: inline-block; font-size: 12px; font-weight: 700; letter-spacing: .08em;
    color: var(--cyan); background: rgba(34,229,212,.10); border: 1px solid rgba(34,229,212,.25);
    padding: 5px 12px; border-radius: 20px; margin-bottom: 8px;
}

/* ---------- STAT CARDS ---------- */

.stat-card {
    position: relative; overflow: hidden; border-radius: 24px; padding: 22px;
    background: var(--glass); backdrop-filter: blur(14px);
    border: 1px solid var(--glass-line);
    box-shadow: 0 14px 34px rgba(0,0,0,.30);
    animation: rise .8s cubic-bezier(.2,.8,.2,1) both;
    transition: transform .35s ease, box-shadow .35s ease, border-color .35s ease;
}
.stat-card::before {
    content: ""; position: absolute; left: 0; right: 0; top: 0; height: 3px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    animation: slide 3s ease-in-out infinite;
}
.stat-card::after {
    content: ""; position: absolute; right: -50px; bottom: -50px; width: 150px; height: 150px; border-radius: 50%;
    background: var(--accent); opacity: .20; filter: blur(30px);
}
.stat-card:hover { transform: translateY(-8px); border-color: var(--accent); box-shadow: 0 22px 44px rgba(0,0,0,.4), 0 0 34px color-mix(in srgb, var(--accent) 40%, transparent); }
.stat-icon {
    width: 44px; height: 44px; border-radius: 14px; display: flex; align-items: center; justify-content: center;
    font-size: 21px; margin-bottom: 14px; background: color-mix(in srgb, var(--accent) 20%, transparent);
}
.stat-value, .gauge-num {
    font-family: 'Outfit', sans-serif; font-weight: 800; color: #fff; line-height: 1;
    counter-reset: num var(--n);
    animation: countup 1.5s cubic-bezier(.2,.8,.2,1) .2s forwards;
}
.stat-value { font-size: 40px; }
.stat-value::after, .gauge-num::after { content: counter(num); }
@keyframes countup { from { --n: 0; } to { --n: var(--ti); } }
.stat-label { font-size: 13.5px; font-weight: 600; color: var(--muted); margin-top: 8px; }

/* ---------- TABS ---------- */

[data-testid="stTabs"] [role="tablist"] {
    background: var(--glass); backdrop-filter: blur(14px);
    border: 1px solid var(--glass-line); border-radius: 20px; padding: 7px; gap: 4px;
    overflow-x: auto; box-shadow: 0 10px 30px rgba(0,0,0,.30);
}
[data-testid="stTabs"] button[role="tab"] {
    border-radius: 14px; padding: 10px 18px; height: auto; font-weight: 600;
    color: var(--muted) !important; transition: all .25s ease;
}
[data-testid="stTabs"] button[role="tab"] * { color: inherit !important; }
[data-testid="stTabs"] button[role="tab"]:hover { background: rgba(255,255,255,.07); color: #fff !important; transform: translateY(-2px); }
[data-testid="stTabs"] button[aria-selected="true"] {
    color: #fff !important;
    background: linear-gradient(100deg, var(--blue), var(--violet), var(--pink));
    background-size: 200% 100%; animation: flow 6s linear infinite;
    box-shadow: 0 8px 24px rgba(139,92,246,.5);
}
[data-testid="stTabs"] [data-baseweb="tab-highlight"],
[data-testid="stTabs"] [data-baseweb="tab-border"] { display: none; }
[data-testid="stTabs"] [role="tabpanel"] { animation: rise .55s cubic-bezier(.2,.8,.2,1) both; }

/* ---------- GLASS CARDS WITH GLOWING BORDER ---------- */

[data-testid="stVerticalBlockBorderWrapper"] {
    border: 1px solid transparent !important; border-radius: 26px;
    background:
        linear-gradient(rgba(14,20,58,.80), rgba(14,20,58,.80)) padding-box,
        linear-gradient(120deg, rgba(79,124,255,.55), rgba(34,229,212,.45), rgba(255,92,138,.50), rgba(79,124,255,.55)) border-box;
    background-size: 100% 100%, 300% 300%;
    backdrop-filter: blur(14px);
    box-shadow: 0 16px 40px rgba(0,0,0,.32);
    animation: borderflow 9s linear infinite;
    transition: transform .35s ease, box-shadow .35s ease;
}
[data-testid="stVerticalBlockBorderWrapper"]:hover { transform: translateY(-6px); box-shadow: 0 24px 50px rgba(0,0,0,.42), 0 0 40px rgba(139,92,246,.30); }
@keyframes borderflow { to { background-position: 0 0, 300% 0; } }

.feature-icon {
    width: 58px; height: 58px; border-radius: 18px; display: flex; align-items: center; justify-content: center;
    font-size: 28px; margin-bottom: 8px;
    background: linear-gradient(135deg, var(--f1), var(--f2)); box-shadow: 0 0 28px var(--fglow);
    animation: bob 4.5s ease-in-out infinite;
}
.tag {
    display: inline-block; font-size: 12px; font-weight: 700; color: var(--cyan);
    background: rgba(34,229,212,.10); border: 1px solid rgba(34,229,212,.25);
    padding: 5px 11px; border-radius: 10px;
}

.step {
    display: flex; gap: 14px; align-items: flex-start; padding: 18px; border-radius: 20px; height: 100%;
    background: var(--glass); border: 1px solid var(--glass-line);
    transition: transform .3s ease, border-color .3s ease;
}
.step:hover { transform: translateY(-5px); border-color: rgba(34,229,212,.5); }
.step-num {
    flex-shrink: 0; width: 40px; height: 40px; border-radius: 13px; display: flex; align-items: center; justify-content: center;
    font-family: 'Outfit', sans-serif; font-weight: 800; color: #fff;
    background: linear-gradient(135deg, var(--violet), var(--cyan)); box-shadow: 0 0 20px rgba(139,92,246,.5);
}
.step b { display: block; color: #fff; font-size: 15px; margin-bottom: 2px; }
.step span { color: var(--muted); font-size: 13.5px; line-height: 1.55; }

/* ---------- BUTTONS (shimmer) ---------- */

.stButton button, .stDownloadButton button {
    position: relative; overflow: hidden;
    border: 0; border-radius: 15px; min-height: 50px; padding: 0 28px;
    background: linear-gradient(100deg, var(--blue), var(--violet), var(--pink)); background-size: 200% 100%;
    color: #fff !important; font-weight: 700; font-size: 15px;
    box-shadow: 0 10px 26px rgba(139,92,246,.45);
    transition: transform .25s ease, box-shadow .25s ease, background-position .6s ease;
}
.stButton button *, .stDownloadButton button * { color: #fff !important; }
.stButton button::before, .stDownloadButton button::before {
    content: ""; position: absolute; top: 0; left: -80%; width: 50%; height: 100%;
    background: linear-gradient(100deg, transparent, rgba(255,255,255,.45), transparent);
    transform: skewX(-20deg); animation: shimmer 3.6s ease-in-out infinite;
}
.stButton button:hover, .stDownloadButton button:hover {
    transform: translateY(-3px) scale(1.02); background-position: 100% 0; color: #fff !important;
    box-shadow: 0 16px 34px rgba(255,92,138,.45);
}
.stButton button:active { transform: scale(.98); }
.stButton button:disabled { background: rgba(255,255,255,.10); box-shadow: none; opacity: .6; }
.stButton button:disabled::before { display: none; }

/* ---------- INPUTS ---------- */

input, textarea {
    background: rgba(255,255,255,.06) !important; color: #fff !important;
    border: 1.5px solid rgba(255,255,255,.14) !important; border-radius: 15px !important;
    font-family: 'DM Sans', sans-serif !important; transition: all .25s ease;
}
input::placeholder, textarea::placeholder { color: #7C86BA !important; }
input:focus, textarea:focus {
    border-color: var(--cyan) !important; background: rgba(34,229,212,.07) !important;
    box-shadow: 0 0 0 4px rgba(34,229,212,.15), 0 0 30px rgba(34,229,212,.20) !important;
}
[data-baseweb="select"] > div { background: rgba(255,255,255,.06) !important; border: 1.5px solid rgba(255,255,255,.14) !important; border-radius: 15px; }
[data-baseweb="select"] * { color: #fff !important; }
[data-baseweb="input"], [data-baseweb="base-input"], [data-baseweb="textarea"] { background: transparent !important; }

/* ---------- EXPANDERS / ALERTS / CODE ---------- */

[data-testid="stExpander"] {
    background: var(--glass); border: 1px solid var(--glass-line) !important; border-radius: 16px;
    transition: border-color .25s ease, transform .25s ease;
}
[data-testid="stExpander"]:hover { border-color: rgba(34,229,212,.45) !important; transform: translateX(4px); }
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary * { color: #fff !important; font-weight: 600; }
[data-testid="stExpander"] details { border: 0 !important; }

[data-testid="stAlert"] { border-radius: 16px; background: rgba(255,255,255,.06) !important; border: 1px solid var(--glass-line); }
[data-testid="stAlert"] * { color: #DDE3FF !important; }
[data-testid="stCode"], [data-testid="stCode"] pre, [data-testid="stCode"] code { background: #060A26 !important; color: #BFF6F0 !important; border-radius: 14px; }

/* ---------- GAUGE ---------- */

.gauge-card {
    display: flex; align-items: center; gap: 30px; flex-wrap: wrap; padding: 30px; margin: 8px 0 16px;
    border-radius: 28px; background: var(--glass); backdrop-filter: blur(14px);
    border: 1px solid var(--glass-line); box-shadow: 0 20px 50px rgba(0,0,0,.38);
    animation: rise .7s cubic-bezier(.2,.8,.2,1) both;
}
.gauge {
    width: 180px; height: 180px; border-radius: 50%; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    background: conic-gradient(var(--c) calc(var(--p) * 1%), rgba(255,255,255,.09) 0);
    box-shadow: 0 0 44px color-mix(in srgb, var(--c) 55%, transparent);
    animation: fill 1.7s cubic-bezier(.2,.8,.2,1) .15s forwards;
}
@keyframes fill { from { --p: 0; } to { --p: var(--tp); } }
.gauge-in {
    width: 144px; height: 144px; border-radius: 50%; background: #0A1033;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.gauge-num { font-size: 46px; }
.gauge-sub { font-size: 12px; color: var(--muted); font-weight: 600; margin-top: 5px; }

.verdict { flex: 1; min-width: 240px; }
.verdict-chip { display: inline-block; padding: 7px 15px; border-radius: 30px; font-size: 13px; font-weight: 700; margin-bottom: 12px; }
.chip-high { background: rgba(255,92,138,.16); color: #FF9DB8; border: 1px solid rgba(255,92,138,.5); animation: alertglow 1.8s ease-in-out infinite; }
.chip-med  { background: rgba(255,181,71,.14); color: #FFD08A; border: 1px solid rgba(255,181,71,.45); }
.chip-low  { background: rgba(43,227,160,.14); color: #8CF3CB; border: 1px solid rgba(43,227,160,.45); }
.verdict h3 { margin: 0 0 6px !important; font-size: 1.4rem !important; }
.verdict p { margin: 0; font-size: 14.5px; }

.domain-pill {
    display: inline-flex; gap: 8px; align-items: center; padding: 9px 15px; border-radius: 13px; margin-bottom: 12px;
    background: rgba(79,124,255,.14); border: 1px solid rgba(79,124,255,.4); color: #B7C9FF; font-weight: 700; font-size: 14px;
}

.sign {
    display: flex; gap: 12px; align-items: center; padding: 13px 16px; border-radius: 15px; margin-bottom: 9px;
    background: rgba(255,92,138,.09); border: 1px solid rgba(255,92,138,.30);
    color: #FFC2D1; font-size: 14.5px; font-weight: 500;
    animation: slidein .55s cubic-bezier(.2,.8,.2,1) both;
}
.sign.info  { background: rgba(79,124,255,.10); border-color: rgba(79,124,255,.32); color: #BCCBFF; }
.sign.clear { background: rgba(43,227,160,.10); border-color: rgba(43,227,160,.32); color: #9BF1D0; }

/* ---------- ANALYTICS BARS ---------- */

.bar-row { margin-bottom: 18px; }
.bar-head { display: flex; justify-content: space-between; font-size: 14px; font-weight: 600; color: #fff; margin-bottom: 8px; }
.bar-head span:last-child { color: var(--muted); font-weight: 500; }
.bar-track { height: 13px; background: rgba(255,255,255,.08); border-radius: 20px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 20px; background: var(--bc); box-shadow: 0 0 16px rgba(255,255,255,.18); animation: grow 1.3s cubic-bezier(.2,.8,.2,1) both; }

/* ---------- FOOTER ---------- */

.footer { text-align: center; padding: 30px; color: var(--muted); font-size: 13px; }
.footer b { font-family: 'Outfit', sans-serif; color: #fff; letter-spacing: .02em; }

/* ---------- KEYFRAMES ---------- */

@keyframes rise { from { opacity: 0; transform: translateY(22px); } to { opacity: 1; transform: none; } }
@keyframes slidein { from { opacity: 0; transform: translateX(-24px); } to { opacity: 1; transform: none; } }
@keyframes grow { from { width: 0; } }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(43,227,160,.6); } 70% { box-shadow: 0 0 0 10px rgba(43,227,160,0); } 100% { box-shadow: 0 0 0 0 rgba(43,227,160,0); } }
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes bob { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-6px); } }
@keyframes breathe { 0%,100% { transform: scale(1); } 50% { transform: scale(1.07); } }
@keyframes ripple { 0% { transform: scale(1); opacity: .8; } 100% { transform: scale(2.7); opacity: 0; } }
@keyframes blip { 0%,100% { opacity: 0; transform: scale(.4); } 40%,60% { opacity: 1; transform: scale(1.3); } }
@keyframes floatup { 0% { transform: translateY(0) scale(.6); opacity: 0; } 15% { opacity: .9; } 100% { transform: translateY(-420px) scale(1.2); opacity: 0; } }
@keyframes marquee { to { transform: translateX(-50%); } }
@keyframes shimmer { 0% { left: -80%; } 55%,100% { left: 140%; } }
@keyframes slide { 0%,100% { transform: translateX(-60%); } 50% { transform: translateX(60%); } }
@keyframes alertglow { 0%,100% { box-shadow: 0 0 0 0 rgba(255,92,138,.5); } 50% { box-shadow: 0 0 22px 4px rgba(255,92,138,.45); } }

/* ---------- ACCESSIBILITY & MOBILE ---------- */

@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition: none !important; }
    .typer { width: auto; border-right: 0; }
}

@media (max-width: 768px) {
    .hero { padding: 32px 24px; border-radius: 26px; }
    .radar { display: none; }
    .typer { width: auto; border-right: 0; white-space: normal; animation: none; }
    .gauge-card { padding: 20px; }
}
</style>
"""

st.markdown(CSS, unsafe_allow_html=True)


# ==========================================================
# SESSION STATE
# ==========================================================

if "latest_url_result" not in st.session_state:
    st.session_state.latest_url_result = None

if "latest_message_result" not in st.session_state:
    st.session_state.latest_message_result = None


# ==========================================================
# HELPER FUNCTIONS
# ==========================================================

def risk_group(score):
    score = float(score)

    if score >= 70:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"


def message_warning_signs(message):
    """Use the multilingual warning rules defined in predictor.py."""
    return detect_warning_signs(message)


def gauge_colour(score):
    score = float(score)
    if score >= 70:
        return "#FF5C8A"
    if score >= 30:
        return "#FFB547"
    return "#2BE3A0"


def stat_card(icon, value, label, accent, delay=0.0):
    return (
        f'<div class="stat-card" style="--accent:{accent};--ti:{int(value)};'
        f'animation-delay:{delay}s;">'
        f'<div class="stat-icon">{icon}</div>'
        f'<div class="stat-value"></div>'
        f'<div class="stat-label">{label}</div>'
        f'</div>'
    )


def gauge_card(score, chip_class, chip_text, title, text, sub="out of 100"):
    score = float(score)
    pct = min(max(score, 0), 100)
    return (
        '<div class="gauge-card">'
        f'<div class="gauge" style="--tp:{pct:.1f};--c:{gauge_colour(score)};">'
        '<div class="gauge-in">'
        f'<div class="gauge-num" style="--ti:{round(pct)};"></div>'
        f'<div class="gauge-sub">{sub}</div>'
        '</div></div>'
        '<div class="verdict">'
        f'<span class="verdict-chip {chip_class}">{chip_text}</span>'
        f'<h3>{title}</h3>'
        f'<p>{text}</p>'
        '</div></div>'
    )


def sign_list(items, kind="warn", empty_text=""):
    if not items:
        return f'<div class="sign clear">✅ {empty_text}</div>'
    css = "sign info" if kind == "info" else "sign"
    icon = "ℹ️" if kind == "info" else "⚠️"
    return "".join(
        f'<div class="{css}" style="animation-delay:{i * 0.12:.2f}s">'
        f'{icon}&nbsp; {item}</div>'
        for i, item in enumerate(items)
    )


def bar_row(label, count, total_count, colour):
    pct = (count / total_count * 100) if total_count else 0
    return (
        '<div class="bar-row">'
        f'<div class="bar-head"><span>{label}</span>'
        f'<span>{count} scans · {pct:.1f}%</span></div>'
        f'<div class="bar-track"><div class="bar-fill" '
        f'style="width:{pct:.1f}%;--bc:{colour};"></div></div>'
        '</div>'
    )


# ==========================================================
# DATABASE STATISTICS
# ==========================================================

records = database.get_all_scans()

total = len(records)
high = sum(float(r[4]) >= 70 for r in records)
medium = sum(30 <= float(r[4]) < 70 for r in records)
low = sum(float(r[4]) < 30 for r in records)

url_total = sum(r[1] == "URL" for r in records)
message_total = sum(r[1] == "Message" for r in records)


# ==========================================================
# SIDEBAR
# ==========================================================

with st.sidebar:

    st.markdown(
        '<div class="brand">'
        '<div class="brand-logo">🛡️</div>'
        '<div><div class="brand-name">ScamShield AI</div>'
        '<div class="brand-tag">Smart digital protection</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    st.divider()

    st.markdown('<div class="side-title">Live statistics</div>', unsafe_allow_html=True)

    st.markdown(
        f'<div class="side-stat"><span>Total scans</span><span>{total}</span></div>'
        f'<div class="side-stat"><span><i class="dot" style="background:#FF5C8A;color:#FF5C8A"></i>High caution</span><span>{high}</span></div>'
        f'<div class="side-stat"><span><i class="dot" style="background:#FFB547;color:#FFB547"></i>Medium caution</span><span>{medium}</span></div>'
        f'<div class="side-stat"><span><i class="dot" style="background:#2BE3A0;color:#2BE3A0"></i>Low caution</span><span>{low}</span></div>',
        unsafe_allow_html=True,
    )

    st.divider()

    st.markdown('<div class="side-title">System status</div>', unsafe_allow_html=True)

    st.markdown(
        '<div style="display:flex;align-items:center;gap:10px;'
        'font-weight:600;font-size:13px;">'
        '<span class="live-dot"></span> Local scanner available</div>',
        unsafe_allow_html=True,
    )

    st.write("")
    st.caption("Version 4.0 · Python · Machine Learning · SQLite")


# ==========================================================
# HERO SECTION
# ==========================================================

sparks = "".join(
    f'<span class="spark" style="left:{left}%;animation-delay:{delay}s;'
    f'animation-duration:{dur}s"></span>'
    for left, delay, dur in [
        (6, 0, 9), (14, 2.5, 11), (23, 5, 8), (33, 1, 10), (45, 3.5, 12),
        (56, 6, 9), (67, 0.8, 11), (76, 4, 8), (85, 2, 10), (93, 5.5, 12),
    ]
)

st.markdown(f"""
<div class="hero">
    {sparks}
    <div class="hero-inner">
        <div class="hero-text">
            <div class="hero-pill"><span class="live-dot"></span> Local scanner available</div>
            <h1 class="hero-title">
                Spot the scam<br>
                <span class="grad"><span class="typer">before it spots you.</span></span>
            </h1>
            <p class="hero-desc">
                Paste a suspicious link or message. ScamShield AI points out
                the warning signs so you can decide what to do next.
            </p>
            <div class="hero-chips">
                <span class="hero-chip">🔗 Link checker</span>
                <span class="hero-chip">💬 Message checker</span>
                <span class="hero-chip">📁 Scan history</span>
            </div>
        </div>
        <div class="radar">
            <div class="ring r1"></div>
            <div class="ring r2"></div>
            <div class="ring r3"></div>
            <div class="pulse-ring"></div>
            <div class="pulse-ring two"></div>
            <div class="sweep"></div>
            <div class="blip b1"></div>
            <div class="blip b2"></div>
            <div class="blip b3"></div>
            <div class="core">🛡️</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ==========================================================
# TICKER
# ==========================================================

tips = [
    "Never share your <b>OTP</b>",
    "Your bank will never ask for your <b>UPI PIN</b>",
    "Don't install <b>APK files</b> from strangers",
    "No real prize asks you to <b>pay first</b>",
    "Verify <b>KYC</b> requests in the official app",
    "Report fraud on <b>1930</b>",
]

ticker_html = "".join(f'<span class="ticker-item">🛡️ {t}</span>' for t in tips)

st.markdown(
    f'<div class="ticker"><div class="ticker-track">{ticker_html}{ticker_html}</div></div>',
    unsafe_allow_html=True,
)


# ==========================================================
# DISCLAIMER
# ==========================================================

st.markdown("""
<div class="notice">
    <div>💡</div>
    <p><b>Educational screening tool.</b> It does not verify website ownership,
    live reputation or actual fraud. A low score never proves that a link or
    message is safe.</p>
</div>
""", unsafe_allow_html=True)


# ==========================================================
# DASHBOARD
# ==========================================================

st.markdown('<span class="section-label">Your digital safety</span>', unsafe_allow_html=True)
st.header("Your protection overview")

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(stat_card("📁", total, "Total scans", "#4F7CFF", 0.0), unsafe_allow_html=True)

with c2:
    st.markdown(stat_card("🔴", high, "High caution", "#FF5C8A", 0.12), unsafe_allow_html=True)

with c3:
    st.markdown(stat_card("🟠", medium, "Medium caution", "#FFB547", 0.24), unsafe_allow_html=True)

with c4:
    st.markdown(stat_card("🟢", low, "Low caution", "#2BE3A0", 0.36), unsafe_allow_html=True)

st.write("")


# ==========================================================
# NAVIGATION
# ==========================================================

overview, url_tab, message_tab, analytics, history, guide = st.tabs([
    "🏠 Overview",
    "🔗 URL Scanner",
    "💬 Message Scanner",
    "📊 Analytics",
    "📁 Scan History",
    "🛡️ Safety Guide",
])


# ==========================================================
# OVERVIEW
# ==========================================================

with overview:

    st.write("")
    st.markdown('<span class="section-label">Welcome</span>', unsafe_allow_html=True)
    st.header("Your digital protection center")

    st.write("Choose a tool to check a suspicious website or message.")

    col1, col2 = st.columns(2)

    with col1:
        with st.container(border=True):
            st.markdown(
                '<div class="feature-icon" style="--f1:#4F7CFF;--f2:#8B5CF6;--fglow:rgba(79,124,255,.55)">🔗</div>',
                unsafe_allow_html=True,
            )
            st.markdown("### Website Intelligence")
            st.write(
                "Inspect website links, URL structure, suspicious "
                "wording and selected risk indicators."
            )
            st.markdown('<span class="tag">Rule-based screening</span>', unsafe_allow_html=True)

    with col2:
        with st.container(border=True):
            st.markdown(
                '<div class="feature-icon" style="--f1:#22E5D4;--f2:#4F7CFF;--fglow:rgba(34,229,212,.55)">💬</div>',
                unsafe_allow_html=True,
            )
            st.markdown("### AI Message Intelligence")
            st.write(
                "Use your trained TF-IDF and Logistic Regression "
                "model to estimate SMS spam similarity."
            )
            st.markdown('<span class="tag">Machine learning</span>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        with st.container(border=True):
            st.markdown(
                '<div class="feature-icon" style="--f1:#FF5C8A;--f2:#FFB547;--fglow:rgba(255,92,138,.55)">📊</div>',
                unsafe_allow_html=True,
            )
            st.markdown("### Security Analytics")
            st.write("Review saved scans, risk groups and scanner activity.")
            st.markdown('<span class="tag">SQLite analytics</span>', unsafe_allow_html=True)

    with col2:
        with st.container(border=True):
            st.markdown(
                '<div class="feature-icon" style="--f1:#FFB547;--f2:#2BE3A0;--fglow:rgba(255,181,71,.55)">📁</div>',
                unsafe_allow_html=True,
            )
            st.markdown("### Scan History")
            st.write(
                "Search previous scans, inspect results and "
                "export records as CSV."
            )
            st.markdown('<span class="tag">CSV export</span>', unsafe_allow_html=True)

    st.write("")
    st.markdown("### How it works")

    s1, s2, s3, s4 = st.columns(4)

    steps = [
        ("1", "Choose a scanner", "Open the URL or Message Scanner."),
        ("2", "Enter content", "Paste a website link or message."),
        ("3", "Analyse", "Select the scan button and read the report."),
        ("4", "Stay safe", "Verify suspicious requests through official channels."),
    ]

    for column, (num, title, text) in zip((s1, s2, s3, s4), steps):
        with column:
            st.markdown(
                f'<div class="step"><div class="step-num">{num}</div>'
                f'<div><b>{title}</b><span>{text}</span></div></div>',
                unsafe_allow_html=True,
            )


# ==========================================================
# URL SCANNER
# ==========================================================

with url_tab:

    st.write("")
    st.markdown('<span class="section-label">Website protection</span>', unsafe_allow_html=True)
    st.header("🔗 Website Link Checker")

    st.write(
        "Inspect a website address for selected warning indicators. "
        "The scanner does not open the link."
    )

    with st.container(border=True):

        st.markdown("### Enter a website address")

        url_input = st.text_input(
            "Website URL",
            placeholder="https://example.com",
            key="url_input",
        )

        if st.button("🔍 Analyse Website", key="url_scan"):

            if not url_input.strip():
                st.warning("Please enter a website URL.")

            else:
                try:
                    with st.spinner("Scanning link…"):
                        result = analyze_url(url_input)

                    database.save_scan(
                        "URL",
                        url_input,
                        result["prediction"],
                        result["risk_score"],
                    )

                    st.session_state.latest_url_result = {
                        "url": url_input,
                        **result,
                    }

                    st.rerun()

                except Exception as exc:
                    st.error(f"Could not analyse this URL: {exc}")

    result = st.session_state.latest_url_result

    if result:

        st.write("")
        st.markdown("### 📋 Website analysis report")

        domain = result.get("domain") or "Not identified"
        st.markdown(
            f'<div class="domain-pill">🌐 {domain}</div>',
            unsafe_allow_html=True,
        )

        with st.expander("View full URL"):
            st.code(result["url"], language=None)

        level = result.get(
            "risk_level",
            risk_group(result["risk_score"]),
        )

        if level == "High":
            chip, chip_text = "chip-high", "High caution"
            title = "Multiple warning indicators found"
            text = "Do not enter personal details or payment information on this site."

        elif level == "Medium":
            chip, chip_text = "chip-med", "Needs review"
            title = "Some warning indicators found"
            text = "Check the address carefully and verify it through an official source."

        elif result.get("review_required"):
            chip, chip_text = "chip-med", "Manual review"
            title = "A category indicator was found"
            text = "This is not proof of fraud, but it is worth a second look."

        else:
            chip, chip_text = "chip-low", "No major rule warnings"
            title = "Website remains unverified"
            text = "No major warnings from this rule set. That does not make the site safe."

        st.markdown(
            gauge_card(
                result["risk_score"],
                chip,
                chip_text,
                title,
                text,
                sub="caution score",
            ),
            unsafe_allow_html=True,
        )

        st.markdown("### ⚠️ Warning indicators")

        st.markdown(
            sign_list(
                result["reasons"],
                "warn",
                "No warning patterns from this rule set were detected.",
            ),
            unsafe_allow_html=True,
        )

        if result.get("informational"):
            st.markdown("### ℹ️ Additional context")
            st.markdown(
                sign_list(result["informational"], "info"),
                unsafe_allow_html=True,
            )

        st.caption(
            "The score is a heuristic caution score, not a probability "
            "of fraud. Gambling-related wording is not proof of a scam. "
            "No live threat-intelligence lookup is performed."
        )


# ==========================================================
# MESSAGE SCANNER
# ==========================================================

with message_tab:

    st.write("")
    st.markdown('<span class="section-label">Message protection</span>', unsafe_allow_html=True)
    st.header("💬 AI Message Checker")

    st.write(
        "Estimate whether a message resembles spam in your "
        "model's training dataset."
    )

    with st.container(border=True):

        st.markdown("### Enter your message")

        message_input = st.text_area(
            "Message text",
            placeholder="Paste a suspicious SMS or WhatsApp message...",
            height=170,
        )

        if st.button("✨ Analyse Message", key="message_scan"):

            if not message_input.strip():
                st.warning("Please enter a message.")

            else:
                try:
                    with st.spinner("Scanning message…"):
                        result = analyze_message(message_input)

                    signs = result.get("warning_signs")
                    if signs is None:
                        signs = message_warning_signs(message_input)

                    database.save_scan(
                        "Message",
                        message_input,
                        result["prediction"],
                        result["risk_score"],
                    )

                    st.session_state.latest_message_result = {
                        "message": message_input,
                        **result,
                        "reasons": signs,
                    }

                    st.rerun()

                except Exception as exc:
                    st.error(f"Could not analyse this message: {exc}")

    result = st.session_state.latest_message_result

    if result:

        st.write("")
        st.markdown("### 📋 Message analysis report")

        score = float(result["risk_score"])

        if score >= 70:
            chip, chip_text = "chip-high", "High risk"
            title = "Strong spam-like patterns found"
            text = "Do not reply, click links or share any codes or personal details."

        elif score >= 40:
            chip, chip_text = "chip-med", "Medium risk"
            title = "Review this message carefully"
            text = "Some patterns look like spam. Verify the sender through official channels."

        else:
            chip, chip_text = "chip-low", "Low model score"
            title = "Few spam-like patterns found"
            text = "This does not guarantee the message is safe."

        st.markdown(
            gauge_card(
                score,
                chip,
                chip_text,
                title,
                text,
                sub="spam score %",
            ),
            unsafe_allow_html=True,
        )

        st.markdown("### Model prediction")
        st.write(result["prediction"])

        if result.get("script_indicator"):
            st.caption(f"Text script indicator: {result['script_indicator']}")

        st.markdown("### ⚠️ Additional warning signs")

        st.markdown(
            sign_list(
                result["reasons"],
                "warn",
                "No listed keyword warning signs were detected.",
            ),
            unsafe_allow_html=True,
        )

        st.caption(
            "The model was trained on the UCI SMS Spam Collection. "
            "It estimates spam similarity, not confirmed financial fraud."
        )


# ==========================================================
# ANALYTICS
# ==========================================================

with analytics:

    st.write("")
    st.markdown('<span class="section-label">Security insights</span>', unsafe_allow_html=True)
    st.header("📊 Analytics dashboard")

    if total == 0:

        st.info("No scans yet. Run a scan in the URL or Message Scanner to see insights here.")

    else:

        left, right = st.columns(2)

        with left:
            with st.container(border=True):
                st.markdown("### Risk distribution")
                st.markdown(
                    bar_row("🔴 High caution", high, total, "linear-gradient(90deg,#FF5C8A,#FF9DB8)")
                    + bar_row("🟠 Medium caution", medium, total, "linear-gradient(90deg,#FFB547,#FFD08A)")
                    + bar_row("🟢 Low caution", low, total, "linear-gradient(90deg,#2BE3A0,#7DF3E8)"),
                    unsafe_allow_html=True,
                )

        with right:
            with st.container(border=True):
                st.markdown("### Scanner activity")
                st.markdown(
                    bar_row("🔗 Website scans", url_total, total, "linear-gradient(90deg,#4F7CFF,#8B5CF6)")
                    + bar_row("💬 Message scans", message_total, total, "linear-gradient(90deg,#22E5D4,#4F7CFF)"),
                    unsafe_allow_html=True,
                )

        st.caption(
            "Risk groups describe screening scores, not confirmed "
            "fraud incidents."
        )


# ==========================================================
# SCAN HISTORY
# ==========================================================

with history:

    st.write("")
    st.markdown('<span class="section-label">Your records</span>', unsafe_allow_html=True)
    st.header("📁 Scan History")

    if not records:

        st.info("No saved scans yet.")

    else:

        f1, f2, f3 = st.columns([2, 1, 1])

        with f1:
            search = st.text_input("🔎 Search content or prediction")

        with f2:
            type_filter = st.selectbox(
                "Scan type",
                ["All", "URL", "Message"],
            )

        with f3:
            risk_filter = st.selectbox(
                "Risk group",
                ["All", "High", "Medium", "Low"],
            )

        filtered = []

        for row in records:

            scan_id, scan_type, content, prediction, score, scan_time = row

            if type_filter != "All" and scan_type != type_filter:
                continue

            if risk_filter != "All" and risk_group(score) != risk_filter:
                continue

            if search.lower() not in (
                f"{content} {prediction} {scan_type}".lower()
            ):
                continue

            filtered.append(row)

        st.write(f"Showing **{len(filtered)}** of **{total}** records.")

        output = io.StringIO()

        writer = csv.writer(output)

        writer.writerow([
            "ID",
            "Type",
            "Content",
            "Prediction",
            "Score",
            "Time",
        ])

        writer.writerows(filtered)

        st.download_button(
            "⬇️ Download CSV",
            data=output.getvalue(),
            file_name="scamshield_scan_history.csv",
            mime="text/csv",
        )

        st.write("")

        for row in filtered:

            scan_id, scan_type, content, prediction, score, scan_time = row

            group = risk_group(score)
            icon = {"High": "🔴", "Medium": "🟠", "Low": "🟢"}[group]

            with st.expander(
                f"{icon}  #{scan_id}  ·  {scan_type}  ·  {group} caution"
            ):

                st.write("**Prediction:**", prediction)
                st.write("**Score:**", f"{float(score):.2f}")
                st.write("**Time:**", scan_time)
                st.code(content, language=None)

        st.divider()

        st.warning(
            "Clearing history permanently deletes all saved scan records."
        )

        confirm = st.checkbox(
            "I understand and want to clear all history."
        )

        if st.button(
            "🗑️ Clear all scan history",
            disabled=not confirm,
        ):

            database.clear_history()

            st.session_state.latest_url_result = None
            st.session_state.latest_message_result = None

            st.rerun()


# ==========================================================
# SAFETY GUIDE
# ==========================================================

with guide:

    st.write("")
    st.markdown('<span class="section-label">Digital safety center</span>', unsafe_allow_html=True)
    st.header("🛡️ Protect your digital life")

    st.write(
        "Simple safety practices to protect your money "
        "and personal information."
    )

    g1, g2, g3 = st.columns(3)

    with g1:
        with st.container(border=True):
            st.markdown("### 🔐 Personal information")
            st.markdown("""
- Never share OTP, UPI PIN, ATM PIN, CVV or passwords.
- Never give unknown people remote access to your device.
- Do not install APK files sent by unknown people.
""")

    with g2:
        with st.container(border=True):
            st.markdown("### 🏦 Banking protection")
            st.markdown("""
- Verify banking and KYC requests through official channels.
- Do not pay money to receive a prize, job or loan.
- Contact your bank promptly if you suspect financial fraud.
""")

    with g3:
        with st.container(border=True):
            st.markdown("### 🇮🇳 Report cybercrime")
            st.write(
                "If you suspect financial cyber fraud in India, "
                "contact your bank promptly and report it through "
                "the official cybercrime helpline **1930**."
            )

    st.write("")

    with st.expander("How the URL scanner works"):
        st.write(
            "It checks URL structure and selected wording. "
            "It does not visit websites or query a live blocklist."
        )

    with st.expander("How the message model works"):
        st.write(
            "TF-IDF converts message text into numeric features; "
            "Logistic Regression estimates spam similarity."
        )

    with st.expander("What does the score mean?"):
        st.write(
            "The URL score is a rule-based caution indicator. "
            "The message score estimates similarity to spam in the "
            "training dataset. Neither is a verified fraud probability."
        )

    st.error(
        "ScamShield AI is an educational prototype. It cannot guarantee "
        "that a website or message is safe and must not replace official "
        "bank or security advice."
    )


# ==========================================================
# FOOTER
# ==========================================================

st.markdown("""
<div class="footer">
    🛡️ <b>ScamShield AI</b><br>
    Detect. Analyse. Protect.<br>
    Python · Machine Learning · SQLite
</div>
""", unsafe_allow_html=True)