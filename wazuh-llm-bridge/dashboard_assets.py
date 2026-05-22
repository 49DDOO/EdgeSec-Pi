"""Dashboard presentation assets.

The dashboard HTML is still rendered server-side, but CSS and JavaScript live
here so a future UI redesign can replace presentation assets without touching
route, query, or scoring logic in dashboard_ui.py.
"""
from __future__ import annotations

DASHBOARD_CSS = r"""
  :root {
    --bg: #f7f9fc;
    --panel: #ffffff;
    --text: #0f1f33;
    --muted: #5f6f86;
    --line: #d9e4f2;
    --blue: #2496ed;
    --blue-dark: #1d63ed;
    --blue-soft: #eaf5ff;
    --ok: #14864f;
    --warn: #b26a00;
    --high: #c24135;
    --medium: #b26a00;
    --info: #1d63ed;
    --shadow: 0 1px 2px rgba(15, 31, 51, .05), 0 8px 24px rgba(15, 31, 51, .05);
  }
  html, body { height: 100%; min-height: 100%; overflow: hidden; }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Noto Sans TC", "Segoe UI", sans-serif;
    line-height: 1.5;
  }
  .app-shell {
    min-height: 100vh; display: grid; grid-template-columns: 240px minmax(0, 1fr);
  }
  .sidebar {
    position: sticky; top: 0; height: 100vh; background: #ffffff;
    border-right: 1px solid var(--line); padding: 18px 14px;
    display: flex; flex-direction: column; gap: 18px;
  }
  .brand { display: flex; align-items: center; gap: 10px; padding: 2px 6px 12px; }
  .brand-mark {
    width: 32px; height: 32px; border-radius: 7px; background: var(--blue);
    box-shadow: inset 0 -6px 0 rgba(0, 0, 0, .08);
  }
  .brand strong { display: block; font-size: 16px; line-height: 1.1; }
  .brand span { display: block; color: var(--muted); font-size: 12px; }
  .nav { display: grid; gap: 4px; }
  .nav a {
    display: flex; align-items: center; gap: 10px; min-height: 38px; padding: 0 10px;
    border-radius: 7px; color: #334155; font-weight: 650; text-decoration: none;
  }
  .nav a:hover { background: #f1f6fd; text-decoration: none; }
  .nav a.active { background: var(--blue-soft); color: #0b5cad; }
  .nav-icon {
    width: 18px; height: 18px; border-radius: 5px; border: 1px solid #9ccdf7;
    background: #ffffff; flex: 0 0 auto;
  }
  .sidebar-foot {
    margin-top: auto; border: 1px solid var(--line); border-radius: 8px; padding: 10px;
    color: var(--muted); font-size: 13px; background: #fbfdff;
  }
  .content-shell { min-width: 0; }
  .topbar {
    min-height: 66px; background: #ffffff; border-bottom: 1px solid var(--line);
    display: flex; align-items: center;
  }
  .topbar-inner {
    width: min(1220px, calc(100% - 48px)); margin: 0 auto;
    display: flex; justify-content: space-between; gap: 16px; align-items: center;
  }
  .eyebrow { color: var(--muted); font-size: 12px; font-weight: 750; text-transform: uppercase; }
  h1 { margin: 0; font-size: 23px; font-weight: 750; letter-spacing: 0; }
  .updated {
    color: var(--muted); font-size: 13px; white-space: nowrap; border: 1px solid var(--line);
    border-radius: 999px; padding: 6px 10px; background: #fbfdff;
  }
  .wrap { width: min(1220px, calc(100% - 48px)); margin: 0 auto; }
  main { padding: 24px 0 42px; }
  .dashboard-grid {
    display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 18px; align-items: start;
  }
  .primary-column, .side-column { display: grid; gap: 18px; min-width: 0; }
  .risk-band, .panel, .event {
    background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
    box-shadow: var(--shadow);
  }
  .risk-band { padding: 22px; border-top: 4px solid var(--ok); }
  .risk-band.risk-critical, .risk-band.risk-high { border-top-color: var(--high); }
  .risk-band.risk-medium { border-top-color: var(--medium); }
  .risk-band.risk-ok { border-top-color: var(--ok); }
  .risk-label { color: var(--muted); font-size: 13px; font-weight: 750; }
  .risk-value { font-size: 44px; font-weight: 800; margin: 4px 0 6px; letter-spacing: 0; }
  .risk-desc { max-width: 720px; font-size: 17px; }
  .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 18px; }
  .metric { border: 1px solid var(--line); border-radius: 7px; padding: 10px; min-width: 0; background: #fbfdff; }
  .metric strong { display: block; font-size: 24px; }
  .metric span { display: block; color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }
  .panel { padding: 18px; }
  .panel h2, .events h2 { margin: 0 0 12px; font-size: 18px; }
  .status-row {
    display: grid; grid-template-columns: 14px minmax(70px, .8fr) minmax(0, 1fr);
    gap: 8px; align-items: center; padding: 10px 0; border-top: 1px solid var(--line);
  }
  .status-row:first-of-type { border-top: 0; }
  .status-row strong { text-align: right; overflow-wrap: anywhere; }
  .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
  .dot-ok { background: var(--ok); }
  .dot-warn { background: var(--warn); }
  .events { min-width: 0; }
  .event { padding: 16px; margin-bottom: 12px; border-left: 4px solid var(--info); }
  .event-critical, .event-high { border-left-color: var(--high); }
  .event-medium { border-left-color: var(--medium); }
  .event-info { border-left-color: var(--info); }
  .event-top { display: flex; justify-content: space-between; gap: 12px; align-items: center; }
  .sev {
    display: inline-flex; align-items: center; min-height: 26px; padding: 3px 10px;
    border-radius: 999px; font-size: 13px; font-weight: 750; background: var(--blue-soft); color: #0b5cad;
  }
  .sev-critical, .sev-high { background: #fee2e2; color: #991b1b; }
  .sev-medium { background: #fef3c7; color: #92400e; }
  .sev-low { background: #dcfce7; color: #166534; }
  .event-time { color: var(--muted); font-size: 13px; white-space: nowrap; }
  .event h3 { margin: 12px 0; font-size: 19px; line-height: 1.35; letter-spacing: 0; }
  dl { margin: 0; display: grid; gap: 9px; }
  dl div { display: grid; grid-template-columns: 70px minmax(0, 1fr); gap: 10px; }
  dt { color: var(--muted); font-weight: 700; }
  dd { margin: 0; overflow-wrap: anywhere; }
  details { margin-top: 12px; border-top: 1px solid var(--line); padding-top: 10px; }
  summary { cursor: pointer; color: #334155; font-weight: 650; }
  .tech-grid { display: grid; grid-template-columns: 100px minmax(0, 1fr); gap: 8px; margin-top: 10px; }
  code { background: #eef4fb; padding: 2px 6px; border-radius: 4px; overflow-wrap: anywhere; }
  .side-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
  .side-list li { display: grid; grid-template-columns: 42px minmax(0, 1fr); gap: 10px; align-items: start; }
  .side-list strong { font-size: 22px; line-height: 1; }
  .side-list span { color: var(--muted); overflow-wrap: anywhere; }
  .agent-list { display: grid; gap: 0; }
  .agent-row { border-top: 1px solid var(--line); padding: 14px 0; }
  .agent-row:first-child { border-top: 0; padding-top: 0; }
  .agent-row:last-child { padding-bottom: 0; }
  .agent-unprofiled { background: #fffaf0; margin: 0 -10px; padding-left: 10px; padding-right: 10px; border-radius: 7px; }
  .agent-head {
    display: grid; grid-template-columns: 14px minmax(0, 1fr) auto;
    gap: 10px; align-items: start;
  }
  .agent-title strong { display: block; font-size: 16px; line-height: 1.25; overflow-wrap: anywhere; }
  .agent-title span { display: block; color: var(--muted); margin-top: 2px; overflow-wrap: anywhere; }
  .status-pill {
    border-radius: 999px; padding: 3px 9px; font-size: 12px; font-weight: 800;
    background: #ecfdf3; color: #087443; white-space: nowrap;
  }
  .status-warn { background: #fff7e6; color: #9a5a00; }
  .agent-meta {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px;
    margin: 10px 0 0 24px;
  }
  .agent-meta span {
    border: 1px solid var(--line); border-radius: 7px; padding: 8px;
    color: #334155; background: #fbfdff; min-width: 0; overflow-wrap: anywhere;
  }
  .agent-meta b { display: block; color: var(--muted); font-size: 12px; margin-bottom: 2px; }
  .agent-note { margin: 10px 0 0 24px; color: #475569; }
  .profile-link { display: inline-block; margin: 10px 0 0 24px; font-weight: 750; }
  .empty-state { background: white; border: 1px solid var(--line); border-radius: 8px; padding: 22px; box-shadow: var(--shadow); }
  .empty-state.compact { box-shadow: none; padding: 14px; }
  .empty-state strong, .empty-state span { display: block; }
  .empty-state span { color: var(--muted); margin-top: 6px; }
  a { color: var(--blue-dark); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .links { display: grid; gap: 8px; margin-top: 12px; }
  .self-test { margin-top: 16px; border-top: 1px solid var(--line); padding-top: 14px; }
  .self-test-head { display: flex; justify-content: space-between; gap: 10px; align-items: center; }
  .self-test-head h3 { margin: 0; font-size: 16px; }
  .check-button {
    border: 1px solid var(--blue-dark); background: var(--blue-dark); color: white; border-radius: 6px;
    min-height: 34px; padding: 0 12px; font-weight: 700; cursor: pointer;
  }
  .check-button:disabled { opacity: .65; cursor: wait; }
  .self-result {
    margin-top: 12px; border: 1px solid var(--line); border-radius: 8px; padding: 12px;
    background: #f8fafc; max-height: 420px; overflow: auto;
  }
  .self-result.result-ok { border-color: #86efac; background: #f0fdf4; }
  .self-result.result-warn { border-color: #fcd34d; background: #fffbeb; }
  .self-result.result-fail { border-color: #fca5a5; background: #fef2f2; }
  .self-result strong { display: block; font-size: 15px; margin-bottom: 4px; }
  .self-result p { margin: 0; color: #475569; font-size: 14px; }
  .check-list { list-style: none; padding: 0; margin: 12px 0 0; display: grid; gap: 8px; }
  .check-list li {
    display: grid; grid-template-columns: 22px minmax(0, 1fr); gap: 8px;
    border-top: 1px solid rgba(15, 23, 42, .09); padding-top: 8px;
  }
  .check-list li:first-child { border-top: 0; padding-top: 0; }
  .check-icon { font-weight: 800; }
  .check-list b { display: block; }
  .check-list span { display: block; color: #475569; font-size: 13px; }
  .check-list details { grid-column: 2; margin-top: 2px; padding-top: 0; border-top: 0; }
  .check-list summary { font-size: 13px; color: #475569; }
  @media (max-width: 860px) {
    .app-shell { grid-template-columns: 1fr; }
    .sidebar {
      position: static; height: auto; border-right: 0; border-bottom: 1px solid var(--line);
      padding: 12px; gap: 10px;
    }
    .brand { padding-bottom: 6px; }
    .nav { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .nav a { justify-content: center; min-height: 36px; font-size: 13px; }
    .nav-icon, .sidebar-foot { display: none; }
    .topbar-inner, .event-top { align-items: flex-start; flex-direction: column; }
    .dashboard-grid { grid-template-columns: 1fr; }
    .self-result { max-height: none; }
    .metrics, .agent-meta { grid-template-columns: repeat(2, 1fr); }
    .updated, .event-time { white-space: normal; }
  }
  @media (max-width: 520px) {
    .wrap, .topbar-inner { width: min(100% - 20px, 1220px); }
    .topbar { padding: 12px 0; }
    .nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    main { padding-top: 14px; }
    h1 { font-size: 21px; }
    .risk-value { font-size: 36px; }
    .metrics, .agent-meta, dl div, .tech-grid { grid-template-columns: 1fr; }
    .agent-head { grid-template-columns: 14px minmax(0, 1fr); }
    .status-pill { grid-column: 2; justify-self: start; }
    .status-row { grid-template-columns: 14px minmax(0, 1fr); }
    .status-row strong { grid-column: 2; text-align: left; }
  }
  .management-shell { min-height: 100vh; }
  .management-top {
    background: #ffffff; border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 5;
  }
  .management-top-inner {
    width: min(1040px, calc(100% - 40px)); min-height: 68px; margin: 0 auto;
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
  }
  .management-brand { display: flex; align-items: center; gap: 10px; }
  .management-brand strong { display: block; font-size: 17px; }
  .management-brand span { color: var(--muted); font-size: 13px; }
  .management-main { width: min(1040px, calc(100% - 40px)); margin: 0 auto; padding: 24px 0 48px; }
  .management-updated { color: var(--muted); font-size: 13px; white-space: nowrap; }
  .decision {
    background: #ffffff; border: 1px solid var(--line); border-top: 5px solid var(--ok);
    border-radius: 8px; box-shadow: var(--shadow); padding: 26px;
  }
  .decision-critical, .decision-high { border-top-color: var(--high); }
  .decision-medium { border-top-color: var(--medium); }
  .decision-label { color: var(--muted); font-size: 13px; font-weight: 800; }
  .decision h1 { font-size: 42px; line-height: 1.05; margin: 8px 0 10px; }
  .decision p { margin: 0; font-size: 18px; max-width: 760px; }
  .owner-action {
    margin-top: 18px; padding: 14px 16px; border-radius: 8px;
    background: #f6fafe; border: 1px solid #cfe6fb;
  }
  .owner-action span { display: block; color: var(--muted); font-size: 13px; font-weight: 800; }
  .owner-action strong { display: block; margin-top: 4px; font-size: 17px; }
  .summary-grid {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 16px;
  }
  .summary-card {
    background: #ffffff; border: 1px solid var(--line); border-radius: 8px; padding: 14px; box-shadow: var(--shadow);
  }
  .summary-card strong { display: block; font-size: 26px; line-height: 1.1; }
  .summary-card span { display: block; margin-top: 6px; color: var(--muted); font-size: 13px; }
  .owner-grid { display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 18px; margin-top: 18px; align-items: start; }
  .owner-main, .owner-side { display: grid; gap: 18px; min-width: 0; }
  .section-card {
    background: #ffffff; border: 1px solid var(--line); border-radius: 8px; padding: 18px; box-shadow: var(--shadow);
  }
  .section-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
  .section-head h2 { margin: 0; font-size: 20px; }
  .section-head p { margin: 4px 0 0; color: var(--muted); }
  .service-list { display: grid; gap: 10px; }
  .service-item { border: 1px solid var(--line); border-radius: 8px; padding: 13px; background: #fbfdff; }
  .service-item.agent-unprofiled { background: #fffaf0; }
  .service-head { display: grid; grid-template-columns: 12px minmax(0, 1fr) auto; gap: 10px; align-items: start; }
  .service-title strong { display: block; font-size: 16px; }
  .service-title span { display: block; color: var(--muted); margin-top: 2px; overflow-wrap: anywhere; }
  .service-meta { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin: 10px 0 0 22px; }
  .service-meta span { border: 1px solid var(--line); border-radius: 7px; padding: 8px; background: #ffffff; }
  .service-meta b { display: block; color: var(--muted); font-size: 12px; }
  .profile-missing { margin: 10px 0 0 22px; border: 1px solid #f5c76b; border-radius: 7px; padding: 10px; background: #fff8e6; }
  .profile-missing strong { display: block; color: #8a4b08; }
  .profile-missing span { display: block; margin-top: 3px; color: #7a5a23; }
  .service-details { margin-left: 22px; }
  .profile-link { margin-left: 22px; }
  .event-impact { margin: 0 0 12px; color: #334155; }
  .event-action { border: 1px solid #cfe6fb; background: #f6fafe; border-radius: 8px; padding: 12px; }
  .event-action span { display: block; color: var(--muted); font-size: 13px; font-weight: 800; }
  .event-action strong { display: block; margin-top: 4px; }
  .quiet-links { display: grid; gap: 8px; }
  @media (max-width: 900px) {
    .management-top-inner, .management-main { width: min(100% - 24px, 1040px); }
    .summary-grid, .owner-grid { grid-template-columns: 1fr; }
    .decision h1 { font-size: 34px; }
  }
  @media (max-width: 560px) {
    .management-top-inner { align-items: flex-start; flex-direction: column; padding: 12px 0; }
    .summary-grid { gap: 10px; }
    .service-head { grid-template-columns: 12px minmax(0, 1fr); }
    .status-pill { grid-column: 2; justify-self: start; }
    .service-meta { grid-template-columns: 1fr; }
  }
  .management-shell {
    --surface: #ffffff;
    --surface-muted: #f6f8fa;
    --text: #1f2328;
    --muted: #59636e;
    --line: #d0d7de;
    --line-soft: #eaeef2;
    --accent: #0969da;
    --ok: #1a7f37;
    --warn: #9a6700;
    --high: #cf222e;
    height: 100vh; min-height: 100vh; overflow-y: auto; overscroll-behavior: contain;
    background: #f6f8fa;
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Helvetica, sans-serif;
  }
  .management-shell * { box-shadow: none; letter-spacing: 0; }
  .management-top {
    position: sticky; top: 0; z-index: 5;
    background: rgba(255,255,255,.96); border-bottom: 1px solid var(--line);
  }
  .management-top-inner {
    width: min(1180px, calc(100% - 32px)); min-height: 56px; margin: 0 auto;
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
  }
  .management-brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .management-brand .brand-mark {
    width: 24px; height: 24px; border-radius: 4px; background: #2496ed;
    box-shadow: inset 0 -4px 0 rgba(0,0,0,.12);
  }
  .management-brand strong { display: block; font-size: 15px; line-height: 1.2; }
  .management-brand span { display: block; margin-top: 1px; color: var(--muted); font-size: 12px; }
  .management-updated { color: var(--muted); font-size: 12px; white-space: nowrap; }
  .management-main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 16px 0 36px; }
  .status-strip {
    display: grid; grid-template-columns: minmax(0, 1fr) minmax(280px, 420px); gap: 18px;
    border: 1px solid var(--line); border-left: 4px solid var(--ok);
    background: var(--surface); border-radius: 6px; padding: 16px;
  }
  .status-strip.status-critical, .status-strip.status-high { border-left-color: var(--high); }
  .status-strip.status-medium { border-left-color: var(--warn); }
  .status-strip h1 { margin: 2px 0 4px; font-size: 22px; line-height: 1.25; }
  .status-strip p { margin: 0; color: var(--muted); font-size: 14px; }
  .status-label { color: var(--muted); font-size: 12px; font-weight: 700; }
  .next-action { border-left: 1px solid var(--line-soft); padding-left: 18px; }
  .next-action span { display: block; color: var(--muted); font-size: 12px; font-weight: 700; }
  .next-action strong { display: block; margin-top: 4px; font-size: 14px; line-height: 1.45; }
  .summary-row {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
    border: 1px solid var(--line); border-radius: 6px; background: var(--surface); margin-top: 12px;
  }
  .summary-item { padding: 12px 14px; border-left: 1px solid var(--line-soft); }
  .summary-item:first-child { border-left: 0; }
  .summary-item strong { display: block; font-size: 18px; line-height: 1.2; }
  .summary-item span { display: block; margin-top: 4px; color: var(--muted); font-size: 12px; }
  .management-grid { display: grid; grid-template-columns: minmax(0, 1fr) 330px; gap: 16px; margin-top: 16px; align-items: start; }
  .main-stack, .side-stack { display: grid; gap: 16px; min-width: 0; }
  .section-card { background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: 0; }
  .section-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--line-soft); margin: 0; }
  .section-head h2 { margin: 0; font-size: 15px; }
  .section-head p { display: none; }
  .todo-list { display: grid; }
  .todo-row { display: grid; grid-template-columns: 92px minmax(0, 1fr); gap: 14px; padding: 14px; border-top: 1px solid var(--line-soft); }
  .todo-row:first-child { border-top: 0; }
  .todo-status span { display: block; color: var(--muted); font-weight: 700; }
  .todo-status strong {
    display: inline-flex; margin-top: 6px; border: 1px solid #f0c36a; border-radius: 999px;
    padding: 2px 8px; color: #7d4e00; background: #fff8e5; font-size: 12px;
  }
  .todo-high .todo-status span, .todo-critical .todo-status span { color: var(--high); }
  .todo-medium .todo-status span { color: var(--warn); }
  .todo-main h3 { margin: 0 0 6px; font-size: 15px; line-height: 1.45; }
  .todo-main p { margin: 0; color: var(--muted); font-size: 13px; }
  .todo-meta { display: flex; gap: 10px; flex-wrap: wrap; color: var(--muted); font-size: 12px; margin-bottom: 5px; }
  .todo-action { margin-top: 10px; border-left: 3px solid var(--line); padding-left: 10px; font-size: 13px; }
  .todo-tech { margin-top: 10px; border: 0; padding: 0; font-size: 12px; }
  .todo-tech summary {
    display: inline-flex; width: auto; color: var(--accent); font-weight: 650;
    cursor: pointer; outline-offset: 2px;
  }
  .todo-tech[open] { border-top: 1px solid var(--line-soft); padding-top: 10px; }
  .todo-tech[open] summary { margin-bottom: 8px; }
  .asset-table-wrap { overflow-x: auto; }
  .asset-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .asset-table th, .asset-table td { padding: 10px 12px; border-top: 1px solid var(--line-soft); text-align: left; vertical-align: top; }
  .asset-table thead th { border-top: 0; color: var(--muted); font-size: 12px; font-weight: 700; background: var(--surface-muted); }
  .asset-table strong, .asset-table small, .asset-table td > span { display: block; }
  .asset-table small { color: var(--muted); margin-top: 2px; }
  .agent-unprofiled td { background: #fff8e1; }
  .profile-warning { color: var(--warn); font-weight: 700; }
  .profile-link { display: inline-block; margin-top: 6px; font-weight: 600; }
  .state-ok { color: var(--ok); font-weight: 700; }
  .state-warn { color: var(--warn); font-weight: 700; }
  .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .dot-ok { background: var(--ok); }
  .dot-warn { background: var(--warn); }
  .status-row { display: grid; grid-template-columns: 10px minmax(0, .8fr) minmax(0, 1fr); gap: 4px 8px; align-items: center; padding: 10px 14px; border-top: 1px solid var(--line-soft); }
  .status-row:first-child { border-top: 0; }
  .status-row span { color: var(--muted); }
  .status-row strong { text-align: right; font-size: 13px; }
  .status-row small { grid-column: 2 / 4; color: var(--muted); font-size: 12px; }
  .self-test { margin: 0; border-top: 1px solid var(--line-soft); padding: 12px 14px; }
  .self-test-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .self-test-head h3 { margin: 0; font-size: 14px; }
  .check-button { min-height: 30px; border: 1px solid var(--line); background: var(--surface); color: var(--text); border-radius: 6px; padding: 0 10px; font-weight: 600; cursor: pointer; }
  .check-button:hover { background: var(--surface-muted); }
  .self-result { margin-top: 10px; border: 1px solid var(--line-soft); border-radius: 6px; padding: 10px; background: var(--surface-muted); max-height: 360px; overflow: auto; }
  .quiet-links { display: grid; padding: 8px 14px 12px; }
  .quiet-links a { padding: 7px 0; border-top: 1px solid var(--line-soft); }
  .quiet-links a:first-child { border-top: 0; }
  .tech-grid { display: grid; grid-template-columns: 70px minmax(0, 1fr); gap: 6px; margin-top: 8px; }
  code { background: var(--surface-muted); border: 1px solid var(--line-soft); border-radius: 4px; padding: 1px 4px; overflow-wrap: anywhere; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .empty-state { padding: 14px; border: 0; background: var(--surface); }
  .empty-state strong, .empty-state span { display: block; }
  .empty-state span { color: var(--muted); margin-top: 4px; }
  @media (max-width: 900px) {
    .management-top-inner, .management-main { width: min(100% - 24px, 1180px); }
    .status-strip, .management-grid, .summary-row { grid-template-columns: 1fr; }
    .next-action, .summary-item { border-left: 0; border-top: 1px solid var(--line-soft); padding-left: 0; padding-top: 12px; }
    .summary-item:first-child { border-top: 0; }
    .todo-row { grid-template-columns: 1fr; }
  }
  @media (max-width: 560px) {
    .management-top-inner { align-items: flex-start; flex-direction: column; padding: 10px 0; }
  }
  .cal-shell {
    --surface: #ffffff;
    --surface-muted: #f7f8fa;
    --text: #111827;
    --muted: #6b7280;
    --line: #e5e7eb;
    --line-strong: #d1d5db;
    --accent: #111827;
    --accent-soft: #f3f4f6;
    --blue: #2563eb;
    --ok: #16803c;
    --warn: #b7791f;
    --high: #d92d20;
    height: 100vh; min-height: 100vh; overflow-y: auto; overscroll-behavior: contain;
    background: #f7f8fa;
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Noto Sans TC", "Segoe UI", sans-serif;
  }
  .cal-shell * { box-shadow: none; letter-spacing: 0; }
  .cal-top {
    position: sticky; top: 0; z-index: 10;
    background: #ffffff;
    border-bottom: 1px solid var(--line);
  }
  .cal-top-inner {
    width: min(1160px, calc(100% - 32px)); min-height: 64px; margin: 0 auto;
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
  }
  .cal-brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .cal-mark {
    width: 30px; height: 30px; border-radius: 7px; background: #111827;
    display: inline-flex; align-items: center; justify-content: center; color: #ffffff; font-size: 13px; font-weight: 800;
  }
  .cal-brand strong { display: block; font-size: 15px; line-height: 1.2; }
  .cal-brand span { display: block; margin-top: 1px; color: var(--muted); font-size: 12px; }
  .cal-updated { color: var(--muted); font-size: 12px; white-space: nowrap; }
  .cal-main { width: min(1160px, calc(100% - 32px)); margin: 0 auto; padding: 22px 0 44px; }
  .cal-tabs {
    display: flex; align-items: center; gap: 4px; margin-bottom: 16px;
    border-bottom: 1px solid var(--line); overflow-x: auto;
  }
  .cal-tab {
    flex: 0 0 auto; min-height: 38px; display: inline-flex; align-items: center;
    padding: 0 12px; border-bottom: 2px solid transparent;
    color: var(--muted); font-size: 14px; font-weight: 650; text-decoration: none;
  }
  .cal-tab:hover { color: var(--text); text-decoration: none; }
  .cal-tab.active { color: var(--text); border-bottom-color: var(--text); }
  .cal-layout {
    display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 18px; align-items: start;
  }
  .cal-layout-services {
    grid-template-columns: minmax(0, 1fr);
  }
  .cal-layout-services .cal-aside {
    display: none;
  }
  .cal-primary, .cal-aside { display: grid; gap: 16px; min-width: 0; }
  .cal-hero, .cal-panel, .section-card {
    background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
  }
  .cal-hero { padding: 20px; }
  .cal-kicker { color: var(--muted); font-size: 12px; font-weight: 750; }
  .cal-hero h1 { margin: 6px 0 8px; font-size: 28px; line-height: 1.18; font-weight: 760; }
  .cal-hero p { margin: 0; max-width: 720px; color: var(--muted); font-size: 15px; }
  .score-panel {
    display: grid; grid-template-columns: 132px minmax(0, 1fr) auto; gap: 18px; align-items: center;
    background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 20px;
  }
  .score-ring {
    width: 108px; height: 108px; border-radius: 50%; border: 8px solid #111827;
    display: grid; place-content: center; text-align: center; background: #ffffff;
  }
  .score-ring strong { display: block; font-size: 34px; line-height: 1; }
  .score-ring span { display: block; margin-top: 4px; color: var(--muted); font-size: 12px; font-weight: 700; }
  .score-ok .score-ring { border-color: var(--ok); }
  .score-warn .score-ring { border-color: #f59e0b; }
  .score-high .score-ring { border-color: var(--high); }
  .score-label { color: var(--muted); font-size: 13px; font-weight: 750; }
  .score-copy h1 { margin: 4px 0 6px; font-size: 26px; line-height: 1.2; }
  .score-copy p { margin: 0; color: var(--muted); font-size: 15px; }
  .score-copy small, .endpoint-score-copy small { display: block; margin-top: 6px; color: var(--muted); font-size: 12px; }
  .score-actions { display: flex; flex-wrap: wrap; gap: 10px; justify-content: flex-end; }
  .primary-action, .secondary-action {
    min-height: 38px; display: inline-flex; align-items: center; justify-content: center;
    border-radius: 8px; padding: 0 14px; font-weight: 700; text-decoration: none; white-space: nowrap;
  }
  .primary-action { background: #111827; color: #ffffff; border: 1px solid #111827; }
  .secondary-action { background: #ffffff; color: var(--text); border: 1px solid var(--line-strong); }
  .primary-action:hover, .secondary-action:hover { text-decoration: none; }
  .primary-action:hover { background: #1f2937; }
  .secondary-action:hover { background: var(--surface-muted); }
  .flow-steps {
    list-style: none; margin: 18px 0 0; padding: 0;
    display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); border: 1px solid var(--line); border-radius: 8px; overflow: hidden;
  }
  .flow-steps li {
    min-width: 0; display: grid; grid-template-columns: 32px minmax(0, 1fr); gap: 10px;
    padding: 12px; border-left: 1px solid var(--line); background: #ffffff;
  }
  .flow-steps li:first-child { border-left: 0; }
  .flow-steps span {
    width: 28px; height: 28px; border-radius: 50%; background: var(--accent-soft);
    display: inline-flex; align-items: center; justify-content: center; font-weight: 750; font-size: 13px;
  }
  .flow-steps .active span { background: #111827; color: #ffffff; }
  .flow-steps strong { display: block; font-size: 13px; }
  .flow-steps small { display: block; margin-top: 2px; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
  .owner-flow {
    list-style: none; margin: 0; padding: 8px 16px 16px; display: grid; gap: 10px;
  }
  .owner-flow li {
    display: grid; grid-template-columns: minmax(120px, .35fr) minmax(0, 1fr) auto;
    gap: 12px; align-items: center; min-height: 54px; padding: 12px;
    border: 1px solid var(--line); border-radius: 8px; background: #ffffff;
  }
  .owner-flow li.active { border-left: 4px solid #111827; padding-left: 9px; }
  .owner-flow li.done { border-left: 4px solid var(--ok); padding-left: 9px; }
  .owner-flow strong { font-size: 14px; }
  .owner-flow span { color: var(--muted); font-size: 13px; }
  .owner-flow a {
    min-height: 32px; display: inline-flex; align-items: center; justify-content: center;
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 0 10px;
    color: var(--text); font-size: 13px; font-weight: 650; white-space: nowrap;
  }
  .owner-flow a:hover { background: var(--surface-muted); text-decoration: none; }
  .owner-flow.compact { padding-top: 0; }
  .setup-panel { align-items: center; }
  .setup-checklist {
    list-style: none; margin: 0; padding: 8px 16px 16px; display: grid; gap: 10px;
  }
  .setup-checklist li {
    display: grid; grid-template-columns: 82px minmax(160px, .5fr) minmax(0, 1fr) auto;
    gap: 12px; align-items: center; min-height: 62px; padding: 12px;
    border: 1px solid var(--line); border-radius: 8px; background: #ffffff;
  }
  .setup-checklist li.done { border-left: 4px solid var(--ok); padding-left: 9px; }
  .setup-checklist li.active { border-left: 4px solid #111827; padding-left: 9px; }
  .setup-checklist li.pending { opacity: .72; }
  .setup-checklist span {
    display: inline-flex; align-items: center; justify-content: center; min-height: 26px;
    border: 1px solid var(--line); border-radius: 999px; color: var(--muted); font-size: 12px; font-weight: 750;
    background: var(--surface-muted);
  }
  .setup-checklist li.done span { color: var(--ok); background: #f0fdf4; }
  .setup-checklist li.active span { color: var(--text); background: #ffffff; border-color: var(--line-strong); }
  .setup-checklist strong { font-size: 14px; }
  .setup-checklist p { margin: 0; color: var(--muted); font-size: 13px; }
  .setup-checklist a {
    min-height: 34px; display: inline-flex; align-items: center; justify-content: center;
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 0 10px;
    color: var(--text); font-size: 13px; font-weight: 650; white-space: nowrap;
  }
  .setup-checklist a:hover { background: var(--surface-muted); text-decoration: none; }
  .cal-panel { overflow: hidden; }
  .cal-panel-head, .section-head {
    display: flex; align-items: flex-start; justify-content: flex-start; gap: 16px;
    padding: 14px 16px; border-bottom: 1px solid var(--line); margin: 0;
  }
  .section-title { min-width: 0; }
  .cal-panel-head h2, .section-head h2 { margin: 0; font-size: 16px; line-height: 1.3; }
  .cal-panel-head p, .section-head p { margin: 4px 0 0; color: var(--muted); font-size: 13px; display: block; }
  .task-list { display: grid; }
  .cal-task {
    display: grid; grid-template-columns: 70px minmax(0, 1fr) 150px; gap: 16px;
    padding: 16px; border-top: 1px solid var(--line); background: #ffffff;
  }
  .cal-task:first-child { border-top: 0; }
  .cal-task-high, .cal-task-critical { border-left: 3px solid var(--high); }
  .cal-task-medium { border-left: 3px solid var(--warn); }
  .task-time span, .task-owner span { display: block; color: var(--muted); font-size: 12px; }
  .task-time strong { display: block; margin-top: 2px; font-size: 15px; }
  .task-body { min-width: 0; }
  .task-meta { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; color: var(--muted); font-size: 12px; margin-bottom: 6px; }
  .risk-pill {
    display: inline-flex; align-items: center; min-height: 22px; padding: 0 8px; border-radius: 999px;
    background: #eef2ff; color: #3730a3; font-weight: 750;
  }
  .risk-high { background: #fef3f2; color: var(--high); }
  .risk-medium { background: #fffbeb; color: #92400e; }
  .risk-info { background: #eff6ff; color: #1d4ed8; }
  .repeat-pill {
    display: inline-flex; align-items: center; min-height: 22px; padding: 0 8px; border-radius: 999px;
    background: var(--surface-muted); color: var(--muted); font-weight: 750;
  }
  .task-body h3 { margin: 0 0 6px; font-size: 16px; line-height: 1.45; }
  .task-body p { margin: 0; color: var(--muted); font-size: 14px; }
  .task-action {
    margin-top: 12px; border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px;
    background: var(--surface-muted);
  }
  .task-action span { display: block; color: var(--muted); font-size: 12px; font-weight: 750; }
  .task-action strong { display: block; margin-top: 3px; font-size: 14px; line-height: 1.45; }
  .task-steps { margin: 8px 0 0; padding-left: 20px; color: var(--text); }
  .task-steps li { margin-top: 4px; font-size: 13px; line-height: 1.45; }
  .task-owner {
    min-width: 0; border-left: 1px solid var(--line); padding-left: 14px;
  }
  .task-owner strong { display: block; margin-top: 2px; font-size: 14px; overflow-wrap: anywhere; }
  .case-status {
    display: inline-flex; align-items: center; justify-content: center; min-height: 26px;
    margin-top: 10px; border-radius: 999px; padding: 0 9px;
    font-size: 12px; font-weight: 800; border: 1px solid var(--line);
    background: #ffffff; color: var(--text);
  }
  .case-open { background: #fffbeb; color: #92400e; border-color: #f6d58a; }
  .case-progress { background: #eff6ff; color: #1d4ed8; border-color: #bfdbfe; }
  .case-closed { background: #f0fdf4; color: var(--ok); border-color: #bbf7d0; }
  .case-actions {
    display: grid; grid-template-columns: 1fr; gap: 7px; margin-top: 10px;
  }
  .case-form { margin: 0; }
  .case-form button {
    width: 100%; min-height: 32px; border: 1px solid var(--line-strong);
    border-radius: 7px; background: #ffffff; color: var(--text);
    font: inherit; font-size: 13px; font-weight: 750; cursor: pointer;
  }
  .case-form button:hover { background: var(--surface-muted); }
  .owner-link {
    display: inline-flex; align-items: center; justify-content: center; min-height: 32px;
    margin-top: 10px; border: 1px solid var(--line-strong); border-radius: 7px;
    padding: 0 10px; background: #ffffff; color: var(--text); font-size: 13px; font-weight: 650;
  }
  .owner-link:hover { background: var(--surface-muted); text-decoration: none; }
  .reply-note {
    margin-top: 10px; padding-left: 10px; border-left: 3px solid var(--line);
    color: var(--muted); font-size: 12px; line-height: 1.45; font-weight: 650;
  }
  .events { overflow: visible; }
  .todo-tech { margin-top: 12px; border: 0; padding: 0; font-size: 12px; }
  .todo-tech summary {
    min-height: 34px; display: flex; align-items: center; justify-content: space-between;
    width: 100%; border: 1px solid var(--line); border-radius: 7px; padding: 0 10px;
    background: #ffffff; color: var(--text); font-weight: 700; cursor: pointer; list-style: none;
  }
  .todo-tech summary::-webkit-details-marker { display: none; }
  .todo-tech summary::after { content: "⌄"; color: var(--muted); font-size: 13px; }
  .todo-tech[open] summary { background: var(--surface-muted); }
  .todo-tech[open] summary::after { content: "⌃"; }
  .tech-grid { display: grid; grid-template-columns: 82px minmax(0, 1fr); gap: 7px; margin-top: 8px; }
  code { background: var(--surface-muted); border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px; overflow-wrap: anywhere; }
  .summary-card { padding: 16px; }
  .summary-card h2 { margin: 0 0 12px; font-size: 16px; }
  .summary-metric { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; padding: 10px 0; border-top: 1px solid var(--line); }
  .summary-metric:first-of-type { border-top: 0; padding-top: 0; }
  .summary-metric span { color: var(--muted); font-size: 13px; }
  .summary-metric strong { font-size: 15px; text-align: right; }
  .next-step-card { padding: 16px; border-left: 3px solid var(--accent); }
  .next-step-card h2 { margin: 0 0 8px; font-size: 16px; }
  .next-step-card p { margin: 0; color: var(--muted); }
  .service-next-card { border-left-color: #f59e0b; }
  .status-row { display: grid; grid-template-columns: 10px minmax(0, .8fr) minmax(0, 1fr); gap: 4px 8px; align-items: center; padding: 10px 16px; border-top: 1px solid var(--line); }
  .status-row:first-child { border-top: 0; }
  .status-row span { color: var(--muted); }
  .status-row strong { text-align: right; font-size: 13px; }
  .status-row small { grid-column: 2 / 4; color: var(--muted); font-size: 12px; }
  .install-menu { position: relative; justify-self: start; }
  .install-menu summary {
    display: inline-flex; align-items: center; justify-content: center; min-height: 32px;
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 0 12px;
    background: #ffffff; color: var(--text); font-size: 13px; font-weight: 650;
    cursor: pointer; list-style: none; white-space: nowrap;
  }
  .install-menu summary::-webkit-details-marker { display: none; }
  .install-menu summary::after { content: "⌄"; margin-left: 8px; color: var(--muted); font-size: 12px; }
  .install-menu[open] summary { background: var(--surface-muted); }
  .download-grid {
    position: absolute; top: calc(100% + 8px); left: 0; z-index: 20;
    width: min(560px, calc(100vw - 40px)); display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px; padding: 10px; border: 1px solid var(--line); border-radius: 8px;
    background: #ffffff; box-shadow: 0 12px 28px rgba(31,35,40,.14);
  }
  .install-hint { grid-column: 1 / -1; margin: 0 0 2px; color: var(--muted); font-size: 12px; }
  .download-button {
    min-width: 0; display: grid; gap: 2px; padding: 10px 12px; border: 1px solid var(--line);
    border-radius: 8px; background: #ffffff; color: var(--text); text-decoration: none;
  }
  .download-button:hover { background: var(--surface-muted); text-decoration: none; }
  .download-button span { color: var(--muted); font-size: 12px; }
  .download-button strong { font-size: 13px; overflow-wrap: anywhere; }
  .install-steps { grid-column: 1 / -1; border: 1px solid var(--line); border-radius: 8px; background: #ffffff; }
  .install-steps summary {
    min-height: 34px; padding: 0 10px; border: 0; border-radius: 8px; justify-content: flex-start;
    color: var(--text); background: #ffffff; font-size: 13px;
  }
  .install-steps[open] summary { border-bottom: 1px solid var(--line); border-radius: 8px 8px 0 0; }
  .install-steps p { margin: 10px 10px 6px; color: var(--muted); font-size: 12px; }
  .install-steps pre {
    margin: 8px 10px 10px; padding: 10px; border: 1px solid var(--line); border-radius: 6px;
    background: var(--surface-muted); color: var(--text); font-size: 12px; line-height: 1.5;
    white-space: pre-wrap; overflow-wrap: anywhere;
  }
  .service-panel { overflow: visible; padding: 0; }
  .endpoint-score-card {
    display: grid; grid-template-columns: 96px minmax(0, 1fr) auto; gap: 16px; align-items: center;
    margin: 14px 16px; padding: 14px; border: 1px solid var(--line); border-radius: 8px;
    background: #ffffff;
  }
  .endpoint-score-number {
    width: 78px; height: 78px; border-radius: 50%; border: 6px solid #111827;
    display: grid; place-content: center; text-align: center;
  }
  .endpoint-score-number strong { display: block; font-size: 25px; line-height: 1; }
  .endpoint-score-number span { display: block; margin-top: 3px; color: var(--muted); font-size: 11px; font-weight: 700; }
  .endpoint-score-card.score-ok .endpoint-score-number { border-color: var(--ok); }
  .endpoint-score-card.score-warn .endpoint-score-number { border-color: #f59e0b; }
  .endpoint-score-card.score-high .endpoint-score-number { border-color: var(--high); }
  .endpoint-score-copy span { display: block; color: var(--muted); font-size: 12px; font-weight: 750; }
  .endpoint-score-copy strong { display: block; margin-top: 2px; font-size: 18px; line-height: 1.3; }
  .endpoint-score-copy p { margin: 4px 0 0; color: var(--muted); font-size: 13px; }
  .service-list-v2 { display: grid; }
  .service-card {
    display: grid; grid-template-columns: 10px minmax(260px, 1fr) minmax(360px, 460px) minmax(260px, 1fr); gap: 20px;
    padding: 16px; border-top: 1px solid var(--line); align-items: start; background: #ffffff;
  }
  .service-card:first-child { border-top: 0; }
  .service-card.agent-unprofiled {
    margin: 0; border-radius: 0; background: #ffffff;
    border-left: 3px solid #f59e0b; padding-left: 13px; padding-right: 16px;
  }
  .service-card > .dot { margin-top: 8px; }
  .service-main strong, .service-main small { display: block; }
  .service-main small { color: var(--muted); margin-top: 2px; }
  .business-context {
    min-width: 0; display: grid; gap: 5px; align-content: center;
    padding: 0;
  }
  .business-context div {
    display: grid; grid-template-columns: 42px minmax(0, 1fr); gap: 8px; align-items: baseline;
  }
  .business-context b { color: var(--muted); font-size: 12px; font-weight: 650; }
  .business-context strong {
    min-width: 0; color: var(--text); font-size: 14px; line-height: 1.35; font-weight: 720;
    overflow-wrap: anywhere;
  }
  .business-empty {
    width: 100%; min-height: 64px; display: flex; align-items: center; justify-content: center;
    padding: 0;
  }
  .service-status {
    grid-column: 3; align-self: center; justify-self: center; width: min(100%, 460px);
    display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; align-items: center;
  }
  .service-status:empty { display: none; }
  .context-empty strong { color: var(--muted); font-weight: 650; }
  .endpoint-row-score {
    grid-column: 4; justify-self: end; align-self: center;
    min-width: 96px; border: 1px solid var(--line); border-left: 4px solid var(--ok);
    border-radius: 8px; padding: 10px 12px; background: #ffffff;
  }
  .endpoint-row-score.score-warn { border-left-color: #f59e0b; }
  .endpoint-row-score.score-high { border-left-color: var(--high); }
  .endpoint-score-detail { cursor: pointer; }
  .endpoint-score-detail summary {
    display: block; list-style: none;
  }
  .endpoint-score-detail summary::-webkit-details-marker { display: none; }
  .endpoint-score-detail summary::after {
    content: "分數說明"; display: inline-flex; margin-top: 8px; min-height: 26px; align-items: center;
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 0 8px;
    color: var(--text); background: #ffffff; font-size: 12px; font-weight: 700;
  }
  .endpoint-score-detail[open] summary::after { content: "收起說明"; }
  .endpoint-row-score strong { display: block; font-size: 24px; line-height: 1; color: var(--text); }
  .endpoint-row-score span { display: block; margin-top: 4px; font-size: 12px; font-weight: 750; color: var(--text); }
  .endpoint-row-score small { display: block; margin-top: 2px; color: var(--muted); font-size: 12px; }
  .endpoint-score-breakdown {
    margin-top: 10px; border-top: 1px solid var(--line); padding-top: 8px;
  }
  .endpoint-score-breakdown b { display: block; margin-bottom: 6px; font-size: 12px; }
  .endpoint-score-breakdown div {
    display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; padding: 4px 0;
  }
  .endpoint-score-breakdown div span { margin: 0; color: var(--muted); font-weight: 650; }
  .endpoint-score-breakdown div strong { font-size: 12px; text-align: right; }
  .profile-link {
    display: inline-flex; align-items: center; justify-content: center; min-height: 32px;
    border: 1px solid var(--line-strong); border-radius: 7px; padding: 0 10px;
    margin: 0; background: #ffffff; color: var(--text); font-size: 13px; font-weight: 650; white-space: nowrap;
  }
  .profile-link:hover { background: var(--surface-muted); text-decoration: none; }
  .icon-link {
    width: 32px; padding: 0; font-size: 15px; line-height: 1;
  }
  .drawer-backdrop {
    position: fixed; inset: 0; z-index: 40; display: none;
    background: rgba(17, 24, 39, .28);
  }
  .drawer-backdrop.open { display: block; }
  .drawer-panel {
    position: absolute; top: 0; right: 0; width: min(520px, 100vw); height: 100%;
    background: #ffffff; border-left: 1px solid var(--line); box-shadow: -12px 0 32px rgba(15, 23, 42, .16);
    transform: translateX(100%); transition: transform .18s ease; display: grid; grid-template-rows: 52px minmax(0, 1fr);
  }
  .drawer-backdrop.open .drawer-panel { transform: translateX(0); }
  .drawer-head {
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    padding: 0 16px; border-bottom: 1px solid var(--line);
  }
  .drawer-head strong { font-size: 14px; }
  .drawer-close {
    width: 44px; height: 44px; border: 1px solid var(--line-strong); border-radius: 8px;
    background: #ffffff; color: var(--text); cursor: pointer; font-size: 24px; line-height: 1;
  }
  .drawer-close:hover { background: var(--surface-muted); }
  .drawer-frame { width: 100%; height: 100%; border: 0; }
  .service-tech {
    grid-column: 2 / 5; margin: 0; border-top: 1px solid var(--line); padding-top: 10px;
    min-width: 0; font-size: 13px;
  }
  .service-tech summary {
    display: inline-flex; color: var(--muted); font-weight: 650; cursor: pointer; outline-offset: 2px;
  }
  .service-tech summary:focus-visible { outline: 2px solid var(--line-strong); border-radius: 4px; }
  .service-tech[open] summary { color: var(--text); margin-bottom: 10px; }
  .service-tech-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
  .tech-field {
    min-width: 0; border: 1px solid var(--line); border-radius: 7px; padding: 8px 10px;
    background: var(--surface-muted);
  }
  .tech-field span { display: block; margin-bottom: 3px; color: var(--muted); font-size: 12px; }
  .tech-field code {
    display: block; border: 0; background: transparent; padding: 0; border-radius: 0;
    color: var(--text); overflow-wrap: anywhere; word-break: break-word;
  }
  .quiet-links { display: grid; padding: 8px 16px 14px; }
  .quiet-links a, .quiet-links .disabled-link { padding: 8px 0; border-top: 1px solid var(--line); }
  .quiet-links a:first-child, .quiet-links .disabled-link:first-child { border-top: 0; }
  .disabled-link { color: var(--muted); cursor: not-allowed; }
  .top-rules { list-style: none; margin: 0; padding: 8px 16px 14px; display: grid; }
  .top-rules li { display: grid; grid-template-columns: 42px minmax(0, 1fr); gap: 10px; padding: 10px 0; border-top: 1px solid var(--line); }
  .top-rules li:first-child { border-top: 0; }
  .top-rules strong { font-size: 18px; line-height: 1.2; }
  .top-rules span { color: var(--muted); overflow-wrap: anywhere; }
  .self-test { margin: 0; border-top: 1px solid var(--line); padding: 14px 16px; }
  .self-test-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .self-test-head h3 { margin: 0; font-size: 14px; }
  .check-button { min-height: 32px; border: 1px solid var(--line-strong); background: #ffffff; color: var(--text); border-radius: 7px; padding: 0 12px; font-weight: 650; cursor: pointer; }
  .check-button:hover { background: var(--surface-muted); }
  .self-result { margin-top: 10px; border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: var(--surface-muted); max-height: 360px; overflow: auto; }
  .notification-list { display: grid; padding: 6px 16px 14px; }
  .notification-list div { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; padding: 10px 0; border-top: 1px solid var(--line); }
  .notification-list div:first-child { border-top: 0; }
  .notification-list span { color: var(--muted); font-size: 13px; }
  .notification-list strong { font-size: 13px; text-align: right; }
  .empty-state { padding: 16px; border: 0; background: #ffffff; }
  .empty-state strong, .empty-state span { display: block; }
  .empty-state span { color: var(--muted); margin-top: 4px; }
  a { color: var(--blue); text-decoration: none; }
  a:hover { text-decoration: underline; }
  @media (max-width: 960px) {
    .cal-layout { grid-template-columns: 1fr; }
    .cal-layout-services .cal-aside { grid-template-columns: 1fr; }
    .score-panel { grid-template-columns: 110px minmax(0, 1fr); }
    .score-actions { grid-column: 1 / 3; justify-content: flex-start; }
    .score-ring { width: 96px; height: 96px; }
    .owner-flow li { grid-template-columns: 1fr; align-items: start; }
    .owner-flow a { justify-self: start; }
    .setup-checklist li { grid-template-columns: 1fr; align-items: start; }
    .setup-checklist span, .setup-checklist a { justify-self: start; }
    .endpoint-score-card { grid-template-columns: 86px minmax(0, 1fr); }
    .endpoint-score-card .primary-action { grid-column: 1 / 3; justify-self: start; }
    .cal-task { grid-template-columns: 70px minmax(0, 1fr); }
    .task-owner { grid-column: 2; border-left: 0; border-top: 1px solid var(--line); padding: 10px 0 0; }
    .service-card { grid-template-columns: 18px minmax(0, 1fr); align-items: start; }
    .service-status, .endpoint-row-score, .service-tech { grid-column: 2; }
    .service-status { margin-top: 10px; }
    .endpoint-row-score { justify-self: start; min-width: 120px; }
    .service-tech-grid { grid-template-columns: 1fr; }
  }
  @media (max-width: 640px) {
    .cal-top-inner { align-items: flex-start; flex-direction: column; padding: 10px 0; }
    .cal-main, .cal-top-inner { width: min(100% - 24px, 1160px); }
    .flow-steps, .cal-task { grid-template-columns: 1fr; }
    .score-panel { grid-template-columns: 1fr; }
    .score-ring { width: 108px; height: 108px; }
    .score-actions { grid-column: auto; }
    .endpoint-score-card { grid-template-columns: 1fr; }
    .endpoint-score-card .primary-action { grid-column: auto; justify-self: stretch; }
    .endpoint-score-number { width: 84px; height: 84px; }
    .section-head { align-items: flex-start; }
    .download-grid { width: min(320px, calc(100vw - 32px)); grid-template-columns: 1fr; }
    .service-status { grid-template-columns: 1fr; }
    .icon-link { width: 100%; }
    .flow-steps li { border-left: 0; border-top: 1px solid var(--line); }
    .flow-steps li:first-child { border-top: 0; }
    .task-owner { grid-column: auto; }
    .tech-grid { grid-template-columns: 1fr; }
  }
"""

DASHBOARD_JS = r"""
const button = document.getElementById("self-test-button");
const result = document.getElementById("self-test-result");
const iconMap = { ok: "✓", warn: "!", fail: "×", skip: "·" };
const drawer = document.getElementById("context-drawer");
const drawerFrame = drawer ? drawer.querySelector(".drawer-frame") : null;
const drawerClose = drawer ? drawer.querySelector(".drawer-close") : null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}

function renderSelfTest(data) {
  const overall = data.overall || "warn";
  result.className = `self-result result-${overall}`;
  const checks = (data.checks || []).map((check) => {
    const icon = iconMap[check.status] || "?";
    const detail = check.detail_zh
      ? `<details><summary>給 IT 的細節</summary><code>${escapeHtml(check.detail_zh)}</code></details>`
      : "";
    return `
      <li>
        <span class="check-icon">${icon}</span>
        <div>
          <b>${escapeHtml(check.label_zh)}</b>
          <span>${escapeHtml(check.summary_zh)}</span>
          ${check.next_step_zh ? `<span>${escapeHtml(check.next_step_zh)}</span>` : ""}
        </div>
        ${detail}
      </li>`;
  }).join("");
  result.innerHTML = `
    <strong>${escapeHtml(data.title_zh || "檢查完成")}</strong>
    <p>${escapeHtml(data.message_zh || "")}</p>
    ${data.next_step_zh ? `<p>${escapeHtml(data.next_step_zh)}</p>` : ""}
    <ul class="check-list">${checks}</ul>`;
}

if (button && result) {
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "檢查中";
    result.className = "self-result";
    result.innerHTML = "<strong>檢查中</strong><p>正在確認系統服務狀態，請稍候。</p>";
    try {
      const response = await fetch("/self-test", { headers: { "Accept": "application/json" } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      renderSelfTest(await response.json());
    } catch (err) {
      result.className = "self-result result-fail";
      result.innerHTML = "<strong>自我檢查無法執行</strong><p>請 IT 檢查 EdgeSec-Pi API 是否正常。</p>";
    } finally {
      button.disabled = false;
      button.textContent = "重新檢查";
    }
  });
}

function drawerUrl(url) {
  const next = new URL(url, window.location.origin);
  next.searchParams.set("embed", "1");
  return next.toString();
}

if (drawer && drawerFrame && drawerClose) {
  document.addEventListener("click", (event) => {
    document.querySelectorAll(".install-menu[open]").forEach((menu) => {
      if (!menu.contains(event.target)) menu.removeAttribute("open");
    });
  });
  document.querySelectorAll('a[href^="/admin/quick-add"], a[href*="/admin/quick-add"]').forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      drawerFrame.src = drawerUrl(link.href);
      drawer.classList.add("open");
      drawer.setAttribute("aria-hidden", "false");
      drawerClose.focus();
    });
  });
  function closeDrawer() {
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    drawerFrame.removeAttribute("src");
  }
  drawerClose.addEventListener("click", closeDrawer);
  drawer.addEventListener("click", (event) => {
    if (event.target === drawer) closeDrawer();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && drawer.classList.contains("open")) closeDrawer();
  });
  window.addEventListener("message", (event) => {
    if (event.origin === window.location.origin && event.data && event.data.type === "edgesec-close-drawer") {
      closeDrawer();
      if (event.data.refresh) window.location.reload();
    }
  });
}
"""
